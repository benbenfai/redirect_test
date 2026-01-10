import pydivert
import ipaddress
import time
import socket
import struct
from functools import lru_cache

# -----------------------------
# Config
# -----------------------------
SSL_PORTS = {12, 13, 14, 15, 16, 17, 18, 19, 20, 22, 443, 2053, 2083, 2087, 2096, 8443, 853}

VERBOSE_FLOW_ASSIGN = False
VERBOSE_FALLBACK = True
VERBOSE_CLEANUP = False

CLEANUP_INTERVAL = 180
FLOW_IDLE_TIMEOUT = 180

PROTO_TCP = 6
PROTO_UDP = 17

# -----------------------------
# IP helpers
# -----------------------------
@lru_cache(maxsize=200000)
def ip_to_int(ip_str: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", ip_int))

# -----------------------------
# Cloudflare ranges
# -----------------------------
CLOUDFLARE_RANGES_INT = []

with open("cloudflare.txt", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        start_int = int(net.network_address)
        end_int = int(net.broadcast_address)
        CLOUDFLARE_RANGES_INT.append((start_int, end_int))

def is_cloudflare_ip_int(ip_int: int) -> bool:
    for start, end in CLOUDFLARE_RANGES_INT:
        if start <= ip_int <= end:
            return True
    return False

# -----------------------------
# Targets
# -----------------------------
with open("target.txt", encoding="utf-8") as f:
    TARGET_IPS = [line.strip() for line in f if line.strip()]

if not TARGET_IPS:
    raise SystemExit("No targets in target.txt")

NUM_TARGETS = len(TARGET_IPS)
TARGET_IPS_INT = [ip_to_int(ip) for ip in TARGET_IPS]

# -----------------------------
# NAT state
# -----------------------------
nat_flow_target_index = {}
nat_map_outbound = {}
nat_map_inbound = {}
nat_flow_last_seen = {}
icmp_index = {}
dead_flows = set()

last_cleanup_time = time.time()

# -----------------------------
# Helpers
# -----------------------------
def icmp_index_add(target_ip_int, flow_key):
    flows = icmp_index.get(target_ip_int)
    if flows is None:
        flows = set()
        icmp_index[target_ip_int] = flows
    flows.add(flow_key)

def icmp_index_remove(target_ip_int, flow_key):
    flows = icmp_index.get(target_ip_int)
    if flows is not None:
        flows.discard(flow_key)
        if not flows:
            icmp_index.pop(target_ip_int, None)

def try_set_target_for_flow(current_index):
    if current_index is None:
        new_index = 0
    else:
        new_index = current_index + 1

    if new_index >= NUM_TARGETS:
        return None, None

    return TARGET_IPS_INT[new_index], new_index

def install_nat_mapping(flow_key, orig_dst_ip_int, target_ip_int, target_index):
    src_ip_int, src_port, _, dst_port, proto = flow_key

    nat_flow_target_index[flow_key] = target_index
    nat_map_outbound[flow_key] = target_ip_int

    rev_key = (target_ip_int, dst_port, src_ip_int, src_port, proto)
    nat_map_inbound[rev_key] = orig_dst_ip_int

    nat_flow_last_seen[flow_key] = time.time()
    icmp_index_add(target_ip_int, flow_key)

    if VERBOSE_FLOW_ASSIGN:
        print(f"[CF → TARGET] {int_to_ip(orig_dst_ip_int)} → {int_to_ip(target_ip_int)} (idx {target_index})")

def fallback_to_next_target(flow_key, orig_dst_ip_int, current_target_ip_int):
    current_index = nat_flow_target_index.get(flow_key)
    if current_index is None:
        return False

    target_ip_int, new_index = try_set_target_for_flow(current_index)
    if target_ip_int is None:
        if flow_key not in dead_flows:
            if VERBOSE_FALLBACK:
                print(f"[FALLBACK] No more targets for {int_to_ip(orig_dst_ip_int)}, all failed")
            dead_flows.add(flow_key)
        return False

    src_ip_int, src_port, _, dst_port, proto = flow_key
    old_rev_key = (current_target_ip_int, dst_port, src_ip_int, src_port, proto)
    nat_map_inbound.pop(old_rev_key, None)
    icmp_index_remove(current_target_ip_int, flow_key)

    nat_flow_target_index[flow_key] = new_index
    nat_map_outbound[flow_key] = target_ip_int

    new_rev_key = (target_ip_int, dst_port, src_ip_int, src_port, proto)
    nat_map_inbound[new_rev_key] = orig_dst_ip_int
    nat_flow_last_seen[flow_key] = time.time()
    icmp_index_add(target_ip_int, flow_key)

    if VERBOSE_FALLBACK:
        print(f"[FALLBACK] {int_to_ip(orig_dst_ip_int)} → {int_to_ip(target_ip_int)} (idx {new_index})")

    return True

def touch_flow(flow_key):
    if flow_key in nat_flow_last_seen:
        nat_flow_last_seen[flow_key] = time.time()

def cleanup_flows():
    global last_cleanup_time
    now = time.time()
    if now - last_cleanup_time <= CLEANUP_INTERVAL:
        return

    stale_keys = [
        fk for fk, last in nat_flow_last_seen.items()
        if now - last > FLOW_IDLE_TIMEOUT
    ]
    if not stale_keys:
        last_cleanup_time = now
        return

    for fk in stale_keys:
        dead_flows.discard(fk)

        target_ip_int = nat_map_outbound.pop(fk, None)
        nat_flow_target_index.pop(fk, None)

        src_ip_int, src_port, orig_dst_ip_int, dst_port, proto = fk

        if target_ip_int is not None:
            rev_key = (target_ip_int, dst_port, src_ip_int, src_port, proto)
            nat_map_inbound.pop(rev_key, None)
            icmp_index_remove(target_ip_int, fk)
        else:
            for key in list(nat_map_inbound.keys()):
                t_ip_int, t_port, c_ip_int, c_port, p = key
                if c_ip_int == src_ip_int and c_port == src_port and p == proto and t_port == dst_port:
                    nat_map_inbound.pop(key, None)
                    icmp_index_remove(t_ip_int, fk)

        nat_flow_last_seen.pop(fk, None)

    if VERBOSE_CLEANUP:
        print(f"[CLEANUP] Removed {len(stale_keys)} stale flows")

    last_cleanup_time = now

# -----------------------------
# WinDivert
# -----------------------------
FILTER = "ip and (tcp or udp or icmp)"

w = pydivert.WinDivert(FILTER)
w.open()

def send_packet_safe(pkt):
    try:
        w.send(pkt)
    except OSError:
        pass  # drop bad packet

print("NAT redirector running... (single-queue max-performance edition)")

get_outbound = nat_map_outbound.get
get_inbound = nat_map_inbound.get

# -----------------------------
# Main loop
# -----------------------------
try:
    for packet in w:

        cleanup_flows()

        if not packet.ipv4:
            send_packet_safe(packet)
            continue

        # ICMP fallback
        if packet.icmp:
            src_ip_int = ip_to_int(packet.src_addr)
            flows_for_target = icmp_index.get(src_ip_int)
            if flows_for_target:
                for flow_key in list(flows_for_target):
                    _, _, orig_dst_ip_int, dst_port, proto = flow_key
                    if flow_key not in dead_flows:
                        fallback_to_next_target(flow_key, orig_dst_ip_int, src_ip_int)
            send_packet_safe(packet)
            continue

        tcp = packet.tcp
        udp = packet.udp

        if not (tcp or udp):
            send_packet_safe(packet)
            continue

        proto = PROTO_TCP if tcp else PROTO_UDP

        # OUTBOUND
        if packet.is_outbound:
            dst_port = packet.dst_port
            if dst_port not in SSL_PORTS:
                send_packet_safe(packet)
                continue

            dst_ip_int = ip_to_int(packet.dst_addr)
            if not is_cloudflare_ip_int(dst_ip_int):
                send_packet_safe(packet)
                continue

            src_ip_int = ip_to_int(packet.src_addr)
            src_port = packet.src_port

            flow_key = (src_ip_int, src_port, dst_ip_int, dst_port, proto)

            target_ip_int = get_outbound(flow_key)
            if target_ip_int is None:
                target_ip_int, index = try_set_target_for_flow(None)
                if target_ip_int is None:
                    send_packet_safe(packet)
                    continue
                install_nat_mapping(flow_key, dst_ip_int, target_ip_int, index)

            touch_flow(flow_key)

            packet.dst_addr = int_to_ip(target_ip_int)
            packet.recalculate_checksums()
            send_packet_safe(packet)
            continue

        # INBOUND
        src_ip_int = ip_to_int(packet.src_addr)
        dst_ip_int = ip_to_int(packet.dst_addr)
        src_port = packet.src_port
        dst_port = packet.dst_port

        flow_key_inbound = (src_ip_int, src_port, dst_ip_int, dst_port, proto)

        if tcp and tcp.rst:
            orig_dst_ip_int = get_inbound(flow_key_inbound)
            if orig_dst_ip_int is not None:
                client_ip_int = dst_ip_int
                client_port = dst_port
                target_ip_int = src_ip_int

                flow_key = (client_ip_int, client_port, orig_dst_ip_int, src_port, proto)
                if flow_key not in dead_flows:
                    fallback_to_next_target(flow_key, orig_dst_ip_int, target_ip_int)
                touch_flow(flow_key)

            send_packet_safe(packet)
            continue

        orig_dst_ip_int = get_inbound(flow_key_inbound)
        if orig_dst_ip_int is not None and src_port in SSL_PORTS:
            client_ip_int = dst_ip_int
            client_port = dst_port

            flow_key = (client_ip_int, client_port, orig_dst_ip_int, src_port, proto)
            touch_flow(flow_key)

            packet.src_addr = int_to_ip(orig_dst_ip_int)
            packet.recalculate_checksums()
            send_packet_safe(packet)
        else:
            send_packet_safe(packet)

except KeyboardInterrupt:
    print("\nStopped.")

finally:
    w.close()
