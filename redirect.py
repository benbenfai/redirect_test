#!/usr/bin/env python3
"""
redirect_single_thread.py

- Single-threaded WinDivert capture + send in main thread.
- No packet cloning.
- Asyncio thread only for health checks (no sending).
- Local JSON metrics endpoint.

Run as Administrator on Windows.
"""

import ssl
import pydivert
import ipaddress
import time
import socket
import struct
import ctypes
import logging
import threading
import asyncio
from functools import lru_cache
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

import urllib.request

CLOUDFLARE_REFRESH_INTERVAL = 12 * 3600  # 12 hours
CLOUDFLARE_V4_URL = "https://www.cloudflare.com/ips-v4"

def refresh_cloudflare_ranges():
    global CLOUDFLARE_RANGES_INT
    cf_file = Path("cloudflare.txt")

    while True:
        time.sleep(CLOUDFLARE_REFRESH_INTERVAL)

        try:
            r = urllib.request.get(CLOUDFLARE_V4_URL, timeout=10)
            if r.status_code != 200:
                log.warning("Cloudflare refresh: HTTP %s", r.status_code)
                continue

            new_ranges = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    if net.version == 4:
                        new_ranges.append((int(net.network_address), int(net.broadcast_address)))
                except Exception:
                    log.warning("Cloudflare refresh: invalid CIDR %s", line)

            if not new_ranges:
                log.warning("Cloudflare refresh: empty list, skipping update")
                continue

            tmp = cf_file.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                for s, e in new_ranges:
                    f.write(f"{ipaddress.ip_network((s, e), strict=False)}\n")

            tmp.replace(cf_file)

            with state_lock:
                CLOUDFLARE_RANGES_INT = new_ranges

            log.info("Cloudflare ranges refreshed: %d networks", len(new_ranges))

        except Exception as e:
            log.warning("Cloudflare refresh failed: %s", e)

# Start the background refresher
threading.Thread(target=refresh_cloudflare_ranges, daemon=True).start()

TARGET_UPDATE_INTERVAL = 6 * 3600  # every 6 hours
TARGET_FILE = Path("target.txt")
TARGET_UPDATE_FILE = Path("targetUpdate.txt")
TEST_PORT = 443
TEST_SNI = "cloudflare.com"
TOP_N = 5  # keep fastest 5 targets

def measure_latency(ip):
    start = time.time()
    try:
        s = socket.create_connection((ip, TEST_PORT), timeout=2)
        s.close()
        return (time.time() - start) * 1000
    except:
        return float("inf")

def measure_tls(ip):
    ctx = ssl.create_default_context()
    start = time.time()
    try:
        s = socket.create_connection((ip, TEST_PORT), timeout=2)
        tls = ctx.wrap_socket(s, server_hostname=TEST_SNI)
        tls.close()
        return (time.time() - start) * 1000
    except:
        return float("inf")

def measure_udp_quic(ip, timeout=1.0):
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x00", (ip, 443))
        try:
            s.recvfrom(1024)
        except socket.timeout:
            pass
        finally:
            s.close()
        return (time.time() - start) * 1000
    except:
        return float("inf")

def score_target(ip):
    udp_ms = measure_udp_quic(ip)
    tcp_ms = measure_latency(ip)
    tls_ms = measure_tls(ip)

    score = udp_ms * 0.7 + tcp_ms * 0.2 + tls_ms * 0.1
    return score, udp_ms, tcp_ms, tls_ms

def update_targets():
    while True:
        time.sleep(TARGET_UPDATE_INTERVAL)

        try:
            ips = [line.strip() for line in TARGET_FILE.read_text().splitlines() if line.strip()]
            results = []

            for ip in ips:
                score, latency, tls = score_target(ip)
                results.append((score, ip, latency, tls))

            results.sort(key=lambda x: x[0])
            best = results[:TOP_N]

            with TARGET_UPDATE_FILE.open("w") as f:
                for _, ip, _, _ in best:
                    f.write(ip + "\n")

            TARGET_UPDATE_FILE.replace(TARGET_FILE)

            log.info("target.txt updated with fastest %d targets", TOP_N)
            for score, ip, latency, tls in best:
                log.info("  %s  latency=%.1fms  tls=%.1fms  score=%.1f",
                         ip, latency, tls, score)

            # reload in-memory target list
            with state_lock:
                global TARGET_IPS, TARGET_IPS_INT, NUM_TARGETS
                TARGET_IPS = [line.strip() for line in TARGET_FILE.read_text().splitlines() if line.strip()]
                TARGET_IPS_INT = [ip_to_int(ip) for ip in TARGET_IPS]
                NUM_TARGETS = len(TARGET_IPS)

            log.info("In-memory target list reloaded (%d targets)", NUM_TARGETS)

        except Exception as e:
            log.warning("Target update failed: %s", e)

# Start the background updater
threading.Thread(target=update_targets, daemon=True).start()


# -----------------------------
# Config
# -----------------------------
SSL_PORTS = {443, 8443, 2053, 2083, 2087, 2096, 853}
CLEANUP_INTERVAL = 180
FLOW_IDLE_TIMEOUT = 180

HEALTH_CHECK_INTERVAL = 10
HEALTH_CHECK_TIMEOUT = 2.0
ASYNC_PROBE_CONCURRENCY = 200
HEALTH_BACKOFF_BASE = 2
HEALTH_BACKOFF_MAX = 300

METRICS_HOST = "127.0.0.1"
METRICS_PORT = 8000

PROTO_TCP = 6
PROTO_UDP = 17

# -----------------------------
# Logging / startup checks
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nat-redirector")

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

if not is_admin():
    log.critical("This script must be run as Administrator.")
    raise SystemExit(1)

# -----------------------------
# IP helpers (IPv4 only)
# -----------------------------
@lru_cache(maxsize=8192)
def ip_to_int(ip_str: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]

def int_to_ip(ip_int: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def is_valid_ipv4(addr: str) -> bool:
    try:
        socket.inet_aton(addr)
        return True
    except Exception:
        return False

# -----------------------------
# Load cloudflare ranges (optional)
# -----------------------------
CLOUDFLARE_RANGES_INT = []
cf_path = Path("cloudflare.txt")
if cf_path.exists():
    with cf_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                log.warning("Skipping invalid network in cloudflare.txt: %s", line)
                continue
            if net.version != 4:
                log.warning("Skipping non-IPv4 network in cloudflare.txt: %s", line)
                continue
            CLOUDFLARE_RANGES_INT.append((int(net.network_address), int(net.broadcast_address)))
else:
    log.info("cloudflare.txt not found; Cloudflare filtering disabled.")

def is_cloudflare_ip_int(ip_int: int) -> bool:
    for s, e in CLOUDFLARE_RANGES_INT:
        if s <= ip_int <= e:
            return True
    return False

# -----------------------------
# Load targets
# -----------------------------
target_path = Path("target.txt")
if not target_path.exists():
    log.critical("target.txt not found.")
    raise SystemExit(1)

TARGET_IPS = []
with target_path.open(encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        if not is_valid_ipv4(line):
            log.warning("Skipping non-IPv4 or invalid target: %s", line)
            continue
        TARGET_IPS.append(line)

if not TARGET_IPS:
    log.critical("No valid IPv4 targets found in target.txt")
    raise SystemExit(1)

NUM_TARGETS = len(TARGET_IPS)
TARGET_IPS_INT = [ip_to_int(ip) for ip in TARGET_IPS]
log.info("Loaded %d targets", NUM_TARGETS)

# -----------------------------
# NAT state (shared)
# -----------------------------
nat_flow_target_index = {}
nat_map_outbound = {}
nat_map_inbound = {}
nat_flow_last_seen = {}
icmp_index = {}
dead_flows = set()
last_cleanup_time = time.time()

state_lock = threading.RLock()

def make_outbound_flow_key(src_ip_int, src_port, dst_ip_int, dst_port, proto):
    return (src_ip_int, src_port, dst_ip_int, dst_port, proto)

def make_inbound_rev_key(target_ip_int, target_port, client_ip_int, client_port, proto):
    return (target_ip_int, target_port, client_ip_int, client_port, proto)

def make_client_side_flow_key(client_ip_int, client_port, orig_dst_ip_int, orig_dst_port, proto):
    return (client_ip_int, client_port, orig_dst_ip_int, orig_dst_port, proto)

# -----------------------------
# Metrics
# -----------------------------
metrics = {
    "send_ok": 0,
    "send_fail": 0,
    "rotate_events": 0,
}

# -----------------------------
# NAT helpers
# -----------------------------
def icmp_index_add(target_ip_int, flow_key):
    with state_lock:
        flows = icmp_index.get(target_ip_int)
        if flows is None:
            flows = set()
            icmp_index[target_ip_int] = flows
        flows.add(flow_key)

def icmp_index_remove(target_ip_int, flow_key):
    with state_lock:
        flows = icmp_index.get(target_ip_int)
        if flows is not None:
            flows.discard(flow_key)
            if not flows:
                icmp_index.pop(target_ip_int, None)

def try_set_target_for_flow(current_index):
    start = 0 if current_index is None else current_index + 1
    with state_lock:
        for idx in range(start, NUM_TARGETS):
            t_ip = TARGET_IPS_INT[idx]
            st = target_status.get(t_ip, {"up": True})
            if st.get("up", True):
                return t_ip, idx
    return None, None

def install_nat_mapping(flow_key, orig_dst_ip_int, target_ip_int, target_index):
    src_ip_int, src_port, _, dst_port, proto = flow_key
    with state_lock:
        nat_flow_target_index[flow_key] = target_index
        nat_map_outbound[flow_key] = target_ip_int
        rev_key = make_inbound_rev_key(target_ip_int, dst_port, src_ip_int, src_port, proto)
        nat_map_inbound[rev_key] = orig_dst_ip_int
        nat_flow_last_seen[flow_key] = time.time()
        icmp_index_add(target_ip_int, flow_key)
    log.debug("[CF→TARGET] %s → %s (idx %d)", int_to_ip(orig_dst_ip_int), int_to_ip(target_ip_int), target_index)

def fallback_to_next_target(flow_key, orig_dst_ip_int, current_target_ip_int):
    with state_lock:
        current_index = nat_flow_target_index.get(flow_key)
    if current_index is None:
        return False

    target_ip_int, new_index = try_set_target_for_flow(current_index)
    if target_ip_int is None:
        if flow_key not in dead_flows:
            log.warning("[FALLBACK] No more targets for %s, all failed", int_to_ip(orig_dst_ip_int))
            dead_flows.add(flow_key)
        return False

    src_ip_int, src_port, _, dst_port, proto = flow_key
    old_rev_key = make_inbound_rev_key(current_target_ip_int, dst_port, src_ip_int, src_port, proto)
    with state_lock:
        nat_map_inbound.pop(old_rev_key, None)
        icmp_index_remove(current_target_ip_int, flow_key)
        nat_flow_target_index[flow_key] = new_index
        nat_map_outbound[flow_key] = target_ip_int
        new_rev_key = make_inbound_rev_key(target_ip_int, dst_port, src_ip_int, src_port, proto)
        nat_map_inbound[new_rev_key] = orig_dst_ip_int
        nat_flow_last_seen[flow_key] = time.time()
        icmp_index_add(target_ip_int, flow_key)

    log.info("[FALLBACK] %s → %s (idx %d)", int_to_ip(orig_dst_ip_int), int_to_ip(target_ip_int), new_index)
    return True

def touch_flow(flow_key):
    with state_lock:
        if flow_key in nat_flow_last_seen:
            nat_flow_last_seen[flow_key] = time.time()

def cleanup_flows():
    global last_cleanup_time
    now = time.time()
    if now - last_cleanup_time <= CLEANUP_INTERVAL:
        return

    with state_lock:
        stale_keys = [fk for fk, last in nat_flow_last_seen.items() if now - last > FLOW_IDLE_TIMEOUT]
    if not stale_keys:
        last_cleanup_time = now
        return

    for fk in stale_keys:
        dead_flows.discard(fk)
        with state_lock:
            target_ip_int = nat_map_outbound.pop(fk, None)
            nat_flow_target_index.pop(fk, None)
        src_ip_int, src_port, orig_dst_ip_int, dst_port, proto = fk

        if target_ip_int is not None:
            rev_key = make_inbound_rev_key(target_ip_int, dst_port, src_ip_int, src_port, proto)
            with state_lock:
                nat_map_inbound.pop(rev_key, None)
                icmp_index_remove(target_ip_int, fk)
        else:
            with state_lock:
                for key in list(nat_map_inbound.keys()):
                    t_ip_int, t_port, c_ip_int, c_port, p = key
                    if c_ip_int == src_ip_int and c_port == src_port and p == proto and t_port == dst_port:
                        nat_map_inbound.pop(key, None)
                        icmp_index_remove(t_ip_int, fk)

        with state_lock:
            nat_flow_last_seen.pop(fk, None)

    log.debug("[CLEANUP] Removed %d stale flows", len(stale_keys))
    last_cleanup_time = now

# -----------------------------
# Health-check state
# -----------------------------
target_status = {}
with state_lock:
    for ip_int in TARGET_IPS_INT:
        target_status[ip_int] = {"up": True, "last_change": time.time(), "fail_count": 0, "backoff_until": 0.0}

# -----------------------------
# Async health-check (no sending)
# -----------------------------
asyncio_stop = threading.Event()
asyncio_loop = None
asyncio_thread = None

async def async_probe(ip_int: int, port: int = 443, timeout: float = HEALTH_CHECK_TIMEOUT):
    ip = int_to_ip(ip_int)
    loop = asyncio.get_running_loop()
    def sync_connect():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return False
    try:
        return await loop.run_in_executor(None, sync_connect)
    except Exception:
        return False

async def health_scheduler(stop_event: threading.Event):
    sem = asyncio.Semaphore(ASYNC_PROBE_CONCURRENCY)
    while not stop_event.is_set():
        now = time.time()
        tasks = []
        with state_lock:
            for ip_int, st in target_status.items():
                if st.get("backoff_until", 0) > now:
                    continue
                tasks.append(ip_int)

        async def probe_and_update(ip_int):
            async with sem:
                ok = await async_probe(ip_int)
            with state_lock:
                st = target_status[ip_int]
                prev_up = st["up"]
                if ok:
                    st["fail_count"] = 0
                    st["backoff_until"] = 0.0
                    if not prev_up:
                        st["up"] = True
                        st["last_change"] = time.time()
                        log.info("Target %s marked UP", int_to_ip(ip_int))
                else:
                    st["fail_count"] += 1
                    backoff = min(HEALTH_BACKOFF_BASE ** st["fail_count"], HEALTH_BACKOFF_MAX)
                    st["backoff_until"] = time.time() + backoff
                    if prev_up:
                        st["up"] = False
                        st["last_change"] = time.time()
                        log.warning("Target %s marked DOWN (fail_count=%d)", int_to_ip(ip_int), st["fail_count"])

        probe_coros = [probe_and_update(ip_int) for ip_int in tasks]
        if probe_coros:
            try:
                await asyncio.wait_for(asyncio.gather(*probe_coros), timeout=HEALTH_CHECK_INTERVAL)
            except asyncio.TimeoutError:
                pass
        await asyncio.sleep(0.1)

def start_asyncio_thread():
    global asyncio_loop, asyncio_thread
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        globals()["asyncio_loop"] = loop
        task = loop.create_task(health_scheduler(asyncio_stop))
        try:
            loop.run_forever()
        finally:
            try:
                task.cancel()
            except Exception:
                pass
            try:
                loop.close()
            except Exception:
                pass
    asyncio_thread = threading.Thread(target=_run, daemon=True)
    asyncio_thread.start()

start_asyncio_thread()

# -----------------------------
# Metrics HTTP endpoint
# -----------------------------
class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        with state_lock:
            targets = []
            for ip_int in TARGET_IPS_INT:
                st = target_status.get(ip_int, {})
                flows = sum(1 for t in nat_map_outbound.values() if t == ip_int)
                targets.append({
                    "ip": int_to_ip(ip_int),
                    "up": bool(st.get("up", False)),
                    "fail_count": int(st.get("fail_count", 0)),
                    "backoff_until": float(st.get("backoff_until", 0.0)),
                    "flows": flows
                })
            total_flows = len(nat_map_outbound)
            send_ok = metrics["send_ok"]
            send_fail = metrics["send_fail"]
            rotate_events = metrics["rotate_events"]
        payload = {
            "targets": targets,
            "total_flows": total_flows,
            "send_ok": send_ok,
            "send_fail": send_fail,
            "rotate_events": rotate_events,
            "timestamp": time.time()
        }
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def start_metrics_server():
    try:
        server = HTTPServer((METRICS_HOST, METRICS_PORT), MetricsHandler)
        try:
            server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except Exception:
            pass
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        log.info("Metrics endpoint listening on http://%s:%d/metrics", METRICS_HOST, METRICS_PORT)
        return server
    except Exception as e:
        log.error("Failed to start metrics server: %s", e)
        return None

metrics_server = start_metrics_server()

# -----------------------------
# WinDivert capture + send (single thread)
# -----------------------------
FILTER = "ip and (tcp or udp or icmp)"
try:
    w = pydivert.WinDivert(FILTER)
    w.open()
except Exception as e:
    log.critical("Failed to open WinDivert capture handle: %s", e)
    raise SystemExit(1)

get_outbound = lambda fk: nat_map_outbound.get(fk)
get_inbound = lambda fk: nat_map_inbound.get(fk)

log.info("NAT redirector running (single-thread capture + send)")

try:
    for packet in w:
        cleanup_flows()

        if not packet.ipv4:
            try:
                w.send(packet)
                metrics["send_ok"] += 1
            except Exception:
                metrics["send_fail"] += 1
            continue

        if packet.icmp:
            try:
                src_ip_int = ip_to_int(packet.src_addr)
            except Exception:
                try:
                    w.send(packet)
                    metrics["send_ok"] += 1
                except Exception:
                    metrics["send_fail"] += 1
                continue
            with state_lock:
                flows_for_target = icmp_index.get(src_ip_int)
            if flows_for_target:
                for flow_key in list(flows_for_target):
                    _, _, orig_dst_ip_int, dst_port, proto = flow_key
                    if flow_key not in dead_flows:
                        fallback_to_next_target(flow_key, orig_dst_ip_int, src_ip_int)
                        metrics["rotate_events"] += 1
            try:
                w.send(packet)
                metrics["send_ok"] += 1
            except Exception:
                metrics["send_fail"] += 1
            continue

        tcp = packet.tcp
        udp = packet.udp
        if not (tcp or udp):
            try:
                w.send(packet)
                metrics["send_ok"] += 1
            except Exception:
                metrics["send_fail"] += 1
            continue

        proto = PROTO_TCP if tcp else PROTO_UDP

        if packet.is_outbound:
            dst_port = packet.dst_port
            if dst_port not in SSL_PORTS:
                try:
                    w.send(packet)
                    metrics["send_ok"] += 1
                except Exception:
                    metrics["send_fail"] += 1
                continue

            try:
                dst_ip_int = ip_to_int(packet.dst_addr)
            except Exception:
                try:
                    w.send(packet)
                    metrics["send_ok"] += 1
                except Exception:
                    metrics["send_fail"] += 1
                continue

            if CLOUDFLARE_RANGES_INT and not is_cloudflare_ip_int(dst_ip_int):
                try:
                    w.send(packet)
                    metrics["send_ok"] += 1
                except Exception:
                    metrics["send_fail"] += 1
                continue

            try:
                src_ip_int = ip_to_int(packet.src_addr)
            except Exception:
                try:
                    w.send(packet)
                    metrics["send_ok"] += 1
                except Exception:
                    metrics["send_fail"] += 1
                continue

            src_port = packet.src_port
            flow_key = make_outbound_flow_key(src_ip_int, src_port, dst_ip_int, dst_port, proto)

            with state_lock:
                target_ip_int = nat_map_outbound.get(flow_key)
            if target_ip_int is None:
                target_ip_int, index = try_set_target_for_flow(None)
                if target_ip_int is None:
                    try:
                        w.send(packet)
                        metrics["send_ok"] += 1
                    except Exception:
                        metrics["send_fail"] += 1
                    continue
                install_nat_mapping(flow_key, dst_ip_int, target_ip_int, index)

            touch_flow(flow_key)
            packet.dst_addr = int_to_ip(target_ip_int)
            fn = getattr(packet, "recalculate_checksums", None) or getattr(packet, "calc_checksum", None) or getattr(packet, "calc_checksums", None)
            if callable(fn):
                try:
                    fn()
                except Exception:
                    pass
            try:
                w.send(packet)
                metrics["send_ok"] += 1
            except Exception:
                metrics["send_fail"] += 1
            continue

        # INBOUND
        try:
            src_ip_int = ip_to_int(packet.src_addr)
            dst_ip_int = ip_to_int(packet.dst_addr)
        except Exception:
            try:
                w.send(packet)
                metrics["send_ok"] += 1
            except Exception:
                metrics["send_fail"] += 1
            continue

        src_port = packet.src_port
        dst_port = packet.dst_port
        flow_key_inbound = make_inbound_rev_key(src_ip_int, src_port, dst_ip_int, dst_port, proto)

        if tcp and tcp.rst:
            orig_dst_ip_int = get_inbound(flow_key_inbound)
            if orig_dst_ip_int is not None:
                client_ip_int = dst_ip_int
                client_port = dst_port
                target_ip_int = src_ip_int
                flow_key = make_client_side_flow_key(client_ip_int, client_port, orig_dst_ip_int, src_port, proto)
                if flow_key not in dead_flows:
                    fallback_to_next_target(flow_key, orig_dst_ip_int, target_ip_int)
                    metrics["rotate_events"] += 1
                touch_flow(flow_key)
            try:
                w.send(packet)
                metrics["send_ok"] += 1
            except Exception:
                metrics["send_fail"] += 1
            continue

        orig_dst_ip_int = get_inbound(flow_key_inbound)
        if orig_dst_ip_int is not None and src_port in SSL_PORTS:
            client_ip_int = dst_ip_int
            client_port = dst_port
            flow_key = make_client_side_flow_key(client_ip_int, client_port, orig_dst_ip_int, src_port, proto)
            touch_flow(flow_key)
            packet.src_addr = int_to_ip(orig_dst_ip_int)
            fn = getattr(packet, "recalculate_checksums", None) or getattr(packet, "calc_checksum", None) or getattr(packet, "calc_checksums", None)
            if callable(fn):
                try:
                    fn()
                except Exception:
                    pass
            try:
                w.send(packet)
                metrics["send_ok"] += 1
            except Exception:
                metrics["send_fail"] += 1
        else:
            try:
                w.send(packet)
                metrics["send_ok"] += 1
            except Exception:
                metrics["send_fail"] += 1

except KeyboardInterrupt:
    log.info("Stopped by user.")
except Exception as e:
    log.exception("Unhandled exception: %s", e)
finally:
    try:
        asyncio_stop.set()
        if asyncio_loop is not None:
            try:
                asyncio_loop.call_soon_threadsafe(asyncio_loop.stop)
            except Exception:
                pass
    except Exception:
        pass

    try:
        w.close()
    except Exception:
        pass

    try:
        if metrics_server:
            metrics_server.shutdown()
    except Exception:
        pass

    log.info("Shutdown complete")
    time.sleep(0.2)
    sys.exit(0)
