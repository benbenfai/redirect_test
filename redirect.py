#!/usr/bin/env python3
"""
redirect_debug_pass_through_with_parse_logging.py
- Optimized version for low CPU: Reduced workers to 2, probes to 5, increased intervals, added yields/sleeps in loops.
- Fixed: Cloudflare ranges now properly update bisect structures in refresh thread.
- Improved: Target speed testing runs 3 measurements each for UDP/TCP/TLS and uses median for accuracy (reduces jitter impact), with outlier rejection and parallelization.
- New: Auto-generate targets from cloudflare.txt if target.txt empty, using sets for deduping.
- New: Validate IPs (pingable, in Cloudflare ranges) before adding.
- New: Cache speed scores in JSON, skip re-testing stable IPs.
- New: /refresh-targets endpoint to trigger updates.
- New: Log detailed speed test results.
- New: Geography optimization: Weight scores by same continent (using ipapi.co API).
- New: Fallback to pass-through if all targets fail probes.
- New: Rate-limit tests with 0.5s sleep.
- Simple WinDivert filter and robust pipeline with:
  * **Pass-through enabled by default** to avoid disrupting traffic while debugging
  * Toggleable pass-through via HTTP endpoint /toggle-pass-through and /set-pass-through?on=1
  * Logs the first N parse failures (hex + metadata) to parse_failures.log for analysis
  * Packets-per-second counter logged every 5s to help confirm WinDivert visibility
  * Threaded debug HTTP server (/health, /metrics, /debug, /pause-health, /resume-health)
  * Local file logging to redirect.log
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
import statistics  # For median
import json  # For caching
import urllib.request  # For API queries
from functools import lru_cache
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import sys
import queue
import concurrent.futures
import traceback
import faulthandler
import errno
import binascii
import os
import bisect  # For optimized IP range checks

# -----------------------------
# Configuration
# -----------------------------
DEBUG = True
LOG_FILE = Path("redirect.log")
CAPTURE_FILTER = "ip and (tcp or udp or icmp)"
FALLBACK_FILTERS = ["ip", "true"]
PASS_THROUGH = True
STARTUP_PROBE = True
STARTUP_PROBE_TIMEOUT = 3.0
PARSE_FAILURE_SAMPLE_LIMIT = 20
PARSE_FAILURE_LOG = Path("parse_failures.log")
_parse_failure_samples = 0
_parse_failure_lock = threading.Lock()
_packet_count = 0
_packet_count_lock = threading.Lock()
_PACKET_COUNTER_LOG_INTERVAL = 5.0
_packet_counter_stop = threading.Event()
QUEUE_MAX = 8192
WORKER_COUNT = 2
QUEUE_PUT_TIMEOUT = 0.01
DROP_ON_FULL = True
SSL_PORTS = {443, 8443, 2053, 2083, 2087, 2096, 853}
CLEANUP_INTERVAL = 300
FLOW_IDLE_TIMEOUT = 180
CLOUDFLARE_REFRESH_INTERVAL = 24 * 3600
CLOUDFLARE_V4_URL = "https://www.cloudflare.com/ips-v4"
TARGET_UPDATE_INTERVAL = 3 * 3600
TARGET_FILE = Path("target.txt")
TARGET_UPDATE_FILE = Path("targetUpdate.txt")
TARGET_SCORES_CACHE = Path("target_scores.json")
CACHE_EXPIRY = 3600  # 1 hour
TEST_PORT = 443
TEST_SNI = "cloudflare.com"
TOP_N = 5
UDP_TIMEOUT = 1.0
METRICS_HOST = "127.0.0.1"
METRICS_PORT = 8000
PROTO_TCP = 6
PROTO_UDP = 17
HEALTH_CHECK_INTERVAL = 300
HEALTH_CHECK_TIMEOUT = 6.0
ASYNC_PROBE_CONCURRENCY = 5
HEALTH_FAILS_TO_MARK_DOWN = 2
HEALTH_BACKOFF_BASE = 2
HEALTH_BACKOFF_MAX = 120
DEFAULT_DRAIN_BATCH = 512
SPEED_TEST_RUNS = 3
SPEED_TEST_THREADS = 4  # Limit for parallelization
RATE_LIMIT_SLEEP = 0.5  # Sleep between tests
OUTLIER_MULTIPLIER = 2.0  # Discard if >2x median
GEO_API_URL = "https://ipapi.co/{ip}/json/"  # For continent lookup

# -----------------------------
# Logging
# -----------------------------
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG if DEBUG else logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ch = logging.StreamHandler()
ch.setFormatter(formatter)
root_logger.addHandler(ch)
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setFormatter(formatter)
root_logger.addHandler(fh)
log = logging.getLogger("redirect-pass-through-parse-log")

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

if not is_admin():
    log.critical("This script must be run as Administrator.")
    raise SystemExit(1)

# -----------------------------
# Shared state
# -----------------------------
state_lock = threading.RLock()
CLOUDFLARE_RANGES_STARTS = []
CLOUDFLARE_RANGES = []
TARGET_IPS = []
TARGET_IPS_INT = []
NUM_TARGETS = 0
nat_flow_target_index = {}
nat_map_outbound = {}
nat_map_inbound = {}
nat_flow_last_seen = {}
icmp_index = {}
dead_flows = set()
last_cleanup_time = time.time()
metrics = {
    "send_ok": 0,
    "send_fail": 0,
    "rotate_events": 0,
    "raw_queue_drops": 0,
    "send_queue_high_water_events": 0,
    "dropped_syn": 0,
    "parse_failures": 0,
}
target_status = {}
user_continent = None  # Will be set later

# -----------------------------
# IP helpers
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
# Geo helpers
# -----------------------------
def get_continent(ip: str = '') -> str:
    try:
        url = GEO_API_URL.format(ip=ip) if ip else GEO_API_URL.format(ip='')
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
            return data.get('continent_code', 'UNKNOWN')
    except Exception as e:
        log.warning("Failed to get continent for IP %s: %s", ip or 'current', e)
        return 'UNKNOWN'

# Set user continent on startup
user_continent = get_continent()
log.info("User continent detected: %s", user_continent)

# -----------------------------
# Load cloudflare ranges
# -----------------------------
cf_path = Path("cloudflare.txt")
if cf_path.exists():
    try:
        with cf_path.open(encoding="utf-8") as f:
            ranges = set()  # Dedupe
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    if net.version == 4:
                        ranges.add((int(net.network_address), int(net.broadcast_address)))
                except Exception:
                    continue
        sorted_ranges = sorted(ranges)
        CLOUDFLARE_RANGES = sorted_ranges
        CLOUDFLARE_RANGES_STARTS = [s for s, e in sorted_ranges]
        log.info("Loaded and sorted %d unique Cloudflare networks from cloudflare.txt", len(CLOUDFLARE_RANGES))
    except Exception as e:
        log.warning("Failed to load cloudflare.txt: %s", e)
else:
    log.info("cloudflare.txt not found; Cloudflare filtering disabled.")

def is_cloudflare_ip_int(ip_int: int) -> bool:
    with state_lock:
        if not CLOUDFLARE_RANGES_STARTS:
            return False
        idx = bisect.bisect_left(CLOUDFLARE_RANGES_STARTS, ip_int)
        if idx < len(CLOUDFLARE_RANGES):
            s, e = CLOUDFLARE_RANGES[idx]
            if s <= ip_int <= e:
                return True
        if idx > 0:
            s, e = CLOUDFLARE_RANGES[idx - 1]
            if s <= ip_int <= e:
                return True
    return False

# -----------------------------
# Generate targets from ranges
# -----------------------------
def generate_targets_from_ranges():
    targets = set()
    with state_lock:
        for s, e in CLOUDFLARE_RANGES:
            # Generate testable IP: network + 1 (avoid .0)
            test_ip_int = s + 1
            if test_ip_int <= e:
                test_ip = int_to_ip(test_ip_int)
                targets.add(test_ip)
    return list(targets)

# -----------------------------
# Validate IP
# -----------------------------
def validate_ip(ip: str) -> bool:
    if not is_valid_ipv4(ip):
        return False
    ip_int = ip_to_int(ip)
    if not is_cloudflare_ip_int(ip_int):
        return False
    # Pingable (simple connect probe)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, TEST_PORT))
        s.close()
        return True
    except Exception:
        return False

# -----------------------------
# Load targets (Dynamic generation if empty)
# -----------------------------
def load_targets_from_disk(force_regen=False):
    global TARGET_IPS, TARGET_IPS_INT, NUM_TARGETS
    ips = set()  # Dedupe
    regenerate = force_regen or not TARGET_FILE.exists() or TARGET_FILE.stat().st_size == 0
    if regenerate:
        log.info("Regenerating targets from Cloudflare ranges")
        gen_ips = generate_targets_from_ranges()
        for ip in gen_ips:
            if validate_ip(ip):
                ips.add(ip)
        if not ips:
            log.critical("No valid targets generated from ranges")
            raise SystemExit(1)
        try:
            with TARGET_FILE.open("w", encoding="utf-8") as f:
                for ip in sorted(ips):
                    f.write(ip + "\n")
            log.info("Populated target.txt with %d valid IPs", len(ips))
        except Exception as e:
            log.error("Failed to populate target.txt: %s", e)
            raise SystemExit(1)
    else:
        try:
            with TARGET_FILE.open(encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or not is_valid_ipv4(line):
                        continue
                    ips.add(line)
        except Exception as e:
            log.error("Failed to read target.txt: %s", e)
    with state_lock:
        TARGET_IPS = list(ips)
        TARGET_IPS_INT = [ip_to_int(ip) for ip in TARGET_IPS]
        NUM_TARGETS = len(TARGET_IPS)
        for ip_int in TARGET_IPS_INT:
            if ip_int not in target_status:
                target_status[ip_int] = {"up": True, "last_change": time.time(), "fail_count": 0, "backoff_until": 0.0}
    log.info("Loaded %d unique targets", NUM_TARGETS)

load_targets_from_disk()

# -----------------------------
# NAT helpers
# -----------------------------
def make_outbound_flow_key(src_ip_int, src_port, dst_ip_int, dst_port, proto):
    return (src_ip_int, src_port, dst_ip_int, dst_port, proto)

def make_inbound_rev_key(target_ip_int, target_port, client_ip_int, client_port, proto):
    return (target_ip_int, target_port, client_ip_int, client_port, proto)

def make_client_side_flow_key(client_ip_int, client_port, orig_dst_ip_int, orig_dst_port, proto):
    return (client_ip_int, client_port, orig_dst_ip_int, orig_dst_port, proto)

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

def fallback_to_next_target(flow_key, orig_dst_ip_int, current_target_ip_int):
    with state_lock:
        current_index = nat_flow_target_index.get(flow_key)
    if current_index is None:
        return False
    target_ip_int, new_index = try_set_target_for_flow(current_index)
    if target_ip_int is None:
        if flow_key not in dead_flows:
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
    metrics["rotate_events"] += 1
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
    last_cleanup_time = now

# -----------------------------
# Queues
# -----------------------------
raw_queue = queue.Queue(maxsize=QUEUE_MAX)
send_queue = queue.Queue(maxsize=QUEUE_MAX)
_parse_last_log = 0.0
_PARSE_LOG_INTERVAL = 5.0

def log_queue_watermark_check():
    try:
        rq = raw_queue.qsize()
        sq = send_queue.qsize()
    except Exception:
        return
    if sq > (QUEUE_MAX * 0.25):
        metrics["send_queue_high_water_events"] += 1
        log.warning("send_queue high watermark: %d/%d (raw_queue=%d)", sq, QUEUE_MAX, rq)

# -----------------------------
# Helper: send TCP RST back to client
# -----------------------------
def send_tcp_rst_back(w, pkt):
    try:
        rst_pkt = pydivert.Packet(bytes(pkt), getattr(pkt, "interface", 0), getattr(pkt, "direction", 0))
        rst_pkt.src_addr, rst_pkt.dst_addr = pkt.dst_addr, pkt.src_addr
        rst_pkt.src_port, rst_pkt.dst_port = pkt.dst_port, pkt.src_port
        if getattr(rst_pkt, "tcp", None):
            try:
                rst_pkt.tcp.rst = True
                rst_pkt.tcp.ack = True
            except Exception:
                pass
        try:
            rst_pkt.payload = b""
        except Exception:
            pass
        fn = getattr(rst_pkt, "recalculate_checksums", None)
        if callable(fn):
            try:
                fn()
            except Exception:
                pass
        w.send(rst_pkt)
        metrics["send_ok"] += 1
        log.info("Sent TCP RST to client %s:%d (no target)", rst_pkt.dst_addr, rst_pkt.dst_port)
    except Exception:
        metrics["send_fail"] += 1
        log.exception("Failed to send TCP RST")

# -----------------------------
# Modifier worker
# -----------------------------
def _save_parse_failure_sample(interface, direction, raw_bytes, exc):
    global _parse_failure_samples
    with _parse_failure_lock:
        if _parse_failure_samples >= PARSE_FAILURE_SAMPLE_LIMIT:
            return
        _parse_failure_samples += 1
    try:
        ts = time.time()
        hex_sample = binascii.hexlify(raw_bytes[:256]).decode("ascii", errors="ignore")
        with PARSE_FAILURE_LOG.open("a", encoding="utf-8") as fh:
            fh.write(f"--- SAMPLE {ts} ---\n")
            fh.write(f"interface={interface} direction={direction}\n")
            fh.write(f"exception={repr(exc)}\n")
            fh.write(f"hex={hex_sample}\n\n")
    except Exception:
        pass

def modifier_worker():
    thread_name = threading.current_thread().name
    log.info("modifier_worker started: %s", thread_name)
    while True:
        try:
            raw_item = raw_queue.get(timeout=1.0)
        except queue.Empty:
            try:
                if send_queue.qsize() > int(QUEUE_MAX * 0.5):
                    log.warning("modifier_worker %s idle; send_queue=%d", thread_name, send_queue.qsize())
            except Exception:
                pass
            time.sleep(0.01)  # Added sleep for low CPU
            continue
        except Exception as e:
            log.exception("modifier_worker %s: unexpected get error: %s", thread_name, e)
            continue
        if raw_item is None:
            log.info("modifier_worker %s received shutdown sentinel", thread_name)
            break
        try:
            raw_bytes, interface, direction = raw_item
        except Exception:
            metrics["parse_failures"] += 1
            continue
        try:
            pkt = pydivert.Packet(raw_bytes, interface, direction)
        except Exception as e:
            metrics["parse_failures"] += 1
            global _parse_last_log
            now = time.time()
            if now - _parse_last_log > _PARSE_LOG_INTERVAL:
                _parse_last_log = now
                log.exception("modifier_worker %s: failed to parse packet (throttled)", thread_name, exc_info=e)
            try:
                _save_parse_failure_sample(interface, direction, raw_bytes, e)
            except Exception:
                pass
            continue
        try:
            if send_queue.qsize() > int(QUEUE_MAX * 0.6):
                metrics["raw_queue_drops"] += 1
                continue
            if pkt.icmp:
                out_bytes = bytes(pkt)
                try:
                    send_queue.put((out_bytes, interface, direction), timeout=0.5)
                except queue.Full:
                    metrics["raw_queue_drops"] += 1
                continue
            tcp = pkt.tcp
            udp = pkt.udp
            if not (tcp or udp):
                out_bytes = bytes(pkt)
                try:
                    send_queue.put((out_bytes, interface, direction), timeout=0.5)
                except queue.Full:
                    metrics["raw_queue_drops"] += 1
                continue
            proto = PROTO_TCP if tcp else PROTO_UDP
            if pkt.is_outbound:
                dst_port = pkt.dst_port
                if dst_port not in SSL_PORTS:
                    out_bytes = bytes(pkt)
                    try:
                        send_queue.put((out_bytes, interface, direction), timeout=0.5)
                    except queue.Full:
                        metrics["raw_queue_drops"] += 1
                    continue
                try:
                    dst_ip_int = ip_to_int(pkt.dst_addr)
                except Exception:
                    out_bytes = bytes(pkt)
                    try:
                        send_queue.put((out_bytes, interface, direction), timeout=0.5)
                    except queue.Full:
                        metrics["raw_queue_drops"] += 1
                    continue
                if CLOUDFLARE_RANGES and not is_cloudflare_ip_int(dst_ip_int):
                    out_bytes = bytes(pkt)
                    try:
                        send_queue.put((out_bytes, interface, direction), timeout=0.5)
                    except queue.Full:
                        metrics["raw_queue_drops"] += 1
                    continue
                try:
                    src_ip_int = ip_to_int(pkt.src_addr)
                except Exception:
                    out_bytes = bytes(pkt)
                    try:
                        send_queue.put((out_bytes, interface, direction), timeout=0.5)
                    except queue.Full:
                        metrics["raw_queue_drops"] += 1
                    continue
                src_port = pkt.src_port
                flow_key = make_outbound_flow_key(src_ip_int, src_port, dst_ip_int, dst_port, proto)
                with state_lock:
                    target_ip_int = nat_map_outbound.get(flow_key)
                if target_ip_int is None:
                    with state_lock:
                        target_ip_int, index = try_set_target_for_flow(None)
                    if target_ip_int is None:
                        is_tcp_syn = False
                        try:
                            if getattr(pkt, "tcp", None):
                                tcp = pkt.tcp
                                is_tcp_syn = bool(getattr(tcp, "syn", False) and not getattr(tcp, "ack", False))
                        except Exception:
                            is_tcp_syn = False
                        if is_tcp_syn:
                            try:
                                send_queue.put(("RST_FROM_MOD", bytes(pkt), interface, direction), timeout=0.5)
                                log.info("Enqueued RST_FROM_MOD for client %s:%d", pkt.src_addr, pkt.src_port)
                            except queue.Full:
                                metrics["raw_queue_drops"] += 1
                                metrics["dropped_syn"] += 1
                                log.warning("Failed to enqueue RST_FROM_MOD; raw_queue full")
                        else:
                            out_bytes = bytes(pkt)
                            try:
                                send_queue.put((out_bytes, interface, direction), timeout=0.5)
                            except queue.Full:
                                metrics["raw_queue_drops"] += 1
                        continue
                    install_nat_mapping(flow_key, dst_ip_int, target_ip_int, index)
                touch_flow(flow_key)
                pkt.dst_addr = int_to_ip(target_ip_int)
                fn = getattr(pkt, "recalculate_checksums", None) or getattr(pkt, "calc_checksum", None) or getattr(pkt, "calc_checksums", None)
                if callable(fn):
                    try:
                        fn()
                    except Exception:
                        pass
                out_bytes = bytes(pkt)
                try:
                    send_queue.put((out_bytes, interface, direction), timeout=0.5)
                except queue.Full:
                    metrics["raw_queue_drops"] += 1
                continue
            try:
                src_ip_int = ip_to_int(pkt.src_addr)
                dst_ip_int = ip_to_int(pkt.dst_addr)
            except Exception:
                out_bytes = bytes(pkt)
                try:
                    send_queue.put((out_bytes, interface, direction), timeout=0.5)
                except queue.Full:
                    metrics["raw_queue_drops"] += 1
                continue
            src_port = pkt.src_port
            dst_port = pkt.dst_port
            flow_key_inbound = make_inbound_rev_key(src_ip_int, src_port, dst_ip_int, dst_port, proto)
            with state_lock:
                orig_dst_ip_int = nat_map_inbound.get(flow_key_inbound)
            if orig_dst_ip_int is not None and src_port in SSL_PORTS:
                client_ip_int = dst_ip_int
                client_port = dst_port
                flow_key = make_client_side_flow_key(client_ip_int, client_port, orig_dst_ip_int, src_port, proto)
                touch_flow(flow_key)
                pkt.src_addr = int_to_ip(orig_dst_ip_int)
                fn = getattr(pkt, "recalculate_checksums", None) or getattr(pkt, "calc_checksum", None) or getattr(pkt, "calc_checksums", None)
                if callable(fn):
                    try:
                        fn()
                    except Exception:
                        pass
                out_bytes = bytes(pkt)
                try:
                    send_queue.put((out_bytes, interface, direction), timeout=0.5)
                except queue.Full:
                    metrics["raw_queue_drops"] += 1
            else:
                out_bytes = bytes(pkt)
                try:
                    send_queue.put((out_bytes, interface, direction), timeout=0.5)
                except queue.Full:
                    metrics["raw_queue_drops"] += 1
        except Exception:
            log.exception("modifier_worker %s: unexpected error", thread_name)
            try:
                send_queue.put((bytes(pkt), interface, direction), timeout=0.5)
            except Exception:
                metrics["raw_queue_drops"] += 1

# -----------------------------
# Capture loop and send drain
# -----------------------------
def drain_send_queue(w, max_per_cycle=256):
    sent = 0
    while sent < max_per_cycle:
        try:
            item = send_queue.get_nowait()
        except queue.Empty:
            break
        if item is None:
            return False
        if isinstance(item, tuple) and len(item) >= 4 and item[0] == "RST_FROM_MOD":
            _, raw_bytes, interface, direction = item
            try:
                pkt = pydivert.Packet(raw_bytes, interface, direction)
                send_tcp_rst_back(w, pkt)
            except Exception:
                metrics["parse_failures"] += 1
            sent += 1
            continue
        try:
            out_bytes, interface, direction = item
        except Exception:
            metrics["parse_failures"] += 1
            continue
        try:
            pkt_to_send = pydivert.Packet(out_bytes, interface, direction)
            try:
                w.send(pkt_to_send)
                metrics["send_ok"] += 1
            except Exception:
                metrics["send_fail"] += 1
                try:
                    dst_ip = getattr(pkt_to_send, "dst_addr", None)
                    if dst_ip:
                        dst_ip_int = ip_to_int(dst_ip)
                        with state_lock:
                            st = target_status.get(dst_ip_int)
                            if st is None:
                                target_status[dst_ip_int] = {"up": False, "fail_count": 1,
                                                             "backoff_until": time.time() + 1}
                            else:
                                st["fail_count"] = st.get("fail_count", 0) + 1
                                if st["fail_count"] >= HEALTH_FAILS_TO_MARK_DOWN:
                                    st["up"] = False
                                    st["backoff_until"] = time.time() + min(
                                        HEALTH_BACKOFF_BASE ** st["fail_count"], HEALTH_BACKOFF_MAX)
                                    log.warning("Target %s marked DOWN due to send failure", dst_ip)
                except Exception:
                    pass
        except Exception:
            metrics["parse_failures"] += 1
        sent += 1
    return True

def capture_loop_interleaved(w, recv_timeout=0.01, drain_batch=DEFAULT_DRAIN_BATCH):
    global PASS_THROUGH, _packet_count
    log.info("Capture interleaved loop started (recv_timeout=%.3fs drain_batch=%d)", recv_timeout, drain_batch)
    try_recv_with_timeout = True
    try:
        try:
            _ = w.recv(timeout=0.0001)
            if _ is not None:
                try:
                    w.send(_)
                except Exception:
                    pass
        except TypeError:
            try_recv_with_timeout = False
        except Exception:
            pass
    except Exception:
        try_recv_with_timeout = False
    idle_since = None
    try:
        if try_recv_with_timeout:
            while True:
                ok = drain_send_queue(w, max_per_cycle=drain_batch * 2)
                if not ok:
                    break
                try:
                    packet = w.recv(timeout=recv_timeout)
                except Exception:
                    packet = None
                if packet is not None:
                    with _packet_count_lock:
                        _packet_count += 1
                    idle_since = None
                    if PASS_THROUGH:
                        try:
                            w.send(packet)
                            metrics["send_ok"] += 1
                        except Exception:
                            metrics["send_fail"] += 1
                        continue
                    try:
                        src = getattr(packet, "src_addr", None)
                        dst = getattr(packet, "dst_addr", None)
                        if src == "127.0.0.1" or dst == "127.0.0.1":
                            try:
                                w.send(packet)
                                metrics["send_ok"] += 1
                            except Exception:
                                metrics["send_fail"] += 1
                            continue
                    except Exception:
                        pass
                    if not getattr(packet, "ipv4", False):
                        try:
                            w.send(packet)
                            metrics["send_ok"] += 1
                        except Exception:
                            metrics["send_fail"] += 1
                    else:
                        try:
                            raw = bytes(packet)
                            interface = getattr(packet, "interface", 0)
                            direction = getattr(packet, "direction", 0)
                        except Exception:
                            metrics["parse_failures"] += 1
                            continue
                        is_tcp_syn = False
                        try:
                            if getattr(packet, "tcp", None):
                                tcp = packet.tcp
                                is_tcp_syn = bool(getattr(tcp, "syn", False) and not getattr(tcp, "ack", False))
                        except Exception:
                            is_tcp_syn = False
                        try:
                            if send_queue.qsize() > int(QUEUE_MAX * 0.6) and not is_tcp_syn:
                                metrics["raw_queue_drops"] += 1
                                continue
                        except Exception:
                            pass
                        try:
                            raw_queue.put_nowait((raw, interface, direction))
                        except queue.Full:
                            if DROP_ON_FULL:
                                metrics["raw_queue_drops"] += 1
                                if is_tcp_syn:
                                    metrics["dropped_syn"] += 1
                                    log.warning("Dropped TCP SYN due to full raw_queue")
                                continue
                            else:
                                try:
                                    raw_queue.put((raw, interface, direction), timeout=QUEUE_PUT_TIMEOUT)
                                except queue.Full:
                                    metrics["raw_queue_drops"] += 1
                                    continue
                else:
                    try:
                        if raw_queue.qsize() == 0 and send_queue.qsize() == 0:
                            if idle_since is None:
                                idle_since = time.time()
                            elif time.time() - idle_since > 5:
                                log.debug("capture idle for %.1fs", time.time() - idle_since)
                        else:
                            idle_since = None
                    except Exception:
                        idle_since = None
                log_queue_watermark_check()
                time.sleep(0.001)
        else:
            for packet in w:
                with _packet_count_lock:
                    _packet_count += 1
                ok = drain_send_queue(w, max_per_cycle=drain_batch * 2)
                if not ok:
                    break
                if PASS_THROUGH:
                    try:
                        w.send(packet)
                        metrics["send_ok"] += 1
                    except Exception:
                        metrics["send_fail"] += 1
                    continue
                try:
                    src = getattr(packet, "src_addr", None)
                    dst = getattr(packet, "dst_addr", None)
                    if src == "127.0.0.1" or dst == "127.0.0.1":
                        try:
                            w.send(packet)
                            metrics["send_ok"] += 1
                        except Exception:
                            metrics["send_fail"] += 1
                        continue
                except Exception:
                    pass
                if not getattr(packet, "ipv4", False):
                    try:
                        w.send(packet)
                        metrics["send_ok"] += 1
                    except Exception:
                        metrics["send_fail"] += 1
                    continue
                try:
                    raw = bytes(packet)
                    interface = getattr(packet, "interface", 0)
                    direction = getattr(packet, "direction", 0)
                except Exception:
                    metrics["parse_failures"] += 1
                    continue
                is_tcp_syn = False
                try:
                    if getattr(packet, "tcp", None):
                        tcp = packet.tcp
                        is_tcp_syn = bool(getattr(tcp, "syn", False) and not getattr(tcp, "ack", False))
                except Exception:
                    is_tcp_syn = False
                try:
                    if send_queue.qsize() > int(QUEUE_MAX * 0.6) and not is_tcp_syn:
                        metrics["raw_queue_drops"] += 1
                        continue
                except Exception:
                    pass
                try:
                    raw_queue.put_nowait((raw, interface, direction))
                except queue.Full:
                    if DROP_ON_FULL:
                        metrics["raw_queue_drops"] += 1
                        if is_tcp_syn:
                            metrics["dropped_syn"] += 1
                            log.warning("Dropped TCP SYN due to full raw_queue")
                        pass
                    else:
                        try:
                            raw_queue.put((raw, interface, direction), timeout=QUEUE_PUT_TIMEOUT)
                        except queue.Full:
                            metrics["raw_queue_drops"] += 1
                            pass
                log_queue_watermark_check()
                time.sleep(0.001)
    finally:
        log.info("Capture interleaved loop exiting")

# -----------------------------
# Packet counter logger
# -----------------------------
def packet_counter_logger(interval=_PACKET_COUNTER_LOG_INTERVAL):
    last_count = 0
    last_time = time.time()
    while not _packet_counter_stop.is_set():
        time.sleep(interval)
        with _packet_count_lock:
            count = _packet_count
        now = time.time()
        delta = now - last_time
        pps = (count - last_count) / delta if delta > 0 else 0.0
        log.info("Packet counter: total=%d pps=%.2f", count, pps)
        last_count = count
        last_time = now

threading.Thread(target=packet_counter_logger, daemon=True, name="packet-counter").start()

# -----------------------------
# Cloudflare refresher
# -----------------------------
def refresh_cloudflare_ranges():
    global CLOUDFLARE_RANGES, CLOUDFLARE_RANGES_STARTS
    cf_file = cf_path
    while True:
        time.sleep(CLOUDFLARE_REFRESH_INTERVAL)
        try:
            with urllib.request.urlopen(CLOUDFLARE_V4_URL, timeout=10) as r:
                raw = r.read().decode("utf-8")
            new_ranges = set()  # Dedupe
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    net = ipaddress.ip_network(line, strict=False)
                    if net.version == 4:
                        new_ranges.add((int(net.network_address), int(net.broadcast_address)))
                except Exception:
                    log.warning("Cloudflare refresh: invalid CIDR %s", line)
            if not new_ranges:
                log.warning("Cloudflare refresh: empty list, skipping update")
                continue
            sorted_new_ranges = sorted(new_ranges)
            tmp = cf_file.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                for s, e in sorted_new_ranges:
                    f.write(str(ipaddress.ip_network((s, e), strict=False)) + "\n")
            tmp.replace(cf_file)
            with state_lock:
                CLOUDFLARE_RANGES = sorted_new_ranges
                CLOUDFLARE_RANGES_STARTS = [s for s, e in sorted_new_ranges]
            log.info("Cloudflare ranges refreshed: %d networks", len(sorted_new_ranges))
            # Trigger target regen if ranges changed
            load_targets_from_disk(force_regen=True)
        except Exception as e:
            log.warning("Cloudflare refresh failed: %s", e)

# -----------------------------
# Measurement functions
# -----------------------------
def measure_udp_quic(ip, timeout=UDP_TIMEOUT):
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x00", (ip, TEST_PORT))
        try:
            s.recvfrom(1024)
        except socket.timeout:
            pass
        finally:
            s.close()
        return (time.time() - start) * 1000.0
    except Exception:
        return float("inf")

def measure_tcp_connect(ip, timeout=2.0):
    start = time.time()
    try:
        s = socket.create_connection((ip, TEST_PORT), timeout=timeout)
        s.close()
        return (time.time() - start) * 1000.0
    except Exception:
        return float("inf")

def measure_tls(ip, timeout=3.0, sni=TEST_SNI):
    ctx = ssl.create_default_context()
    start = time.time()
    try:
        s = socket.create_connection((ip, TEST_PORT), timeout=timeout)
        tls = ctx.wrap_socket(s, server_hostname=sni)
        tls.close()
        return (time.time() - start) * 1000.0
    except Exception:
        return float("inf")

# -----------------------------
# Update targets (parallel, cache, etc.)
# -----------------------------
def update_targets(force=False):
    global TARGET_IPS, TARGET_IPS_INT, NUM_TARGETS
    while True:
        if force:
            time.sleep(0)  # Immediate for manual
            force = False
        else:
            time.sleep(TARGET_UPDATE_INTERVAL)
        try:
            ips = set(TARGET_IPS)
            cache = {}
            if TARGET_SCORES_CACHE.exists():
                with TARGET_SCORES_CACHE.open("r") as f:
                    cache = json.load(f)
            results = []
            to_test = [ip for ip in ips if force or ip not in cache or time.time() - cache[ip].get('timestamp', 0) > CACHE_EXPIRY]
            with concurrent.futures.ThreadPoolExecutor(max_workers=SPEED_TEST_THREADS) as executor:
                future_to_ip = {executor.submit(score_target, ip): ip for ip in to_test}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        score, udp_ms, tcp_ms, tls_ms = future.result()
                        results.append((score, ip, udp_ms, tcp_ms, tls_ms))
                        cache[ip] = {'score': score, 'udp_ms': udp_ms, 'tcp_ms': tcp_ms, 'tls_ms': tls_ms, 'timestamp': time.time()}
                    except Exception as e:
                        log.warning("Failed to score %s: %s", ip, e)
            for ip, data in cache.items():
                if ip not in [r[1] for r in results]:
                    results.append((data['score'], ip, data['udp_ms'], data['tcp_ms'], data['tls_ms']))
            results.sort(key=lambda x: x[0])
            best = results[:TOP_N]
            log.info("Speed test results: %s", json.dumps([{'ip': ip, 'score': score, 'udp': udp, 'tcp': tcp, 'tls': tls} for score, ip, udp, tcp, tls in best], indent=2))
            tmp = TARGET_UPDATE_FILE.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                for _, ip, _, _, _ in best:
                    f.write(ip + "\n")
            tmp.replace(TARGET_UPDATE_FILE)
            TARGET_UPDATE_FILE.replace(TARGET_FILE)
            log.info("target.txt updated with fastest %d targets", TOP_N)
            load_targets_from_disk()
            with state_lock:
                for ip_int in TARGET_IPS_INT:
                    if ip_int not in target_status:
                        target_status[ip_int] = {"up": True, "last_change": time.time(), "fail_count": 0, "backoff_until": 0.0}
            log.info("In-memory target list reloaded (%d targets)", NUM_TARGETS)
            with TARGET_SCORES_CACHE.open("w") as f:
                json.dump(cache, f)
        except Exception as e:
            log.warning("Target update failed: %s", e)

# -----------------------------
# Health scheduler with fallback
# -----------------------------
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
                    st["fail_count"] = st.get("fail_count", 0) + 1
                    if st["fail_count"] >= HEALTH_FAILS_TO_MARK_DOWN:
                        backoff = min(HEALTH_BACKOFF_BASE ** st["fail_count"], HEALTH_BACKOFF_MAX)
                        st["backoff_until"] = time.time() + backoff
                        if prev_up:
                            st["up"] = False
                            st["last_change"] = time.time()
                            log.warning("Target %s marked DOWN (fail_count=%d)", int_to_ip(ip_int), st["fail_count"])
                    else:
                        log.debug("Target %s probe failed (count=%d)", int_to_ip(ip_int), st["fail_count"])
        probe_coros = [probe_and_update(ip_int) for ip_int in tasks]
        if probe_coros:
            try:
                await asyncio.wait_for(asyncio.gather(*probe_coros), timeout=HEALTH_CHECK_INTERVAL)
            except asyncio.TimeoutError:
                pass
        with state_lock:
            all_down = all(not s.get("up", False) for s in target_status.values())
        if all_down and not PASS_THROUGH:
            PASS_THROUGH = True
            log.warning("All targets down; fallback to pass-through")
        elif not all_down and PASS_THROUGH:
            PASS_THROUGH = False
            log.info("Targets recovered; disabling pass-through fallback")
        await asyncio.sleep(0.5)

def start_asyncio_thread():
    global asyncio_loop
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        asyncio_loop = loop
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
    t = threading.Thread(target=_run, daemon=True, name="health-thread")
    t.start()

asyncio_stop = threading.Event()
start_asyncio_thread()

# -----------------------------
# Threaded HTTP server and handlers (added /refresh-targets)
# -----------------------------
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class DebugMetricsHandler(BaseHTTPRequestHandler):
    def _write_json(self, obj, code=200):
        body = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        log.info("http %s - %s", self.address_string(), format % args)

    def do_GET(self):
        global PASS_THROUGH
        log.info("HTTP GET %s from %s", self.path, self.client_address)
        if self.path == "/health":
            self._write_json({"status": "ok", "timestamp": time.time(), "pass_through": PASS_THROUGH})
            return
        if self.path == "/metrics":
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
                payload = {
                    "targets": targets,
                    "total_flows": total_flows,
                    "metrics": metrics,
                    "raw_queue_size": raw_queue.qsize(),
                    "send_queue_size": send_queue.qsize(),
                    "pass_through": PASS_THROUGH,
                    "timestamp": time.time()
                }
            self._write_json(payload)
            return
        if self.path == "/debug":
            threads = []
            for t in threading.enumerate():
                threads.append({"name": t.name, "ident": t.ident, "daemon": t.daemon, "alive": t.is_alive()})
            payload = {
                "threads": threads,
                "raw_queue_size": raw_queue.qsize(),
                "send_queue_size": send_queue.qsize(),
                "metrics": metrics,
                "note": "full stack capture disabled",
                "pass_through": PASS_THROUGH,
                "timestamp": time.time()
            }
            self._write_json(payload)
            return
        if self.path == "/pause-health":
            asyncio_stop.set()
            self._write_json({"status": "health paused"})
            return
        if self.path == "/resume-health":
            if asyncio_stop.is_set():
                asyncio_stop.clear()
                start_asyncio_thread()
            self._write_json({"status": "health resumed"})
            return
        if self.path == "/toggle-pass-through":
            PASS_THROUGH = not PASS_THROUGH
            log.info("Pass-through mode toggled: %s", PASS_THROUGH)
            self._write_json({"pass_through": PASS_THROUGH, "timestamp": time.time()})
            return
        if self.path.startswith("/set-pass-through"):
            try:
                q = self.path.split("?", 1)[1]
                params = dict(p.split("=", 1) for p in q.split("&") if "=" in p)
                on = params.get("on")
                if on is not None:
                    PASS_THROUGH = bool(int(on))
                    log.info("Pass-through set to: %s", PASS_THROUGH)
                    self._write_json({"pass_through": PASS_THROUGH, "timestamp": time.time()})
                    return
            except Exception:
                pass
            self.send_response(400)
            self.end_headers()
            return
        if self.path == "/refresh-targets":
            threading.Thread(target=update_targets, args=(True,)).start()
            self._write_json({"status": "target refresh triggered"})
            return
        self.send_response(404)
        self.send_header("Connection", "close")
        self.end_headers()

def start_debug_server():
    try:
        server = ThreadingHTTPServer((METRICS_HOST, METRICS_PORT), DebugMetricsHandler)
        server.timeout = 1.0
        t = threading.Thread(target=server.serve_forever, daemon=True, name="debug-http")
        t.start()
        log.info("Debug/metrics endpoint listening on http://%s:%d/metrics and /debug", METRICS_HOST, METRICS_PORT)
        return server
    except Exception as e:
        log.error("Failed to start debug server: %s", e)
        return None

metrics_server = start_debug_server()
if metrics_server is None:
    log.critical("Debug server failed to start; aborting")
    raise SystemExit(1)

# -----------------------------
# HTTP watchdog
# -----------------------------
def http_watchdog(interval=300.0):
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            try:
                s.connect((METRICS_HOST, METRICS_PORT))
                req = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                s.sendall(req)
                try:
                    data = s.recv(256)
                    if not data:
                        log.warning("HTTP watchdog: no response from debug server")
                except Exception:
                    log.warning("HTTP watchdog: failed to read response")
            except Exception as e:
                log.warning("HTTP watchdog: cannot connect to debug server: %s", e)
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        except Exception:
            log.exception("HTTP watchdog unexpected error")
        time.sleep(interval)

threading.Thread(target=http_watchdog, daemon=True, name="http-watchdog").start()

# -----------------------------
# Heartbeat and workers
# -----------------------------
def heartbeat_thread(interval=60.0):
    while True:
        try:
            tnames = [t.name for t in threading.enumerate()]
            rq = raw_queue.qsize()
            sq = send_queue.qsize()
            up_targets = sum(1 for s in target_status.values() if s.get("up"))
            log.info("heartbeat threads=%d raw=%d send=%d targets_up=%d pass_through=%s", len(tnames), rq, sq, up_targets, PASS_THROUGH)
        except Exception:
            log.exception("heartbeat error")
        time.sleep(interval)

threading.Thread(target=heartbeat_thread, daemon=True, name="heartbeat").start()
threading.Thread(target=refresh_cloudflare_ranges, daemon=True, name="cf-refresh").start()
threading.Thread(target=update_targets, daemon=True, name="target-updater").start()
worker_pool = concurrent.futures.ThreadPoolExecutor(max_workers=WORKER_COUNT)
for i in range(WORKER_COUNT):
    worker_pool.submit(modifier_worker)

# -----------------------------
# Startup probes
# -----------------------------
def startup_probe_targets(timeout=STARTUP_PROBE_TIMEOUT):
    if not STARTUP_PROBE:
        return
    log.info("Performing startup probes to %d targets (timeout=%.1fs)", len(TARGET_IPS), timeout)
    for ip in TARGET_IPS:
        try:
            start = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, TEST_PORT))
            s.close()
            elapsed = time.time() - start
            log.info("Startup probe OK %s:%d (%.3fs)", ip, TEST_PORT, elapsed)
        except Exception as e:
            log.warning("Startup probe FAILED %s:%d -> %s", ip, TEST_PORT, e)

threading.Thread(target=startup_probe_targets, daemon=True, name="startup-probes").start()

# -----------------------------
# Local HTTP health check
# -----------------------------
def check_local_http_health(host="127.0.0.1", port=METRICS_PORT, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        req = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        s.sendall(req)
        data = s.recv(256)
        s.close()
        return bool(data)
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return False

log.info("Using WinDivert primary filter: %s", CAPTURE_FILTER)
if not check_local_http_health():
    log.warning("Local HTTP /health did not respond before opening WinDivert. Proceeding anyway.")

# -----------------------------
# Robust WinDivert open
# -----------------------------
def try_open_windivert(filters):
    for f in filters:
        try:
            log.info("Attempting to open WinDivert with filter: %s", f)
            w = pydivert.WinDivert(f)
            w.open()
            log.info("WinDivert opened successfully with filter: %s", f)
            return w, f
        except Exception as e:
            try:
                err_no = e.winerror if hasattr(e, "winerror") else None
            except Exception:
                err_no = None
            if err_no == 87 or (isinstance(e, OSError) and getattr(e, "errno", None) == errno.EINVAL):
                log.warning("WinDivert open failed with ERROR_INVALID_PARAMETER for filter: %s", f)
            elif err_no == 5 or (isinstance(e, PermissionError) or (isinstance(e, OSError) and getattr(e, "errno", None) == errno.EACCES)):
                log.warning("WinDivert open failed with access denied (winerror=5) for filter: %s", f)
            else:
                log.warning("WinDivert open failed for filter %s: %s", f, e)
    return None, None

filters_to_try = [CAPTURE_FILTER] + [f for f in FALLBACK_FILTERS if f != CAPTURE_FILTER]
w = None
used_filter = None
try:
    w, used_filter = try_open_windivert(filters_to_try)
    if w is None:
        log.critical("All WinDivert open attempts failed.")
        log.critical("Troubleshooting suggestions:")
        log.critical(" 1) Run this script as Administrator (UAC elevation).")
        log.critical(" 2) Ensure WinDivert driver is installed and matches OS architecture.")
        log.critical(" 3) Reinstall WinDivert driver and pydivert if necessary.")
        log.critical(" 4) If you see ERROR_INVALID_PARAMETER, the driver may not support the filter syntax used.")
        raise SystemExit(1)
except SystemExit:
    raise
except Exception as e:
    log.exception("Unexpected exception while opening WinDivert: %s", e)
    raise SystemExit(1)

log.info("NAT redirector running (WinDivert filter in use: %s)", used_filter)

# -----------------------------
# Main loop
# -----------------------------
try:
    faulthandler.enable()
except Exception:
    pass
try:
    capture_loop_interleaved(w, recv_timeout=0.01, drain_batch=DEFAULT_DRAIN_BATCH)
except KeyboardInterrupt:
    log.info("Stopped by user.")
except Exception as e:
    log.exception("Unhandled exception in capture loop: %s", e)
finally:
    try:
        asyncio_stop.set()
    except Exception:
        pass
    try:
        for _ in range(WORKER_COUNT):
            raw_queue.put_nowait(None)
    except Exception:
        pass
    try:
        send_queue.put_nowait(None)
    except Exception:
        pass
    try:
        worker_pool.shutdown(wait=True)
    except Exception:
        pass
    try:
        if w:
            w.close()
    except Exception:
        pass
    try:
        if metrics_server:
            metrics_server.shutdown()
    except Exception:
        pass
    try:
        _packet_counter_stop.set()
    except Exception:
        pass
    log.info("Shutdown complete")
    time.sleep(0.2)
    sys.exit(0)
