#!/usr/bin/env python3
"""
Run as Administrator.
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
import statistics
import json
import urllib.request
import subprocess
from functools import lru_cache
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import sys
import queue
import concurrent.futures
import faulthandler
import binascii
import bisect

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
_packet_count = 0
_packet_count_lock = threading.Lock()
_PACKET_COUNTER_LOG_INTERVAL = 5.0
_packet_counter_stop = threading.Event()
QUEUE_MAX = 8192
WORKER_COUNT = 2
QUEUE_PUT_TIMEOUT = 0.01
DROP_ON_FULL = True
SSL_PORTS = {443, 8443, 2053, 2083, 2087, 2096, 853}
EXCLUDED_PORTS = {80, 2099, 5222, 5223, 8088, 8393}
CLEANUP_INTERVAL = 300
FLOW_IDLE_TIMEOUT = 180
CLOUDFLARE_REFRESH_INTERVAL = 24 * 3600
TARGET_UPDATE_INTERVAL = 7200
TARGET_FILE = Path("target.txt")
TARGET_UPDATE_FILE = Path("targetUpdate.txt")
TARGET_SCORES_CACHE = Path("target_scores.json")
CACHE_EXPIRY = 7200
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
SPEED_TEST_THREADS = 3
RATE_LIMIT_SLEEP = 0.5
OUTLIER_MULTIPLIER = 2.0
GEO_API_URL = "https://ipapi.co/{ip}/json/"

# CloudflareSpeedTest
CFST_EXE = Path("cfst_windows_amd64") / "cfst.exe"
CFST_ARGS = ["-f", "cloudflare.txt", "-p", "443", "-t", "10", "-dd"]

# -----------------------------
# Logging + globals
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
log = logging.getLogger("redirect-optimized")

_parse_last_log = 0.0
_parse_failure_samples = 0
_parse_failure_lock = threading.Lock()

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
metrics = {"send_ok": 0, "send_fail": 0, "rotate_events": 0, "raw_queue_drops": 0, "send_queue_high_water_events": 0, "dropped_syn": 0, "parse_failures": 0}
target_status = {}
user_continent = None

# -----------------------------
# IP + Geo + cfst
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

def get_continent(ip: str = '') -> str:
    try:
        url = GEO_API_URL.format(ip=ip) if ip else GEO_API_URL.format(ip='')
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
            return data.get('continent_code', 'UNKNOWN')
    except Exception:
        return 'UNKNOWN'

user_continent = get_continent()
log.info("User continent detected: %s", user_continent)

def run_cf_speed_test() -> bool:
    if not CFST_EXE.exists():
        log.warning("cfst.exe NOT FOUND at %s", CFST_EXE)
        return False
    log.info("Running cfst.exe (~30-90s real speed+loss test)...")
    try:
        result = subprocess.run([str(CFST_EXE)] + CFST_ARGS, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, check=False)
        if result.stdout:
            log.debug("cfst stdout preview: %s", result.stdout[:400])
        if result.stderr:
            log.debug("cfst stderr: %s", result.stderr[:400])
        if result.returncode == 0:
            log.info("cfst.exe SUCCESS → result.csv created")
            return True
        else:
            log.error("cfst.exe failed (code %d)", result.returncode)
            return False
    except subprocess.TimeoutExpired:
        log.warning("cfst.exe timed out — trying to use result.csv anyway")
        return False
    except Exception as e:
        log.error("cfst.exe error: %s", e)
        return False

# -----------------------------
# Cloudflare ranges
# -----------------------------
cf_path = Path("cloudflare.txt")
if cf_path.exists():
    try:
        with cf_path.open(encoding="utf-8") as f:
            ranges = set()
            for line in f:
                line = line.strip()
                if line:
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        if net.version == 4:
                            ranges.add((int(net.network_address), int(net.broadcast_address)))
                    except Exception:
                        continue
        sorted_ranges = sorted(ranges)
        CLOUDFLARE_RANGES = sorted_ranges
        CLOUDFLARE_RANGES_STARTS = [s for s, e in sorted_ranges]
        log.info("Loaded %d Cloudflare networks", len(CLOUDFLARE_RANGES))
    except Exception as e:
        log.warning("cloudflare.txt load failed: %s", e)

def is_cloudflare_ip_int(ip_int: int) -> bool:
    with state_lock:
        if not CLOUDFLARE_RANGES_STARTS:
            return False
        idx = bisect.bisect_left(CLOUDFLARE_RANGES_STARTS, ip_int)
        if idx < len(CLOUDFLARE_RANGES):
            s, e = CLOUDFLARE_RANGES[idx]
            if s <= ip_int <= e: return True
        if idx > 0:
            s, e = CLOUDFLARE_RANGES[idx - 1]
            if s <= ip_int <= e: return True
    return False

def generate_targets_from_ranges():
    targets = set()
    with state_lock:
        for s, e in CLOUDFLARE_RANGES:
            test_ip_int = s + 1
            if test_ip_int <= e:
                targets.add(int_to_ip(test_ip_int))
    return list(targets)

def validate_ip(ip: str) -> bool:
    if not is_valid_ipv4(ip) or not is_cloudflare_ip_int(ip_to_int(ip)):
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, TEST_PORT))
        s.close()
        return True
    except Exception:
        return False

# -----------------------------
# LOAD TARGETS (the fixed flow)
# -----------------------------
def load_targets_from_disk(force_regen=False):
    global TARGET_IPS, TARGET_IPS_INT, NUM_TARGETS

    csv_path = CFST_EXE.parent / "result.csv"

    # Run cfst if needed
    if not TARGET_FILE.exists() or TARGET_FILE.stat().st_size == 0 or force_regen:
        log.info("target.txt empty or forced regen → running cfst.exe")
        run_cf_speed_test()
        time.sleep(3)  # let file system flush

    # Parse result.csv (primary path)
    if csv_path.exists():
        log.info("Found result.csv → extracting top 10 IPs")
        ips = []
        try:
            with csv_path.open(encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            for line in lines[1:]:  # skip header
                line = line.strip()
                if not line: continue
                parts = line.split(',')
                if parts:
                    ip = parts[0].strip()
                    if is_valid_ipv4(ip) and ip not in ips:
                        ips.append(ip)
                if len(ips) >= 10:
                    break
            if ips:
                with TARGET_FILE.open("w", encoding="utf-8") as f:
                    for ip in ips:
                        f.write(ip + "\n")
                log.info("Written top 10 IPs from result.csv to target.txt")
                with state_lock:
                    TARGET_IPS = ips[:]
                    TARGET_IPS_INT = [ip_to_int(ip) for ip in TARGET_IPS]
                    NUM_TARGETS = len(TARGET_IPS)
                    for ip_int in TARGET_IPS_INT:
                        if ip_int not in target_status:
                            target_status[ip_int] = {"up": True, "last_change": time.time(), "fail_count": 0, "backoff_until": 0.0}
                log.info("✅ Loaded %d unique targets from CSV", NUM_TARGETS)
                return
        except Exception as e:
            log.warning("Failed to parse result.csv: %s", e)

    # Fallback
    log.warning("No result.csv or parse failed - using fallback")
    ips = set()
    if not TARGET_FILE.exists() or TARGET_FILE.stat().st_size == 0:
        gen_ips = generate_targets_from_ranges()
        for ip in gen_ips:
            if validate_ip(ip):
                ips.add(ip)
        if ips:
            with TARGET_FILE.open("w", encoding="utf-8") as f:
                for ip in sorted(ips):
                    f.write(ip + "\n")
    else:
        with TARGET_FILE.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and is_valid_ipv4(line):
                    ips.add(line)
    with state_lock:
        TARGET_IPS = list(ips)
        TARGET_IPS_INT = [ip_to_int(ip) for ip in TARGET_IPS]
        NUM_TARGETS = len(TARGET_IPS)
        for ip_int in TARGET_IPS_INT:
            if ip_int not in target_status:
                target_status[ip_int] = {"up": True, "last_change": time.time(), "fail_count": 0, "backoff_until": 0.0}
    log.info("Loaded %d unique targets (fallback)", NUM_TARGETS)

load_targets_from_disk()

# -----------------------------
# Daily refresh (forces update)
# -----------------------------
def daily_cf_speed_test_refresh():
    while True:
        time.sleep(24 * 3600)
        log.info("=== Daily cfst.exe refresh started ===")
        if run_cf_speed_test():
            time.sleep(3)
            if TARGET_FILE.exists():
                TARGET_FILE.unlink(missing_ok=True)
            load_targets_from_disk(force_regen=True)
            if TARGET_SCORES_CACHE.exists():
                TARGET_SCORES_CACHE.unlink()

threading.Thread(target=daily_cf_speed_test_refresh, daemon=True, name="cfst-daily").start()

# -----------------------------
# NAT helpers (original)
# -----------------------------
def make_outbound_flow_key(src_ip_int, src_port, dst_ip_int, dst_port, proto):
    return (src_ip_int, src_port, dst_ip_int, dst_port, proto)

def make_inbound_rev_key(target_ip_int, target_port, client_ip_int, client_port, proto):
    return (target_ip_int, target_port, client_ip_int, client_port, proto)

def make_client_side_flow_key(client_ip_int, client_port, orig_dst_ip_int, orig_dst_port, proto):
    return (client_ip_int, client_port, orig_dst_ip_int, orig_dst_port, proto)

def icmp_index_add(target_ip_int, flow_key):
    with state_lock:
        if target_ip_int not in icmp_index:
            icmp_index[target_ip_int] = set()
        icmp_index[target_ip_int].add(flow_key)

def icmp_index_remove(target_ip_int, flow_key):
    with state_lock:
        if target_ip_int in icmp_index:
            icmp_index[target_ip_int].discard(flow_key)
            if not icmp_index[target_ip_int]:
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
        with state_lock:
            nat_flow_last_seen.pop(fk, None)
    last_cleanup_time = now

# -----------------------------
# Queues + helpers
# -----------------------------
raw_queue = queue.Queue(maxsize=QUEUE_MAX)
send_queue = queue.Queue(maxsize=QUEUE_MAX)

def log_queue_watermark_check():
    try:
        sq = send_queue.qsize()
        if sq > QUEUE_MAX * 0.25:
            metrics["send_queue_high_water_events"] += 1
            log.warning("send_queue high watermark: %d/%d", sq, QUEUE_MAX)
    except Exception:
        pass

def send_tcp_rst_back(w, pkt):
    try:
        rst_pkt = pydivert.Packet(bytes(pkt), getattr(pkt, "interface", 0), getattr(pkt, "direction", 0))
        rst_pkt.src_addr, rst_pkt.dst_addr = pkt.dst_addr, pkt.src_addr
        rst_pkt.src_port, rst_pkt.dst_port = pkt.dst_port, pkt.src_port
        if getattr(rst_pkt, "tcp", None):
            rst_pkt.tcp.rst = True
            rst_pkt.tcp.ack = True
        rst_pkt.payload = b""
        fn = getattr(rst_pkt, "recalculate_checksums", None)
        if callable(fn):
            fn()
        w.send(rst_pkt)
        metrics["send_ok"] += 1
    except Exception:
        metrics["send_fail"] += 1

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
            fh.write(f"--- SAMPLE {ts} ---\ninterface={interface} direction={direction}\nexception={repr(exc)}\nhex={hex_sample}\n\n")
    except Exception:
        pass

# -----------------------------
# modifier_worker (FULL original)
# -----------------------------
def modifier_worker():
    global _parse_last_log
    thread_name = threading.current_thread().name
    log.info("modifier_worker started: %s", thread_name)
    while True:
        try:
            raw_item = raw_queue.get(timeout=1.0)
        except queue.Empty:
            time.sleep(0.01)
            continue
        if raw_item is None:
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
            now = time.time()
            if now - _parse_last_log > 5.0:
                _parse_last_log = now
                log.exception("modifier_worker %s: parse failed", thread_name)
            try:
                _save_parse_failure_sample(interface, direction, raw_bytes, e)
            except Exception:
                pass
            continue
        try:
            if send_queue.qsize() > QUEUE_MAX * 0.6:
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
                if dst_port in EXCLUDED_PORTS or dst_port not in SSL_PORTS:
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
                                is_tcp_syn = bool(getattr(pkt.tcp, "syn", False) and not getattr(pkt.tcp, "ack", False))
                        except Exception:
                            pass
                        if is_tcp_syn:
                            try:
                                send_queue.put(("RST_FROM_MOD", bytes(pkt), interface, direction), timeout=0.5)
                            except queue.Full:
                                metrics["raw_queue_drops"] += 1
                                metrics["dropped_syn"] += 1
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
                fn = getattr(pkt, "recalculate_checksums", None) or getattr(pkt, "calc_checksums", None)
                if callable(fn):
                    fn()
                out_bytes = bytes(pkt)
                try:
                    send_queue.put((out_bytes, interface, direction), timeout=0.5)
                except queue.Full:
                    metrics["raw_queue_drops"] += 1
                continue
            # inbound
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
            if src_port in EXCLUDED_PORTS or dst_port in EXCLUDED_PORTS:
                out_bytes = bytes(pkt)
                try:
                    send_queue.put((out_bytes, interface, direction), timeout=0.5)
                except queue.Full:
                    metrics["raw_queue_drops"] += 1
                continue
            flow_key_inbound = make_inbound_rev_key(src_ip_int, src_port, dst_ip_int, dst_port, proto)
            with state_lock:
                orig_dst_ip_int = nat_map_inbound.get(flow_key_inbound)
            if orig_dst_ip_int is not None and src_port in SSL_PORTS:
                client_ip_int = dst_ip_int
                client_port = dst_port
                flow_key = make_client_side_flow_key(client_ip_int, client_port, orig_dst_ip_int, src_port, proto)
                touch_flow(flow_key)
                pkt.src_addr = int_to_ip(orig_dst_ip_int)
                fn = getattr(pkt, "recalculate_checksums", None) or getattr(pkt, "calc_checksums", None)
                if callable(fn):
                    fn()
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
            log.exception("modifier_worker error")
            try:
                send_queue.put((bytes(pkt), interface, direction), timeout=0.5)
            except Exception:
                metrics["raw_queue_drops"] += 1

# -----------------------------
# drain + capture (original)
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
            pkt_to_send = pydivert.Packet(out_bytes, interface, direction)
            w.send(pkt_to_send)
            metrics["send_ok"] += 1
        except Exception:
            metrics["send_fail"] += 1
            try:
                dst_ip = getattr(pkt_to_send, "dst_addr", None)
                if dst_ip:
                    dst_ip_int = ip_to_int(dst_ip)
                    with state_lock:
                        st = target_status.setdefault(dst_ip_int, {"up": False, "fail_count": 1, "backoff_until": time.time() + 1})
                        st["fail_count"] = st.get("fail_count", 0) + 1
                        if st["fail_count"] >= HEALTH_FAILS_TO_MARK_DOWN:
                            st["up"] = False
                            st["backoff_until"] = time.time() + min(HEALTH_BACKOFF_BASE ** st["fail_count"], HEALTH_BACKOFF_MAX)
            except Exception:
                pass
        sent += 1
    return True

def capture_loop_interleaved(w, recv_timeout=0.01, drain_batch=DEFAULT_DRAIN_BATCH):
    global PASS_THROUGH, _packet_count
    log.info("Capture interleaved loop started")
    try:
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
                raw = bytes(packet)
                interface = getattr(packet, "interface", 0)
                direction = getattr(packet, "direction", 0)
            except Exception:
                metrics["parse_failures"] += 1
                continue
            try:
                raw_queue.put_nowait((raw, interface, direction))
            except queue.Full:
                if DROP_ON_FULL:
                    metrics["raw_queue_drops"] += 1
                else:
                    try:
                        raw_queue.put((raw, interface, direction), timeout=QUEUE_PUT_TIMEOUT)
                    except queue.Full:
                        metrics["raw_queue_drops"] += 1
            log_queue_watermark_check()
            time.sleep(0.001)
    finally:
        log.info("Capture loop exiting")

# -----------------------------
# packet counter
# -----------------------------
def packet_counter_logger():
    last_count = 0
    last_time = time.time()
    while not _packet_counter_stop.is_set():
        time.sleep(_PACKET_COUNTER_LOG_INTERVAL)
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
    while True:
        time.sleep(CLOUDFLARE_REFRESH_INTERVAL)
        try:
            with urllib.request.urlopen("https://www.cloudflare.com/ips-v4", timeout=10) as r:
                raw = r.read().decode("utf-8")
            new_ranges = set()
            for line in raw.splitlines():
                line = line.strip()
                if line:
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        if net.version == 4:
                            new_ranges.add((int(net.network_address), int(net.broadcast_address)))
                    except Exception:
                        continue
            if new_ranges:
                sorted_new = sorted(new_ranges)
                CLOUDFLARE_RANGES = sorted_new
                CLOUDFLARE_RANGES_STARTS = [s for s, e in sorted_new]
                log.info("Cloudflare ranges refreshed: %d networks", len(sorted_new))
                load_targets_from_disk(force_regen=True)
        except Exception as e:
            log.warning("Cloudflare refresh failed: %s", e)

# -----------------------------
# Measurement + scoring
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

def measure_throughput(ip: str, size_bytes: int = 64 * 1024) -> float:
    start = time.time()
    try:
        req = urllib.request.Request(f"https://{ip}/cdn-cgi/trace", headers={"Host": "cloudflare.com", "User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as r:
            data = r.read(size_bytes)
        elapsed = max(time.time() - start, 0.001)
        mbps = (len(data) * 8) / (elapsed * 1_000_000)
        return max(mbps, 0.1)
    except Exception:
        return 0.0

def score_target(ip: str) -> tuple[float, float, float, float, float]:
    runs = SPEED_TEST_RUNS
    udps = [measure_udp_quic(ip) for _ in range(runs)]
    tcps = [measure_tcp_connect(ip) for _ in range(runs)]
    tlss = [measure_tls(ip) for _ in range(runs)]
    def clean_median(vals):
        if not vals: return float('inf')
        med = statistics.median(vals)
        cleaned = [v for v in vals if v <= med * OUTLIER_MULTIPLIER]
        return statistics.median(cleaned) if cleaned else med
    udp_ms = clean_median(udps)
    tcp_ms = clean_median(tcps)
    tls_ms = clean_median(tlss)
    throughput = measure_throughput(ip)
    loss_proxy = 1.0 if tcp_ms == float('inf') or tls_ms == float('inf') else max(0.0, (udp_ms - tcp_ms) / 100.0)
    latency_score = (tcp_ms + tls_ms) / 2.0
    geo_bonus = 0.85 if get_continent(ip) == user_continent and user_continent != 'UNKNOWN' else 1.0
    score = latency_score * geo_bonus / max(throughput, 0.5) * (1 + loss_proxy * 3)
    return score, udp_ms, tcp_ms, tls_ms, throughput

# -----------------------------
# update_targets
# -----------------------------
def update_targets(force=False):
    global TARGET_IPS, TARGET_IPS_INT, NUM_TARGETS
    while True:
        if force:
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
            log.info("Testing %d IPs", len(to_test))
            with concurrent.futures.ThreadPoolExecutor(max_workers=SPEED_TEST_THREADS) as executor:
                future_to_ip = {executor.submit(score_target, ip): ip for ip in to_test}
                for future in concurrent.futures.as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        score, udp, tcp, tls, thru = future.result()
                        results.append((score, ip, udp, tcp, tls, thru))
                        cache[ip] = {'score': score, 'udp_ms': udp, 'tcp_ms': tcp, 'tls_ms': tls, 'throughput': thru, 'timestamp': time.time()}
                    except Exception as e:
                        log.warning("score %s failed: %s", ip, e)
            for ip, data in cache.items():
                if ip not in [r[1] for r in results]:
                    results.append((data['score'], ip, data.get('udp_ms',0), data.get('tcp_ms',0), data.get('tls_ms',0), data.get('throughput',0)))
            results.sort(key=lambda x: x[0])
            best = results[:TOP_N]
            log.info("Top targets: %s", json.dumps([{'ip':ip,'score':round(score,2),'thru':round(thru,1)} for score,ip,_,_,_,thru in best], indent=2))
            tmp = TARGET_UPDATE_FILE.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                for _, ip, _, _, _, _ in best:
                    f.write(ip + "\n")
            tmp.replace(TARGET_UPDATE_FILE)
            TARGET_UPDATE_FILE.replace(TARGET_FILE)
            load_targets_from_disk()
            with state_lock:
                for ip_int in TARGET_IPS_INT:
                    if ip_int not in target_status:
                        target_status[ip_int] = {"up": True, "last_change": time.time(), "fail_count": 0, "backoff_until": 0.0}
            with TARGET_SCORES_CACHE.open("w") as f:
                json.dump(cache, f)
            log.info("target.txt updated with top %d stable IPs", TOP_N)
        except Exception as e:
            log.warning("Target update failed: %s", e)

# -----------------------------
# Health + HTTP + WinDivert + main loop
# -----------------------------
async def async_probe(ip_int: int):
    ip = int_to_ip(ip_int)
    loop = asyncio.get_running_loop()
    def sync_connect():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(HEALTH_CHECK_TIMEOUT)
        try:
            s.connect((ip, TEST_PORT))
            s.close()
            return True
        except Exception:
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
                        log.info("Target %s UP", int_to_ip(ip_int))
                else:
                    st["fail_count"] = st.get("fail_count", 0) + 1
                    if st["fail_count"] >= HEALTH_FAILS_TO_MARK_DOWN:
                        st["backoff_until"] = time.time() + min(HEALTH_BACKOFF_BASE ** st["fail_count"], HEALTH_BACKOFF_MAX)
                        if prev_up:
                            st["up"] = False
                            st["last_change"] = time.time()
                            log.warning("Target %s DOWN", int_to_ip(ip_int))
        if tasks:
            await asyncio.gather(*(probe_and_update(ip) for ip in tasks), return_exceptions=True)
        await asyncio.sleep(0.5)

def start_asyncio_thread():
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        task = loop.create_task(health_scheduler(asyncio_stop))
        try:
            loop.run_forever()
        finally:
            task.cancel()
            loop.close()
    t = threading.Thread(target=_run, daemon=True, name="health-thread")
    t.start()

asyncio_stop = threading.Event()
start_asyncio_thread()

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
    def do_GET(self):
        global PASS_THROUGH
        if self.path == "/health":
            self._write_json({"status": "ok", "pass_through": PASS_THROUGH})
            return
        if self.path == "/metrics":
            with state_lock:
                targets = []
                for ip_int in TARGET_IPS_INT:
                    st = target_status.get(ip_int, {})
                    flows = sum(1 for t in nat_map_outbound.values() if t == ip_int)
                    targets.append({"ip": int_to_ip(ip_int), "up": bool(st.get("up", False)), "fail_count": int(st.get("fail_count", 0)), "flows": flows})
                payload = {"targets": targets, "total_flows": len(nat_map_outbound), "metrics": metrics, "pass_through": PASS_THROUGH}
            self._write_json(payload)
            return
        if self.path == "/refresh-targets":
            threading.Thread(target=update_targets, args=(True,)).start()
            self._write_json({"status": "refresh triggered"})
            return
        self.send_response(404)
        self.end_headers()

def start_debug_server():
    try:
        server = ThreadingHTTPServer((METRICS_HOST, METRICS_PORT), DebugMetricsHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True, name="debug-http")
        t.start()
        log.info("Debug server on http://%s:%d", METRICS_HOST, METRICS_PORT)
        return server
    except Exception as e:
        log.error("Debug server failed: %s", e)
        return None

metrics_server = start_debug_server()

def http_watchdog():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((METRICS_HOST, METRICS_PORT))
            s.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            s.recv(256)
            s.close()
        except Exception:
            pass
        time.sleep(300)

threading.Thread(target=http_watchdog, daemon=True, name="http-watchdog").start()

def heartbeat_thread():
    while True:
        try:
            log.info("heartbeat: targets_up=%d pass=%s", sum(1 for s in target_status.values() if s.get("up")), PASS_THROUGH)
        except Exception:
            pass
        time.sleep(60)

threading.Thread(target=heartbeat_thread, daemon=True, name="heartbeat").start()

def startup_probe_targets():
    if not STARTUP_PROBE: return
    for ip in TARGET_IPS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(STARTUP_PROBE_TIMEOUT)
            s.connect((ip, TEST_PORT))
            s.close()
        except Exception:
            pass

threading.Thread(target=startup_probe_targets, daemon=True, name="startup-probes").start()

def try_open_windivert(filters):
    for f in filters:
        try:
            w = pydivert.WinDivert(f)
            w.open()
            log.info("WinDivert opened with filter: %s", f)
            return w
        except Exception as e:
            log.warning("WinDivert %s failed: %s", f, e)
    return None

filters_to_try = [CAPTURE_FILTER] + FALLBACK_FILTERS
w = try_open_windivert(filters_to_try)
if w is None:
    log.critical("WinDivert failed to open")
    raise SystemExit(1)

# -----------------------------
# Start everything
# -----------------------------
log.info("=== OPTIMIZED REDIRECTOR WITH FIXED CFST STARTED ===")
threading.Thread(target=refresh_cloudflare_ranges, daemon=True, name="cf-refresh").start()
threading.Thread(target=update_targets, daemon=True, name="target-updater").start()

worker_pool = concurrent.futures.ThreadPoolExecutor(max_workers=WORKER_COUNT)
for i in range(WORKER_COUNT):
    worker_pool.submit(modifier_worker)

try:
    faulthandler.enable()
    capture_loop_interleaved(w)
except KeyboardInterrupt:
    log.info("Stopped by user")
except Exception as e:
    log.exception("Main loop error: %s", e)
finally:
    asyncio_stop.set()
    for _ in range(WORKER_COUNT):
        raw_queue.put_nowait(None)
    send_queue.put_nowait(None)
    worker_pool.shutdown(wait=True)
    if w:
        w.close()
    if metrics_server:
        metrics_server.shutdown()
    _packet_counter_stop.set()
    log.info("Shutdown complete")
    sys.exit(0)
