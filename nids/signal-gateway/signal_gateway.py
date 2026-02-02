#!/usr/bin/env python3
import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
import selectors
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, Set, List

import yaml


@dataclass
class FlowStats:
    pkts: int = 0
    bytes: int = 0
    syn_only: int = 0  # tcp syn=1 ack=0


@dataclass
class MinuteAggregator:
    # key = (src_ip, dst_ip, proto, dst_port)
    flows: Dict[Tuple[str, str, str, str], FlowStats] = field(default_factory=dict)

    def add(self, key: Tuple[str, str, str, str], frame_len: int, syn_only: int) -> None:
        st = self.flows.get(key)
        if st is None:
            st = FlowStats()
            self.flows[key] = st
        st.pkts += 1
        st.bytes += max(frame_len, 0)
        st.syn_only += syn_only


def is_public_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.version == 4 and addr.is_global
    except ValueError:
        return False


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_gateway_ip(cfg: dict) -> str:
    if isinstance(cfg.get("gateway_ip"), str):
        return cfg.get("gateway_ip") or ""
    return (cfg.get("home_lan", {}) or {}).get("gateway_ip", "") or ""


def device_policy_allow_wan(cfg: dict, ip: str) -> bool:
    devices = cfg.get("devices", {}) or {}
    defaults = cfg.get("defaults", {}) or {}
    default_allow = (defaults.get("policy", {}) or {}).get("allow_wan", True)

    dev = devices.get(ip)
    if not dev:
        return default_allow
    pol = dev.get("policy", {}) or {}
    return pol.get("allow_wan", default_allow)


def _normalize_ip_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for item in value:
            if item is None:
                continue
            s = str(item).strip()
            if s:
                out.append(s)
        return out
    return []


def device_policy_blacklist(cfg: dict, ip: str) -> List[str]:
    devices = cfg.get("devices", {}) or {}
    defaults = cfg.get("defaults", {}) or {}
    default_blacklist = (defaults.get("policy", {}) or {}).get("blacklist", [])

    dev = devices.get(ip)
    if not dev:
        return _normalize_ip_list(default_blacklist)
    pol = dev.get("policy", {}) or {}
    if "blacklist" in pol:
        return _normalize_ip_list(pol.get("blacklist"))
    return _normalize_ip_list(default_blacklist)


def device_info(cfg: dict, ip: str) -> dict:
    dev = (cfg.get("devices", {}) or {}).get(ip, {}) or {}
    return {
        "ip": ip,
        "name": dev.get("name", ip),
        "role": dev.get("role", "unknown"),
        "allow_wan": device_policy_allow_wan(cfg, ip),
        "blacklist": device_policy_blacklist(cfg, ip),
    }


def is_iot_device(cfg: dict, ip: str) -> bool:
    role = ((cfg.get("devices", {}) or {}).get(ip, {}) or {}).get("role", "") or ""
    return "iot" in str(role).lower()


def spawn_tshark(iface: str) -> subprocess.Popen:
    # Fields (tab-separated):
    #   0 frame.time_epoch
    #   1 ip.src
    #   2 ip.dst
    #   3 ip.proto
    #   4 tcp.dstport
    #   5 udp.dstport
    #   6 frame.len
    #   7 tcp.flags.syn
    #   8 tcp.flags.ack
    cmd = [
        "tshark",
        "-l",
        "-i", iface,
        "-f", "ip",
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.proto",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "frame.len",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
    ]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)


def safe_int(x: str, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def post_webhook(url: str, payload: dict, timeout_s: int = 2) -> None:
    if not url:
        return
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as _:
            return
    except (urllib.error.URLError, urllib.error.HTTPError):
        # Best-effort only; summaries are still persisted to disk.
        return


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)


def emit_jsonl(path: str, obj: dict) -> None:
    ensure_parent_dir(path)
    line = json.dumps(obj, ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    # Also print to stdout for easy piping.
    print(line, flush=True)


def build_minute_summary(
    cfg: dict,
    cam_subnet: ipaddress.IPv4Network,
    gateway_ip: str,
    ts_start: int,
    ts_end: int,
    agg: MinuteAggregator,
    seen_public_dests: Set[str],
) -> dict:
    top_limit = int((cfg.get("output", {}) or {}).get("top_flows_limit", 20))
    wan_flow_limit = int((cfg.get("output", {}) or {}).get("wan_flows_limit", 10))
    scan_unique_ports_threshold = int((cfg.get("thresholds", {}) or {}).get("scan_unique_ports", 10))

    # Prepare flow list
    flow_rows: List[dict] = []
    flows_to_public: List[dict] = []
    local_initiations: List[dict] = []

    public_dests_this_minute: Set[str] = set()

    for (src, dst, proto, dport), st in agg.flows.items():
        row = {
            "src": src,
            "dst": dst,
            "proto": proto,
            "dport": int(dport) if str(dport).isdigit() else dport,
            "pkts": st.pkts,
            "bytes": st.bytes,
            "syn_only": st.syn_only if proto == "tcp" else 0,
        }
        flow_rows.append(row)

        if is_public_ipv4(dst):
            public_dests_this_minute.add(dst)
            flows_to_public.append(row)

        # TCP initiations inside local subnet (camera->local)
        try:
            if proto == "tcp" and st.syn_only > 0:
                if ipaddress.ip_address(dst) in cam_subnet and ipaddress.ip_address(src) in cam_subnet:
                    if src != dst and (not gateway_ip or dst != gateway_ip):
                        if is_iot_device(cfg, src):
                            local_initiations.append({
                                "src": src,
                                "dst": dst,
                                "proto": "tcp",
                                "dport": int(dport) if str(dport).isdigit() else dport,
                                "syn_only": st.syn_only,
                            })
        except ValueError:
            pass

    # Compute scan indicators: unique dports where syn_only>0 per (src,dst)
    scan_counts: Dict[Tuple[str, str], Set[str]] = {}
    for (src, dst, proto, dport), st in agg.flows.items():
        if proto != "tcp" or st.syn_only <= 0:
            continue
        try:
            if ipaddress.ip_address(src) not in cam_subnet or ipaddress.ip_address(dst) not in cam_subnet:
                continue
        except ValueError:
            continue
        if src == dst:
            continue
        if gateway_ip and dst == gateway_ip:
            continue
        if not is_iot_device(cfg, src):
            continue
        scan_counts.setdefault((src, dst), set()).add(str(dport or "0"))

    scan_indicators: List[dict] = []
    for (src, dst), ports in scan_counts.items():
        if len(ports) >= scan_unique_ports_threshold:
            scan_indicators.append({
                "src": src,
                "dst": dst,
                "proto": "tcp",
                "unique_dports_syn_only": len(ports),
            })

    # Determine new public destinations
    new_public = sorted([ip for ip in public_dests_this_minute if ip not in seen_public_dests])
    seen_public_dests.update(public_dests_this_minute)

    flows_to_public_all = list(flows_to_public)

    # Select top flows by bytes and packets, merge unique
    by_bytes = sorted(flow_rows, key=lambda r: (r["bytes"], r["pkts"]), reverse=True)[:top_limit]
    by_pkts = sorted(flow_rows, key=lambda r: (r["pkts"], r["bytes"]), reverse=True)[:top_limit]
    merged = []
    seen_keys = set()
    for r in by_bytes + by_pkts:
        k = (r["src"], r["dst"], r["proto"], r["dport"])
        if k in seen_keys:
            continue
        seen_keys.add(k)
        merged.append(r)
        if len(merged) >= top_limit:
            break

    # WAN activity subset
    flows_to_public = sorted(flows_to_public, key=lambda r: (r["pkts"], r["bytes"]), reverse=True)[:wan_flow_limit]

    # Device map (include configured devices)
    devices_cfg = cfg.get("devices", {}) or {}
    devices_out = {ip: device_info(cfg, ip) for ip in devices_cfg.keys()}

    # Policy violations
    policy_violations_map: Dict[Tuple[str, str, str, object], dict] = {}
    blacklist_cache: Dict[str, Set[str]] = {}

    def get_blacklist(ip: str) -> Set[str]:
        bl = blacklist_cache.get(ip)
        if bl is None:
            bl = set(device_policy_blacklist(cfg, ip))
            blacklist_cache[ip] = bl
        return bl

    def add_violation(row: dict, reason: str) -> None:
        key = (row["src"], row["dst"], row["proto"], row["dport"])
        existing = policy_violations_map.get(key)
        if existing is None:
            policy_violations_map[key] = {
                "src": row["src"],
                "dst": row["dst"],
                "proto": row["proto"],
                "dport": row["dport"],
                "pkts": row["pkts"],
                "bytes": row["bytes"],
                "reason": [reason],
            }
            return
        if reason not in existing["reason"]:
            existing["reason"].append(reason)

    for r in flows_to_public_all:
        if not device_policy_allow_wan(cfg, r["src"]):
            add_violation(r, "allow_wan=false but contacted public IP")

    for r in flow_rows:
        if r["dst"] in get_blacklist(r["src"]):
            add_violation(r, "blacklisted destination")

    policy_violations = []
    for v in policy_violations_map.values():
        v["reason"] = "; ".join(v["reason"])
        policy_violations.append(v)
    policy_violations = sorted(policy_violations, key=lambda r: (r["pkts"], r["bytes"]), reverse=True)

    summary = {
        "ts_start": ts_start,
        "ts_end": ts_end,
        "subnet": str(cam_subnet),
        "gateway_ip": gateway_ip,
        "devices": devices_out,
        "summary": {
            "top_flows": merged,
            "wan_activity": {
                "flows_to_public": flows_to_public,
                "new_public_dests": new_public,
            },
            "local_initiations": sorted(local_initiations, key=lambda r: r["syn_only"], reverse=True)[:top_limit],
            "scan_indicators": sorted(scan_indicators, key=lambda r: r["unique_dports_syn_only"], reverse=True),
            "policy_violations": policy_violations,
        },
    }
    return summary


def main() -> int:
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.yml"
    cfg = load_config(cfg_path)

    iface = (cfg.get("home_lan", {}) or {}).get("iface", "wlan1")
    subnet_str = (cfg.get("home_lan", {}) or {}).get("subnet")
    cam_subnet = ipaddress.ip_network(subnet_str, strict=False)

    gateway_ip = get_gateway_ip(cfg)

    # Fixed 1-minute windows (aligned to wall-clock minute)
    window_seconds = 60

    out_cfg = cfg.get("output", {}) or {}
    jsonl_path = out_cfg.get("jsonl_path") or "./telemetry_minute.jsonl"
    webhook_url = out_cfg.get("webhook_url") or ""
    webhook_timeout_s = int(out_cfg.get("webhook_timeout_s", 2))

    print(f"[+] Starting telemetry gateway on iface={iface}, subnet={cam_subnet}, window={window_seconds}s", file=sys.stderr)
    proc = spawn_tshark(iface)

    sel = selectors.DefaultSelector()
    if proc.stdout:
        sel.register(proc.stdout, selectors.EVENT_READ)

    seen_public_dests: Set[str] = set()
    agg = MinuteAggregator()

    window_start = int(time.time() // 60 * 60)

    def flush(now_ts: int) -> None:
        nonlocal window_start, agg
        ts_start = window_start
        ts_end = window_start + window_seconds
        summary = build_minute_summary(cfg, cam_subnet, gateway_ip, ts_start, ts_end, agg, seen_public_dests)

        emit_jsonl(jsonl_path, summary)
        if webhook_url:
            post_webhook(webhook_url, summary, timeout_s=webhook_timeout_s)

        agg = MinuteAggregator()
        window_start = ts_end

    try:
        while True:
            now = int(time.time())

            # Flush any overdue minutes (in case we were blocked or no traffic)
            while now >= window_start + window_seconds:
                flush(now)

            events = sel.select(timeout=0.5)
            if not events:
                continue

            for key, _ in events:
                line = key.fileobj.readline()
                if not line:
                    err = proc.stderr.read() if proc.stderr else ""
                    print("[!] tshark stopped. stderr:\n" + err, file=sys.stderr)
                    return 1

                parts = line.strip().split("\t")
                # Expect 9 fields
                if len(parts) != 9:
                    continue

                _ts, src_ip, dst_ip, ip_proto, tcp_dport, udp_dport, frame_len, syn_f, ack_f = parts

                if not src_ip or not dst_ip:
                    continue

                try:
                    if ipaddress.ip_address(src_ip) not in cam_subnet:
                        continue
                except ValueError:
                    continue

                proto = "tcp" if ip_proto == "6" else "udp" if ip_proto == "17" else ip_proto
                dst_port = tcp_dport if proto == "tcp" else udp_dport if proto == "udp" else "0"
                if not dst_port:
                    dst_port = "0"

                flen = safe_int(frame_len, 0)

                syn_only = 0
                if proto == "tcp":
                    syn = 1 if syn_f == "True" else 0
                    ack = 1 if ack_f == "True" else 0
                    if syn == 1 and ack == 0:
                        syn_only = 1

                agg.add((src_ip, dst_ip, proto, dst_port), flen, syn_only)

    except KeyboardInterrupt:
        print("\n[+] Stopping...", file=sys.stderr)
        # Flush current partial minute too
        now = int(time.time())
        flush(now)
        proc.terminate()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())