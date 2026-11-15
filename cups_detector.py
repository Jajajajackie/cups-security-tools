#!/usr/bin/env python3
"""
CUPS browse/IPP traffic detector for the DAT505 lab.

Passively analyses UDP/631 printer-discovery adverts and IPP
connections (live or from PCAP) and raises alerts for unauthorized
printers, malformed browse packets, discovery floods, and suspicious
IPP content. Export to CSV/JSON.

Usage:
    python3 cups_detector.py --pcap capture.pcapng --output alerts.csv
    python3 cups_detector.py --iface eth0 --format json --output alerts.json

For use only inside the isolated lab environment.
"""

import argparse
import re
import csv
import json
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, PcapReader, IP, UDP, TCP, Raw

# configuration
CUPS_BROWSE_PORT = 631
AUTHORIZED_PRINTERS = set()
ALLOWED_URI_SCHEMES = {"ipp", "ipps", "http", "https"}
STANDARD_IPP_PORT = "631"
SUSPICIOUS_CHARS = [";", "|", "`", "$", "&", "<", ">", "\n", "\r"]
DISCOVERY_WINDOW = 10
DISCOVERY_THRESHOLD = 5
IPP_SIGNATURES = [b"application/ipp", b"POST /printers/", b"POST /ipp/"]
IPP_INJECTION_STRINGS = [b"FoomaticRIPCommandLine", b"CommandLine", b"`", b"$("]

# state 
advert_times = defaultdict(list)
ALERTS = []                     # every alert is stored here for export

# alert recorder
def add_alert(ts, severity, rule, src, dst, details):
    alert = {
        "timestamp": datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S"),
        "severity": severity,
        "rule": rule,
        "src": src,
        "dst": dst,
        "details": details,
    }
    ALERTS.append(alert)
    print(f"[ALERT] {severity} | {rule} | {src} -> {dst}")
    print(f"        {details}")

# helper functions
def parse_browse_packet(payload):
    try:
        text = payload.decode("utf-8", errors="replace").strip()
    except Exception:
        return None
    parts = text.split(" ", 3)
    if len(parts) < 3:
        return None
    return {
        "type": parts[0],
        "state": parts[1],
        "uri": parts[2],
        "rest": parts[3] if len(parts) > 3 else "",
        "raw": text,
    }

def uri_host(uri):
    m = re.match(r"[a-zA-Z]+://([^/]+)", uri)
    return m.group(1) if m else None

# detection rules
def check_unauthorized_advert(pkt, src):
    if Raw not in pkt:
        return
    info = parse_browse_packet(pkt[Raw].load)
    if info is None:
        return
    host = uri_host(info["uri"])
    if host not in AUTHORIZED_PRINTERS:
        add_alert(pkt.time, "HIGH", "Unauthorized printer advertisement",
                  src, pkt[IP].dst, f"advertises {info['uri']}")

def check_malformed_fields(pkt, src):
    if Raw not in pkt:
        return
    info = parse_browse_packet(pkt[Raw].load)
    if info is None:
        return
    issues = []

    hexdigits = "0123456789abcdefABCDEF"
    if not all(c in hexdigits for c in info["type"]):
        issues.append(f"non-numeric type field: {info['type']!r}")
    if not all(c in hexdigits for c in info["state"]):
        issues.append(f"non-numeric state field: {info['state']!r}")

    scheme = info["uri"].split("://", 1)[0].lower()
    if scheme not in ALLOWED_URI_SCHEMES:
        issues.append(f"unexpected URI scheme: {scheme!r}")

    host = uri_host(info["uri"]) or ""
    port = host.split(":", 1)[1] if ":" in host else "631"
    if port != STANDARD_IPP_PORT:
        issues.append(f"non-standard printer port: {port}")

    for ch in SUSPICIOUS_CHARS:
        if ch in info["raw"]:
            issues.append(f"suspicious character in payload: {ch!r}")
            break

    if issues:
        add_alert(pkt.time, "MEDIUM", "Malformed/unexpected browse packet",
                  src, pkt[IP].dst, "; ".join(issues))

def check_repeated_discovery(pkt, src):
    now = float(pkt.time)
    advert_times[src].append(now)
    advert_times[src] = [t for t in advert_times[src] if now - t <= DISCOVERY_WINDOW]
    count = len(advert_times[src])
    if count > DISCOVERY_THRESHOLD:
        add_alert(pkt.time, "HIGH", "Repeated/abnormal discovery",
                  src, pkt[IP].dst, f"{count} browse adverts in {DISCOVERY_WINDOW}s")

def check_suspicious_ipp(pkt, src, dst):
    if Raw not in pkt:
        return
    payload = bytes(pkt[Raw].load)
    dport = pkt[TCP].dport
    if not any(sig in payload for sig in IPP_SIGNATURES):
        return
    dest = f"{dst}:{dport}"
    issues = []
    if dest not in AUTHORIZED_PRINTERS:
        issues.append(f"IPP request to unauthorized printer {dest}")
    if str(dport) != STANDARD_IPP_PORT:
        issues.append(f"IPP request on non-standard port {dport}")
    for s in IPP_INJECTION_STRINGS:
        if s in payload:
            issues.append(f"suspicious IPP content: {s.decode(errors='replace')!r}")
            break
    if issues:
        add_alert(pkt.time, "HIGH", "Suspicious IPP connection",
                  src, dest, "; ".join(issues))

# ---- main handler ----
def analyze_packet(pkt):
    if IP not in pkt:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    if UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        print(f"UDP {src}:{sport} -> {dst}:{dport}")
        if dport == CUPS_BROWSE_PORT:
            check_unauthorized_advert(pkt, src)
            check_malformed_fields(pkt, src)
            check_repeated_discovery(pkt, src)
    elif TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        print(f"TCP {src}:{sport} -> {dst}:{dport}")
        check_suspicious_ipp(pkt, src, dst)

# export
def export_csv(path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["timestamp", "severity", "rule", "src", "dst", "details"])
        w.writeheader()
        w.writerows(ALERTS)

def export_json(path):
    with open(path, "w") as f:
        json.dump(ALERTS, f, indent=2)

# entry point
def main():
    ap = argparse.ArgumentParser(description="CUPS attack detection tool")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", help="read packets from a PCAP file")
    group.add_argument("--iface", help="live-capture on this interface")
    ap.add_argument("--output", help="write alerts to this file")
    ap.add_argument("--format", choices=["csv", "json"], default="csv",
                    help="export format (default: csv)")
    args = ap.parse_args()

    if args.pcap:
        for pkt in PcapReader(args.pcap):
            analyze_packet(pkt)
    else:
        sniff(iface=args.iface, prn=analyze_packet, store=False)

    if args.output:
        if args.format == "csv":
            export_csv(args.output)
        else:
            export_json(args.output)
        print(f"\n[+] Wrote {len(ALERTS)} alerts to {args.output}")

if __name__ == "__main__":
    main()
