# CUPS / cups-browsed Attack & Detection Toolkit

**DAT505 – Ethical Hacking · University of Stavanger (UiS) · Assignment 2**

Scapy-based tools that demonstrate and detect the unauthenticated printer-discovery
vulnerability in OpenPrinting `cups-browsed` (CVE-2024-47176 and the related
CVE-2024-4717x chain).

---

> ## ⚠️ Disclaimer — educational use in an isolated lab only
>
> These tools **craft and detect malicious CUPS discovery traffic**. Run them
> **only** against systems you own or are explicitly authorized to test, inside the
> isolated DAT505 lab. Do **not** run them against real networks, university
> infrastructure, or any system you do not have permission to test.
>
> All packet captures in this repository were taken on a **private Docker lab
> network** (`172.18.0.0/16`). No real-world or university traffic is included.

---

## Background

`cups-browsed` listens on **UDP/631** and trusts **unauthenticated** printer-discovery
packets. A single crafted packet can advertise an attacker-controlled printer; the
victim then connects back to the attacker over IPP. In the full vulnerability chain
this can lead to remote code execution via a malicious PPD
(`FoomaticRIPCommandLine`).

This project implements two Scapy tools:

- **`cups_attack.py`** — crafts and sends a CUPS Browsing packet advertising a fake
  printer, then listens for the victim's callback.
- **`cups_detector.py`** — sniffs live traffic or reads a pcap and raises alerts on
  malicious discovery packets using a set of detection rules, logging results to CSV
  and JSON.

## Environment / Prerequisites

| Component | Detail |
|-----------|--------|
| Attacker  | Kali Linux (tested in VirtualBox) |
| Victim    | Vulhub `CVE-2024-47177` `cups-browsed` Docker container (cups-browsed 2.0.1) |
| Lab network | Docker bridge `172.18.0.0/16` — attacker `172.18.0.1`, victim `172.18.0.2` |
| Python    | 3.13.12 |
| Packet analysis | Wireshark |
| Privileges | root — the tools use raw sockets, so run them with `sudo` |

## Installation

```bash
pip install -r requirements.txt
```

The only Python dependency is **`scapy`**. (Wireshark, Docker, and the Vulhub
container are part of the lab environment above, not pip packages.)

## Usage

> Run inside the isolated lab only, with `sudo` (raw socket access).

### Attack tool

```bash
sudo python3 cups_attack.py -v --pcap pcap_files/task2_attack.pcapng
```

Flags:
- `-v` — verbose output
- `--pcap <file>` — save the crafted packet to a pcap

The tool advertises `ipp://172.18.0.1:9100/printers/EvilPrinter` to the victim on
**UDP/631** and listens on **TCP/9100** for the callback. A confirmed callback means
the victim trusted the unauthenticated advertisement.

### Detection tool

The detector reads either a saved capture or a live interface — the two modes are
mutually exclusive, so pick one:

```bash
# offline: analyse a saved capture
python3 cups_detector.py --pcap pcap_files/task4_02attack.pcapng

# live: sniff an interface (needs sudo)
sudo python3 cups_detector.py --iface eth0
```

Alerts are printed to the terminal and can be exported to CSV/JSON with the
`--output` and `--format` flags, producing:
- `alerts.csv`
- `alerts.json`

## Repository structure

```
.
├── cups_attack.py              # Task 2 — attack tool
├── cups_detector.py            # Task 3 — detection tool
├── README.md
├── requirements.txt
├── pcap_files/                 # captured traffic (lab network only)
│   ├── task1_discovery.pcapng          # normal printer discovery (baseline)
│   ├── task2_attack.pcapng             # attack + victim callback
│   ├── task2_crafted_evilprinter_packet.pcap  # the single crafted malicious packet
│   ├── task4_01normal.pcapng           # normal CUPS/IPP traffic
│   ├── task4_02attack.pcapng           # unauthorized discovery
│   ├── task4_03a_spoofed.pcapng        # variation 1 — spoofed source
│   ├── task4_03b_scheme.pcapng         # variation 2 — alternate scheme/port
│   ├── task4_03c_flood.pcapng          # variation 3 — discovery flood
│   └── task5_before_mitigation.pcapng  # vulnerable state before mitigation
└── evidence/                   # logs + screenshots
    ├── alerts.csv                      # detector output
    ├── alerts.json                     # detector output
    ├── env_cupsbrowsed_running.png
    ├── env_network_topology.png
    ├── task1_normal_traffic.png
    ├── task2_attack_callback.png
    ├── task5_after_mitigation.png
    ├── task5_before_mitigation.png
    └── task5_mitigation_kill.png
```

## Task mapping

| Task | Description | Where to find it |
|------|-------------|------------------|
| 1 | Environment setup & normal discovery | `env_*` screenshots, `task1_discovery.pcapng`, `task4_01normal.pcapng` |
| 2 | Attack tool (unauthorized printer advertisement) | `cups_attack.py`, `task2_attack.pcapng`, `task2_attack_callback.png` |
| 3 | Detection tool | `cups_detector.py`, `alerts.csv`, `alerts.json` |
| 4 | Attack simulation & analysis (normal, attack, 3 variations, detection) | `task4_*` pcaps, `alerts.*` |
| 5 | Mitigation (stop cups-browsed → attack blocked) | `task5_*` pcaps & screenshots |

## Author

DAT505 Assignment 2 — Yao Yun Jackie Zhang
