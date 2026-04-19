# 📡 RadarX — IoT Network Discovery Agent
> Autonomous LAN Discovery, Device Fingerprinting & A–F Security Grading

[![Python](https://img.shields.io/badge/Python-3.10+-blue)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)]()
[![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()
[![Hack2Hire](https://img.shields.io/badge/Built%20for-Hack2Hire%201.0-cyan)]()

---

## 🚨 1. Problem Statement

Every home and enterprise network is silently populated with **IoT black boxes** — IP cameras, smart printers, network-attached storage, smart bulbs, thermostats, and tens of other unknown devices. Most of these devices ship with **factory default credentials** (admin/admin, root/root), leave dangerous ports like Telnet and FTP wide open, and run outdated firmware that hasn't been patched in years. They're connected to the network and largely forgotten.

**The core problem:** Most network owners have zero visibility into what devices are actually on their network, what they're communicating with, or what security risks they carry. Whether you manage a home office, small business, or enterprise branch, the default state is *security blindness*. Existing tools are either too complex for non-experts, require expensive enterprise licenses, depend on cloud APIs, or simply don't work in offline/restricted environments.

**The outcome:** Millions of devices act as silent doors for attackers — wide open, completely undetected, and unsecured. A single compromised IoT device can become a pivot point into the rest of the network.

---

## 💡 2. Proposed Solution

**RadarX** makes your network's risk profile visible in seconds with a lightweight, fully offline IoT security agent. It requires no cloud API keys, no expert knowledge, and works on any LAN:

1. **Discovers** every device on your network using ARP broadcasts + nmap + fallback simulation
2. **Fingerprints** each device by analyzing open ports, manufacturer signatures, and service identification
3. **Grades** every device on an A–F security scale with a numeric risk score (0–100)
4. **Remediates** with a prioritized, plain-English action plan for every at-risk device

The entire pipeline runs locally, offline, and in seconds. A non-technical network admin can understand the output immediately: see the red F-grade camera with port 23 (Telnet) open, read the plain-English fix ("Disable Telnet, enforce SSH only"), and act. No certifications required. No subscriptions. Just security visibility.

---

## 🛠️ 3. Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Backend** | Python 3.10+, FastAPI | Core scanning engine + REST API |
| **Network Scanning** | Scapy, python-nmap | ARP/IP discovery + port scanning |
| **Database** | SQLite 3 | Device history + scan session persistence |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript | Real-time cloud-hosted dashboard |
| **CLI** | argparse, rich | Terminal UI + formatted output |
| **Serialization** | JSON | Device/port/remediation data exchange |
| **Deployment** | Render / Railway | Live cloud hosting + public URL |

---

## ✨ 4. Features

- 📡 **Live LAN Scanning** — ARP/nmap auto-discovery with 3-tier fallback for restricted environments
- 🏷️ **Offline Device Fingerprinting** — Identifies cameras, printers, routers, smart appliances by port signatures
- 🛡️ **A–F Security Grading** — Deterministic risk grades (A=secure, F=critical) with numeric risk scores 0–100
- 📋 **Plain-English Remediation** — Prioritized action plans per device (CRITICAL → URGENT → MEDIUM)
- 🧾 **Multi-Mode CLI** — `--demo` (simulation), `--scan` (real), `--report` (saved data), `--api` (dashboard)
- 🗄️ **SQLite Persistence** — Tracks device history + scan sessions over time
- 📊 **Real-Time Dashboard** — Web UI with device cards, security report, progress polling
- 🔍 **Port-Level Risk Detection** — Flags insecure services (Telnet, FTP, HTTP, RTSP, UPnP, MQTT)
- 🎭 **Demo Mode** — Full simulation for testing without a live network (perfect for cloud/CI)

---

## 🏗️ 5. Architecture / Flow

```
╔═════════════╗
║ LAN Network ║
╚══════╤══════╝
       ↓
┌──────────────────────────────────────┐
│  [NetworkScanner]                    │
│  ARP broadcasts → IP discovery       │
│  nmap port scans → open ports list   │
│  Mock simulation for demo/cloud      │
└──────────────────────┬───────────────┘
                       ↓
┌──────────────────────────────────────┐
│  [DeviceFingerprinter]               │
│  Port analysis → device type         │
│  Manufacturer lookup                 │
│  Risk flag detection (Telnet/FTP)    │
└──────────────────────┬───────────────┘
                       ↓
┌──────────────────────────────────────┐
│  [SecurityScorecard]                 │
│  Risk → A–F grade mapping            │
│  Remediation plan generation         │
│  Network summary (fleet-level)       │
└──────────────────────┬───────────────┘
                       ↓
┌──────────────────────────────────────┐
│  [DatabaseManager]                   │
│  SQLite upsert → device persistence  │
│  Scan session history tracking       │
└──────────────────────┬───────────────┘
                       ↓
┌──────────────────────────────────────┐
│  [FastAPI Backend]                   │
│  REST endpoints for dashboard        │
│  Async background scan orchestration │
└──────────────────────┬───────────────┘
                       ↓
┌──────────────────────────────────────┐
│  [HTML5 Dashboard]                   │
│  Real-time polling → device cards    │
│  Security report + remediation list  │
└──────────────────────────────────────┘
```

---

## 🚀 6. Setup Instructions

### Prerequisites
- **Python 3.10** or higher
- **pip** package manager
- **git** (to clone the repo)
- *Optional:* **nmap** (apt install nmap on Linux, brew install nmap on macOS, Windows nmap.org)

### Step 1: Clone & Install
```bash
git clone https://github.com/Nidakhaani/H2H-LOLgorithm-RadarX.git
cd radarx
pip install -r requirements.txt
```

### Step 2: Environment Configuration
```bash
cp .env.example .env
# Edit .env — set NETWORK_RANGE to your subnet (e.g., 192.168.1.0/24)
nano .env  # or use your editor
```

**Key `.env` variables:**
- `NETWORK_RANGE=192.168.1.0/24` — your local network CIDR (adjust this!)
- `DB_PATH=data/devices.db` — where scan history is stored
- `DEMO_MODE=true` — set to `false` for real scanning (Linux + sudo required)

### Step 3: Run Demo Mode (No Sudo, No Local Network Required)
```bash
python run.py --demo
```

**Output:** Rich-formatted table with 8 simulated IoT devices, grades, risk scores, and remediation plans.

### Step 4: Real Scanning (Linux Only)
```bash
# Only works on Linux with nmap + arp-scan tools installed
sudo python run.py --scan
```

### Step 5: Report Mode (Load Saved Scans)
```bash
# Loads from database — shows network grade, D/F devices, remediation checklist
python run.py --report
```

### Step 6: Start the API + Dashboard
```bash
python run.py --api
# Visit http://localhost:8000 in your browser
```

---

## 📸 7. Demo / Screenshots

### Dashboard Home
The main RadarX dashboard shows a dark-themed interface with:
- **Header:** Glowing "RadarX" logo, network health badge (A–F grade), Scan button
- **Stats Row:** Total Devices, Critical (F-grade) count, High Risk (D-grade) count, Secure (A–B) count
- **Device Grid:** Color-coded cards (red border for F, orange for D, etc.) with emoji, device name, ID, manufacturer, open ports, and risk score bar
- **Welcome State:** "No devices yet" message with pulsing radar emoji when database is empty

### Device Detail Modal
Click "View Details" on any card to see:
- IP, MAC, Hostname, Manufacturer
- Large grade badge (A–F) with risk score progress bar
- All open ports with security context (Telnet = critical red)
- Full remediation steps in priority order
- First Seen / Last Seen timestamps

### Security Report Tab
A comprehensive overview showing:
- **Network Overview:** Giant glowing A–F grade + summary text
- **Grade Distribution:** Proportional progress bars for all grades (A, B, C, D, F)
- **Devices Requiring Action:** Table of all F/D-grade devices
- **Full Remediation Checklist:** All actions sorted by severity (CRITICAL → URGENT → MEDIUM)

### Real-Time Scanning
When you click "Scan Network," a progress bar appears:
- 📡 Discovering devices...
- 🏷️ Fingerprinting devices...
- 🛡️ Grading security risk...
- 💾 Saving to database...
- ✅ Complete — X devices scanned

### Video Demo
[Hack2Hire Final Presentation Video — April 22, 2026]
(Upload to YouTube or link internal demo video)

---

## 👥 8. Team Members

| Role | Name | GitHub |
|------|------|--------|
| **Project Lead & Full-Stack Developer** | Nida Khaani | [@Nidakhaani](https://github.com/Nidakhaani) |
| **Cybersecurity & Grading Logic** | Nida Khaani | [@Nidakhaani](https://github.com/Nidakhaani) |

**Team:** RadarX — Built for T John Institute of Technology Hack2Hire 1.0, April 2026

---

## 🌐 9. Deployed Link

**Live Demo:** https://radarx-iot-agent.onrender.com/

*Note: The deployed version runs in DEMO_MODE=true (cloud servers have no local network to scan). Click "Scan Network" to see simulated device data, full grading, remediation plans, and the live dashboard.*

**How to Deploy Your Own:**

### Option 1: Render.com
1. Push code to GitHub
2. Go to https://dashboard.render.com
3. New → Web Service
4. Connect GitHub repo → Select this repo
5. Runtime: Python 3.10
6. Build cmd: `pip install -r requirements.txt`
7. Start cmd: `uvicorn api.main:app --host 0.0.0.0 --port $PORT`
8. Env vars: Set `DEMO_MODE=true`
9. Deploy!

### Option 2: Railway.app
1. Go to https://railway.app
2. New Project → Deploy from GitHub
3. Select this repo
4. Railway auto-detects Python
5. Set env var: `DEMO_MODE=true`
6. Deploy!

---

## 🧪 10. What is Real vs. Simulated

### Real Implementation (100% Production Code)
✅ **All Python modules** — Scanner, Fingerprinter, Scorecard, DatabaseManager  
✅ **Risk scoring logic** — Deterministic A–F grading algorithm with weighted penalties  
✅ **Fingerprinting rules** — Port → device type mapping, manufacturer detection  
✅ **FastAPI backend** — All 9 REST endpoints fully functional  
✅ **SQLite database** — Real persistence with full schema (devices + scan_sessions)  
✅ **HTML5 dashboard** — Production-quality responsive UI, no frameworks  
✅ **Port scanning** — Real socket-based scans + nmap integration  
✅ **Remediation engine** — Real plain-English action plan generation  

### Simulated in Demo Mode
🎭 **Network discovery** — Returns 8 pre-defined mock devices instead of live ARP broadcasts  
🎭 **Device data** — Realistic IoT device profiles (cameras, printers, routers, etc.)  
🎭 **Why simulated?** Cloud servers (Render/Railway) cannot access a local LAN — they have no broadcast network. Demo mode allows full end-to-end testing of the grading + dashboard pipeline without network infrastructure.

### How to Know Which Mode You're In
```bash
# Local demo (no scanning, just simulation)
python run.py --demo

# Real scanning (Linux only, requires nmap + root)
sudo python run.py --scan

# Cloud deployment (inherits DEMO_MODE=true from render.yaml/railway.json)
# Automatically runs mock scan on every POST /api/scan
```

---

## 📋 Requirements

See `requirements.txt`:
```
scapy
python-nmap
python-dotenv
fastapi
uvicorn
rich
requests
python-multipart
```

---

## 📚 Documentation Files

- **[CONTEXT.md](CONTEXT.md)** — Detailed dev notes for all 7 days
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — How to contribute + dev setup
- **[LICENSE](LICENSE)** — MIT License, free to use/modify

---

## 🛠️ Troubleshooting

**"ModuleNotFoundError: No module named 'scapy'"**
→ Run `pip install -r requirements.txt`

**"Scan shows 0 devices on real hardware"**
→ Verify NETWORK_RANGE in `.env` matches your actual subnet (e.g., 10.0.0.0/24 not 192.168.1.0/24)  
→ On Linux, ensure running with `sudo`

**"Dashboard won't load"**
→ Ensure `python run.py --api` is running  
→ Check http://localhost:8000/api/health returns `{"status": "ok"}`

**"Database corruption"**
→ Delete `data/devices.db` and recreate: `python run.py --demo` will reinit schema

---

## 🎓 Learning Outcomes

This project demonstrates:
- **Network security fundamentals** — ARP discovery, port scanning, risk assessment
- **Full-stack development** — Python backend, REST APIs, frontend dashboard
- **Software architecture** — Modular class design, separation of concerns
- **Database design** — SQLite schema, JSON serialization, upsert patterns
- **Real-time web UI** — Polling, progress tracking, responsive design
- **Cloud deployment** — Docker-compatible, environment-driven config
- **Cybersecurity best practices** — Risk scoring, remediation planning, threat modeling

---

## 📝 License

MIT License — See [LICENSE](LICENSE) for full text.  
**Copyright (c) 2026 Nida Khaani & Team RadarX**

---

## 🎉 Acknowledgments

Built during **Hack2Hire 1.0** (April 2026) at **T John Institute of Technology**, Bengaluru.

**Theme:** Cybersecurity  
**Inspiration:** The massive blindspot in home/small-business network security  
**Vision:** Make IoT security visible, actionable, and free for everyone

---

**👉 [Deploy Now](https://dashboard.render.com) | [View on GitHub](https://github.com/Nidakhaani/H2H-LOLgorithm-RadarX) | [Hack2Hire](https://hack2hire.in)**
