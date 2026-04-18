# 📡 RadarX — IoT Network Discovery Agent
> Autonomous LAN Discovery, Device Fingerprinting & Security Grading — Offline, Private, Fast

[![Python](https://img.shields.io/badge/Python-3.10+-blue)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)]()
[![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()

## 🚨 1. Problem Statement
Every home and enterprise network is silently populated with IoT black boxes — IP cameras, smart printers, routers, smart bulbs, and unknown devices that ship with default passwords like admin/admin, leave dangerous ports like Telnet and FTP wide open, and run outdated firmware for years without updates. Most network owners have no idea what devices are on their network or what risks they carry. Existing security tools are either too complex for non-experts or require expensive licenses. The result: millions of devices act as open doors for attackers, completely undetected.

## 💡 2. Proposed Solution
RadarX is a lightweight, offline IoT security agent that makes your network's risk profile visible in seconds. It autonomously discovers every device on the LAN, fingerprints each device's open ports and manufacturer signature, and grades every device on an A–F scale with a prioritized, plain-English remediation plan. No cloud, no API keys, no expert knowledge required — just run it and see exactly where you're exposed.

## 🛠️ 3. Tech Stack
| Layer | Technology | Purpose |
|-------|-----------|---------|
| Backend | Python 3.10, FastAPI | Core engine + REST API |
| Network Scanning | Scapy, python-nmap | ARP discovery + port scanning |
| Database | SQLite (sqlite3) | Device history persistence |
| Frontend | HTML5, CSS3, Vanilla JS | Real-time dashboard |
| CLI | argparse, rich | Terminal output |
| Deployment | Render / Railway | Live hosting |

## ✨ 4. Features
- 📡 Live LAN scanning with ARP + nmap + simulation mode for demo environments
- 🏷️ Offline device fingerprinting — identifies cameras, printers, routers, smart devices
- 🛡️ A–F security grading engine with numeric risk scoring (0–100)
- 📋 Prioritized, plain-English remediation plan for every at-risk device
- 🧾 Day 4 polished CLI pipeline with stage timing + rich security output for demos
- 🗄️ SQLite persistence — tracks device history and scan sessions over time
- 📊 `--report` mode loads saved scan data and prints network grade, D/F devices, and remediation checklist
- 📊 Real-time polling dashboard with device cards and security report
- 🔍 Port-level risk detection — flags Telnet, FTP, HTTP-only, RTSP, UPnP, MQTT
- 🎭 Simulation mode for demo environments where live scanning isn't possible

## 🏗️ 5. Architecture / Flow
```
LAN Network
    ↓
[NetworkScanner] → ARP/nmap discovery → IP, MAC, Hostname, Open Ports
    ↓
[DeviceFingerprinter] → Port + manufacturer analysis → Device type + Risk flags
    ↓
[SecurityScorecard] → Risk scoring → A–F grade + Remediation plan
    ↓
[DatabaseManager] → SQLite → Persist device history + scan sessions
    ↓
[FastAPI Backend] → REST endpoints → /api/scan, /api/devices, /api/summary
    ↓
[HTML Dashboard] → Real-time polling → Device cards + Security report
```

## 🚀 6. Setup Instructions
```bash
git clone https://github.com/YOUR_REPO_URL
cd radarx
pip install -r requirements.txt
cp .env.example .env
# Edit .env — set NETWORK_RANGE to your subnet (e.g., 192.168.1.0/24)
python run.py --demo    # Simulation mode, no sudo needed
# For real scanning (Linux only):
sudo python run.py --scan
# Start the dashboard:
python run.py --api
# Visit http://localhost:8000
```

## 📅 Roadmap progress
- [x] **Day 1**: Project Scaffold & Tech Stack
- [x] **Day 2**: Core Scanner & Device Fingerprinter
  - 📡 3-tier fallback scanner (ARP, Nmap, Mock)
  - 🏷️ Parallel port scanner & Manufacturer lookup
  - 🔍 Device classification & Risk flag detection
- [x] **Day 3**: Security Scorecard Engine
  - 🛡️ A-F Grading & Risk Scoring
  - 📋 Remediation Plan Generator
  - 🧾 Network summary with top threats and devices needing action
- [x] **Day 4**: SQLite Persistence + CLI Polish
  - 🗄️ Added SQLite `DatabaseManager` (`devices` + `scan_sessions`)
  - 💾 Persisted full demo pipeline (`Scanner -> Fingerprinter -> Scorecard -> Database`)
  - 📊 Added `python run.py --report` for DB-backed security reporting
- [x] **Day 5**: FastAPI Backend
  - 🚀 Built full backend orchestration + scan status polling state
  - 🔌 Added REST endpoints for health, scan trigger, devices, summary, and history
  - 🧹 Added API delete endpoint for device-table reset during dashboard testing

## ✅ Day 4 Implementation Summary
- Added `data/database.py` with a full `DatabaseManager` using `sqlite3` (no ORM).
- Implemented schema initialization for persistent `devices` and `scan_sessions`.
- Added upsert logic keyed by IP with JSON serialization for ports, risk flags, and remediation fields.
- Upgraded `run.py --demo` to full Day 4 flow:
  - `Scanner -> Fingerprinter -> Scorecard -> Database`
  - Stage-by-stage status/timing output and polished rich table:
    - `IP | Device Type | Grade | Score | Risk Flag Count`
  - Network summary panel and total pipeline duration line.
- Implemented `python run.py --report` to:
  - Load existing DB scan data (without rescanning),
  - Print network grade summary,
  - List D/F devices with top findings,
  - Print prioritized remediation checklist (URGENT first),
  - Handle empty DB with: `No scan data found. Run --demo or --scan first.`

## ✅ Day 5 Implementation Summary
- Implemented complete `FastAPI` backend in `api/main.py` with title `RadarX — IoT Discovery Agent`.
- Added permissive CORS middleware for hackathon dashboard integration.
- Implemented dashboard-ready API routes:
  - `GET /` → serves `frontend/index.html`
  - `GET /api/health`
  - `POST /api/scan`
  - `GET /api/scan/status`
  - `GET /api/devices`
  - `GET /api/devices/{ip_address}`
  - `GET /api/summary`
  - `GET /api/history`
  - `DELETE /api/devices`
- Added background scan pipeline execution with stage-based progress updates:
  - Discovery -> Port Scan -> Fingerprinting -> Grading -> Database Persistence
- Added startup initialization to auto-create DB tables and print API readiness status.

## 🎬 Demo Day 4 Features
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the complete Day 4 pipeline:
   ```bash
   python run.py --demo
   ```
3. Show persistence-backed reporting:
   ```bash
   python run.py --report
   ```
4. Walk through the output live:
   - Show scanner fallback flow (ARP -> Nmap -> Mock in restricted Windows environments).
   - Highlight stage completion lines and timing for the full 4-stage pipeline.
   - Show the saved table columns (`IP`, `Device Type`, `Grade`, `Score`, `Risk Flag Count`).
   - Run `--report` to show D/F devices and prioritized remediation actions.
