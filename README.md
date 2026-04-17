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
- 🗄️ SQLite persistence — tracks device history and scan sessions over time
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
- [ ] **Day 3**: Security Scorecard Engine (Next)
  - 🛡️ A-F Grading & Risk Scoring
  - 📋 Remediation Plan Generator
