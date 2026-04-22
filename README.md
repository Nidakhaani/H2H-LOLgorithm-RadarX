# 📡 RadarX — IoT Network Discovery Agent
> **Autonomous LAN Discovery, Device Fingerprinting & A–F Security Grading**

[![Python](https://img.shields.io/badge/Python-3.10+-blue)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)]()
[![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()
[![Hack2Hire](https://img.shields.io/badge/Built%20for-Hack2Hire%201.0-cyan)]()

---

## 🚨 Problem Statement

Every home and enterprise network is silently populated with **IoT black boxes** — IP cameras, smart printers, NAS, smart bulbs, and thermostats. Most of these devices ship with **factory default credentials**, leave dangerous ports (Telnet, FTP) wide open, and run outdated firmware.

Most network owners have **zero visibility** into what devices are actually on their network or what security risks they carry. Existing tools are either too complex for non-experts, require expensive licenses, or depend on cloud APIs that compromise privacy.

## 💡 Proposed Solution

**RadarX** is a lightweight, fully offline IoT security agent that makes your network's risk profile visible in seconds. It provides:

1.  **Autonomous Discovery:** Detects every device on your network using ARP broadcasts and nmap scanning.
2.  **Intelligent Fingerprinting:** Identifies device types (cameras, printers, etc.) by analyzing port signatures and manufacturer data.
3.  **A–F Security Grading:** Automatically assigns a security grade and a numeric risk score (0–100) based on vulnerability analysis.
4.  **Actionable Remediation:** Generates prioritized, plain-English action plans for every at-risk device.

The entire pipeline runs locally, ensuring data privacy and offline functionality.

---

## ✨ Key Features

-   📡 **Live LAN Scanning** — Auto-discovery with multi-tier fallback for restricted environments.
-   🏷️ **Offline Fingerprinting** — Identifies devices by port signatures and manufacturer lookups.
-   🛡️ **A–F Security Grading** — Deterministic risk assessment with weighted penalties.
-   📋 **Plain-English Remediation** — Human-readable security advice for every vulnerability.
-   📊 **Real-Time Dashboard** — Tactical web UI with device cards, security reports, and progress tracking.
-   🔍 **Port-Level Detection** — Flags insecure services like Telnet, FTP, UPnP, and RTSP.
-   🎭 **Integrated Demo Mode** — Full simulation capabilities for testing without a live network.

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend** | Python 3.10+, FastAPI | Core engine and REST API |
| **Scanning** | Scapy, python-nmap | Network discovery and port auditing |
| **Database** | SQLite 3 | Persistence for device history and sessions |
| **Frontend** | HTML5, CSS3, JS | Real-time dashboard (no frameworks) |
| **Deployment** | Render / Railway | Live cloud hosting and public URL |

---

## 🏗️ Architecture & Flow

RadarX follows a modular architecture designed for speed and reliability:

1.  **NetworkScanner:** Discovers active IP addresses via ARP and performs port scanning.
2.  **DeviceFingerprinter:** Matches open ports against known service signatures and OUI databases.
3.  **SecurityScorecard:** Calculates risk scores based on open ports and device context.
4.  **DatabaseManager:** Manages SQLite persistence for long-term network monitoring.
5.  **FastAPI Backend:** Orchestrates scans and serves data via a clean REST API.
6.  **Tactical Dashboard:** Provides the user with a real-time visual representation of network health.

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)
- *Optional:* `nmap` (for full scanning capabilities)

### Installation
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Nidakhaani/H2H-LOLgorithm-RadarX.git
    cd RadarX
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Configure environment:**
    ```bash
    # Create a .env file with your network range
    echo "NETWORK_RANGE=192.168.1.0/24" > .env
    echo "DEMO_MODE=true" >> .env
    ```

### Running the Application
-   **Start the Dashboard:**
    ```bash
    python run.py --api
    ```
    Access the dashboard at `http://localhost:8000`.

-   **Run CLI Scan (Demo Mode):**
    ```bash
    python run.py --demo
    ```

---

## 📸 Project Demo

### Tactical Dashboard
The RadarX dashboard provides a high-density overview of your network security, featuring color-coded device cards and a global security grade.

### Security Report
Detailed breakdowns of every device's vulnerabilities, including specific port risks and prioritized remediation steps.

[**Watch the Presentation Video**](https://github.com/Nidakhaani/H2H-LOLgorithm-RadarX)

---

## 🌐 Live Deployment

**Live Demo:** [https://radarx-iot-agent.onrender.com/](https://radarx-iot-agent.onrender.com/)

*(Note: The live version runs in Demo Mode due to cloud networking restrictions.)*

---

## 👥 Team RadarX

| Member | Role | GitHub |
| :--- | :--- | :--- |
| **Nida Khaani** | Project Lead & Full-Stack Developer | [@Nidakhaani](https://github.com/Nidakhaani) |

**Built for:** T John Institute of Technology Hack2Hire 1.0 (April 2026)

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.
