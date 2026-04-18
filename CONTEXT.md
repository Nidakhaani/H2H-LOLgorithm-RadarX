# RadarX Development Context

## Day 1 — Project Scaffold
- ✅ Initialized repository structure.
- ✅ Created `README.md` with project specifications.
- ✅ Added `requirements.txt`.
- ✅ Set up `.env.example`.
- ✅ Created `.gitignore`.
- ✅ Configured `config.py` to handle environment variables.
- ✅ Implemented `run.py` CLI launcher framework.
- ✅ Created `discovery` module stubs (`scanner.py`, `fingerprinter.py`, `scorecard.py`).
- ✅ Created `api` module stub (`main.py`).
- ✅ Added placeholder `frontend/index.html`.
- ✅ Created `data/` directory with `.gitkeep`.

## Day 2 — Core Scanner & Device Fingerprinter
- ✅ Implemented `NetworkScanner` with 3-tier fallback (ARP/Nmap/Mock).
- ✅ Built threaded port scanner with mock profile support.
- ✅ Implemented `DeviceFingerprinter` with confidence-based classification.
- ✅ Integrated risk detection engine with automated flag generation.
- ✅ Created end-to-end terminal demo results.

## Day 3 — Security Scorecard Engine
- ✅ Built A-F security grading engine.
- ✅ Implemented deterministic risk score calculation logic (0-100).
- ✅ Generated prioritized plain-English remediation plans per device.
- ✅ Added network-level summary generation (grade distribution, top threats, action list).
- ✅ Integrated full Scanner -> Fingerprinter -> Scorecard pipeline into `python run.py --demo`.

### Day 3 — What We Built (Detailed)
- Implemented `SecurityScorecard` in `discovery/scorecard.py` with:
  - `grade_device()` for per-device grade/score/findings/remediation output.
  - `grade_all()` to process complete scan results in one pass.
  - `_calculate_risk_score()` with additive weighted penalties and score cap at 100.
  - `_score_to_grade()` mapping risk score to A/B/C/D/F.
  - `_score_to_label()` mapping risk score to human labels (SECURE -> CRITICAL).
  - `_generate_remediation()` returning prioritized, deduplicated plain-English actions.
  - `network_summary()` for fleet-level posture and actionability.
- Updated `run.py --demo` to run the real Day 3 execution path:
  - Scanner -> Fingerprinter -> Scorecard -> Rich table + network summary.
- Verified Day 3 behavior on Windows fallback flow:
  - ARP/Nmap gracefully fallback to mock scan when platform tooling is unavailable.

## Day 4 — SQLite Persistence + CLI Polish
- ✅ Day 4 officially completed and validated end-to-end.
- ✅ Added `DatabaseManager` in `data/database.py` using `sqlite3` only (no ORM).
- ✅ Implemented DB initialization with automatic `data/` directory creation and two tables:
  - `devices` for persistent per-device risk posture and scan counters.
  - `scan_sessions` for historical scan run metadata and network-level grade snapshots.
- ✅ Added robust upsert behavior keyed by `ip_address`:
  - JSON fields are serialized on write and de-serialized on read.
  - `last_seen` updates automatically and `scan_count` increments on conflict.
- ✅ Upgraded `python run.py --demo` to Day 4 full pipeline:
  - Scanner -> Fingerprinter -> Scorecard -> Database.
  - Added stage-by-stage status lines with timings and polished rich output.
  - Added Day 4 table format: IP, Device Type, Grade, Score, Risk Flag Count.
  - Added network summary panel and total pipeline timing line.
- ✅ Implemented `python run.py --report`:
  - Loads existing DB data only (no new scan).
  - Prints network security grade summary.
  - Lists D/F devices with top findings.
  - Prints numbered remediation checklist with CRITICAL/URGENT actions first.
  - Handles empty database gracefully with:
    `"No scan data found. Run --demo or --scan first."`

## Day 5 — FastAPI Backend
- ✅ Implemented complete FastAPI backend in `api/main.py` for dashboard integration.
- ✅ Added full API app setup:
  - App title: `RadarX — IoT Discovery Agent`.
  - CORS middleware allowing all origins/methods/headers (hackathon mode).
  - Global `scan_state` tracking for polling (`active`, `progress`, `stage`, `devices_found`).
- ✅ Added all required Day 5 endpoints:
  - `GET /` serves `frontend/index.html`.
  - `GET /api/health` returns status/version/scan state/demo mode.
  - `POST /api/scan` triggers background scan and prevents concurrent runs.
  - `GET /api/scan/status` returns live scan progress for polling.
  - `GET /api/devices` returns risk-sorted DB-backed device list.
  - `GET /api/devices/{ip_address}` returns one device or 404.
  - `GET /api/summary` returns network scorecard summary.
  - `GET /api/history` returns last 10 scan sessions.
  - `DELETE /api/devices` clears only device rows and returns confirmation.
- ✅ Implemented async background orchestration:
  - `NetworkScanner -> DeviceFingerprinter -> SecurityScorecard -> DatabaseManager`.
  - Stage-wise progress updates with user-facing status text.
  - Session duration tracking and scan session persistence.
- ✅ Added startup hook:
  - Ensures DB tables exist at app startup.
  - Prints API readiness message for local run confirmation.
