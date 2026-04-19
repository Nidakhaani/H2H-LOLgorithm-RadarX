"""
RadarX FastAPI Backend — IoT Network Discovery Agent

Provides REST API endpoints for device scanning, fingerprinting, grading, and
real-time dashboard polling. Supports both live scanning (local networks) and
demo mode (simulation for cloud deployments).
"""

from fastapi import BackgroundTasks, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
import os
import time
import uuid

from config import APP_VERSION, DEMO_MODE
from data.database import DatabaseManager
from discovery.fingerprinter import DeviceFingerprinter
from discovery.scanner import NetworkScanner
from discovery.scorecard import SecurityScorecard

app = FastAPI(title="RadarX — IoT Discovery Agent", version=APP_VERSION)

# Global scan state tracking for frontend polling.
scan_state = {"active": False, "progress": 0, "stage": "Idle", "devices_found": 0}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _print_startup_message() -> None:
    message = "📡 RadarX API ready — visit http://localhost:8000"
    try:
        print(message)
    except UnicodeEncodeError:
        print("RadarX API ready - visit http://localhost:8000")


async def run_background_scan(state: dict, demo: bool = True):
    start_time = time.time()
    try:
        state.update({"active": True, "progress": 10, "stage": "📡 Discovering devices..."})
        scanner = NetworkScanner()
        devices = scanner.scan()
        for device in devices:
            device["open_ports"] = scanner.scan_ports(device["ip"])

        state.update(
            {
                "progress": 35,
                "stage": "🏷️ Fingerprinting devices...",
                "devices_found": len(devices),
            }
        )
        devices = DeviceFingerprinter().fingerprint_all(devices)

        state.update({"progress": 60, "stage": "🛡️ Grading security risk..."})
        devices = SecurityScorecard().grade_all(devices)

        state.update({"progress": 85, "stage": "💾 Saving to database..."})
        db = DatabaseManager()
        db.init_db()
        for device in devices:
            db.upsert_device(device)
        duration = time.time() - start_time
        method = devices[0].get("scan_method", "mock") if devices else "mock"
        if demo:
            method = "demo-ui"
        db.save_scan_session(devices, duration, method)
        db.close()

        state.update(
            {
                "active": False,
                "progress": 100,
                "stage": f"✅ Complete — {len(devices)} devices scanned",
                "devices_found": len(devices),
            }
        )
    except Exception as exc:
        state.update({"active": False, "progress": 0, "stage": f"❌ Scan failed: {str(exc)}"})


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    file_path = os.path.join(os.path.dirname(__file__), "../frontend/index.html")
    if not os.path.exists(file_path):
        return HTMLResponse(
            "<h1>Frontend not found</h1><p>Please ensure frontend/index.html exists.</p>",
            status_code=404,
        )

    with open(file_path, "r", encoding="utf-8") as file_handle:
        return file_handle.read()


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "version": APP_VERSION,
        "scan_active": scan_state["active"],
        "demo_mode": DEMO_MODE,
    }


@app.post("/api/scan")
async def start_scan(background_tasks: BackgroundTasks, payload: dict = None):
    """Trigger a new scan — uses DEMO_MODE if configured."""
    if scan_state["active"]:
        return JSONResponse(status_code=409, content={"error": "Scan already in progress"})

    # Force demo mode if configured in environment (cloud deployments have no local network)
    demo = DEMO_MODE

    scan_state.update({"active": True, "progress": 0, "stage": "Starting...", "devices_found": 0})
    background_tasks.add_task(run_background_scan, scan_state, demo)
    return {"message": "Scan started", "scan_id": str(uuid.uuid4())}


@app.get("/api/scan/status")
async def get_scan_status():
    return scan_state


@app.get("/api/devices")
async def get_devices():
    db = DatabaseManager()
    devices = db.get_all_devices()
    db.close()
    return devices


@app.get("/api/devices/{ip_address}")
async def get_device_by_ip(ip_address: str):
    db = DatabaseManager()
    devices = db.get_all_devices()
    db.close()

    device = next((device for device in devices if device.get("ip") == ip_address), None)
    if not device:
        return JSONResponse(status_code=404, content={"error": "Device not found"})
    return device


@app.get("/api/summary")
async def get_network_summary():
    db = DatabaseManager()
    devices = db.get_all_devices()
    db.close()

    if not devices:
        return {
            "total_devices": 0,
            "grade_distribution": {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0},
            "critical_count": 0,
            "high_risk_count": 0,
            "network_grade": "N/A",
            "top_threats": [],
            "devices_needing_action": [],
        }

    return SecurityScorecard().network_summary(devices)


@app.get("/api/history")
async def get_history():
    db = DatabaseManager()
    history = db.get_scan_history(limit=10)
    db.close()
    return history


@app.delete("/api/devices")
async def clear_devices():
    db = DatabaseManager()
    db.clear_devices()
    db.close()
    return {"cleared": True, "message": "All device records deleted"}


@app.on_event("startup")
async def startup_event():
    """Initialize database and print startup message."""
    db = DatabaseManager()
    db.init_db()
    db.close()
    _print_startup_message()


if __name__ == "__main__":
    import uvicorn

    # Read PORT from environment (for Render/Railway), default to 8000 locally
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
