"""
RadarX Configuration Module

Loads environment variables from .env file and provides sensible defaults
for network range, database path, scan interval, and demo mode.
"""

import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # In case dotenv is not installed yet

NETWORK_RANGE = os.getenv("NETWORK_RANGE", "192.168.1.0/24")
DB_PATH = os.getenv("DB_PATH", "data/devices.db")
try:
    SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", 60))
except ValueError:
    SCAN_INTERVAL = 60
DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
APP_VERSION = "1.0.0"

if __name__ == "__main__":
    try:
        print("✅ Config loaded successfully.")
        print(f"📡 NETWORK_RANGE: {NETWORK_RANGE}")
        print(f"💾 DB_PATH: {DB_PATH}")
        print(f"⏱️ SCAN_INTERVAL: {SCAN_INTERVAL}s")
        print(f"🎭 DEMO_MODE: {DEMO_MODE}")
        print(f"🏷️ APP_VERSION: {APP_VERSION}")
    except Exception as e:
        print(f"❌ Error printing config: {str(e)}")
