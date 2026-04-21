"""
Database Manager Module

Handles SQLite persistence for devices and scan sessions.
Provides upsert operations with JSON serialization for complex fields.
"""

import json
import os
import sqlite3
from typing import Any

from config import DB_PATH


class DatabaseManager:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or DB_PATH
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.init_db()

    def init_db(self):
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                mac_address TEXT DEFAULT '',
                hostname TEXT DEFAULT '',
                manufacturer TEXT DEFAULT 'Unknown',
                device_type TEXT DEFAULT 'Unknown',
                open_ports TEXT DEFAULT '{}',
                risk_flags TEXT DEFAULT '[]',
                risk_score INTEGER DEFAULT 0,
                grade TEXT DEFAULT 'C',
                remediation TEXT DEFAULT '[]',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_count INTEGER DEFAULT 1
            );
            """
        )
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_method TEXT DEFAULT 'mock',
                total_devices INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_risk_count INTEGER DEFAULT 0,
                network_grade TEXT DEFAULT 'C',
                duration_seconds REAL DEFAULT 0.0
            );
            """
        )
        self.conn.commit()

    def upsert_device(self, device: dict):
        ip_address = device.get("ip", "") or device.get("ip_address", "")
        if not ip_address:
            return

        # Prefer the dict form of ports for storage (has service names)
        raw_ports = device.get("open_ports_dict") or device.get("open_ports", {})
        if isinstance(raw_ports, list):
            # list of ints only — store as {"port": ""}
            raw_ports = {str(p): "" for p in raw_ports}
        elif isinstance(raw_ports, dict):
            raw_ports = {str(k): v for k, v in raw_ports.items()}  # stringify keys for JSON
        open_ports = json.dumps(raw_ports)
        risk_flags = json.dumps(device.get("risk_flags", []))
        remediation = json.dumps(
            device.get("remediation_plan", device.get("remediation", []))
        )

        self.conn.execute(
            """
            INSERT INTO devices (
                ip_address, mac_address, hostname, manufacturer, device_type,
                open_ports, risk_flags, risk_score, grade, remediation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                mac_address=excluded.mac_address,
                hostname=excluded.hostname,
                manufacturer=excluded.manufacturer,
                device_type=excluded.device_type,
                open_ports=excluded.open_ports,
                risk_flags=excluded.risk_flags,
                risk_score=excluded.risk_score,
                grade=excluded.grade,
                remediation=excluded.remediation,
                last_seen=CURRENT_TIMESTAMP,
                scan_count=devices.scan_count + 1
            """,
            (
                ip_address,
                device.get("mac", ""),
                device.get("hostname", ""),
                device.get("manufacturer", "Unknown"),
                device.get("device_type", "Unknown"),
                open_ports,
                risk_flags,
                int(device.get("risk_score", 0)),
                device.get("grade", "C"),
                remediation,
            ),
        )
        self.conn.commit()

    def save_scan_session(self, devices: list[dict], duration: float, method: str):
        critical_count = sum(1 for d in devices if d.get("grade") == "F")
        high_risk_count = sum(1 for d in devices if d.get("grade") == "D")
        network_grade = self._network_grade(devices)

        for device in devices:
            self.upsert_device(device)

        self.conn.execute(
            """
            INSERT INTO scan_sessions (
                scan_method, total_devices, critical_count, high_risk_count,
                network_grade, duration_seconds
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                method,
                len(devices),
                critical_count,
                high_risk_count,
                network_grade,
                float(duration),
            ),
        )
        self.conn.commit()

    def get_all_devices(self) -> list[dict]:
        cursor = self.conn.execute(
            """
            SELECT * FROM devices
            ORDER BY risk_score DESC, ip_address ASC
            """
        )
        return [self._row_to_device(row) for row in cursor.fetchall()]

    def get_high_risk_devices(self) -> list[dict]:
        cursor = self.conn.execute(
            """
            SELECT * FROM devices
            WHERE grade IN ('D', 'F')
            ORDER BY risk_score DESC, ip_address ASC
            """
        )
        return [self._row_to_device(row) for row in cursor.fetchall()]

    def get_scan_history(self, limit: int = 10) -> list[dict]:
        cursor = self.conn.execute(
            """
            SELECT * FROM scan_sessions
            ORDER BY scan_time DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def clear_devices(self):
        """Delete all rows from devices table only."""
        self.conn.execute("DELETE FROM devices")
        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

    def _row_to_device(self, row: sqlite3.Row) -> dict[str, Any]:
        raw_ports = json.loads(row["open_ports"] or "{}")
        # Normalize: always store as {int: str} internally but return both forms
        if isinstance(raw_ports, dict):
            ports_dict = {int(k): v for k, v in raw_ports.items()}
        else:
            ports_dict = {}
        # Frontend expects a flat list of port numbers
        ports_list = sorted(ports_dict.keys())

        return {
            "id": row["id"],
            "ip": row["ip_address"],          # used by Python backend
            "ip_address": row["ip_address"],   # used by frontend JS
            "mac": row["mac_address"],
            "mac_address": row["mac_address"], # frontend alias
            "hostname": row["hostname"],
            "manufacturer": row["manufacturer"],
            "device_type": row["device_type"],
            "open_ports": ports_list,           # frontend: list of ints for getPortColor()
            "open_ports_dict": ports_dict,      # backend: dict for fingerprinter
            "risk_flags": json.loads(row["risk_flags"] or "[]"),
            "risk_score": row["risk_score"],
            "grade": row["grade"],
            "remediation": json.loads(row["remediation"] or "[]"),
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "scan_count": row["scan_count"],
        }

    def _network_grade(self, devices: list[dict]) -> str:
        rank = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
        worst = "A"
        for device in devices:
            grade = device.get("grade", "A")
            if rank.get(grade, 0) > rank[worst]:
                worst = grade
        return worst
