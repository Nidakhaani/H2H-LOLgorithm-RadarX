"""
Device Fingerprinter Module

Analyzes open ports and manufacturer data to classify device types and
detect security risk flags (Telnet, FTP, HTTP, RTSP, UPnP, MQTT).
"""

class DeviceFingerprinter:
    def __init__(self):
        self.risk_library = {
            "telnet_open":          "CRITICAL: Telnet (port 23) - passwords sent unencrypted",
            "ftp_open":             "HIGH: FTP (port 21) - file transfers unencrypted",
            "http_no_https":        "HIGH: HTTP only, no HTTPS - web traffic unencrypted",
            "default_creds_likely": "CRITICAL: Unknown device with Telnet = likely default credentials",
            "upnp_enabled":         "MEDIUM: UPnP enabled - device may auto-open firewall ports",
            "rtsp_unencrypted":     "MEDIUM: Camera RTSP stream has no encryption",
            "mqtt_open":            "MEDIUM: MQTT port 1883 - IoT commands unencrypted",
            "smb_open":             "MEDIUM: SMB port 445 - potential file share exposure",
        }

    def fingerprint(self, device: dict) -> dict:
        """Analyzes a single device and adds classification and risk data"""
        device_type, confidence = self._classify_device_type(device)
        device["device_type"] = device_type
        device["type_confidence"] = confidence
        device["risk_flags"] = self._detect_risk_flags(device)
        return device

    def fingerprint_all(self, devices: list[dict]) -> list[dict]:
        """Analyzes a list of devices"""
        return [self.fingerprint(d) for d in devices]

    def _classify_device_type(self, device: dict) -> tuple[str, int]:
        ports = device.get("open_ports", {})
        mfr = device.get("manufacturer", "").lower()
        hostname = device.get("hostname", "").lower()

        classifications = []

        # 1. By open ports
        if 554 in ports and 23 in ports:
            classifications.append(("IP Camera (CRITICAL)", 95))
        elif 554 in ports:
            classifications.append(("IP Camera", 90))
        
        if 9100 in ports or 631 in ports:
            classifications.append(("Printer", 90))
        
        if 1883 in ports:
            classifications.append(("IoT Sensor/Hub", 80))
            
        if 5353 in ports:
            classifications.append(("Apple Device", 75))
            
        if 1900 in ports:
            classifications.append(("Smart Device", 70))

        # 2. By manufacturer
        if "hikvision" in mfr or "dahua" in mfr:
            classifications.append(("IP Camera", 95))
        elif "apple" in mfr:
            classifications.append(("Apple Device", 85))
        elif "samsung" in mfr:
            classifications.append(("Smart TV / Mobile", 80))
        elif any(x in mfr for x in ["hp", "canon", "epson"]):
            classifications.append(("Printer", 85))
        elif any(x in mfr for x in ["netgear", "cisco", "d-link"]):
            classifications.append(("Router/Gateway", 80))
        elif any(x in mfr for x in ["tp-link", "belkin"]):
            classifications.append(("Smart Device", 75))
        elif "amazon" in mfr:
            classifications.append(("Smart Speaker", 85))
        elif "raspberry" in mfr:
            classifications.append(("IoT Controller", 85))
        elif "unknown" in mfr:
            classifications.append(("Unknown Device", 0))

        # 3. By hostname
        if any(x in hostname for x in ["iphone", "ipad", "macbook"]):
            classifications.append(("Apple Device", 95))
        elif "printer" in hostname:
            classifications.append(("Printer", 90))
        elif "camera" in hostname:
            classifications.append(("IP Camera", 90))
        elif "router" in hostname:
            classifications.append(("Router/Gateway", 90))
        elif "tv" in hostname:
            classifications.append(("Smart TV", 90))

        if not classifications:
            return "Unknown Device", 0

        # Return the classification with the highest confidence
        return max(classifications, key=lambda x: x[1])

    def _detect_risk_flags(self, device: dict) -> list[str]:
        ports = device.get("open_ports", {})
        mfr = device.get("manufacturer", "")
        flags = []

        if 23 in ports:
            flags.append(self.risk_library["telnet_open"])
        if 21 in ports:
            flags.append(self.risk_library["ftp_open"])
        if 80 in ports and 443 not in ports:
            flags.append(self.risk_library["http_no_https"])
        if mfr == "Unknown" and 23 in ports:
            flags.append(self.risk_library["default_creds_likely"])
        if 1900 in ports:
            flags.append(self.risk_library["upnp_enabled"])
        if 554 in ports:
            flags.append(self.risk_library["rtsp_unencrypted"])
        if 1883 in ports:
            flags.append(self.risk_library["mqtt_open"])
        if 445 in ports:
            flags.append(self.risk_library["smb_open"])

        return flags

if __name__ == "__main__":
    fingerprinter = DeviceFingerprinter()
    test_device = {
        "ip": "192.168.1.103",
        "manufacturer": "Hikvision",
        "hostname": "IP-Camera",
        "open_ports": {23: "Telnet", 80: "HTTP", 554: "RTSP"}
    }
    result = fingerprinter.fingerprint(test_device)
    print(f"Fingerprint Result: {result}")
