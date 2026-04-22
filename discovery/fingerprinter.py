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
            "ssh_old_version":      "MEDIUM: SSH service detected - ensure strong password",
            "dns_open":             "LOW: DNS service detected - potential for DNS amplification",
            "snmp_open":            "MEDIUM: SNMP (port 161) - may leak network configuration",
        }

    def fingerprint(self, device: dict) -> dict:
        """Analyzes a single device and adds classification and risk data"""
        # Normalize open_ports to a dict of {int: str} regardless of source
        raw_ports = device.get("open_ports", {})
        if isinstance(raw_ports, list):
            # Came from DB as a list of port ints — use open_ports_dict if available
            raw_ports = device.get("open_ports_dict", {int(p): "" for p in raw_ports})
        elif isinstance(raw_ports, dict):
            raw_ports = {int(k): v for k, v in raw_ports.items()}
        device["open_ports"] = raw_ports  # normalize in place
        device["open_ports_dict"] = raw_ports

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

        # 1. By open ports (Signatures)
        if 554 in ports or 8554 in ports:
            classifications.append(("IP Camera", 90))
            if 23 in ports:
                classifications.append(("IP Camera (Older/Insecure)", 95))
        
        if 9100 in ports or 631 in ports or 515 in ports:
            classifications.append(("Printer", 90))
        
        if 1883 in ports or 8883 in ports:
            classifications.append(("IoT Hub/Sensor", 85))
            
        if 5353 in ports: # mDNS
            if "apple" in mfr or any(x in hostname for x in ["iphone", "ipad", "mac", "apple"]):
                classifications.append(("Apple Device", 80))
            else:
                classifications.append(("mDNS-enabled Device", 50))
            
        if 1900 in ports: # UPnP / SSDP
            classifications.append(("Smart Device (UPnP)", 60))

        if 5000 in ports or 7000 in ports or 7100 in ports:
            classifications.append(("Media Streamer (AirPlay/DLNA)", 80))

        if 8008 in ports or 8009 in ports:
            classifications.append(("Google Cast Device (Chromecast/Nest)", 90))

        if 22 in ports:
            if "raspberry" in mfr:
                classifications.append(("Raspberry Pi Controller", 90))
            elif "linux" in hostname:
                classifications.append(("Linux Server/PC", 80))
            else:
                classifications.append(("SSH-enabled Device", 40))

        if 445 in ports or 139 in ports:
            classifications.append(("Windows PC / File Server", 80))

        if 3389 in ports:
            classifications.append(("Windows Workstation (RDP)", 90))

        # 2. By manufacturer
        if any(x in mfr for x in ["hikvision", "dahua", "amcrest", "reolink", "axis"]):
            classifications.append(("IP Camera", 95))
        elif "apple" in mfr:
            if any(x in hostname for x in ["iphone", "ipad"]):
                classifications.append(("Apple Mobile Device", 95))
            elif "apple-tv" in hostname:
                classifications.append(("Apple TV", 95))
            else:
                classifications.append(("Apple Device", 85))
        elif any(x in mfr for x in ["samsung", "sony", "lg", "vizio", "panasonic"]) or "tv" in hostname:
            classifications.append(("Smart TV", 85))
        elif any(x in mfr for x in ["hp", "canon", "epson", "lexmark", "brother", "xerox"]):
            classifications.append(("Printer", 90))
        elif any(x in mfr for x in ["netgear", "cisco", "d-link", "tp-link", "linksys", "asus", "ubiquiti", "mikrotik"]):
            classifications.append(("Router/Network Infrastructure", 85))
        elif any(x in mfr for x in ["amazon", "echo", "alexa"]):
            classifications.append(("Smart Speaker (Alexa)", 90))
        elif "google" in mfr or "nest" in mfr:
            classifications.append(("Google Nest / Hub", 90))
        elif "raspberry" in mfr:
            classifications.append(("IoT Controller (Raspberry Pi)", 90))
        elif "tesla" in mfr:
            classifications.append(("Tesla Vehicle/Charger", 95))
        elif "philips" in mfr and "hue" in hostname:
            classifications.append(("Philips Hue Bridge", 95))
        elif "unknown" in mfr:
            classifications.append(("Generic Device", 10))

        # 3. By hostname patterns
        if any(x in hostname for x in ["iphone", "ipad", "macbook", "airpods"]):
            classifications.append(("Apple Device", 95))
        elif "printer" in hostname:
            classifications.append(("Printer", 90))
        elif "camera" in hostname or "cam-" in hostname:
            classifications.append(("IP Camera", 90))
        elif "router" in hostname or "gateway" in hostname:
            classifications.append(("Router", 90))
        elif "tv" in hostname or "smarttv" in hostname:
            classifications.append(("Smart TV", 90))
        elif "android" in hostname:
            classifications.append(("Android Device", 80))
        elif "windows" in hostname or "desktop" in hostname or "laptop" in hostname:
            classifications.append(("Windows Machine", 75))

        if not classifications:
            return "Unknown Device", 0

        # Return the classification with the highest confidence
        best_match = max(classifications, key=lambda x: x[1])
        return best_match

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
        if 554 in ports or 8554 in ports:
            flags.append(self.risk_library["rtsp_unencrypted"])
        if 1883 in ports:
            flags.append(self.risk_library["mqtt_open"])
        if 445 in ports:
            flags.append(self.risk_library["smb_open"])
        if 53 in ports:
            flags.append(self.risk_library["dns_open"])
        if 161 in ports:
            flags.append(self.risk_library["snmp_open"])

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
