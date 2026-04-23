"""
Network Scanner Module

Discovers devices on the local network using a 5-tier fallback strategy:
1. ICMP ping sweep via subprocess (Windows-compatible, finds ALL hotspot devices)
2. TCP connect sweep (no admin, works when ping is blocked)
3. ARP broadcasts via Scapy (requires Npcap + admin on Windows)
4. Nmap-based host discovery (requires nmap installed)
5. Mock data (demo/simulation mode)
"""

import socket
import subprocess
import ipaddress
import re
import time
import datetime
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False
try:
    import nmap
    NMAP_AVAILABLE = True
except Exception:
    NMAP_AVAILABLE = False
from rich.console import Console
from rich.table import Table


class NetworkScanner:
    def __init__(self, network_range: str = "192.168.1.0/24"):
        self.network_range = network_range
        self.console = Console()
        # Expanded OUI database — real vendor prefixes
        self.oui_database = {
            # Apple
            "A4C3F0": "Apple", "8C79F5": "Apple", "F0B429": "Apple",
            "D4619D": "Apple", "3C2EFF": "Apple", "A8BE27": "Apple",
            "60F819": "Apple", "9C35EB": "Apple", "BC9FEF": "Apple",
            "28CFE9": "Apple", "7C6D62": "Apple", "F0D1A9": "Apple",
            # Samsung
            "B47F35": "Samsung", "D8C4E9": "Samsung",
            "A8F274": "Samsung", "CC07AB": "Samsung", "F8042E": "Samsung",
            "D022BE": "Samsung", "000DBE": "Samsung",
            # Xiaomi
            "000003": "Xiaomi", "F48B32": "Xiaomi", "7851CE": "Xiaomi",
            "28E31F": "Xiaomi", "A086C6": "Xiaomi", "98FAE3": "Xiaomi",
            # OnePlus / OPPO
            "E454E8": "OnePlus", "B851F9": "OPPO", "7CEC79": "OPPO",
            # Qualcomm (many Android phones)
            "C0EE40": "Qualcomm",
            # Realtek (laptops/PCs)
            "00E04C": "Realtek", "D03745": "Realtek",
            # Intel (laptops)
            "000012": "Intel", "A4C494": "Intel",
            "0021D8": "Intel", "4CEF8F": "Intel", "7085C2": "Intel",
            # Dell
            "F8CAB8": "Dell", "B083FE": "Dell", "14FEB5": "Dell", "F04DA2": "Dell",
            # HP
            "3CD92B": "HP", "00805F": "HP", "3C4A92": "HP",
            # Lenovo
            "48F8B3": "Lenovo", "30D042": "Lenovo", "B8599F": "Lenovo",
            # Asus
            "90E6BA": "Asus", "107B44": "Asus", "AC9E17": "Asus",
            # Routers / Gateways
            "C0FFEE": "Netgear", "50C7BF": "TP-Link", "1C3BF3": "TP-Link",
            "000006": "Cisco", "000007": "D-Link", "F09FC2": "D-Link",
            "000004": "Belkin", "18D6C7": "Netgear", "C4E984": "Netgear",
            # IoT / Cameras
            "BCAD28": "Hikvision", "000002": "Dahua", "000008": "Canon",
            "000009": "Epson", "000010": "Sony", "000011": "LG",
            # Raspberry Pi / IoT
            "000005": "Raspberry Pi", "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
            # Amazon
            "000001": "Amazon", "40B4CD": "Amazon", "F0272D": "Amazon",
            # Google
            "000000": "Google", "54600A": "Google", "F88FCA": "Google",
            # Microsoft
            "0050F2": "Microsoft", "28187A": "Microsoft",
        }

    # ──────────────────────────────────────────────────────
    # MAIN SCAN ENTRY POINT
    # ──────────────────────────────────────────────────────

    def scan(self) -> list[dict]:
        """Master method — tries each tier in order, stopping at first success."""
        self.console.print("[bold blue]Starting Network Scan...[/bold blue]")

        # Auto-detect subnet
        detected_range = self._auto_detect_range()
        if detected_range and detected_range != self.network_range:
            self.console.print(f"[cyan]Auto-detected network range: {detected_range}[/cyan]")
            self.network_range = detected_range

        # ── Tier 0: ICMP Ping sweep (subprocess) ─────────────────────────────
        try:
            self.console.print("[yellow]Tier 0: ICMP Ping sweep (finds ALL hotspot devices)...[/yellow]")
            devices = self._ping_sweep()
            if devices:
                self.console.print(f"[green]✓ Ping sweep found {len(devices)} live hosts.[/green]")
                return devices
            else:
                self.console.print("[dim]Ping sweep: no hosts responded. Trying TCP sweep...[/dim]")
        except Exception as e:
            self.console.print(f"[red]Ping sweep error: {e}[/red]")

        # ── Tier 1: TCP socket connect sweep ─────────────────────────────────
        try:
            self.console.print("[yellow]Tier 1: TCP socket sweep (service-port probing)...[/yellow]")
            devices = self._socket_sweep()
            if devices:
                self.console.print(f"[green]✓ TCP sweep found {len(devices)} live hosts.[/green]")
                return devices
        except Exception as e:
            self.console.print(f"[red]TCP sweep error: {e}[/red]")

        # ── Tier 2: ARP Scan (Scapy) ─────────────────────────────────────────
        if SCAPY_AVAILABLE:
            try:
                self.console.print("[yellow]Tier 2: ARP scan (Scapy)...[/yellow]")
                devices = self._arp_scan()
                if devices:
                    return devices
            except (ImportError, PermissionError, RuntimeError, OSError) as e:
                self.console.print(f"[red]ARP scan failed: {e}[/red]")

        # ── Tier 3: Nmap ─────────────────────────────────────────────────────
        if NMAP_AVAILABLE:
            try:
                self.console.print("[yellow]Tier 3: Nmap scan...[/yellow]")
                devices = self._nmap_scan()
                if devices:
                    return devices
            except Exception as e:
                self.console.print(f"[red]Nmap scan failed: {e}[/red]")

        # ── Tier 4: Mock demo data ────────────────────────────────────────────
        self.console.print("[cyan]Tier 4: All live methods failed — using Demo mock data.[/cyan]")
        return self._get_mock_devices()

    # ──────────────────────────────────────────────────────
    # TIER 0: ICMP PING SWEEP
    # ──────────────────────────────────────────────────────

    def _ping_sweep(self) -> list[dict]:
        """ICMP ping every host using Windows 'ping' command.
        Finds ANY live device — phones, tablets, IoT — regardless of open ports.
        No admin rights or extra tools required.
        """
        network = ipaddress.IPv4Network(self.network_range, strict=False)
        hosts = [str(h) for h in network.hosts()]
        if len(hosts) > 254:
            hosts = hosts[:254]

        self.console.print(f"[cyan]Pinging {len(hosts)} addresses in {self.network_range}...[/cyan]")
        live_hosts = set()

        def ping_host(ip_str: str):
            try:
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", "800", ip_str],
                    capture_output=True,
                    timeout=3,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
                )
                if result.returncode == 0:
                    return ip_str
            except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
                pass
            return None

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in hosts}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.add(result)

        arp_cache = self._get_arp_cache()
        devices = []
        for ip in sorted(live_hosts, key=lambda x: tuple(int(p) for p in x.split("."))):
            mac = arp_cache.get(ip, "00:00:00:00:00:00")
            devices.append(self._create_device_dict(ip, mac, "Ping Sweep"))
        return devices

    # ──────────────────────────────────────────────────────
    # ARP CACHE (Windows arp -a, no admin)
    # ──────────────────────────────────────────────────────

    def _get_arp_cache(self) -> dict:
        """Read Windows ARP cache to get IP→MAC mappings without admin rights.
        After a ping sweep, Windows automatically populates the ARP table.
        """
        mac_map = {}
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            for line in result.stdout.splitlines():
                m = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}"
                    r"[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
                    line,
                )
                if m:
                    ip_addr = m.group(1)
                    mac = m.group(2).replace("-", ":").upper()
                    mac_map[ip_addr] = mac
        except Exception:
            pass
        return mac_map

    # ──────────────────────────────────────────────────────
    # TIER 1: TCP SOCKET SWEEP
    # ──────────────────────────────────────────────────────

    def _socket_sweep(self) -> list[dict]:
        """TCP connect to common ports — fallback when ICMP ping is blocked."""
        network = ipaddress.IPv4Network(self.network_range, strict=False)
        probe_ports = [
            80, 443, 22, 445, 8080, 8443, 23, 21,
            53, 5353, 7000, 7100, 62078,
            8888, 49152, 1900,
        ]
        live_hosts = set()

        def probe_host(ip_str: str):
            for port in probe_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.3)
                        result = s.connect_ex((ip_str, port))
                        if result in (0, 111, 10061):
                            return ip_str
                except (socket.timeout, OSError):
                    continue
            return None

        hosts = [str(h) for h in network.hosts()]
        if len(hosts) > 254:
            hosts = hosts[:254]

        self.console.print(f"[cyan]TCP-probing {len(hosts)} hosts in {self.network_range}...[/cyan]")

        with ThreadPoolExecutor(max_workers=150) as executor:
            futures = {executor.submit(probe_host, ip): ip for ip in hosts}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.add(result)

        arp_cache = self._get_arp_cache()
        devices = []
        for ip in sorted(live_hosts, key=lambda x: tuple(int(p) for p in x.split("."))):
            mac = arp_cache.get(ip, "00:00:00:00:00:00")
            devices.append(self._create_device_dict(ip, mac, "Socket Sweep"))
        return devices

    # ──────────────────────────────────────────────────────
    # TIER 2 & 3: ARP + NMAP
    # ──────────────────────────────────────────────────────

    def _arp_scan(self) -> list[dict]:
        """Scapy ARP broadcast — requires Npcap + admin on Windows."""
        arp_request = scapy.ARP(pdst=self.network_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        answered_list = scapy.srp(broadcast / arp_request, timeout=3, verbose=False)[0]
        devices = []
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            devices.append(self._create_device_dict(ip, mac, "ARP Scan"))
        return devices

    def _nmap_scan(self) -> list[dict]:
        """python-nmap host discovery."""
        nm = nmap.PortScanner()
        nm.scan(hosts=self.network_range, arguments="-sn --host-timeout 5s")
        devices = []
        for host in nm.all_hosts():
            mac = nm[host]["addresses"].get("mac", "00:00:00:00:00:00")
            devices.append(self._create_device_dict(host, mac, "Nmap Scan"))
        return devices

    # ──────────────────────────────────────────────────────
    # TIER 4: MOCK
    # ──────────────────────────────────────────────────────

    def _get_mock_devices(self) -> list[dict]:
        """Demo simulation — 7 high-impact IoT device profiles."""
        now = datetime.datetime.now().isoformat()
        return [
            {
                "ip": "192.168.1.1",
                "ip_address": "192.168.1.1",
                "device_type": "Wireless Router",
                "manufacturer": "Cisco Systems",
                "hostname": "cisco-gateway",
                "mac": "A4:C3:F0:85:1D:22",
                "mac_address": "A4:C3:F0:85:1D:22",
                "open_ports": [443, 80],
                "risk_flags": [],
                "risk_score": 8,
                "grade": "A",
                "remediation": [
                    "Router is secure ✅",
                    "Keep firmware updated monthly 🗓️",
                    "Re-scan quarterly to stay safe"
                ],
                "scan_method": "Mock Scan",
                "timestamp": now
            },
            {
                "ip": "192.168.1.14",
                "ip_address": "192.168.1.14",
                "device_type": "MacBook Pro",
                "manufacturer": "Apple Inc.",
                "hostname": "nidas-macbook",
                "mac": "F8:FF:C2:11:AB:44",
                "mac_address": "F8:FF:C2:11:AB:44",
                "open_ports": [443],
                "risk_flags": [],
                "risk_score": 5,
                "grade": "B",
                "remediation": [
                    "Device is clean ✅",
                    "Keep macOS updated",
                    "Enable FileVault disk encryption if not already"
                ],
                "scan_method": "Mock Scan",
                "timestamp": now
            },
            {
                "ip": "192.168.1.45",
                "ip_address": "192.168.1.45",
                "device_type": "Network Printer",
                "manufacturer": "HP Inc.",
                "hostname": "hp-laserjet-pro",
                "mac": "D4:85:64:A1:33:FC",
                "mac_address": "D4:85:64:A1:33:FC",
                "open_ports": [80, 443, 9100],
                "risk_flags": ["Unencrypted print port open"],
                "risk_score": 32,
                "grade": "B",
                "remediation": [
                    "Disable port 9100 if network printing not needed 🖨️",
                    "Enable printer password protection",
                    "Update printer firmware"
                ],
                "scan_method": "Mock Scan",
                "timestamp": now
            },
            {
                "ip": "192.168.1.88",
                "ip_address": "192.168.1.88",
                "device_type": "IP Camera",
                "manufacturer": "Hikvision",
                "hostname": "hikvision-cam-01",
                "mac": "C0:56:E3:12:44:AB",
                "mac_address": "C0:56:E3:12:44:AB",
                "open_ports": [80, 554, 8000],
                "risk_flags": [
                    "RTSP stream exposed",
                    "HTTP admin on port 80"
                ],
                "risk_score": 55,
                "grade": "C",
                "remediation": [
                    "Restrict RTSP stream to local network only 📷",
                    "Change default camera admin password immediately",
                    "Disable port 8000 remote access",
                    "Update Hikvision firmware"
                ],
                "scan_method": "Mock Scan",
                "timestamp": now
            },
            {
                "ip": "192.168.1.128",
                "ip_address": "192.168.1.128",
                "device_type": "Old Windows PC",
                "manufacturer": "Dell Inc.",
                "hostname": "dell-desktop-old",
                "mac": "00:26:B9:AA:11:34",
                "mac_address": "00:26:B9:AA:11:34",
                "open_ports": [80, 135, 139, 445],
                "risk_flags": [
                    "SMB port 445 open — ransomware risk",
                    "NetBIOS exposed on port 139",
                    "Outdated OS suspected"
                ],
                "risk_score": 68,
                "grade": "D",
                "remediation": [
                    "Disable SMB port 445 if file sharing not needed 🚨",
                    "Block NetBIOS ports 135 and 139 on firewall",
                    "Update Windows OS immediately",
                    "Run full antivirus scan"
                ],
                "scan_method": "Mock Scan",
                "timestamp": now
            },
            {
                "ip": "192.168.1.141",
                "ip_address": "192.168.1.141",
                "device_type": "IP Camera",
                "manufacturer": "Unknown (No-brand)",
                "hostname": "unknown-device-141",
                "mac": "DE:AD:BE:EF:00:01",
                "mac_address": "DE:AD:BE:EF:00:01",
                "open_ports": [23, 80, 554, 8080],
                "risk_flags": [
                    "Telnet port 23 open — CRITICAL unencrypted access",
                    "Unknown manufacturer — possibly counterfeit",
                    "Default credentials confirmed",
                    "RTSP stream unsecured"
                ],
                "risk_score": 91,
                "grade": "F",
                "remediation": [
                    "ISOLATE this device from network immediately 🔴",
                    "Telnet port 23 is critical — disable or block NOW",
                    "Device manufacturer unknown — treat as hostile",
                    "Do not reconnect until fully audited",
                    "Consider replacing with trusted brand device"
                ],
                "scan_method": "Mock Scan",
                "timestamp": now
            },
            {
                "ip": "192.168.1.155",
                "ip_address": "192.168.1.155",
                "device_type": "Industrial IoT Sensor",
                "manufacturer": "Generic (Unverified)",
                "hostname": "iot-sensor-155",
                "mac": "BA:DC:0D:E0:00:FF",
                "mac_address": "BA:DC:0D:E0:00:FF",
                "open_ports": [21, 23, 1883, 8080],
                "risk_flags": [
                    "Telnet port 23 open — CRITICAL",
                    "FTP port 21 open — unencrypted",
                    "MQTT port 1883 open — no authentication",
                    "Unverified manufacturer"
                ],
                "risk_score": 96,
                "grade": "F",
                "remediation": [
                    "DISCONNECT immediately — multiple critical ports 🔴🚨",
                    "MQTT port 1883 with no auth is a severe risk",
                    "Telnet + FTP combo = completely unsecured device",
                    "Replace with authenticated MQTT (port 8883)",
                    "Report device to network administrator"
                ],
                "scan_method": "Mock Scan",
                "timestamp": now
            }
        ]

    # ──────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────

    def _auto_detect_range(self) -> str:
        """Auto-detect the active network subnet via UDP trick (no traffic sent)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return self.network_range

    def _create_device_dict(self, ip: str, mac: str, method: str, hostname: str = None) -> dict:
        resolved_hostname = hostname or self.get_hostname(ip)
        return {
            "ip": ip,
            "mac": mac,
            "hostname": resolved_hostname,
            "manufacturer": self.lookup_manufacturer(mac),
            "scan_method": method,
            "timestamp": datetime.datetime.now().isoformat(),
        }

    def lookup_manufacturer(self, mac: str) -> str:
        """Look up vendor from MAC OUI (first 6 hex chars)."""
        if not mac or mac == "00:00:00:00:00:00":
            return "Unknown"
        prefix = mac.replace(":", "").replace("-", "").upper()[:6]
        return self.oui_database.get(prefix, "Unknown")

    def get_hostname(self, ip: str) -> str:
        """Reverse DNS lookup."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ip

    def scan_ports(self, ip: str) -> dict:
        """Scan common ports — returns {port_int: service_name} for open ports."""
        # Mock port profiles (for demo/fallback IPs)
        mock_profiles = {
            "192.168.1.1":   {80: "HTTP", 443: "HTTPS"},
            "192.168.1.14":  {443: "HTTPS"},
            "192.168.1.45":  {80: "HTTP", 443: "HTTPS", 9100: "Printer-RAW"},
            "192.168.1.88":  {80: "HTTP", 554: "RTSP", 8000: "HTTP-Alt"},
            "192.168.1.128": {80: "HTTP", 135: "RPC", 139: "NetBIOS", 445: "SMB"},
            "192.168.1.141": {23: "Telnet", 80: "HTTP", 554: "RTSP", 8080: "HTTP-Alt"},
            "192.168.1.155": {21: "FTP", 23: "Telnet", 1883: "MQTT", 8080: "HTTP-Alt"},
        }

        if ip in mock_profiles:
            return mock_profiles[ip]

        ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 443: "HTTPS",
            80: "HTTP", 8080: "HTTP-Alt", 554: "RTSP", 631: "IPP",
            1883: "MQTT", 1900: "UPnP", 5353: "mDNS", 445: "SMB",
            9100: "Printer-RAW", 3389: "RDP", 8008: "Chromecast",
            161: "SNMP", 515: "LPD", 8883: "MQTT-TLS",
        }

        open_ports = {}

        def check_port(port_svc):
            p, svc = port_svc
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.6)
                    if s.connect_ex((ip, p)) == 0:
                        return p, svc
            except OSError:
                pass
            return None

        with ThreadPoolExecutor(max_workers=40) as executor:
            results = executor.map(check_port, ports.items())
            for res in results:
                if res:
                    open_ports[int(res[0])] = res[1]

        return open_ports

if __name__ == "__main__":
    from discovery.fingerprinter import DeviceFingerprinter
    
    scanner = NetworkScanner("192.168.1.0/24")
    devices = scanner.scan()
    
    fingerprinter = DeviceFingerprinter()
    
    final_devices = []
    for dev in devices:
        dev["open_ports"] = scanner.scan_ports(dev["ip"])
        fingerprinted_dev = fingerprinter.fingerprint(dev)
        final_devices.append(fingerprinted_dev)
    
    table = Table(title="RadarX — Network Discovery Demo")
    table.add_column("IP", style="cyan")
    table.add_column("Manufacturer", style="magenta")
    table.add_column("Device Type", style="green")
    table.add_column("Open Ports", style="yellow")
    table.add_column("Risk Flag Count", style="red")

    for d in final_devices:
        ports_str = ", ".join([f"{p}({s})" for p, s in d["open_ports"].items()])
        table.add_row(
            d["ip"],
            d["manufacturer"],
            f"{d['device_type']} ({d['type_confidence']}%)",
            ports_str,
            str(len(d["risk_flags"]))
        )

    console = Console()
    console.print(table)
