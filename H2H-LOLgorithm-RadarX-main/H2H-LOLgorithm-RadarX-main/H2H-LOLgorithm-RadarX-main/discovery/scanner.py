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
        return self._mock_scan()

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

    def _mock_scan(self) -> list[dict]:
        """Demo simulation — 8 realistic IoT device profiles."""
        mock_devices = [
            ("192.168.1.1",   "C0:FF:EE:00:01:01", "Router"),
            ("192.168.1.101", "A4:C3:F0:00:01:02", "iPhone"),
            ("192.168.1.102", "8C:79:F5:00:01:03", "Smart-TV"),
            ("192.168.1.103", "BC:AD:28:00:01:04", "IP-Camera"),
            ("192.168.1.104", "F8:CA:B8:00:01:05", "Dell-Laptop"),
            ("192.168.1.105", "50:C7:BF:00:01:06", "Smart-Bulb"),
            ("192.168.1.106", "3C:D9:2B:00:01:07", "HP-Printer"),
            ("192.168.1.107", "00:11:22:00:01:08", "Unknown-IoT"),
        ]
        return [self._create_device_dict(ip, mac, "Mock Scan", hostname)
                for ip, mac, hostname in mock_devices]

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
        """Scan common ports — returns {port_int: service_name} for open ports.
        Expanded to cover routers, printers, cameras, IoT, and mobile services.
        """
        mock_profiles = {
            "192.168.1.1":   {22: "SSH", 80: "HTTP", 443: "HTTPS"},
            "192.168.1.101": {5353: "mDNS"},
            "192.168.1.102": {1900: "UPnP", 8080: "HTTP-Alt"},
            "192.168.1.103": {23: "Telnet", 80: "HTTP", 554: "RTSP"},
            "192.168.1.104": {22: "SSH", 443: "HTTPS", 5353: "mDNS"},
            "192.168.1.105": {1883: "MQTT", 1900: "UPnP"},
            "192.168.1.106": {80: "HTTP", 631: "IPP", 9100: "Printer-RAW"},
            "192.168.1.107": {23: "Telnet", 80: "HTTP"},
        }
        if ip in mock_profiles:
            return mock_profiles[ip]

        ports = {
            21: "FTP", 23: "Telnet", 445: "SMB",
            22: "SSH", 443: "HTTPS", 8443: "HTTPS-Alt",
            80: "HTTP", 8080: "HTTP-Alt", 8888: "HTTP-Dev",
            554: "RTSP", 8554: "RTSP-Alt",
            631: "IPP", 9100: "Printer-RAW",
            1883: "MQTT", 8883: "MQTT-TLS",
            1900: "UPnP", 5353: "mDNS",
            7000: "AirPlay", 7100: "AirPlay-Alt", 62078: "Apple-iTunes-Sync",
            2049: "NFS",
        }

        open_ports = {}

        def check_port(port_svc):
            port, svc = port_svc
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.6)
                    if s.connect_ex((ip, port)) == 0:
                        return port, svc
            except OSError:
                pass
            return None

        with ThreadPoolExecutor(max_workers=40) as executor:
            results = executor.map(check_port, ports.items())
            for res in results:
                if res:
                    open_ports[int(res[0])] = res[1]

        return open_ports

        """Tier 0: TCP connect sweep — works on Windows without admin/Npcap.
        Tries port 80, 443, 22, 445 on every host in the subnet.
        If any port responds (open or refused), the host is alive."""
        network = ipaddress.IPv4Network(self.network_range, strict=False)
        probe_ports = [80, 443, 22, 445, 8080, 8443, 23, 21]
        live_hosts = set()

        def probe_host(ip_str: str) -> str | None:
            for port in probe_ports:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.4)
                        result = s.connect_ex((ip_str, port))
                        # 0 = open, 111/10061 = connection refused (still alive)
                        if result in (0, 111, 10061):
                            return ip_str
                except (socket.timeout, OSError):
                    continue
            return None

        # Skip network/broadcast addresses
        hosts = [str(h) for h in network.hosts()]
        # Limit to /24 for speed (max 254 hosts)
        if len(hosts) > 254:
            hosts = hosts[:254]

        self.console.print(f"[cyan]Sweeping {len(hosts)} hosts in {self.network_range}...[/cyan]")

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(probe_host, ip): ip for ip in hosts}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.add(result)

        devices = []
        for ip in sorted(live_hosts):
            devices.append(self._create_device_dict(ip, "00:00:00:00:00:00", "Socket Sweep"))
        return devices

    def _arp_scan(self) -> list[dict]:
        """Tier 1: scapy ARP"""
        arp_request = scapy.ARP(pdst=self.network_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

        devices = []
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            devices.append(self._create_device_dict(ip, mac, "ARP Scan"))
        return devices

    def _nmap_scan(self) -> list[dict]:
        """Tier 2: python-nmap"""
        nm = nmap.PortScanner()
        nm.scan(hosts=self.network_range, arguments='-sn')
        
        devices = []
        for host in nm.all_hosts():
            ip = host
            mac = nm[host]['addresses'].get('mac', '00:00:00:00:00:00')
            devices.append(self._create_device_dict(ip, mac, "Nmap Scan"))
        return devices

    def _mock_scan(self) -> list[dict]:
        """Tier 3: always returns 8 mock devices"""
        mock_devices = [
            ("192.168.1.1", "C0:FF:EE:00:01:01", "Router"),
            ("192.168.1.101", "A4:C3:F0:00:01:02", "iPhone"),
            ("192.168.1.102", "8C:79:F5:00:01:03", "Smart-TV"),
            ("192.168.1.103", "BC:AD:28:00:01:04", "IP-Camera"),
            ("192.168.1.104", "F8:CA:B8:00:01:05", "Dell-Laptop"),
            ("192.168.1.105", "50:C7:BF:00:01:06", "Smart-Bulb"),
            ("192.168.1.106", "3C:D9:2B:00:01:07", "HP-Printer"),
            ("192.168.1.107", "00:11:22:00:01:08", "Unknown-IoT")
        ]
        
        devices = []
        for ip, mac, hostname in mock_devices:
            devices.append(self._create_device_dict(ip, mac, "Mock Scan", hostname))
        return devices

    def _create_device_dict(self, ip: str, mac: str, method: str, hostname: str = None) -> dict:
        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname or self.get_hostname(ip),
            "manufacturer": self.lookup_manufacturer(mac),
            "scan_method": method,
            "timestamp": datetime.datetime.now().isoformat()
        }

    def lookup_manufacturer(self, mac: str) -> str:
        prefix = mac.replace(":", "").upper()[:6]
        return self.oui_database.get(prefix, "Unknown")

    def get_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown"

    def scan_ports(self, ip: str) -> dict:
        """Returns {port_number: service_name} for OPEN ports only.
        Keys are always integers."""
        # Mock port profiles (for demo/fallback IPs)
        mock_profiles = {
            "192.168.1.1": {22: "SSH", 80: "HTTP", 443: "HTTPS"},
            "192.168.1.101": {5353: "mDNS"},
            "192.168.1.102": {1900: "UPnP", 8080: "HTTP-Alt"},
            "192.168.1.103": {23: "Telnet", 80: "HTTP", 554: "RTSP"},
            "192.168.1.104": {22: "SSH", 443: "HTTPS", 5353: "mDNS"},
            "192.168.1.105": {1883: "MQTT", 1900: "UPnP"},
            "192.168.1.106": {80: "HTTP", 631: "IPP", 9100: "Printer-RAW"},
            "192.168.1.107": {23: "Telnet", 80: "HTTP"}
        }

        if ip in mock_profiles:
            return mock_profiles[ip]

        # Real port scan — always use integer keys
        ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP",
            443: "HTTPS", 445: "SMB", 554: "RTSP", 631: "IPP",
            1883: "MQTT", 1900: "UPnP", 5353: "mDNS", 8080: "HTTP-Alt",
            9100: "Printer-RAW"
        }

        open_ports = {}

        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) == 0:
                        return port, ports[port]
            except OSError:
                pass
            return None

        with ThreadPoolExecutor(max_workers=30) as executor:
            results = executor.map(check_port, ports.keys())
            for res in results:
                if res:
                    open_ports[int(res[0])] = res[1]  # always int keys

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
