import socket
import time
import datetime
from concurrent.futures import ThreadPoolExecutor
import scapy.all as scapy
import nmap
from rich.console import Console
from rich.table import Table

class NetworkScanner:
    def __init__(self, network_range: str = "192.168.1.0/24"):
        self.network_range = network_range
        self.console = Console()
        self.oui_database = {
            "A4C3F0": "Apple",
            "8C79F5": "Samsung",
            "C0FFEE": "Netgear",
            "50C7BF": "TP-Link",
            "BCAD28": "Hikvision",
            "3CD92B": "HP",
            "F8CAB8": "Dell",
            "000000": "Google",
            "000001": "Amazon",
            "000002": "Dahua",
            "000003": "Xiaomi",
            "000004": "Belkin",
            "000005": "Raspberry Pi",
            "000006": "Cisco",
            "000007": "D-Link",
            "000008": "Canon",
            "000009": "Epson",
            "000010": "Sony",
            "000011": "LG",
            "000012": "Intel"
        }

    def scan(self) -> list[dict]:
        """Master method — tries each tier in order"""
        self.console.print("[bold blue]Starting Network Scan...[/bold blue]")
        
        # Tier 1: ARP Scan
        try:
            self.console.print("[yellow]Tier 1: Attempting ARP Scan...[/yellow]")
            devices = self._arp_scan()
            if devices:
                return devices
        except (ImportError, PermissionError, RuntimeError) as e:
            self.console.print(f"[red]ARP Scan failed: {e}. Falling back to Tier 2...[/red]")

        # Tier 2: Nmap Scan
        try:
            self.console.print("[yellow]Tier 2: Attempting Nmap Scan...[/yellow]")
            devices = self._nmap_scan()
            if devices:
                return devices
        except Exception as e:
            self.console.print(f"[red]Nmap Scan failed: {e}. Falling back to Tier 3...[/red]")

        # Tier 3: Mock Scan
        self.console.print("[green]Tier 3: Using Mock Data...[/green]")
        return self._mock_scan()

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
        """Returns {port_number: service_name} for OPEN ports only"""
        # Mock port profiles first
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

        ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 
            443: "HTTPS", 445: "SMB", 554: "RTSP", 631: "IPP", 
            1883: "MQTT", 1900: "UPnP", 5353: "mDNS", 8080: "HTTP-Alt", 
            9100: "Printer-RAW"
        }
        
        open_ports = {}
        
        def check_port(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    return port, ports[port]
            return None

        with ThreadPoolExecutor(max_workers=30) as executor:
            results = executor.map(check_port, ports.keys())
            for res in results:
                if res:
                    open_ports[res[0]] = res[1]
        
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
