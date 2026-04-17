import sys
import argparse
import codecs

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:
    print("❌ Cannot import rich. Please run: pip install -r requirements.txt")
    # Graceful fallback so it doesn't crash if imported, but cli will fail later if not checked
    class DummyConsole:
        def print(self, msg): print(msg)
    Console = DummyConsole

console = Console()


def _grade_style(grade: str) -> str:
    styles = {
        "A": "[green]A[/green]",
        "B": "[cyan]B[/cyan]",
        "C": "[yellow]C[/yellow]",
        "D": "[bright_red]D[/bright_red]",
        "F": "[bold red]F[/bold red]",
    }
    return styles.get(grade, grade)


def run_demo_pipeline() -> None:
    from discovery.scanner import NetworkScanner
    from discovery.fingerprinter import DeviceFingerprinter
    from discovery.scorecard import SecurityScorecard

    console.print("[bold yellow]Running DEMO mode (Simulation)[/bold yellow]")

    scanner = NetworkScanner("192.168.1.0/24")
    discovered_devices = scanner.scan()
    for device in discovered_devices:
        device["open_ports"] = scanner.scan_ports(device["ip"])

    fingerprinter = DeviceFingerprinter()
    fingerprinted_devices = fingerprinter.fingerprint_all(discovered_devices)

    scorecard = SecurityScorecard()
    graded_devices = scorecard.grade_all(fingerprinted_devices)
    summary = scorecard.network_summary(graded_devices)

    table = Table(title="RadarX - Day 3 Security Scorecard Demo")
    table.add_column("IP", style="cyan")
    table.add_column("Device Type", style="green")
    table.add_column("Grade", justify="center")
    table.add_column("Score", justify="right", style="magenta")
    table.add_column("Top Risk Finding", style="yellow")

    for device in graded_devices:
        top_finding = device.get("risk_findings", [{"msg": "No findings"}])[0].get("msg", "No findings")
        table.add_row(
            device.get("ip", "Unknown"),
            device.get("device_type", "Unknown"),
            _grade_style(device.get("grade", "A")),
            str(device.get("risk_score", 0)),
            top_finding,
        )

    console.print(table)
    console.print("[bold blue]Network Summary[/bold blue]")
    console.print(summary)

def print_banner():
    banner = r"""
    ____            __           _  __
   / __ \____ _____/ /___ ______| |/ /
  / /_/ / __ `/ __  / __ `/ ___/|   / 
 / _, _/ /_/ / /_/ / /_/ / /    /   | 
/_/ |_|\__,_/\__,_/\__,_/_/    /_/|_| 
    IoT Network Discovery Agent
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")

def main():
    try:
        parser = argparse.ArgumentParser(description="RadarX - IoT Network Discovery Agent")
        parser.add_argument("--demo", action="store_true", help="Runs full pipeline in simulation mode, prints rich table")
        parser.add_argument("--scan", action="store_true", help="Runs one live scan (requires sudo on Linux)")
        parser.add_argument("--api", action="store_true", help="Starts FastAPI server on port 8000")
        parser.add_argument("--report", action="store_true", help="Loads last scan from DB and prints security report")
        
        args = parser.parse_args()
        print_banner()

        if args.demo:
            run_demo_pipeline()
        elif args.scan:
            console.print("[bold green]📡 Starting FULL LIVE SCAN...[/bold green]")
        elif args.api:
            console.print("[bold blue]🚀 Starting FastAPI backend on port 8000...[/bold blue]")
            try:
                import uvicorn
                uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
            except ImportError:
                console.print("[bold red]❌ uvicorn not installed. Please install requirements.[/bold red]")
        elif args.report:
            console.print("[bold magenta]📊 Generating Security Report...[/bold magenta]")
        else:
            parser.print_help()
    except Exception as e:
        console.print(f"[bold red]❌ Error in CLI execution: {str(e)}[/bold red]")

if __name__ == "__main__":
    main()
