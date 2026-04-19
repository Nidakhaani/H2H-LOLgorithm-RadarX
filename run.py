"""
RadarX CLI — Main Entry Point

Provides command-line interface for running the IoT network discovery agent.
Modes: --demo (simulation), --scan (real), --report (saved data), --api (dashboard).
"""

import argparse
import codecs
import sys
import time

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

try:
    from rich.console import Console
    from rich.panel import Panel
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


def _risk_priority(item: dict) -> tuple[int, int]:
    level_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    return (level_rank.get(item.get("level", "INFO"), 9), -len(item.get("msg", "")))


def _render_device_table(devices: list[dict], title: str) -> None:
    table = Table(title=title)
    table.add_column("IP", style="cyan")
    table.add_column("Device Type", style="green")
    table.add_column("Grade", justify="center")
    table.add_column("Score", justify="right", style="magenta")
    table.add_column("Risk Flag Count", justify="right", style="yellow")

    for device in devices:
        table.add_row(
            device.get("ip", "Unknown"),
            device.get("device_type", "Unknown"),
            _grade_style(device.get("grade", "C")),
            str(device.get("risk_score", 0)),
            str(len(device.get("risk_flags", []))),
        )
    console.print(table)


def _render_network_summary_box(summary: dict) -> None:
    grade_dist = summary.get("grade_distribution", {})
    summary_text = (
        f"[bold]Network Grade:[/bold] {_grade_style(summary.get('network_grade', 'C'))}\n"
        f"[bold]Total Devices:[/bold] {summary.get('total_devices', 0)}\n"
        f"[bold]Critical (F):[/bold] {summary.get('critical_count', 0)}\n"
        f"[bold]High Risk (D):[/bold] {summary.get('high_risk_count', 0)}\n"
        f"[bold]Grade Distribution:[/bold] "
        f"A:{grade_dist.get('A', 0)}  B:{grade_dist.get('B', 0)}  C:{grade_dist.get('C', 0)}  "
        f"D:{grade_dist.get('D', 0)}  F:{grade_dist.get('F', 0)}"
    )
    console.print(Panel(summary_text, title="Network Security Summary", border_style="blue"))


def _pipeline_scan_method(devices: list[dict]) -> str:
    if not devices:
        return "mock"
    return devices[0].get("scan_method", "mock").lower().replace(" ", "_")


def run_demo_pipeline() -> None:
    from discovery.scanner import NetworkScanner
    from discovery.fingerprinter import DeviceFingerprinter
    from discovery.scorecard import SecurityScorecard
    from data.database import DatabaseManager

    console.print("[bold yellow]Running DEMO mode (Simulation)[/bold yellow]\n")
    pipeline_start = time.perf_counter()

    scanner = NetworkScanner("192.168.1.0/24")
    t0 = time.perf_counter()
    discovered_devices = scanner.scan()
    for device in discovered_devices:
        device["open_ports"] = scanner.scan_ports(device["ip"])
    t1 = time.perf_counter()
    console.print(
        f"📡 Discovering devices...           ✅ Found {len(discovered_devices)} devices  ({(t1 - t0):.1f}s)"
    )

    fingerprinter = DeviceFingerprinter()
    t2 = time.perf_counter()
    fingerprinted_devices = fingerprinter.fingerprint_all(discovered_devices)
    t3 = time.perf_counter()
    console.print(
        f"🏷️  Fingerprinting devices...        ✅ {len(fingerprinted_devices)} devices classified  ({(t3 - t2):.1f}s)"
    )

    scorecard = SecurityScorecard()
    t4 = time.perf_counter()
    graded_devices = scorecard.grade_all(fingerprinted_devices)
    summary = scorecard.network_summary(graded_devices)
    t5 = time.perf_counter()
    console.print(
        "🛡️  Calculating security grades...   "
        f"✅ Network Grade: {summary.get('network_grade', 'C')} "
        f"({summary.get('critical_count', 0)} critical)  ({(t5 - t4):.1f}s)"
    )

    db_start = time.perf_counter()
    db = DatabaseManager()
    db.save_scan_session(graded_devices, time.perf_counter() - pipeline_start, _pipeline_scan_method(graded_devices))
    db_end = time.perf_counter()
    console.print(f"💾 Saving to database...            ✅ Saved to {db.db_path}  ({(db_end - db_start):.1f}s)\n")
    db.close()

    _render_device_table(graded_devices, "RadarX - Day 4 Security Pipeline Demo")
    _render_network_summary_box(summary)
    console.print(f"\n[bold cyan]⏱️ Total pipeline time: {(time.perf_counter() - pipeline_start):.2f}s[/bold cyan]")


def run_report() -> None:
    from data.database import DatabaseManager
    from discovery.scorecard import SecurityScorecard

    db = DatabaseManager()
    devices = db.get_all_devices()

    if not devices:
        console.print("[yellow]No scan data found. Run --demo or --scan first.[/yellow]")
        db.close()
        return

    scorecard = SecurityScorecard()
    all_devices = []
    for device in devices:
        normalized = dict(device)
        normalized["remediation_plan"] = normalized.get("remediation", [])
        normalized["risk_findings"] = []
        for flag in normalized.get("risk_flags", []):
            normalized["risk_findings"].append({"level": "MEDIUM", "msg": flag})
        all_devices.append(normalized)

    summary = scorecard.network_summary(all_devices)
    grade_color = {
        "A": "green",
        "B": "cyan",
        "C": "yellow",
        "D": "bright_red",
        "F": "red",
    }.get(summary.get("network_grade", "C"), "white")
    console.print(
        Panel(
            f"[bold {grade_color}]Network Security Grade: {summary.get('network_grade', 'C')}[/bold {grade_color}]\n"
            f"Devices: {summary.get('total_devices', 0)} | "
            f"Critical: {summary.get('critical_count', 0)} | "
            f"High Risk: {summary.get('high_risk_count', 0)}",
            title="RadarX Security Report",
            border_style=grade_color,
        )
    )

    risky_devices = [d for d in all_devices if d.get("grade") in {"D", "F"}]
    if risky_devices:
        console.print("[bold red]Grade D/F Devices and Top Findings[/bold red]")
        for device in risky_devices:
            findings = sorted(device.get("risk_findings", []), key=_risk_priority)
            top_finding = findings[0]["msg"] if findings else "No top finding available"
            console.print(
                f"- [bold]{device.get('ip', 'Unknown')}[/bold] "
                f"({device.get('device_type', 'Unknown')}) "
                f"Grade {_grade_style(device.get('grade', 'C'))}, Score {device.get('risk_score', 0)} "
                f"-> {top_finding}"
            )
    else:
        console.print("[green]No devices currently graded D or F.[/green]")

    remediation_items = []
    for device in risky_devices if risky_devices else all_devices:
        remediation_items.extend(device.get("remediation_plan", []))

    critical = []
    normal = []
    for item in remediation_items:
        if item.startswith("URGENT:"):
            critical.append(item)
        else:
            normal.append(item)

    ordered = []
    seen = set()
    for item in critical + normal:
        if item not in seen:
            ordered.append(item)
            seen.add(item)

    if ordered:
        console.print("\n[bold]Full Remediation Checklist[/bold]")
        for idx, item in enumerate(ordered, start=1):
            if item.startswith("URGENT:"):
                console.print(f"{idx}. [bold red]{item}[/bold red]")
            else:
                console.print(f"{idx}. {item}")
    else:
        console.print("\n[green]No remediation actions required right now.[/green]")

    history = db.get_scan_history(limit=1)
    if history:
        latest = history[0]
        console.print(
            f"\n[dim]Last scan: {latest.get('scan_time')} | Method: {latest.get('scan_method')} | "
            f"Duration: {latest.get('duration_seconds', 0.0):.2f}s[/dim]"
        )
    db.close()

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
            run_report()
        else:
            parser.print_help()
    except Exception as e:
        console.print(f"[bold red]❌ Error in CLI execution: {str(e)}[/bold red]")

if __name__ == "__main__":
    main()
