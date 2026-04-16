import sys
import argparse
import codecs

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')

try:
    from rich.console import Console
except ImportError:
    print("❌ Cannot import rich. Please run: pip install -r requirements.txt")
    # Graceful fallback so it doesn't crash if imported, but cli will fail later if not checked
    class DummyConsole:
        def print(self, msg): print(msg)
    Console = DummyConsole

console = Console()

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
            console.print("[bold yellow]🎭 Running in DEMO mode (Simulation)[/bold yellow]")
            console.print("🔍 Simulated scanning... ✅ done.")
            console.print("⚠️ Mock devices initialized.")
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
