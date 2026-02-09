import click
from rich.console import Console
from rich.table import Table
from ..client import run_command

console = Console()

@click.command()
def status():
    """Show agent status."""
    try:
        data = run_command("status")
        
        console.print("\n[bold green]Sentinel Agent v0.1.0[/bold green]")
        console.print(f"Status: [green]● {data.get('status', 'unknown')}[/green]")
        console.print(f"Uptime: {data.get('uptime', 'N/A')}")
        
        console.print("\n[bold]Monitored Files:[/bold]")
        for f in data.get("monitored_files", []):
            console.print(f"  - {f}")
            
    except ConnectionError:
        console.print("[bold red]Error:[/bold red] Agent not running.")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
