import click
from rich.console import Console
from rich.table import Table
from ..client import run_command

console = Console()

@click.command()
@click.option("--limit", "-n", default=10, help="Number of threats to show")
def threats(limit):
    """List recent threats."""
    try:
        data = run_command("threats", {"limit": limit})
        
        if not data:
            console.print("No threats found.")
            return

        table = Table(title="Recent Threats")
        table.add_column("ID", style="cyan")
        table.add_column("Time", style="dim")
        table.add_column("Severity")
        table.add_column("Source")
        table.add_column("Description")

        for threat in data:
            severity_style = "green"
            if threat["severity"] == "medium": severity_style = "yellow"
            if threat["severity"] == "high": severity_style = "red"
            if threat["severity"] == "critical": severity_style = "bold red"
            
            table.add_row(
                threat["id"],
                threat["created_at"],
                f"[{severity_style}]{threat['severity'].upper()}[/{severity_style}]",
                threat["source"],
                threat["description"]
            )

        console.print(table)
            
    except ConnectionError:
        console.print("[bold red]Error:[/bold red] Agent not running.")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
