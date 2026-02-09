import click
import sys
from .commands.status import status
from .commands.threats import threats
# Import other commands as implemented

@click.group()
@click.version_option(version="0.1.0")
def cli():
    """SentinelAI - Server Security Platform"""
    pass

cli.add_command(status)
cli.add_command(threats)

if __name__ == "__main__":
    cli()
