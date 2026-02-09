import logging
import sys
import os
from pathlib import Path
from rich.logging import RichHandler

def setup_logging(log_level: str = "INFO", log_file: Path = None):
    """
    Configure structured logging with Rich for console output
    and standard formatting for file output.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    if os.environ.get("NO_RICH_LOGGING"):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
        handlers = [handler]
    else:
        handlers = [RichHandler(rich_tracebacks=True, markup=True)]

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers
    )
    
    # Suppress noisy libraries
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)
    logging.getLogger("watchdog").setLevel(logging.WARNING)

def get_logger(name: str):
    return logging.getLogger(name)
