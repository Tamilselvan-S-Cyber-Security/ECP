import logging
from rich.logging import RichHandler
from rich.console import Console

def setup_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger('security_analyzer')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Remove any existing handlers to avoid duplicate logs
    logger.handlers = []

    # Configure rich handler with improved formatting
    console = Console()
    handler = RichHandler(
        rich_tracebacks=True,
        console=console,
        show_time=True,
        show_path=False
    )

    # Use a cleaner format without redundant information
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)

    return logger