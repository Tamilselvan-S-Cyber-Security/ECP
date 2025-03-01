#!/usr/bin/env python3
import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from core.base_plugin import PluginManager
from utils.logger import setup_logger
from utils.validator import validate_domain
import urllib3
import requests

def parse_args():
    parser = argparse.ArgumentParser(description='Security Analysis Tool')
    parser.add_argument('-d', '--domain', help='Target domain to analyze')
    parser.add_argument('-p', '--ports', help='Ports to scan (default: top 1000)', default='1-1000')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates (default: False)')
    return parser.parse_args()

def main():
    args = parse_args()
    console = Console()
    logger = setup_logger(args.verbose)

    if not args.domain:
        console.print("[red]Error: Domain is required[/red]")
        sys.exit(1)

    if not validate_domain(args.domain):
        console.print("[red]Error: Invalid domain format[/red]")
        sys.exit(1)

    # Configure SSL verification
    if not args.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    plugin_manager = PluginManager()

    # Display banner
    console.print("""
[bold blue]Security Analysis Tool[/bold blue]
[italic]A modular security analysis framework[/italic]
    """)

    try:
        results = {}
        plugins = plugin_manager.get_plugins()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for plugin in plugins:
                task_id = progress.add_task(f"Running {plugin.name}...", total=None)
                try:
                    logger.info(f"Starting plugin: {plugin.name}")
                    plugin_results = plugin.run(args.domain, args.ports)
                    results[plugin.name] = plugin_results
                    logger.info(f"Completed plugin: {plugin.name}")
                    progress.update(task_id, completed=True)
                except Exception as e:
                    logger.error(f"Error in plugin {plugin.name}: {str(e)}")
                    results[plugin.name] = {'error': str(e)}
                    progress.update(task_id, completed=True)

        # Display results
        table = Table(title="Analysis Results")
        table.add_column("Module", style="cyan")
        table.add_column("Findings", style="green")

        for module, findings in results.items():
            if isinstance(findings, list):
                findings_str = "\n".join(str(f) for f in findings)
            else:
                findings_str = str(findings)
            table.add_row(module, findings_str)

        console.print(table)

        if args.output:
            with open(args.output, 'w') as f:
                for module, findings in results.items():
                    f.write(f"=== {module} ===\n")
                    if isinstance(findings, list):
                        for finding in findings:
                            f.write(f"{finding}\n")
                    else:
                        f.write(f"{findings}\n")
                    f.write("\n")
            console.print(f"[green]Results saved to {args.output}[/green]")

    except KeyboardInterrupt:
        console.print("\n[red]Analysis interrupted by user[/red]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()