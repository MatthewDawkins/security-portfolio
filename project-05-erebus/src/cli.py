import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from src.modules.headers import HeadersModule
from src.modules.sqli import SQLIModule
from src.modules.xss import XSSModule
from src.modules.traversal import TraversalModule
from src.modules.exposure import ExposureModule
from src.modules.redirect import RedirectModule

console = Console()

ALL_MODULES = [
    HeadersModule,
    SQLIModule,
    XSSModule,
    TraversalModule,
    ExposureModule,
    RedirectModule,
]

BANNER = """[bold #7c3aed]
  _____          _
 | ____|_ __ ___| |__  _   _ ___
 |  _| | '__/ _ \\ '_ \\| | | / __|
 | |___| | |  __/ |_) | |_| \\__ \\
 |_____|_|  \\___|_.__/ \\__,_|___/
[/bold #7c3aed][dim]  web vulnerability scanner[/dim]
"""

DISCLAIMER = (
    "[yellow]For authorized security testing and educational use only.[/yellow]\n"
    "[dim]Scanning systems you do not own or have explicit permission to test is illegal.[/dim]"
)


def _print_banner():
    console.print(BANNER)
    console.print(Panel(DISCLAIMER, expand=False, border_style="dim"))
    console.print()


def _cmd_scan(args):
    from src.scanner import run_scan

    module_names = args.modules.split(",") if args.modules else None

    run_scan(
        target=args.target,
        max_pages=args.max_pages,
        timeout=args.timeout,
        modules=module_names,
        output=args.output,
    )


def _cmd_modules(_args):
    table_data = [(M.name, M.description) for M in ALL_MODULES]
    console.print("\n[bold]Available Modules[/bold]\n")
    for name, desc in table_data:
        console.print(f"  [#7c3aed]{name:<14}[/#7c3aed] {desc}")
    console.print()


def main():
    _print_banner()

    parser = argparse.ArgumentParser(
        prog="erebus",
        description="Erebus — web vulnerability scanner",
        add_help=True,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    # erebus scan
    scan_parser = subparsers.add_parser("scan", help="Scan a target URL")
    scan_parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    scan_parser.add_argument(
        "--max-pages", type=int, default=50,
        help="Maximum pages to crawl (default: 50)",
    )
    scan_parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout in seconds (default: 10)",
    )
    scan_parser.add_argument(
        "--modules",
        help="Comma-separated list of modules to run (default: all). "
             "Available: headers,sqli,xss,traversal,exposure,redirect",
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Write HTML report to this file (e.g. report.html)",
    )

    # erebus modules
    subparsers.add_parser("modules", help="List available scan modules")

    args = parser.parse_args()

    if args.command == "scan":
        _cmd_scan(args)
    elif args.command == "modules":
        _cmd_modules(args)
    else:
        parser.print_help()
        sys.exit(0)
