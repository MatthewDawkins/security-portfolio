import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

from src.engine import run_scan
from src.rules import load_rules
from src import mitre as mitre_db

console = Console()

BANNER = """[bold #7c3aed]
 __   ___       _ _
 \\ \\ / (_) __ _(_) |
  \\ V /| |/ _` | | |
   \\_/ |_|\\__, |_|_|
           |___/
[/bold #7c3aed][dim]  detection rule engine — Sigma-compatible[/dim]
"""

LEVEL_COLOR = {
    "critical":    "bold red",
    "high":        "red",
    "medium":      "yellow",
    "low":         "cyan",
    "informational": "dim white",
}


def _print_banner():
    console.print(BANNER)


def _level_str(level: str) -> str:
    color = LEVEL_COLOR.get(level, "white")
    return f"[{color}]{level.upper()}[/{color}]"


def _cmd_scan(args):
    from src.reporter import generate_report

    log_path = args.log
    rules_dir = args.rules

    if not Path(log_path).exists():
        console.print(f"[red]Error:[/red] Log file not found: {log_path}")
        sys.exit(1)
    if not Path(rules_dir).exists():
        console.print(f"[red]Error:[/red] Rules directory not found: {rules_dir}")
        sys.exit(1)

    console.print(f"[bold]Log:[/bold]   {log_path}")
    console.print(f"[bold]Rules:[/bold] {rules_dir}\n")

    with console.status("[cyan]Processing events...[/cyan]"):
        events, alerts = run_scan(log_path, rules_dir)

    console.print(f"[green]Done.[/green] {len(events)} events processed, {len(alerts)} alerts fired.\n")

    if not alerts:
        console.print("[dim]No alerts.[/dim]")
        return

    # Summary table
    table = Table(box=box.SIMPLE_HEAD, show_lines=False, pad_edge=False)
    table.add_column("Time",      style="dim",  width=10)
    table.add_column("Level",                   width=12)
    table.add_column("Rule",                    width=36)
    table.add_column("Technique",  style="dim", width=12)
    table.add_column("Summary")

    for alert in alerts:
        table.add_row(
            alert.fired_at.strftime("%H:%M:%S"),
            _level_str(alert.level),
            alert.rule_title,
            alert.mitre_technique,
            alert.summary[:80],
        )
    console.print(table)

    # Severity counts
    counts: dict = {}
    for a in alerts:
        counts[a.level] = counts.get(a.level, 0) + 1
    parts = [
        f"{_level_str(lv)}: {counts[lv]}"
        for lv in ["critical", "high", "medium", "low", "informational"]
        if lv in counts
    ]
    console.print("  ".join(parts) + f"  [bold]Total: {len(alerts)}[/bold]\n")

    if args.output:
        generate_report(log_path, events, alerts, args.output)
        console.print(f"[bold green]Report saved:[/bold green] {args.output}\n")


def _cmd_rules(args):
    rules_dir = args.rules
    if not Path(rules_dir).exists():
        console.print(f"[red]Error:[/red] Rules directory not found: {rules_dir}")
        sys.exit(1)

    rules = load_rules(rules_dir)
    console.print(f"\n[bold]Loaded {len(rules)} rules from {rules_dir}[/bold]\n")

    table = Table(box=box.SIMPLE_HEAD, show_lines=False, pad_edge=False)
    table.add_column("ID",          style="dim",  width=12)
    table.add_column("Type",                      width=11)
    table.add_column("Level",                     width=12)
    table.add_column("Technique",   style="dim",  width=12)
    table.add_column("Title")

    for rule in rules:
        table.add_row(
            rule["id"],
            rule["type"],
            _level_str(rule["level"]),
            rule["mitre"]["technique"],
            rule["title"],
        )
    console.print(table)
    console.print()


def main():
    _print_banner()

    parser = argparse.ArgumentParser(
        prog="argus",
        description="Argus — Sigma-compatible detection rule engine",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    # argus scan
    scan_parser = subparsers.add_parser("scan", help="Scan a log file against loaded rules")
    scan_parser.add_argument("log", help="Path to JSONL log file")
    scan_parser.add_argument(
        "--rules", default="rules/",
        help="Directory containing YAML rule files (default: rules/)",
    )
    scan_parser.add_argument(
        "--output", "-o",
        help="Write HTML report to this file (e.g. reports/report.html)",
    )

    # argus rules
    rules_parser = subparsers.add_parser("rules", help="List all loaded rules")
    rules_parser.add_argument(
        "--rules", default="rules/",
        help="Directory containing YAML rule files (default: rules/)",
    )

    args = parser.parse_args()

    if args.command == "scan":
        _cmd_scan(args)
    elif args.command == "rules":
        _cmd_rules(args)
    else:
        parser.print_help()
        sys.exit(0)
