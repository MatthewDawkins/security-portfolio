import argparse
import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from src.scenarios.patch    import PatchManagement
from src.scenarios.honeypot import HoneypotPlacement
from src.scenarios.ids      import IDSSensitivity
from src.scenarios.phishing import PhishingTargeting

console = Console()

ALL_SCENARIOS = [
    PatchManagement(),
    HoneypotPlacement(),
    IDSSensitivity(),
    PhishingTargeting(),
]

SCENARIO_MAP = {s.name: s for s in ALL_SCENARIOS}

BANNER = """[bold #7c3aed]
  ____  _
 |  _ \\| |__  _ __ ___  _ __   ___  ___(_)___
 | |_) | '_ \\| '__/ _ \\| '_ \\ / _ \\/ __| / __|
 |  __/| | | | | | (_) | | | |  __/\\__ \\ \\__ \\
 |_|   |_| |_|_|  \\___/|_| |_|\\___||___/_|___/
[/bold #7c3aed][dim]  adversary simulation via Nash equilibrium[/dim]
"""

DISCLAIMER = (
    "[dim]Strategies are derived from game-theoretic Nash equilibria solved by the "
    "[/dim][#7c3aed]Mieza GTO engine[/#7c3aed][dim]. "
    "Models are parameterisable approximations — calibrate cost inputs to your environment.[/dim]"
)


def _print_banner():
    console.print(BANNER)
    console.print(Panel(DISCLAIMER, expand=False, border_style="dim"))
    console.print()


def _get_api_key(args_key: str | None) -> str:
    key = args_key or os.environ.get("MIEZA_API_KEY", "")
    if not key:
        console.print(
            "[red]Error:[/red] Mieza API key required. "
            "Pass --api-key or set the MIEZA_API_KEY environment variable."
        )
        sys.exit(1)
    return key


def _parse_params(param_strings: list) -> dict:
    """Parse 'key=value' strings into a dict with numeric values."""
    result = {}
    for item in (param_strings or []):
        if "=" not in item:
            console.print(f"[yellow]Warning:[/yellow] Ignoring malformed param '{item}' (expected key=value)")
            continue
        k, v = item.split("=", 1)
        try:
            result[k.strip()] = float(v.strip())
        except ValueError:
            console.print(f"[yellow]Warning:[/yellow] Non-numeric value for '{k}', skipping")
    return result


def _print_result(result, verbose: bool = False):
    d_strat = result.defender_recommendation
    a_strat = result.attacker_profile

    console.print(f"\n[bold #7c3aed]{result.scenario_name.upper()}[/bold #7c3aed]  "
                  f"[dim]{result.scenario_description}[/dim]")
    console.print(f"[dim]Solver: {result.equilibrium.solver} in {result.equilibrium.duration_ms}ms[/dim]\n")

    # Equilibrium table
    table = Table(box=box.SIMPLE_HEAD, show_lines=False, pad_edge=False)
    table.add_column("Player",  style="bold", width=12)
    table.add_column("Action",  width=20)
    table.add_column("Probability", width=14)
    table.add_column("E[Payoff]", width=12)

    for strat in result.equilibrium.strategies:
        color = "#7c3aed" if strat.player == "Defender" else "#ff8800"
        first = True
        for action, prob in sorted(strat.probabilities.items(), key=lambda x: -x[1]):
            table.add_row(
                f"[{color}]{strat.player}[/{color}]" if first else "",
                action,
                f"{prob * 100:.1f}%",
                f"{strat.expected_payoff:.2f}" if first else "",
            )
            first = False

    console.print(table)

    console.print(f"[bold]Defender:[/bold] {d_strat.rationale}\n")
    if verbose:
        console.print(f"[dim]{result.interpretation}[/dim]\n")


def _cmd_run(args):
    from src.reporter import generate_report

    api_key = _get_api_key(args.api_key)
    params  = _parse_params(args.param)

    if args.scenario == "all":
        scenarios = ALL_SCENARIOS
    else:
        if args.scenario not in SCENARIO_MAP:
            console.print(f"[red]Unknown scenario:[/red] '{args.scenario}'. "
                          f"Run 'python phronesis.py scenarios' to list available scenarios.")
            sys.exit(1)
        scenarios = [SCENARIO_MAP[args.scenario]]

    results = []
    for scenario in scenarios:
        with console.status(f"[cyan]Solving {scenario.name}...[/cyan]"):
            try:
                result = scenario.run(params, api_key)
                results.append(result)
                _print_result(result, verbose=args.verbose)
            except Exception as e:
                console.print(f"[red]Error running {scenario.name}:[/red] {e}")

    if results and args.output:
        generate_report(results, args.output)
        console.print(f"[bold green]Report saved:[/bold green] {args.output}\n")


def _cmd_scenarios(_args):
    console.print("\n[bold]Available Scenarios[/bold]\n")
    for s in ALL_SCENARIOS:
        console.print(f"  [#7c3aed]{s.name:<12}[/#7c3aed] {s.description}")
        for param, (default, desc) in s.params_help.items():
            console.print(f"    [dim]{param}={default}[/dim]  {desc}")
        console.print()


def main():
    _print_banner()

    parser = argparse.ArgumentParser(
        prog="phronesis",
        description="Phronesis — adversary simulation via Nash equilibrium",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    # phronesis run
    run_parser = subparsers.add_parser("run", help="Run one or all scenarios")
    run_parser.add_argument(
        "scenario",
        help=f"Scenario name or 'all'. Available: {', '.join(SCENARIO_MAP)} or all",
    )
    run_parser.add_argument(
        "--api-key", help="Mieza API key (or set MIEZA_API_KEY env var)",
    )
    run_parser.add_argument(
        "--param", "-p", action="append", metavar="key=value",
        help="Override a scenario parameter (e.g. --param breach_cost=200). Repeatable.",
    )
    run_parser.add_argument(
        "--output", "-o", help="Write HTML report to this file (e.g. report.html)",
    )
    run_parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print full strategic analysis to terminal",
    )

    # phronesis scenarios
    subparsers.add_parser("scenarios", help="List available scenarios and their parameters")

    args = parser.parse_args()

    if args.command == "run":
        _cmd_run(args)
    elif args.command == "scenarios":
        _cmd_scenarios(args)
    else:
        parser.print_help()
        sys.exit(0)
