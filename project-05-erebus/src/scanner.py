from typing import List, Optional
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.live import Live
from rich import box

from src.models import Finding, SEVERITY_RANK, SEVERITY_COLOR
from src.crawler import crawl
from src.modules.headers import HeadersModule
from src.modules.sqli import SQLIModule
from src.modules.xss import XSSModule
from src.modules.traversal import TraversalModule
from src.modules.exposure import ExposureModule
from src.modules.redirect import RedirectModule

console = Console()

ALL_MODULES = [
    HeadersModule,
    ExposureModule,
    SQLIModule,
    XSSModule,
    TraversalModule,
    RedirectModule,
]


def _build_session(user_agent: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent})
    return s


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity, "white")
    return f"[{color}]{severity.upper()}[/{color}]"


def _findings_table(findings: List[Finding]) -> Table:
    table = Table(box=box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Module", style="dim", width=12)
    table.add_column("Title", width=36)
    table.add_column("URL")

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_RANK.get(f.severity, 99))
    for f in sorted_findings:
        table.add_row(
            _severity_badge(f.severity),
            f.module,
            f.title,
            f.url if len(f.url) <= 60 else f.url[:57] + "...",
        )
    return table


def run_scan(
    target: str,
    max_pages: int = 50,
    timeout: int = 10,
    modules: Optional[List[str]] = None,
    user_agent: str = "Erebus/1.0 (security scanner; educational use only)",
    output: Optional[str] = None,
) -> List[Finding]:
    session = _build_session(user_agent)

    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Max pages:[/bold] {max_pages}  [bold]Timeout:[/bold] {timeout}s\n")

    # Crawl
    with console.status("[cyan]Crawling target...[/cyan]"):
        urls, forms = crawl(target, session, max_pages=max_pages, timeout=timeout)

    console.print(f"[green]Crawl complete.[/green] {len(urls)} URLs, {len(forms)} forms discovered.\n")

    # Select modules
    active_modules = [
        M(session, timeout=timeout)
        for M in ALL_MODULES
        if modules is None or M.name in modules
    ]

    all_findings: List[Finding] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Running modules...", total=len(active_modules))
        for mod in active_modules:
            progress.update(task, description=f"[cyan]{mod.name}[/cyan]")
            try:
                found = mod.run(urls, forms)
                all_findings.extend(found)
            except Exception as e:
                console.print(f"[yellow]Module {mod.name} error: {e}[/yellow]")
            progress.advance(task)

    # Print summary table
    if all_findings:
        console.print(_findings_table(all_findings))
        counts = {}
        for f in all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        summary_parts = [
            f"{_severity_badge(sev)}: {counts[sev]}"
            for sev in ["critical", "high", "medium", "low", "info"]
            if sev in counts
        ]
        console.print("  ".join(summary_parts) + f"  [bold]Total: {len(all_findings)}[/bold]\n")
    else:
        console.print("[green]No findings.[/green]\n")

    # Generate report
    if output:
        from src.reporter import generate_report
        generate_report(target, urls, forms, all_findings, output)
        console.print(f"[bold green]Report saved:[/bold green] {output}\n")

    return all_findings
