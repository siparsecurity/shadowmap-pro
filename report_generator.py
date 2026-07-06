"""
ShadowMap - Module 5: Report Generator
Generates a professional HTML report from all scan data.
"""

from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from rich.console import Console

console = Console()

TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_report(
    domain: str,
    subdomains: list,
    scan_results: dict,
    fp_results: dict,
    vuln_results: dict,
    dns_results: dict = None,
    output_dir: Path = None
) -> Path:
    """
    Generate HTML report from all scan data.
    Returns the path to the generated report.
    """
    console.print(f"\n[bold cyan][*] Generating report...[/bold cyan]")

    output_dir = output_dir or Path.cwd()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build stats
    total_open_ports = sum(len(v.get("ports", [])) for v in scan_results.values())
    total_tech = sum(len(v.get("technologies", {})) for v in fp_results.values())
    total_findings = sum(len(v) for v in vuln_results.values())

    stats = {
        "subdomains": len(subdomains),
        "open_ports":  total_open_ports,
        "technologies": total_tech,
        "findings":    total_findings,
    }

    # Build hosts dict for template
    hosts = {}
    for entry in subdomains:
        sub = entry["subdomain"]
        hosts[sub] = {
            "ip": entry["ip"],
            "ports": scan_results.get(sub, {}).get("ports", [])
        }

    # Render template
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("report.html")

    html = template.render(
        domain=domain,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        stats=stats,
        hosts=hosts,
        fingerprints=fp_results,
        vuln_hints=vuln_results,
        dns=dns_results or {},
    )

    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain.replace('.', '_')}_recon_{timestamp}.html"
    output_path = output_dir / filename

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    console.print(f"[bold green][✓] Report saved:[/bold green] {output_path}")
    return output_path
