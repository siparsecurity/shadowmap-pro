"""
ShadowMap - JSON Output Module
Saves all scan results as machine-readable JSON
by Sipar Security
"""

import json
from datetime import datetime
from pathlib import Path
from rich.console import Console

console = Console()


def build_json_report(
    domain: str,
    subdomains: list,
    scan_results: dict,
    fp_results: dict,
    vuln_results: dict,
    dns_results: dict = None,
) -> dict:
    """Build a structured dict from all scan data."""

    hosts = {}
    for entry in subdomains:
        sub = entry["subdomain"]
        fp = fp_results.get(sub, {})
        hosts[sub] = {
            "ip": entry["ip"],
            "ports": scan_results.get(sub, {}).get("ports", []),
            "technologies": fp.get("technologies", {}),
            "cms": fp.get("cms", []),
            "missing_security_headers": fp.get("missing_security_headers", []),
            "findings": vuln_results.get(sub, []),
        }

    # Summary stats
    total_findings = sum(len(v.get("findings", [])) for v in hosts.values())
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for h in hosts.values():
        for f in h.get("findings", []):
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "meta": {
            "tool": "ShadowMap",
            "version": "1.0",
            "author": "Sipar Security",
            "generated_at": datetime.now().isoformat(),
            "target": domain,
        },
        "summary": {
            "total_subdomains": len(subdomains),
            "total_open_ports": sum(len(v.get("ports", [])) for v in hosts.values()),
            "total_technologies": sum(len(v.get("technologies", {})) for v in hosts.values()),
            "total_findings": total_findings,
            "severity_breakdown": severity_counts,
        },
        "dns": dns_results or {},
        "hosts": hosts,
    }

    return report


def save_json(report: dict, domain: str, output_dir: Path) -> Path:
    """Save JSON report to disk."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain.replace('.', '_')}_shadowmap_{timestamp}.json"
    output_path = output_dir / filename

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    console.print(f"[bold green][✓] JSON report saved:[/bold green] {output_path}")
    return output_path


def generate_json_output(
    domain: str,
    subdomains: list,
    scan_results: dict,
    fp_results: dict,
    vuln_results: dict,
    dns_results: dict = None,
    output_dir: Path = None,
) -> Path:
    """Build and save the JSON report. Returns output path."""
    console.print(f"\n[bold cyan][*] Generating JSON output...[/bold cyan]")
    report = build_json_report(domain, subdomains, scan_results, fp_results, vuln_results, dns_results)
    return save_json(report, domain, output_dir or Path.cwd())
