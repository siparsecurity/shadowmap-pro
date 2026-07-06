#!/usr/bin/env python3
"""
 ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███╗   ███╗ █████╗ ██████╗ 
 ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║████╗ ████║██╔══██╗██╔══██╗
 ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██╔████╔██║███████║██████╔╝
 ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
 ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚═╝ ██║██║  ██║██║     
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
                                          by Sipar Security | v1.0
"""

import argparse
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from subdomain_enum   import enumerate_subdomains
from port_scanner     import scan_subdomains
from tech_fingerprint import fingerprint_all
from vuln_hints       import run_vuln_hints
from report_generator import generate_report
from dns_recon        import run_dns_recon
from stealth          import init_stealth
from json_output      import generate_json_output

console = Console()


def banner():
    console.print(Panel(
        Text(__doc__, style="bold cyan"),
        border_style="cyan",
        padding=(0, 2)
    ))


def parse_args():
    parser = argparse.ArgumentParser(
        description="ShadowMap — Web Reconnaissance Tool by Sipar Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --domain example.com
  python3 main.py --domain example.com --nmap --stealth medium
  python3 main.py --domain example.com --output /tmp/reports --json
  python3 main.py --domain example.com --skip-ports --skip-vuln

Stealth levels:  off | low | medium | high
For authorized testing only. Always have written permission.
        """
    )
    parser.add_argument("--domain",       required=True,            help="Target domain (e.g. example.com)")
    parser.add_argument("--nmap",         action="store_true",      help="Use nmap for port scanning (if installed)")
    parser.add_argument("--output",       default=".",              help="Output directory for reports (default: current dir)")
    parser.add_argument("--stealth",      default="off",            choices=["off", "low", "medium", "high"],
                                                                    help="Stealth level (default: off)")
    parser.add_argument("--json",         action="store_true",      help="Also save results as JSON")
    parser.add_argument("--skip-dns",     action="store_true",      help="Skip DNS recon & zone transfer")
    parser.add_argument("--skip-ports",   action="store_true",      help="Skip port scanning")
    parser.add_argument("--skip-fp",      action="store_true",      help="Skip technology fingerprinting")
    parser.add_argument("--skip-vuln",    action="store_true",      help="Skip vulnerability hints")
    return parser.parse_args()


def print_config(args, domain):
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold dim")
    table.add_column(style="cyan")
    table.add_row("Target",  domain)
    table.add_row("Output",  args.output)
    table.add_row("Stealth", args.stealth.upper())
    table.add_row("nmap",    "enabled" if args.nmap else "disabled (socket scan)")
    table.add_row("JSON",    "yes" if args.json else "no")
    console.print(table)
    console.print()


def main():
    banner()
    args = parse_args()
    domain = args.domain.lower().strip()

    print_config(args, domain)

    # ── Stealth init ──────────────────────────────────────────────────────────
    init_stealth(args.stealth)

    # ── DNS Recon & Zone Transfer ─────────────────────────────────────────────
    dns_results = {}
    if not args.skip_dns:
        dns_results = run_dns_recon(domain)

        # Bonus: add any zone-transfer-leaked hosts to subdomain list later
        leaked = dns_results.get("zone_transfer", {}).get("leaked_hosts", [])
        if leaked:
            console.print(f"[bold red][!!!] {len(leaked)} hosts leaked via zone transfer — added to scope[/bold red]")
    else:
        console.print("[yellow][!] DNS recon skipped.[/yellow]")

    # ── Module 1: Subdomains ──────────────────────────────────────────────────
    subdomains = enumerate_subdomains(domain)

    # Merge zone-transfer leaked hosts into subdomain list
    if dns_results:
        leaked_hosts = dns_results.get("zone_transfer", {}).get("leaked_hosts", [])
        existing = {e["subdomain"] for e in subdomains}
        for host in leaked_hosts:
            if host not in existing:
                import socket
                try:
                    ip = socket.gethostbyname(host)
                    subdomains.append({"subdomain": host, "ip": ip})
                    existing.add(host)
                except Exception:
                    pass

    if not subdomains:
        console.print("[yellow][!] No live subdomains found. Exiting.[/yellow]")
        sys.exit(0)

    # ── Module 2: Port Scan ───────────────────────────────────────────────────
    scan_results = {}
    if not args.skip_ports:
        scan_results = scan_subdomains(subdomains, use_nmap=args.nmap)
    else:
        console.print("[yellow][!] Port scanning skipped.[/yellow]")
        for entry in subdomains:
            scan_results[entry["subdomain"]] = {"ip": entry["ip"], "ports": []}

    # ── Module 3: Fingerprinting ──────────────────────────────────────────────
    fp_results = {}
    if not args.skip_fp:
        fp_results = fingerprint_all(scan_results)
    else:
        console.print("[yellow][!] Fingerprinting skipped.[/yellow]")

    # ── Module 4: Vuln Hints ──────────────────────────────────────────────────
    vuln_results = {}
    if not args.skip_vuln:
        vuln_results = run_vuln_hints(scan_results, fp_results)
    else:
        console.print("[yellow][!] Vuln hints skipped.[/yellow]")

    # ── Module 5: HTML Report ─────────────────────────────────────────────────
    report_path = generate_report(
        domain=domain,
        subdomains=subdomains,
        scan_results=scan_results,
        fp_results=fp_results,
        vuln_results=vuln_results,
        dns_results=dns_results,
        output_dir=Path(args.output)
    )

    # ── Module 6: JSON Output ─────────────────────────────────────────────────
    json_path = None
    if args.json:
        json_path = generate_json_output(
            domain=domain,
            subdomains=subdomains,
            scan_results=scan_results,
            fp_results=fp_results,
            vuln_results=vuln_results,
            dns_results=dns_results,
            output_dir=Path(args.output)
        )

    # ── Final summary ─────────────────────────────────────────────────────────
    console.print(f"\n[bold green]✅ ShadowMap complete![/bold green]")
    console.print(f"[bold]HTML Report:[/bold] [cyan]{report_path}[/cyan]")
    if json_path:
        console.print(f"[bold]JSON Report:[/bold] [cyan]{json_path}[/cyan]")
    console.print("\n[dim]For authorized testing only. Sipar Security.[/dim]\n")


if __name__ == "__main__":
    main()
