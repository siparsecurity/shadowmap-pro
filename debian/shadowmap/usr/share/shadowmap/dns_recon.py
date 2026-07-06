"""
ShadowMap - DNS Recon Module
Zone transfer attempts + NS/MX/TXT record enumeration
by Sipar Security
"""

import dns.resolver
import dns.zone
import dns.query
import dns.exception
from rich.console import Console

console = Console()


# ─── Get nameservers ──────────────────────────────────────────────────────────

def get_nameservers(domain: str) -> list:
    """Resolve NS records for a domain."""
    nameservers = []
    try:
        answers = dns.resolver.resolve(domain, "NS")
        for rdata in answers:
            ns = str(rdata.target).rstrip(".")
            nameservers.append(ns)
    except Exception as e:
        console.print(f"[yellow][!] NS lookup failed: {e}[/yellow]")
    return nameservers


def resolve_ns_ip(ns: str) -> str | None:
    """Get IP of a nameserver."""
    try:
        answers = dns.resolver.resolve(ns, "A")
        return str(answers[0])
    except Exception:
        return None


# ─── Zone Transfer ────────────────────────────────────────────────────────────

def attempt_zone_transfer(domain: str, ns: str, ns_ip: str) -> list:
    """
    Attempt AXFR zone transfer against a single nameserver.
    Returns list of discovered hosts if successful, empty list if refused.
    """
    results = []
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
        for name, node in zone.nodes.items():
            fqdn = f"{name}.{domain}".strip("@.").replace("@", domain)
            if fqdn and fqdn != domain:
                results.append(fqdn)
        if results:
            console.print(f"[bold red][!!!] ZONE TRANSFER SUCCEEDED on {ns} — {len(results)} records leaked![/bold red]")
    except dns.exception.FormError:
        pass  # Refused — normal
    except Exception:
        pass
    return results


def run_zone_transfers(domain: str) -> dict:
    """
    Try zone transfer on all nameservers.
    Returns { "nameservers": [...], "leaked_hosts": [...], "vulnerable_ns": [...] }
    """
    console.print(f"\n[bold cyan][*] DNS Recon & Zone Transfer attempts for {domain}...[/bold cyan]")

    nameservers = get_nameservers(domain)
    if not nameservers:
        console.print("[yellow][!] No nameservers found.[/yellow]")
        return {"nameservers": [], "leaked_hosts": [], "vulnerable_ns": []}

    console.print(f"[green][+] Found {len(nameservers)} nameservers: {', '.join(nameservers)}[/green]")

    leaked_hosts = []
    vulnerable_ns = []

    for ns in nameservers:
        ns_ip = resolve_ns_ip(ns)
        if not ns_ip:
            console.print(f"[yellow][!] Could not resolve IP for {ns}[/yellow]")
            continue

        console.print(f"[cyan][*] Trying zone transfer on {ns} ({ns_ip})...[/cyan]")
        leaked = attempt_zone_transfer(domain, ns, ns_ip)

        if leaked:
            vulnerable_ns.append(ns)
            leaked_hosts.extend(leaked)
        else:
            console.print(f"[dim]    [-] {ns} refused zone transfer (good)[/dim]")

    leaked_hosts = list(set(leaked_hosts))

    if vulnerable_ns:
        console.print(f"[bold red][!!!] {len(vulnerable_ns)} nameserver(s) vulnerable to zone transfer![/bold red]")
    else:
        console.print(f"[green][✓] No zone transfer vulnerabilities found[/green]")

    return {
        "nameservers": nameservers,
        "leaked_hosts": leaked_hosts,
        "vulnerable_ns": vulnerable_ns
    }


# ─── Extra DNS records ────────────────────────────────────────────────────────

def get_dns_records(domain: str) -> dict:
    """Pull MX, TXT, A, AAAA records for the root domain."""
    records = {}
    record_types = ["A", "AAAA", "MX", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []

    # Flag interesting TXT records
    interesting = []
    for txt in records.get("TXT", []):
        txt_lower = txt.lower()
        if any(k in txt_lower for k in ["spf", "dmarc", "dkim", "verification", "google-site", "ms="]):
            interesting.append(txt)
    records["interesting_txt"] = interesting

    return records


def run_dns_recon(domain: str) -> dict:
    """Full DNS recon — zone transfer + record enumeration."""
    zt = run_zone_transfers(domain)

    console.print(f"[cyan][*] Pulling DNS records (A, MX, TXT, SOA...)...[/cyan]")
    dns_records = get_dns_records(domain)

    mx = dns_records.get("MX", [])
    txt = dns_records.get("TXT", [])
    console.print(f"[green][+] DNS records: {len(mx)} MX, {len(txt)} TXT[/green]")

    return {
        "zone_transfer": zt,
        "dns_records": dns_records
    }
