"""
ShadowMap - Module 1: Subdomain Enumeration
Passive (crt.sh) + Active (brute-force) subdomain discovery
Cross-platform: Windows & Linux
"""

import socket
import time
import requests
import concurrent.futures
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Universal wordlist — auto-detects SecLists if installed, falls back to built-in
def _find_wordlist() -> Path:
    seclists_paths = [
        Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"),
        Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"),
        Path("/usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
        Path("/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"),
    ]
    for p in seclists_paths:
        if p.exists():
            return p
    return Path(__file__).parent / "wordlists" / "subdomains.txt"

WORDLIST_PATH = _find_wordlist()
THREADS = 50
TIMEOUT = 3


# ─── Passive: crt.sh ──────────────────────────────────────────────────────────

CRTSH_MAX_ATTEMPTS = 3
CRTSH_TIMEOUTS = [10, 15, 25]  # widening timeout per attempt
CRTSH_RETRY_DELAY = 2  # seconds between attempts


def passive_crtsh(domain: str) -> set:
    """
    Query crt.sh for certificate transparency logs — no API key needed.

    crt.sh is known to be slow/flaky under load. Previously this made a
    single request with a 10s timeout — one timeout meant passive
    enumeration silently returned 0 subdomains for the entire run, even
    though crt.sh normally has hundreds of entries for a domain this size.
    Now retries a few times with a widening timeout before giving up.
    """
    found = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    last_error = None
    for attempt in range(1, CRTSH_MAX_ATTEMPTS + 1):
        timeout = CRTSH_TIMEOUTS[min(attempt - 1, len(CRTSH_TIMEOUTS) - 1)]
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.splitlines():
                        sub = sub.strip().lower().lstrip("*.")
                        if sub.endswith(domain) and sub != domain:
                            found.add(sub)
                return found  # success — no need to retry
            else:
                last_error = f"HTTP {resp.status_code}"
        except Exception as e:
            last_error = str(e)

        if attempt < CRTSH_MAX_ATTEMPTS:
            next_timeout = CRTSH_TIMEOUTS[min(attempt, len(CRTSH_TIMEOUTS) - 1)]
            console.print(
                f"[yellow][!] crt.sh attempt {attempt}/{CRTSH_MAX_ATTEMPTS} failed "
                f"({last_error}) — retrying with {next_timeout}s timeout...[/yellow]"
            )
            time.sleep(CRTSH_RETRY_DELAY)

    console.print(
        f"[red][!] crt.sh query failed after {CRTSH_MAX_ATTEMPTS} attempts ({last_error}) "
        f"— continuing with brute-force results only.[/red]"
    )
    return found


# ─── Active: DNS brute-force ───────────────────────────────────────────────────

def resolve_subdomain(subdomain: str) -> dict | None:
    """Try to resolve a subdomain. Returns dict with IP if alive, else None."""
    try:
        ip = socket.gethostbyname(subdomain)
        return {"subdomain": subdomain, "ip": ip}
    except socket.gaierror:
        return None


def active_bruteforce(domain: str) -> list:
    """Brute-force subdomains from wordlist using multithreading."""
    if not WORDLIST_PATH.exists():
        console.print(f"[red][!] Wordlist not found at {WORDLIST_PATH}[/red]")
        return []

    with open(WORDLIST_PATH, "r") as f:
        words = [line.strip() for line in f if line.strip()]

    targets = [f"{word}.{domain}" for word in words]
    results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Brute-forcing subdomains...[/cyan]"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("brute", total=len(targets))
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {executor.submit(resolve_subdomain, t): t for t in targets}
            for future in concurrent.futures.as_completed(futures):
                progress.advance(task)
                result = future.result()
                if result:
                    results.append(result)

    return results


# ─── Resolve passive results ───────────────────────────────────────────────────

def resolve_passive(subdomains: set) -> list:
    """Resolve IPs for passively discovered subdomains."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(resolve_subdomain, s): s for s in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    return results


# ─── Main entry ───────────────────────────────────────────────────────────────

def enumerate_subdomains(domain: str) -> list:
    """
    Run full subdomain enumeration (passive + active).
    Returns list of dicts: [{"subdomain": ..., "ip": ...}, ...]
    """
    console.print(f"\n[bold cyan][*] Starting subdomain enumeration for:[/bold cyan] [bold]{domain}[/bold]")

    # Passive
    console.print("[cyan][*] Querying crt.sh (passive)...[/cyan]")
    passive_subs = passive_crtsh(domain)
    console.print(f"[green][+] crt.sh found {len(passive_subs)} subdomains[/green]")

    passive_results = resolve_passive(passive_subs)
    console.print(f"[green][+] {len(passive_results)} passive subdomains are live[/green]")

    # Active
    console.print("[cyan][*] Starting active brute-force...[/cyan]")
    active_results = active_bruteforce(domain)
    console.print(f"[green][+] Brute-force found {len(active_results)} live subdomains[/green]")

    # Merge & deduplicate
    seen = set()
    all_results = []
    for entry in passive_results + active_results:
        if entry["subdomain"] not in seen:
            seen.add(entry["subdomain"])
            all_results.append(entry)

    console.print(f"[bold green][✓] Total unique live subdomains: {len(all_results)}[/bold green]")
    return all_results
