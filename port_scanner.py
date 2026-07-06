"""
ShadowMap - Module 2: Port & Service Scanner
Pure Python sockets (cross-platform) with optional nmap fallback.
"""

import socket
import concurrent.futures
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

THREADS = 100
TIMEOUT = 1.5

# Common ports + their service names
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


# ─── Pure Python socket scan ───────────────────────────────────────────────────

def scan_port(ip: str, port: int) -> dict | None:
    """Attempt TCP connection to a port. Returns result dict if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = grab_banner(ip, port)
                return {
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "state": "open"
                }
    except Exception:
        pass
    return None


def grab_banner(ip: str, port: int) -> str:
    """Try to grab a service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((ip, port))
            # Send HTTP request for web ports
            if port in (80, 8080, 8888):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:200] if banner else ""
    except Exception:
        return ""


def scan_host(ip: str, ports: list = None) -> list:
    """Scan all common ports on a given IP using threading."""
    ports = ports or list(COMMON_PORTS.keys())
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


# ─── Optional nmap fallback ────────────────────────────────────────────────────

def scan_with_nmap(ip: str) -> list:
    """Use python-nmap if available for more accurate results."""
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sV --open -T4 --top-ports 100")
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    info = nm[host][proto][port]
                    if info["state"] == "open":
                        results.append({
                            "port": port,
                            "service": info.get("name", "Unknown"),
                            "banner": info.get("product", "") + " " + info.get("version", ""),
                            "state": "open"
                        })
        return results
    except ImportError:
        return None
    except Exception as e:
        console.print(f"[yellow][!] nmap scan failed: {e}, falling back to socket scan[/yellow]")
        return None


# ─── Main entry ───────────────────────────────────────────────────────────────

def scan_subdomains(subdomains: list, use_nmap: bool = False) -> dict:
    """
    Scan ports for all discovered subdomains.
    Returns dict: { "subdomain": { "ip": ..., "ports": [...] } }
    """
    console.print(f"\n[bold cyan][*] Starting port scan on {len(subdomains)} hosts...[/bold cyan]")
    results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan]Scanning ports...[/cyan]"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("ports", total=len(subdomains))

        for entry in subdomains:
            sub = entry["subdomain"]
            ip = entry["ip"]

            # Try nmap first if requested
            ports = None
            if use_nmap:
                ports = scan_with_nmap(ip)

            # Fallback to socket scan
            if ports is None:
                ports = scan_host(ip)

            results[sub] = {
                "ip": ip,
                "ports": ports
            }
            progress.advance(task)

    total_open = sum(len(v["ports"]) for v in results.values())
    console.print(f"[bold green][✓] Port scan complete — {total_open} open ports found[/bold green]")
    return results
