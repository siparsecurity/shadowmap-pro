"""
ShadowMap - Module 3: Technology Fingerprinting
Detects CMS, frameworks, server software from HTTP headers & paths.
"""

import hashlib
import random
import string
import requests
import concurrent.futures
from rich.console import Console

console = Console()

TIMEOUT = 5
THREADS = 20

# Same soft-404 tolerance used in vuln_hints.py — see get_baseline() below.
LENGTH_DIFF_THRESHOLD = 0.15

# ─── Fingerprint signatures ────────────────────────────────────────────────────

CMS_PATHS = {
    "WordPress":   ["/wp-login.php", "/wp-admin/", "/wp-content/"],
    "Joomla":      ["/administrator/", "/components/", "/modules/"],
    "Drupal":      ["/user/login", "/sites/default/", "/core/misc/drupal.js"],
    "Magento":     ["/admin/", "/skin/frontend/", "/js/mage/"],
    "PrestaShop":  ["/admin123/", "/themes/classic/"],
    "OpenCart":    ["/admin/view/", "/catalog/view/theme/"],
    "Laravel":     ["/vendor/laravel/", "/.env"],
    "Django":      ["/admin/login/", "/static/admin/"],
    "Symfony":     ["/app.php", "/app_dev.php", "/bundles/"],
}

HEADER_SIGNATURES = {
    "Server": {
        "Apache":  "Apache",
        "Nginx":   "nginx",
        "IIS":     "Microsoft-IIS",
        "Caddy":   "Caddy",
        "LiteSpeed": "LiteSpeed",
        "Gunicorn": "gunicorn",
    },
    "X-Powered-By": {
        "PHP":         "PHP",
        "ASP.NET":     "ASP.NET",
        "Express.js":  "Express",
        "Next.js":     "Next.js",
    },
    "X-Generator": {
        "WordPress":   "WordPress",
        "Drupal":      "Drupal",
    },
    "X-Drupal-Cache": {
        "Drupal": "",
    },
    "X-WP-Nonce": {
        "WordPress": "",
    },
}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


# ─── Core fingerprinting ───────────────────────────────────────────────────────

def get_http_response(url: str) -> requests.Response | None:
    """Fetch a URL silently, return response or None."""
    try:
        resp = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (ShadowMap/1.0)"}
        )
        return resp
    except Exception:
        return None


def detect_from_headers(headers: dict) -> dict:
    """Detect technologies from HTTP response headers."""
    detected = {}
    for header, sigs in HEADER_SIGNATURES.items():
        value = headers.get(header, "")
        if not value and header in headers:
            # Header exists but empty — mark as present
            for tech in sigs:
                detected[tech] = "detected (header present)"
        for tech, pattern in sigs.items():
            if pattern and pattern.lower() in value.lower():
                detected[tech] = value.strip()
    return detected


def detect_missing_security_headers(headers: dict) -> list:
    """Return list of missing security headers."""
    missing = []
    for h in SECURITY_HEADERS:
        if h not in headers:
            missing.append(h)
    return missing


def _random_path() -> str:
    """Generate a random, near-certainly-nonexistent path segment."""
    junk = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return f"/{junk}-shadowmap-nonexistent"


def get_baseline(base_url: str) -> dict | None:
    """
    Request a random nonexistent path on this host to learn what its
    'not found' response looks like. Many hosts (SPAs, CDNs, catch-all
    routers) return HTTP 200/301/302/403 for ANY path — without this
    baseline, detect_cms_by_paths() below would misidentify almost every
    CMS on almost every such host.
    """
    url = base_url.rstrip("/") + _random_path()
    try:
        resp = requests.get(
            url, timeout=TIMEOUT, verify=False,
            headers={"User-Agent": "Mozilla/5.0 (ShadowMap/1.0)"},
            allow_redirects=False
        )
        body = resp.text or ""
        return {
            "status_code": resp.status_code,
            "length": len(body),
            "hash": hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest(),
        }
    except Exception:
        return None


def _looks_like_baseline(resp: requests.Response, baseline: dict | None) -> bool:
    """Decide whether a response is just the host's generic catch-all page."""
    if not baseline:
        return False

    if resp.status_code != baseline["status_code"]:
        return False

    body = resp.text or ""
    body_hash = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()

    if body_hash == baseline["hash"]:
        return True

    if baseline["length"] > 0:
        diff_ratio = abs(len(body) - baseline["length"]) / baseline["length"]
        if diff_ratio <= LENGTH_DIFF_THRESHOLD:
            return True

    return False


def detect_cms_by_paths(base_url: str) -> list:
    """Check known CMS paths to fingerprint the CMS, filtering out soft-404s."""
    detected = []
    baseline = get_baseline(base_url)

    for cms, paths in CMS_PATHS.items():
        for path in paths:
            url = base_url.rstrip("/") + path
            try:
                resp = requests.get(
                    url, timeout=TIMEOUT, verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (ShadowMap/1.0)"},
                    allow_redirects=False
                )
                if resp.status_code in (200, 301, 302, 403):
                    if _looks_like_baseline(resp, baseline):
                        continue  # same as the nonexistent-path response — not a real hit
                    detected.append({"cms": cms, "path": path, "status": resp.status_code})
                    break  # One hit per CMS is enough
            except Exception:
                continue
    return detected


def fingerprint_host(subdomain: str, ports: list) -> dict:
    """
    Full fingerprinting for a single host.
    Tries HTTPS first, falls back to HTTP.
    """
    result = {
        "technologies": {},
        "cms": [],
        "missing_security_headers": [],
        "raw_headers": {}
    }

    # Determine base URLs from open ports
    base_urls = []
    port_nums = [p["port"] for p in ports]

    if 443 in port_nums:
        base_urls.append(f"https://{subdomain}")
    if 80 in port_nums:
        base_urls.append(f"http://{subdomain}")
    if 8443 in port_nums:
        base_urls.append(f"https://{subdomain}:8443")
    if 8080 in port_nums:
        base_urls.append(f"http://{subdomain}:8080")

    if not base_urls:
        # No web ports — skip
        return result

    base_url = base_urls[0]
    resp = get_http_response(base_url)

    if not resp:
        # Try fallback
        if len(base_urls) > 1:
            resp = get_http_response(base_urls[1])

    if not resp:
        return result

    headers = dict(resp.headers)
    result["raw_headers"] = headers
    result["technologies"] = detect_from_headers(headers)
    result["missing_security_headers"] = detect_missing_security_headers(headers)
    result["cms"] = detect_cms_by_paths(base_url)
    result["base_url"] = base_url

    return result


# ─── Main entry ───────────────────────────────────────────────────────────────

def fingerprint_all(scan_results: dict) -> dict:
    """
    Fingerprint all scanned hosts.
    scan_results: { subdomain: { ip, ports } }
    Returns: { subdomain: { ...fingerprint data } }
    """
    console.print(f"\n[bold cyan][*] Fingerprinting technologies on {len(scan_results)} hosts...[/bold cyan]")

    fp_results = {}

    def _fp(item):
        sub, data = item
        return sub, fingerprint_host(sub, data["ports"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = list(executor.map(_fp, scan_results.items()))

    for sub, fp in futures:
        fp_results[sub] = fp

    total_tech = sum(len(v["technologies"]) for v in fp_results.values())
    total_cms = sum(len(v["cms"]) for v in fp_results.values())
    console.print(f"[bold green][✓] Fingerprinting done — {total_tech} technologies, {total_cms} CMS hits detected[/bold green]")
    return fp_results
