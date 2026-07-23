"""
ShadowMap - Module 3: Technology Fingerprinting
Detects CMS, frameworks, server software from HTTP headers & paths.
"""

import hashlib
import random
import string
import requests
import threading
import concurrent.futures
from rich.console import Console

console = Console()

TIMEOUT = 5
THREADS = 20

# Hard wall-clock budget for fingerprinting a single host, end to end
# (baseline probe + header fetch + all CMS path checks combined).
# requests' `timeout=` does NOT bound total request time for a slow-trickle
# response — it only resets a per-chunk read timer — so a single unlucky
# host can otherwise block forever. This deadline is enforced independently
# of what's happening inside the request itself (see fingerprint_host_bounded).
PER_HOST_TIMEOUT = 30

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

# Module-level flag so we only print the fallback warning once per run,
# not once per host (would be spammy on a 186-host scan).
_fallback_warned = False


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

    if baseline is None:
        # The random-path probe itself failed (timeout / connection error /
        # TLS failure). The host is unresponsive or unreachable on this
        # base_url, so the real CMS paths below will almost certainly fail
        # the same way. Previously we'd still burn up to 27 more requests
        # (9 CMS x up to 3 paths), each eating a full TIMEOUT-second wait,
        # per host — that's what caused runs to look "stuck" on large
        # brute-forced subdomain lists full of dead/filtered hosts.
        return detected

    # Reuse one connection across all path checks for this host instead of
    # opening a fresh TCP/TLS handshake per request — meaningfully faster
    # across ~27 requests per host.
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (ShadowMap/1.0)"})

    for cms, paths in CMS_PATHS.items():
        for path in paths:
            url = base_url.rstrip("/") + path
            try:
                resp = session.get(
                    url, timeout=TIMEOUT, verify=False,
                    allow_redirects=False
                )
                if resp.status_code in (200, 301, 302, 403):
                    if _looks_like_baseline(resp, baseline):
                        continue  # same as the nonexistent-path response — not a real hit
                    detected.append({"cms": cms, "path": path, "status": resp.status_code})
                    break  # One hit per CMS is enough
            except Exception:
                continue

    session.close()
    return detected


def _build_base_urls(subdomain: str, ports: list) -> list:
    """
    Build candidate base URLs for a host from its known open ports.
    Returns [] if no web-relevant ports are known.
    """
    base_urls = []
    port_nums = [p["port"] for p in (ports or [])]

    if 443 in port_nums:
        base_urls.append(f"https://{subdomain}")
    if 80 in port_nums:
        base_urls.append(f"http://{subdomain}")
    if 8443 in port_nums:
        base_urls.append(f"https://{subdomain}:8443")
    if 8080 in port_nums:
        base_urls.append(f"http://{subdomain}:8080")

    return base_urls


def fingerprint_host(subdomain: str, ports: list) -> dict:
    """
    Full fingerprinting for a single host.
    Tries HTTPS first, falls back to HTTP.

    If `ports` is empty (e.g. port scanning was skipped with --skip-ports,
    or the port scanner simply didn't run on this host), this now falls
    back to probing https:// then http:// directly on default ports,
    instead of silently skipping the host. Previously an empty `ports`
    list caused base_urls to stay empty and fingerprint_host() returned
    an all-empty result with no warning — which is why a full
    --skip-ports run reported 0 technologies / 0 CMS hits across every
    single host, not because detection failed, but because it never ran.
    """
    global _fallback_warned

    result = {
        "technologies": {},
        "cms": [],
        "missing_security_headers": [],
        "raw_headers": {}
    }

    base_urls = _build_base_urls(subdomain, ports)
    used_fallback = False

    if not base_urls:
        # No port data available — fall back to probing defaults directly
        # rather than skipping the host outright.
        base_urls = [f"https://{subdomain}", f"http://{subdomain}"]
        used_fallback = True
        if not _fallback_warned:
            console.print(
                "[yellow][!] No port data available for one or more hosts "
                "(port scan skipped or empty) — falling back to direct "
                "https/http probing on default ports for fingerprinting.[/yellow]"
            )
            _fallback_warned = True

    resp = None
    working_base_url = None
    for candidate in base_urls:
        resp = get_http_response(candidate)
        if resp:
            working_base_url = candidate
            break

    if not resp:
        # Genuinely unreachable on any candidate — not a bug, just a dead host
        # (or one on a nonstandard port we didn't try). Record that fact
        # instead of returning an indistinguishable empty result.
        result["fingerprint_status"] = "unreachable"
        result["fallback_used"] = used_fallback
        return result

    headers = dict(resp.headers)
    result["raw_headers"] = headers
    result["technologies"] = detect_from_headers(headers)
    result["missing_security_headers"] = detect_missing_security_headers(headers)
    result["cms"] = detect_cms_by_paths(working_base_url)
    result["base_url"] = working_base_url
    result["fallback_used"] = used_fallback
    result["fingerprint_status"] = "ok"

    return result


def _default_result() -> dict:
    return {
        "technologies": {},
        "cms": [],
        "missing_security_headers": [],
        "raw_headers": {},
    }


def fingerprint_host_bounded(subdomain: str, ports: list, deadline: float = PER_HOST_TIMEOUT) -> dict:
    """
    Run fingerprint_host() with a hard wall-clock deadline, independent of
    whatever requests/urllib3 is doing internally.

    requests' timeout=N does not bound total time for a slow-trickling
    response (the read timer resets on every successful chunk), so a
    single unlucky host can block the calling thread indefinitely. To
    guard against that, the actual work runs in its own daemon thread;
    we wait up to `deadline` seconds for it, and if it hasn't finished,
    we simply give up on it and move on.

    Because the sub-thread is daemon=True, an abandoned/stuck thread can
    NEVER block program exit — unlike ThreadPoolExecutor's own worker
    threads, which are non-daemon and which Python's interpreter shutdown
    will wait on forever via an atexit join (this was the actual cause of
    runs hanging even after Ctrl-C).
    """
    holder = {}

    def _run():
        holder["result"] = fingerprint_host(subdomain, ports)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=deadline)

    if t.is_alive():
        # Still running — abandon it. It will keep running in the
        # background (harmless, and can never block exit since it's
        # daemon), but we don't wait on it any further.
        result = _default_result()
        result["fingerprint_status"] = "timed_out"
        result["fallback_used"] = False
        return result

    return holder.get("result", {**_default_result(), "fingerprint_status": "error"})


# ─── Main entry ───────────────────────────────────────────────────────────────

def fingerprint_all(scan_results: dict) -> dict:
    """
    Fingerprint all scanned hosts.
    scan_results: { subdomain: { ip, ports } }
    Returns: { subdomain: { ...fingerprint data } }
    """
    global _fallback_warned
    _fallback_warned = False  # reset per run so the warning can show again next time

    console.print(f"\n[bold cyan][*] Fingerprinting technologies on {len(scan_results)} hosts...[/bold cyan]")

    fp_results = {}

    def _fp(item):
        sub, data = item
        return sub, fingerprint_host_bounded(sub, data.get("ports"))

    # Each _fp call is now guaranteed to return within PER_HOST_TIMEOUT no
    # matter what happens inside fingerprint_host, so the outer pool's own
    # worker threads can never hang either — safe to let the context
    # manager wait for a clean shutdown.
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = list(executor.map(_fp, scan_results.items()))

    for sub, fp in futures:
        fp_results[sub] = fp

    total_tech = sum(len(v["technologies"]) for v in fp_results.values())
    total_cms = sum(len(v["cms"]) for v in fp_results.values())
    unreachable = sum(1 for v in fp_results.values() if v.get("fingerprint_status") == "unreachable")
    timed_out = sum(1 for v in fp_results.values() if v.get("fingerprint_status") == "timed_out")
    fallback_count = sum(1 for v in fp_results.values() if v.get("fallback_used"))

    console.print(f"[bold green][✓] Fingerprinting done — {total_tech} technologies, {total_cms} CMS hits detected[/bold green]")
    if fallback_count:
        console.print(f"[dim]    ({fallback_count} hosts fingerprinted via https/http fallback due to missing port data)[/dim]")
    if unreachable:
        console.print(f"[dim]    ({unreachable} hosts unreachable on any probed port)[/dim]")
    if timed_out:
        console.print(f"[yellow]    ({timed_out} hosts exceeded the {PER_HOST_TIMEOUT}s per-host fingerprint budget and were skipped)[/yellow]")

    return fp_results
