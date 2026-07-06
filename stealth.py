"""
ShadowMap - Stealth Module
Rotating user-agents, random delays, WAF evasion headers
by Sipar Security
"""

import time
import random
import requests
from rich.console import Console

console = Console()


# ─── User-Agent pool ──────────────────────────────────────────────────────────

USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    # Mobile Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
]

# Referrers to spoof — looks like organic traffic
REFERRERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.yahoo.com/",
    "",  # No referrer (direct)
    "",
    "",  # Weight toward no-referrer
]

# Accept-Language headers — variety looks human
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,es;q=0.8",
    "en-US,en;q=0.8,fr;q=0.6",
    "en-US,en;q=0.9,de;q=0.8",
]


# ─── Stealth config ───────────────────────────────────────────────────────────

class StealthConfig:
    """Holds stealth settings for the current scan session."""

    def __init__(self, level: str = "low"):
        """
        level:
          "off"    — no stealth, fast, obvious
          "low"    — rotate user-agents only, minimal delay
          "medium" — rotate UA + referrer, 0.5-2s delay
          "high"   — full rotation + 2-5s delay + extra headers
        """
        self.level = level
        self._ua_index = 0

    def get_headers(self) -> dict:
        """Generate a realistic-looking header set based on stealth level."""
        if self.level == "off":
            return {"User-Agent": "ShadowMap/1.0 (Sipar Security)"}

        ua = random.choice(USER_AGENTS)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

        if self.level in ("medium", "high"):
            ref = random.choice(REFERRERS)
            if ref:
                headers["Referer"] = ref

        if self.level == "high":
            headers.update({
                "Cache-Control": "max-age=0",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": random.choice(["none", "cross-site"]),
                "Sec-Fetch-User": "?1",
                "DNT": "1",
            })

        return headers

    def delay(self):
        """Sleep for a random duration based on stealth level."""
        if self.level == "off":
            return
        elif self.level == "low":
            time.sleep(random.uniform(0.1, 0.5))
        elif self.level == "medium":
            time.sleep(random.uniform(0.5, 2.0))
        elif self.level == "high":
            time.sleep(random.uniform(2.0, 5.0))

    def get_threads(self, default: int) -> int:
        """Reduce thread count based on stealth level to avoid detection."""
        multipliers = {"off": 1.0, "low": 0.8, "medium": 0.4, "high": 0.15}
        return max(1, int(default * multipliers.get(self.level, 1.0)))

    @property
    def is_active(self) -> bool:
        return self.level != "off"


# ─── Stealth-aware request ────────────────────────────────────────────────────

def stealth_get(url: str, config: StealthConfig, timeout: int = 5, **kwargs) -> requests.Response | None:
    """Make an HTTP GET request with stealth headers and delay."""
    config.delay()
    try:
        resp = requests.get(
            url,
            headers=config.get_headers(),
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            **kwargs
        )
        return resp
    except Exception:
        return None


# ─── Global stealth instance ──────────────────────────────────────────────────

# Default — overridden by main.py based on --stealth flag
_config = StealthConfig("off")


def init_stealth(level: str = "off"):
    """Initialize global stealth config. Call once from main.py."""
    global _config
    _config = StealthConfig(level)
    if level != "off":
        console.print(f"[bold yellow][*] Stealth mode:[/bold yellow] [yellow]{level.upper()}[/yellow] — rotating user-agents, {'random delays enabled' if level != 'low' else 'minimal delays'}")


def get_stealth_config() -> StealthConfig:
    """Get the global stealth config instance."""
    return _config
