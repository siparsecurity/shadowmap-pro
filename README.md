# ShadowMap 🔍

**A professional web reconnaissance tool by [Sipar Security](https://github.com/SiparSecurity)**

> For authorized penetration testing and bug bounty research only. Always have written permission before scanning any target.

---

## Features

| Module | What it does |
|--------|-------------|
| 🌐 DNS Recon | Zone transfer attempts + NS/MX/TXT record enumeration |
| 🔍 Subdomain Enumeration | Passive (crt.sh) + Active brute-force with threading |
| 🔌 Port & Service Scanner | Pure Python sockets (cross-platform) + optional nmap |
| 🧬 Tech Fingerprinting | CMS detection, server software, framework identification |
| ⚠️ Vuln Hints | Exposed .git, .env, misconfigs, missing security headers |
| 🕵️ Stealth Mode | Rotating user-agents, random delays, WAF evasion |
| 📤 JSON Output | Machine-readable results for automation/integrations |
| 📄 HTML Report | Clean dark-themed report ready for bug bounty submissions |

---

## Installation

```bash
git clone https://github.com/SiparSecurity/shadowmap.git
cd shadowmap
pip install -r requirements.txt
```

### Optional: Install nmap (for better port scanning)
```bash
# Linux
sudo apt install nmap

# macOS
brew install nmap

# Windows: download from https://nmap.org/download.html
```

---

## Usage

```bash
# Basic scan
python3 main.py --domain example.com

# With nmap (more accurate port scanning)
python3 main.py --domain example.com --nmap

# Stealth mode (low / medium / high)
python3 main.py --domain example.com --stealth medium

# Save HTML + JSON reports
python3 main.py --domain example.com --json --output /home/user/reports

# Skip specific modules
python3 main.py --domain example.com --skip-ports
python3 main.py --domain example.com --skip-dns --skip-fp --skip-vuln

# Full stealth, nmap, JSON output
python3 main.py --domain example.com --nmap --stealth high --json
```

## Flags

| Flag | Description |
|------|-------------|
| `--domain` | Target domain (required) |
| `--nmap` | Use nmap for port scanning |
| `--stealth` | Stealth level: off / low / medium / high |
| `--json` | Also save results as JSON |
| `--output` | Output directory for reports |
| `--skip-dns` | Skip DNS recon & zone transfer |
| `--skip-ports` | Skip port scanning |
| `--skip-fp` | Skip technology fingerprinting |
| `--skip-vuln` | Skip vulnerability hints |

---

## Output

```
[*] Starting subdomain enumeration for: example.com
[+] crt.sh found 8 subdomains
[+] 6 passive subdomains are live
[+] Brute-force found 3 live subdomains
[✓] Total unique live subdomains: 9

[*] Starting port scan on 9 hosts...
[✓] Port scan complete — 24 open ports found

[*] Fingerprinting technologies on 9 hosts...
[✓] Fingerprinting done — 12 technologies detected

[*] Checking for common misconfigurations...
  [HIGH] dev.example.com — Git repository exposed
  [CRITICAL] staging.example.com — .env file exposed
[✓] Vuln hints complete — 7 findings flagged

[✓] Report saved: example_com_recon_20240115_143022.html
✅ ShadowMap complete!
```

---

## File Structure

```
shadowmap/
├── main.py              # CLI entry point
├── subdomain_enum.py    # Module 1 — Subdomain Enumeration
├── port_scanner.py      # Module 2 — Port & Service Scanning
├── tech_fingerprint.py  # Module 3 — Technology Fingerprinting
├── vuln_hints.py        # Module 4 — Vulnerability Hints
├── report_generator.py  # Module 5 — Report Generator
├── wordlists/
│   └── subdomains.txt   # Built-in subdomain wordlist
├── templates/
│   └── report.html      # Jinja2 report template
├── requirements.txt
└── README.md
```

---

## Legal Disclaimer

This tool is intended for **authorized security testing only**. The author (Sipar Security) is not responsible for any misuse or illegal activity conducted with this tool. Always obtain written permission before scanning any system you do not own.

---

*Built by Sayed Muhammad Subayyal — Sipar Security*
