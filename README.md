# Detective Joe (DJ) — v1 Kali-Only Recon Overkill

## Overview
Detective Joe (**DJ**) is an automated recon assistant for Kali Linux.  
It chains multiple preinstalled OSINT and recon tools, runs them in sequence, and merges all results into a single, clean report.  
No more switching tools manually — enter your target once and DJ does the heavy lifting.

---

## Features
- **Category-based scanning**
  - Website Investigation
  - Organisation Investigation
  - People Investigation
  - IP / Server Investigation
- **Overkill mode** — runs *all* relevant Kali tools in one pass
- **Single report output** in `reports/` directory
- **Config-driven** — add/remove tools without editing core code
- Minimal interaction, maximum data

---

## Requirements
- **Kali Linux** (recommended) — preinstalled tools like:
  - whois, dnsrecon, dig, theHarvester, sublist3r, amass, wafw00f, whatweb, nikto, dirb, sslscan, nmap, geoiplookup, traceroute, hping3, tcpdump
- Python 3.x
- Permissions for network scans (root for some tools)

---

## Installation
```bash
git clone https://github.com/<your-username>/detective-joe.git
cd detective-joe
chmod +x detectivejoe.py
