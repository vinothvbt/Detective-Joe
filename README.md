# Detective Joe (DJ) — v1 Kali-Only Recon Overkill

## 📌 Overview
Detective Joe (**DJ**) is an **automated recon assistant** built for Kali Linux.  
Instead of running individual tools one by one, DJ **chains all the relevant OSINT & recon tools**, executes them in sequence, and merges the results into a **single readable report**.  

**Think of DJ as your personal recon operator** — you say the target once, it handles the rest.

---

## 🚀 Features
- **Four powerful investigation categories:**
  - 🌐 Website Investigation
  - 🏢 Organisation Investigation
  - 👤 People Investigation
  - 🖥️ IP / Server Investigation
- **Overkill Mode:** Runs *all* relevant Kali tools for max intel
- **Single consolidated TXT report**
- **Config-driven:** Easily add/remove tools in `config.py`
- Minimal interaction — more time for analysis, less typing

---

## 🛠️ Built-in Tool Coverage (Kali Preinstalled)
**Website Investigation:**
- whois
- dnsrecon
- dig
- theHarvester
- sublist3r
- amass
- wafw00f
- whatweb
- nikto
- dirb
- sslscan
- nmap

**Organisation Investigation:**
- theHarvester
- recon-ng
- dnsrecon
- amass
- sublist3r
- crt.sh query (curl)
- hunter.io (if API key)
- nmap
- shodan CLI (if API key)

**People Investigation:**
- theHarvester
- sherlock (optional v2 plugin)
- googler
- exiftool
- pipl API (if available)
- socialscan

**IP / Server Investigation:**
- whois
- geoiplookup
- nmap
- sslscan
- whatweb
- traceroute
- hping3
- tcpdump

---

## 📂 Project Structure
```
detective-joe/
│
├── detectivejoe.py   # Main CLI script
├── config.py         # Tool command mapping
├── reports/          # Generated recon reports
└── README.md         # Documentation
```

---

## 📥 Installation
```bash
git clone https://github.com/<your-username>/detective-joe.git
cd detective-joe
chmod +x detectivejoe.py
```

---

## ▶️ Usage
Run DJ:
```bash
python3 detectivejoe.py
```

Example Session:
```
==============================
   DETECTIVE JOE v1 — Kali
==============================

[1] Website Investigation
[2] Organisation Investigation
[3] People Investigation
[4] IP / Server Investigation

Select: 1
Enter target domain: example.com

[+] Running WHOIS...
[+] Running DNSRecon...
[+] Running TheHarvester...
...
[✓] Report saved: reports/example.com_2025-08-11.txt
```

---

## ⚙️ Configuration
All tool commands are stored in **config.py**:
```python
TOOLS = {
    "website": [
        {"name": "Whois", "cmd": "whois {target}"},
        {"name": "DNSRecon", "cmd": "dnsrecon -d {target}"},
        {"name": "Dig", "cmd": "dig {target} ANY +noall +answer"},
        {"name": "TheHarvester", "cmd": "theHarvester -d {target} -b all"},
        {"name": "Sublist3r", "cmd": "sublist3r -d {target}"},
        {"name": "Amass", "cmd": "amass enum -d {target}"},
        {"name": "Wafw00f", "cmd": "wafw00f {target}"},
        {"name": "WhatWeb", "cmd": "whatweb {target}"},
        {"name": "Nikto", "cmd": "nikto -h {target}"},
        {"name": "Dirb", "cmd": "dirb http://{target}"},
        {"name": "SSLScan", "cmd": "sslscan {target}"},
        {"name": "Nmap", "cmd": "nmap -A {target}"}
    ]
}
```
- `{target}` will be replaced with the user input.
- Add/remove tools to customize scans.

---

## 📄 Output
Reports are stored in:
```
reports/<target>_<timestamp>.txt
```
Each section is labeled with the **tool name** and separated for easy reading.

---

## ⚠️ Legal Disclaimer
This tool is intended for:
- Educational purposes
- Authorized penetration testing
- OSINT research

**Unauthorized use of DJ against systems you do not own or have explicit permission to test is illegal** and may result in criminal charges.

---

## 🛣️ Roadmap
- **v1:** Kali-only tools (current release)
- **v2:** External plugins (Sherlock, Shodan, etc.)
- **v3:** API integrations & optional GUI

---

## 💡 Author
Created by: **[Your Name / Handle]**
