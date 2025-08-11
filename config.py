#!/usr/bin/env python3
"""
Detective Joe (DJ) - Configuration File
Tool command mappings for different investigation categories.
Each tool command uses {target} placeholder which will be replaced with user input.
"""

# Tool configurations for different investigation types
TOOLS = {
    "website": [
        {"name": "Whois", "cmd": "whois {target}"},
        {"name": "DNSRecon", "cmd": "dnsrecon -d {target}"},
        {"name": "Dig", "cmd": "dig {target} ANY +noall +answer"},
        {"name": "DNS A Record", "cmd": "dig {target} A +short"},
        {"name": "DNS MX Record", "cmd": "dig {target} MX +short"},
        {"name": "DNS NS Record", "cmd": "dig {target} NS +short"},
        {"name": "TheHarvester", "cmd": "theHarvester -d {target} -b all"},
        {"name": "Sublist3r", "cmd": "sublist3r -d {target}"},
        {"name": "Amass", "cmd": "amass enum -d {target}"},
        {"name": "Wafw00f", "cmd": "wafw00f {target}"},
        {"name": "WhatWeb", "cmd": "whatweb {target}"},
        {"name": "Nikto", "cmd": "nikto -h {target}"},
        {"name": "Dirb", "cmd": "dirb http://{target}"},
        {"name": "SSLScan", "cmd": "sslscan {target}"},
        {"name": "Nmap", "cmd": "nmap -A {target}"}
    ],
    
    "organisation": [
        {"name": "TheHarvester", "cmd": "theHarvester -d {target} -b all"},
        {"name": "DNSRecon", "cmd": "dnsrecon -d {target}"},
        {"name": "Amass", "cmd": "amass enum -d {target}"},
        {"name": "Sublist3r", "cmd": "sublist3r -d {target}"},
        {"name": "Certificate Transparency", "cmd": "curl -s 'https://crt.sh/?q={target}&output=json' | jq -r '.[].name_value' | sort -u"},
        {"name": "Nmap", "cmd": "nmap -A {target}"},
        {"name": "Recon-ng", "cmd": "echo 'use recon/domains-hosts/hackertarget\\nset SOURCE {target}\\nrun\\nexit' | recon-ng"},
        {"name": "Shodan CLI", "cmd": "shodan search {target}"}
    ],
    
    "people": [
        {"name": "TheHarvester", "cmd": "theHarvester -d {target} -b all"},
        {"name": "Sherlock", "cmd": "sherlock {target}"},
        {"name": "Googler", "cmd": "googler -n 10 '{target}'"},
        {"name": "ExifTool", "cmd": "exiftool {target}"},
        {"name": "Socialscan", "cmd": "socialscan {target}"},
        {"name": "WhitePages", "cmd": "curl -s 'https://www.whitepages.com/name/{target}' | grep -i 'phone\\|address\\|email'"}
    ],
    
    "ip_server": [
        {"name": "Whois", "cmd": "whois {target}"},
        {"name": "GeoIP Lookup", "cmd": "geoiplookup {target}"},
        {"name": "Nmap", "cmd": "nmap -A {target}"},
        {"name": "SSLScan", "cmd": "sslscan {target}"},
        {"name": "WhatWeb", "cmd": "whatweb {target}"},
        {"name": "Traceroute", "cmd": "traceroute {target}"},
        {"name": "Ping Test", "cmd": "ping -c 4 {target}"},
        {"name": "Hping3", "cmd": "hping3 -c 5 {target}"},
        {"name": "Reverse DNS", "cmd": "dig -x {target}"},
        {"name": "Port Scan", "cmd": "nmap -sS -O {target}"}
    ]
}

# Investigation type mappings
INVESTIGATION_TYPES = {
    "1": {"name": "Website Investigation", "key": "website"},
    "2": {"name": "Organisation Investigation", "key": "organisation"},
    "3": {"name": "People Investigation", "key": "people"},
    "4": {"name": "IP / Server Investigation", "key": "ip_server"}
}

# Optional tools that might not be available on all systems
OPTIONAL_TOOLS = [
    "sherlock",
    "socialscan", 
    "shodan",
    "geoiplookup",
    "recon-ng"
]

# Tools that require special handling or API keys
API_DEPENDENT_TOOLS = [
    "shodan",
    "hunter.io",
    "pipl"
]