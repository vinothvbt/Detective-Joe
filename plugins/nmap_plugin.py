#!/usr/bin/env python3
"""
Detective Joe v1.5 - Nmap Plugin
Network scanning plugin using Nmap for port discovery and service detection.
"""

import re
from typing import Dict, Any, List
from .base import PluginBase


class NmapPlugin(PluginBase):
    """
    Nmap plugin for network reconnaissance.
    
    Supports different scan types based on investigation category:
    - Website: Service detection and basic port scan
    - Organisation: Comprehensive network mapping
    - IP/Server: Detailed host analysis
    """
    
    def __init__(self):
        super().__init__("nmap", "1.0")
        
    @property
    def tool_name(self) -> str:
        return "nmap"
    
    @property
    def categories(self) -> List[str]:
        return ["website", "organisation", "ip_server"]
    
    @property
    def required_tools(self) -> List[str]:
        return ["nmap"]
    
    def build_command(self, target: str, category: str, **kwargs) -> str:
        """
        Build Nmap command based on category and target.
        
        Args:
            target: Target host/domain
            category: Investigation category
            **kwargs: Additional options (scan_type, ports, etc.)
            
        Returns:
            Nmap command string
        """
        scan_type = kwargs.get('scan_type', 'default')
        
        # Base command
        cmd = "nmap"
        
        # Category-specific scanning profiles
        if category == "website":
            if scan_type == "basic":
                cmd += f" -sV -sC --top-ports 1000 {target}"
            else:
                cmd += f" -sV -sC -A --top-ports 1000 {target}"
                
        elif category == "organisation":
            if scan_type == "basic":
                cmd += f" -sS --top-ports 100 {target}"
            else:
                cmd += f" -sS -sV -O --top-ports 1000 {target}"
                
        elif category == "ip_server":
            if scan_type == "basic":
                cmd += f" -sS -sV --top-ports 1000 {target}"
            else:
                cmd += f" -sS -sV -sC -A -O {target}"
        
        # Add custom ports if specified
        if 'ports' in kwargs:
            ports = kwargs['ports']
            cmd = cmd.replace('--top-ports 1000', f'-p {ports}')
            cmd = cmd.replace('--top-ports 100', f'-p {ports}')
        
        # Add timing template
        timing = kwargs.get('timing', 'T4')
        cmd += f" -{timing}"
        
        # Additional flags
        if kwargs.get('aggressive', False):
            cmd += " -A"
        
        if kwargs.get('no_ping', False):
            cmd += " -Pn"
            
        if kwargs.get('script', None):
            cmd += f" --script={kwargs['script']}"
        
        return cmd
    
    def parse_output(self, output: str, target: str, category: str) -> Dict[str, Any]:
        """
        Parse Nmap output into structured data.
        
        Args:
            output: Raw Nmap output
            target: Target that was scanned
            category: Investigation category
            
        Returns:
            Parsed Nmap data
        """
        parsed = {
            "target": target,
            "category": category,
            "hosts": [],
            "open_ports": [],
            "services": [],
            "os_info": {},
            "scripts": [],
            "scan_stats": {}
        }
        
        if not output:
            return parsed
        
        lines = output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Host discovery
            if line.startswith("Nmap scan report for"):
                host_match = re.search(r'Nmap scan report for (.+)', line)
                if host_match:
                    current_host = host_match.group(1)
                    parsed["hosts"].append(current_host)
            
            # Open ports
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(.+)', line)
            if port_match:
                port_info = {
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": port_match.group(3),
                    "service": port_match.group(4),
                    "host": current_host
                }
                parsed["open_ports"].append(port_info)
                
                if port_match.group(3) == "open":
                    parsed["services"].append({
                        "port": int(port_match.group(1)),
                        "service": port_match.group(4),
                        "host": current_host
                    })
            
            # OS detection
            if "OS details:" in line:
                os_info = line.replace("OS details:", "").strip()
                parsed["os_info"]["details"] = os_info
            
            if "Running:" in line:
                running_info = line.replace("Running:", "").strip()
                parsed["os_info"]["running"] = running_info
            
            # Script results
            if line.startswith("|"):
                script_line = line[1:].strip()
                if script_line:
                    parsed["scripts"].append(script_line)
            
            # Scan statistics
            if "Nmap done:" in line:
                stats_match = re.search(r'(\d+) IP address.*scanned in ([\d.]+) seconds', line)
                if stats_match:
                    parsed["scan_stats"] = {
                        "hosts_scanned": int(stats_match.group(1)),
                        "scan_time": float(stats_match.group(2))
                    }
        
        # Summary statistics
        parsed["summary"] = {
            "total_hosts": len(parsed["hosts"]),
            "total_open_ports": len([p for p in parsed["open_ports"] if p["state"] == "open"]),
            "total_services": len(parsed["services"]),
            "has_os_info": bool(parsed["os_info"]),
            "script_count": len(parsed["scripts"])
        }
        
        return parsed
    
    def validate_target(self, target: str, category: str) -> bool:
        """
        Validate target for Nmap scanning.
        
        Args:
            target: Target to validate
            category: Investigation category
            
        Returns:
            True if target is valid for Nmap
        """
        if not target or not target.strip():
            return False
        
        # Basic validation - Nmap is quite flexible with target formats
        # It can handle IPs, hostnames, CIDR notation, etc.
        
        # Remove common URL prefixes if present
        target = target.lower()
        if target.startswith(('http://', 'https://')):
            return False  # Nmap doesn't scan URLs directly
        
        # Check for obviously invalid characters
        invalid_chars = ['<', '>', '"', "'", '&', '|', ';']
        if any(char in target for char in invalid_chars):
            return False
        
        return True