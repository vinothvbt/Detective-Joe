#!/usr/bin/env python3
"""
Detective Joe v1.5 - theHarvester Plugin
Email harvesting and OSINT plugin using theHarvester for information gathering.
"""

import re
from typing import Dict, Any, List
from .base import PluginBase


class TheHarvesterPlugin(PluginBase):
    """
    theHarvester plugin for OSINT and email harvesting.
    
    Supports information gathering for:
    - Website: Domain-based information gathering
    - Organisation: Company email and subdomain discovery
    - People: Email address harvesting
    """
    
    def __init__(self):
        super().__init__("theharvester", "1.0")
        
    @property
    def tool_name(self) -> str:
        return "theHarvester"
    
    @property
    def categories(self) -> List[str]:
        return ["website", "organisation", "people"]
    
    @property
    def required_tools(self) -> List[str]:
        return ["theHarvester"]
    
    def build_command(self, target: str, category: str, **kwargs) -> str:
        """
        Build theHarvester command based on category and target.
        
        Args:
            target: Target domain/organization
            category: Investigation category
            **kwargs: Additional options (sources, limit, etc.)
            
        Returns:
            theHarvester command string
        """
        # Base command
        cmd = "theHarvester"
        
        # Add domain/target
        cmd += f" -d {target}"
        
        # Source selection based on category and preferences
        sources = kwargs.get('sources', None)
        if not sources:
            if category == "website":
                sources = "google,bing,duckduckgo,yahoo"
            elif category == "organisation":
                sources = "google,bing,linkedin,yahoo,duckduckgo"
            elif category == "people":
                sources = "google,bing,linkedin,twitter,yahoo"
            else:
                sources = "all"
        
        cmd += f" -b {sources}"
        
        # Add limit if specified
        limit = kwargs.get('limit', 500)
        cmd += f" -l {limit}"
        
        # Additional options
        if kwargs.get('screenshot', False):
            cmd += " -t"
        
        if kwargs.get('dns_brute', False):
            cmd += " -c"
        
        if kwargs.get('dns_tld', False):
            cmd += " -h"
        
        if kwargs.get('shodan', False):
            cmd += " -n"
        
        # Output format
        output_format = kwargs.get('format', None)
        if output_format:
            cmd += f" -f {output_format}"
        
        return cmd
    
    def parse_output(self, output: str, target: str, category: str) -> Dict[str, Any]:
        """
        Parse theHarvester output into structured data.
        
        Args:
            output: Raw theHarvester output
            target: Target that was investigated
            category: Investigation category
            
        Returns:
            Parsed theHarvester data
        """
        parsed = {
            "target": target,
            "category": category,
            "emails": [],
            "hosts": [],
            "ips": [],
            "urls": [],
            "people": [],
            "linkedin_profiles": [],
            "twitter_profiles": [],
            "interesting_files": []
        }
        
        if not output:
            return parsed
        
        lines = output.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # Section headers
            if "[*] Emails found:" in line:
                current_section = "emails"
                continue
            elif "[*] Hosts found:" in line:
                current_section = "hosts"
                continue
            elif "[*] IPs found:" in line:
                current_section = "ips"
                continue
            elif "[*] URLs found:" in line:
                current_section = "urls"
                continue
            elif "[*] People found:" in line:
                current_section = "people"
                continue
            elif "[*] LinkedIn profiles:" in line:
                current_section = "linkedin"
                continue
            elif "[*] Twitter profiles:" in line:
                current_section = "twitter"
                continue
            elif "[*] Interesting files:" in line:
                current_section = "files"
                continue
            elif line.startswith("[-]") or line.startswith("[!]") or line.startswith("[*]"):
                current_section = None
                continue
            
            # Skip empty lines and headers
            if not line or line.startswith("=") or line.startswith("-"):
                continue
            
            # Parse content based on current section
            if current_section == "emails":
                email_match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', line)
                if email_match:
                    email = email_match.group(0)
                    if email not in parsed["emails"]:
                        parsed["emails"].append(email)
            
            elif current_section == "hosts":
                # Extract hostnames/subdomains
                host_match = re.search(r'\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', line)
                if host_match:
                    host = host_match.group(0)
                    if host not in parsed["hosts"]:
                        parsed["hosts"].append(host)
            
            elif current_section == "ips":
                # Extract IP addresses
                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                if ip_match:
                    ip = ip_match.group(0)
                    if ip not in parsed["ips"]:
                        parsed["ips"].append(ip)
            
            elif current_section == "urls":
                # Extract URLs
                url_match = re.search(r'https?://[^\s<>"\']+', line)
                if url_match:
                    url = url_match.group(0)
                    if url not in parsed["urls"]:
                        parsed["urls"].append(url)
            
            elif current_section == "people":
                # Extract people names (usually from LinkedIn)
                if line and not line.startswith("http") and not "@" in line:
                    person = line.strip()
                    if person and person not in parsed["people"]:
                        parsed["people"].append(person)
            
            elif current_section == "linkedin":
                linkedin_match = re.search(r'linkedin\.com/[^\s<>"\']+', line)
                if linkedin_match:
                    profile = linkedin_match.group(0)
                    if profile not in parsed["linkedin_profiles"]:
                        parsed["linkedin_profiles"].append(profile)
            
            elif current_section == "twitter":
                twitter_match = re.search(r'twitter\.com/[^\s<>"\']+', line)
                if twitter_match:
                    profile = twitter_match.group(0)
                    if profile not in parsed["twitter_profiles"]:
                        parsed["twitter_profiles"].append(profile)
            
            elif current_section == "files":
                if line.strip():
                    parsed["interesting_files"].append(line.strip())
        
        # Extract additional information from the full output
        self._extract_additional_info(output, parsed)
        
        # Generate summary
        parsed["summary"] = {
            "total_emails": len(parsed["emails"]),
            "total_hosts": len(parsed["hosts"]),
            "total_ips": len(parsed["ips"]),
            "total_urls": len(parsed["urls"]),
            "total_people": len(parsed["people"]),
            "total_linkedin": len(parsed["linkedin_profiles"]),
            "total_twitter": len(parsed["twitter_profiles"]),
            "total_files": len(parsed["interesting_files"])
        }
        
        return parsed
    
    def _extract_additional_info(self, output: str, parsed: Dict[str, Any]) -> None:
        """
        Extract additional information from theHarvester output.
        
        Args:
            output: Full theHarvester output
            parsed: Parsed data dictionary to update
        """
        # Extract information about sources used
        sources_match = re.search(r'Searching in (.+?)\.', output)
        if sources_match:
            parsed["sources_used"] = sources_match.group(1)
        
        # Extract virtual hosts information
        vhost_section = re.search(r'\[.*Virtual hosts found.*\](.+?)(?=\[|$)', output, re.DOTALL)
        if vhost_section:
            vhosts = []
            for line in vhost_section.group(1).split('\n'):
                line = line.strip()
                if line and not line.startswith('[') and not line.startswith('-'):
                    vhosts.append(line)
            parsed["virtual_hosts"] = vhosts
        
        # Check for errors or warnings
        if "Error:" in output or "ERROR" in output:
            parsed["errors"] = []
            for line in output.split('\n'):
                if "Error:" in line or "ERROR" in line:
                    parsed["errors"].append(line.strip())
    
    def validate_target(self, target: str, category: str) -> bool:
        """
        Validate target for theHarvester.
        
        Args:
            target: Target to validate
            category: Investigation category
            
        Returns:
            True if target is valid for theHarvester
        """
        if not target or not target.strip():
            return False
        
        target = target.strip().lower()
        
        # Remove URL prefixes
        if target.startswith(('http://', 'https://')):
            target = target.replace('http://', '').replace('https://', '')
            target = target.split('/')[0]  # Remove path if any
        
        # For people category, allow email addresses
        if category == "people":
            if "@" in target:
                return re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$', target) is not None
            else:
                # Allow names for people search
                return True
        
        # For other categories, validate domain format
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(domain_pattern, target) is not None