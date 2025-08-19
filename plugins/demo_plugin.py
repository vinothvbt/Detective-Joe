#!/usr/bin/env python3
"""
Detective Joe v1.5 - Demo Plugin
A simple demo plugin that works without external tools to demonstrate the framework.
"""

from plugins.base import PluginBase
from typing import Dict, Any, List


class DemoPlugin(PluginBase):
    """Demo plugin for testing Detective Joe functionality."""
    
    def __init__(self):
        super().__init__("demo")
    
    @property
    def tool_name(self) -> str:
        return "demo"
    
    @property
    def categories(self) -> List[str]:
        return ["website", "organisation", "ip_server"]
    
    @property
    def required_tools(self) -> List[str]:
        return ["echo", "curl"]  # These are available on most systems
    
    def build_command(self, target: str, category: str, **kwargs) -> str:
        """Build demo command based on category."""
        if category == "website":
            return f"curl -s -I --max-time 10 {target} 2>/dev/null || echo 'Demo: HTTP check for {target}'"
        elif category == "organisation":
            return f"echo 'Demo: Organization info for {target}'"
        elif category == "ip_server":
            return f"echo 'Demo: Server info for {target}'"
        else:
            return f"echo 'Demo: Basic check for {target}'"
    
    def parse_output(self, output: str, target: str, category: str) -> Dict[str, Any]:
        """Parse demo output into structured format."""
        artifacts = []
        
        if "HTTP" in output and category == "website":
            # Extract HTTP status info if available
            lines = output.strip().split('\n')
            if lines:
                status_line = lines[0]
                artifacts.append({
                    "type": "http_status",
                    "value": status_line,
                    "confidence": 0.9
                })
                
                # Look for server header
                for line in lines:
                    if line.lower().startswith('server:'):
                        artifacts.append({
                            "type": "server_software",
                            "value": line.split(':', 1)[1].strip(),
                            "confidence": 0.8
                        })
        
        # Always add basic connectivity info
        artifacts.append({
            "type": "demo_info",
            "value": f"Demo scan completed for {target}",
            "confidence": 1.0
        })
        
        return {
            "target": target,
            "category": category,
            "status": "completed",
            "raw_output": output,
            "artifacts": artifacts,
            "summary": f"Demo plugin executed for {target} ({category} investigation)"
        }
    
    def validate_target(self, target: str, category: str) -> bool:
        """Validate target format."""
        if not target or len(target.strip()) == 0:
            return False
        return True