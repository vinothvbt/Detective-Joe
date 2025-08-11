#!/usr/bin/env python3
"""
Detective Joe (DJ) - Main CLI Script
Automated recon assistant for Kali Linux.

This script provides a menu-based interface for running various
reconnaissance tools against different target types.
"""

import os
import sys
import subprocess
import datetime
import shutil
from pathlib import Path

# Import configuration
try:
    from config import TOOLS, INVESTIGATION_TYPES, OPTIONAL_TOOLS, API_DEPENDENT_TOOLS
except ImportError:
    print("Error: config.py not found. Please ensure config.py is in the same directory.")
    sys.exit(1)

class DetectiveJoe:
    """Main Detective Joe class for handling investigations."""
    
    def __init__(self):
        """Initialize Detective Joe with reports directory."""
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        self.current_report = ""
        
    def display_banner(self):
        """Display the Detective Joe banner."""
        banner = """
==============================
   DETECTIVE JOE v1 — Kali
==============================
        """
        print(banner)
    
    def display_menu(self):
        """Display the main investigation menu."""
        print("\nSelect Investigation Type:")
        for key, value in INVESTIGATION_TYPES.items():
            print(f"[{key}] {value['name']}")
        print("[q] Quit")
    
    def get_user_choice(self):
        """Get and validate user's menu choice."""
        while True:
            choice = input("\nSelect: ").strip().lower()
            
            if choice == 'q':
                print("Goodbye!")
                sys.exit(0)
            
            if choice in INVESTIGATION_TYPES:
                return choice
            
            print("Invalid choice. Please select a valid option.")
    
    def get_target(self, investigation_type):
        """Get target from user with appropriate prompt."""
        type_name = INVESTIGATION_TYPES[investigation_type]['name']
        
        if investigation_type == "1":  # Website
            prompt = "Enter target domain (e.g., example.com): "
        elif investigation_type == "2":  # Organisation
            prompt = "Enter organisation domain (e.g., company.com): "
        elif investigation_type == "3":  # People
            prompt = "Enter person name or email (e.g., john.doe): "
        elif investigation_type == "4":  # IP/Server
            prompt = "Enter IP address or hostname (e.g., 192.168.1.1): "
        else:
            prompt = "Enter target: "
        
        target = input(prompt).strip()
        
        if not target:
            print("Error: Target cannot be empty.")
            return self.get_target(investigation_type)
        
        return target
    
    def check_tool_availability(self, tool_name):
        """Check if a tool is available on the system."""
        # Extract the actual command from the tool name
        cmd_parts = tool_name.split()
        if cmd_parts:
            tool_binary = cmd_parts[0]
            
            # Special cases for complex commands
            if tool_binary == "curl":
                return shutil.which("curl") is not None
            elif tool_binary == "echo":
                return True  # echo is always available
            
            return shutil.which(tool_binary) is not None
        return False
    
    def execute_tool(self, tool_config, target):
        """Execute a single tool and return its output."""
        tool_name = tool_config['name']
        cmd_template = tool_config['cmd']
        
        # Replace {target} placeholder with actual target
        cmd = cmd_template.format(target=target)
        
        print(f"[+] Running {tool_name}...")
        
        # Check if tool is available
        tool_binary = cmd.split()[0]
        
        # Skip optional tools that aren't available
        if tool_binary.lower() in OPTIONAL_TOOLS and not self.check_tool_availability(cmd):
            return f"[SKIPPED] {tool_name} - Tool not available on this system\\n"
        
        try:
            # Execute the command with timeout
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
                check=False
            )
            
            output = ""
            if result.stdout:
                output += result.stdout
            if result.stderr:
                output += f"\\nSTDERR:\\n{result.stderr}"
            
            if result.returncode != 0 and not output:
                output = f"Command failed with return code {result.returncode}"
            
            return output if output.strip() else f"No output from {tool_name}"
            
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] {tool_name} - Command timed out after 2 minutes"
        except subprocess.SubprocessError as e:
            return f"[ERROR] {tool_name} - {str(e)}"
        except Exception as e:
            return f"[ERROR] {tool_name} - Unexpected error: {str(e)}"
    
    def generate_report_filename(self, target):
        """Generate a timestamped report filename."""
        # Clean target for filename (remove special characters)
        clean_target = "".join(c for c in target if c.isalnum() or c in ".-_")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return f"{clean_target}_{timestamp}.txt"
    
    def save_report(self, content, filename):
        """Save the investigation report to file."""
        report_path = self.reports_dir / filename
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return report_path
        except Exception as e:
            print(f"Error saving report: {e}")
            return None
    
    def run_investigation(self, investigation_type, target):
        """Run the selected investigation type against the target."""
        type_info = INVESTIGATION_TYPES[investigation_type]
        type_name = type_info['name']
        tools_key = type_info['key']
        
        print(f"\\n[*] Starting {type_name} for target: {target}")
        print("=" * 60)
        
        # Get tools for this investigation type
        tools = TOOLS.get(tools_key, [])
        
        if not tools:
            print(f"Error: No tools configured for {type_name}")
            return
        
        # Initialize report content
        report_content = f"""DETECTIVE JOE INVESTIGATION REPORT
=======================================
Investigation Type: {type_name}
Target: {target}
Date: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
=======================================

"""
        
        # Execute each tool
        for i, tool_config in enumerate(tools, 1):
            tool_name = tool_config['name']
            
            # Add tool section to report
            report_content += f"\\n[{i}] {tool_name.upper()}\\n"
            report_content += "=" * 50 + "\\n"
            
            # Execute tool and capture output
            output = self.execute_tool(tool_config, target)
            report_content += output + "\\n\\n"
            
            # Print progress
            print(f"[✓] {tool_name} completed")
        
        # Save report
        filename = self.generate_report_filename(target)
        report_path = self.save_report(report_content, filename)
        
        if report_path:
            print(f"\\n[✓] Investigation completed!")
            print(f"[✓] Report saved: {report_path}")
        else:
            print("\\n[!] Investigation completed but failed to save report.")
    
    def run(self):
        """Main run loop for Detective Joe."""
        try:
            self.display_banner()
            
            while True:
                self.display_menu()
                choice = self.get_user_choice()
                target = self.get_target(choice)
                
                self.run_investigation(choice, target)
                
                # Ask if user wants to continue
                continue_choice = input("\\nRun another investigation? (y/n): ").strip().lower()
                if continue_choice not in ['y', 'yes']:
                    print("\\nGoodbye!")
                    break
                    
        except KeyboardInterrupt:
            print("\\n\\nOperation cancelled by user. Goodbye!")
            sys.exit(0)
        except Exception as e:
            print(f"\\nUnexpected error: {e}")
            sys.exit(1)

def main():
    """Main entry point."""
    # Check if running on appropriate system
    if not sys.platform.startswith('linux'):
        print("Warning: Detective Joe is designed for Kali Linux. Some tools may not be available.")
    
    # Create and run Detective Joe
    dj = DetectiveJoe()
    dj.run()

if __name__ == "__main__":
    main()