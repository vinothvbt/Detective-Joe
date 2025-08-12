#!/usr/bin/env python3
"""
Detective Joe v1.5 - Next-Gen Recon Framework
Automated reconnaissance assistant with async execution and plugin architecture.

This script provides both CLI argument parsing and interactive menu interfaces
for running modular reconnaissance plugins against various target types.
"""

import os
import sys
import argparse
import asyncio
import datetime
import logging
import shutil
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional

# Check if running in virtual environment
def check_virtual_environment():
    """Check if script is running inside a virtual environment."""
    if sys.prefix == sys.base_prefix:
        print("❌ Error: Detective Joe must be run inside a virtual environment")
        print("")
        print("🔧 To fix this issue:")
        print("   1. Run the setup script: ./setup.sh")
        print("   2. Activate the virtual environment: source .venv/bin/activate")
        print("   3. Then run Detective Joe again")
        print("")
        print("💡 This prevents pip installation conflicts on systems like Kali Linux")
        print("   with externally-managed-environment restrictions (PEP 668).")
        sys.exit(1)

# Import framework components
try:
    from config import TOOLS, INVESTIGATION_TYPES, OPTIONAL_TOOLS, API_DEPENDENT_TOOLS
    from async_worker import AsyncWorkerPool, Task, TaskStatus
    from plugins import PluginBase, NmapPlugin, TheHarvesterPlugin
except ImportError as e:
    print(f"Error: Failed to import required modules: {e}")
    print("Please ensure all framework components are in the same directory.")
    sys.exit(1)

class DetectiveJoe:
    """Main Detective Joe v1.5 class for handling investigations."""
    
    def __init__(self, profile: str = "standard", config_file: str = "profiles.yaml"):
        """
        Initialize Detective Joe v1.5 with async capabilities.
        
        Args:
            profile: Profile name to use for investigations
            config_file: Path to profiles configuration file
        """
        # Setup directories
        self.base_dir = Path(".")
        self.reports_dir = self.base_dir / "reports"
        self.cache_dir = self.base_dir / "cache"
        self.state_dir = self.base_dir / "state"
        self.plugins_dir = self.base_dir / "plugins"
        
        # Create directories
        for directory in [self.reports_dir, self.cache_dir, self.state_dir, self.plugins_dir]:
            directory.mkdir(exist_ok=True)
        
        # Load configuration
        self.config_file = config_file
        self.profile_name = profile
        self.config = self._load_config()
        self.profile = self._load_profile(profile)
        
        # Setup logging
        self._setup_logging()
        self.logger = logging.getLogger("dj.main")
        
        # Initialize async worker pool
        max_workers = self.profile.get("parallel_workers", 4)
        timeout = self.profile.get("timeout", 120)
        self.worker_pool = AsyncWorkerPool(max_workers=max_workers, default_timeout=timeout)
        
        # Initialize plugins
        self.plugins = self._init_plugins()
        
        self.logger.info(f"Detective Joe v1.5 initialized with profile '{profile}'")
    
    def _setup_logging(self) -> None:
        """Setup logging configuration."""
        log_level = logging.INFO
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(self.state_dir / "detective_joe.log")
            ]
        )
    
    def _load_config(self) -> Dict[str, Any]:
        """Load profiles configuration from YAML file."""
        try:
            if not Path(self.config_file).exists():
                print(f"Warning: Config file {self.config_file} not found, using defaults")
                return self._get_default_config()
            
            with open(self.config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error: Failed to load config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration if no config file is available."""
        return {
            "profiles": {
                "standard": {
                    "name": "Standard Scan",
                    "timeout": 120,
                    "parallel_workers": 4,
                    "enabled_categories": ["website", "ip_server"],
                    "tools": {
                        "website": ["nmap", "theharvester"],
                        "ip_server": ["nmap"]
                    }
                }
            },
            "default_profile": "standard",
            "global_settings": {
                "max_parallel_workers": 8,
                "default_timeout": 120,
                "cache_enabled": True
            }
        }
    
    def _load_profile(self, profile_name: str) -> Dict[str, Any]:
        """Load specific profile configuration."""
        profiles = self.config.get("profiles", {})
        
        if profile_name not in profiles:
            print(f"Warning: Profile '{profile_name}' not found, using default")
            default_profile = self.config.get("default_profile", "standard")
            profile_name = default_profile
        
        if profile_name not in profiles:
            print("Error: No valid profiles found in configuration")
            return self._get_default_config()["profiles"]["standard"]
        
        return profiles[profile_name]
    
    def _init_plugins(self) -> Dict[str, PluginBase]:
        """Initialize available plugins."""
        plugins = {}
        
        # Initialize built-in plugins
        try:
            plugins["nmap"] = NmapPlugin()
            plugins["theharvester"] = TheHarvesterPlugin()
        except Exception as e:
            print(f"Error: Failed to initialize plugins: {e}")
        
        # Log available plugins
        available_plugins = [name for name, plugin in plugins.items() if plugin.is_available()]
        self.logger.info(f"Available plugins: {', '.join(available_plugins)}")
        
        return plugins
        
    def display_banner(self):
        """Display the Detective Joe v1.5 banner."""
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                    DETECTIVE JOE v1.5                       ║
║                 Next-Gen Recon Framework                     ║
║                                                              ║
║  Profile: {self.profile_name:<20} Workers: {self.profile.get('parallel_workers', 4):<8}       ║
║  Async Execution │ Plugin Architecture │ CLI & Interactive   ║
╚══════════════════════════════════════════════════════════════╝
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
    
    async def run_investigation_async(self, investigation_type: str, target: str, **kwargs) -> Dict[str, Any]:
        """
        Run investigation asynchronously using the plugin system.
        
        Args:
            investigation_type: Type of investigation to run
            target: Target to investigate
            **kwargs: Additional parameters
            
        Returns:
            Investigation results
        """
        type_info = INVESTIGATION_TYPES.get(investigation_type)
        if not type_info:
            raise ValueError(f"Invalid investigation type: {investigation_type}")
        
        type_name = type_info['name']
        category = type_info['key']
        
        self.logger.info(f"Starting {type_name} for target: {target}")
        
        # Get plugins for this category from profile
        profile_tools = self.profile.get("tools", {}).get(category, [])
        if not profile_tools:
            self.logger.warning(f"No tools configured for category '{category}' in profile '{self.profile_name}'")
            return {"error": f"No tools configured for category '{category}'"}
        
        # Filter available plugins
        available_plugins = []
        for tool_name in profile_tools:
            if tool_name in self.plugins and self.plugins[tool_name].is_available():
                available_plugins.append(self.plugins[tool_name])
            else:
                self.logger.warning(f"Plugin '{tool_name}' not available")
        
        if not available_plugins:
            return {"error": "No available plugins for this investigation"}
        
        # Execute plugins asynchronously
        self.logger.info(f"Executing {len(available_plugins)} plugins: {[p.name for p in available_plugins]}")
        
        try:
            results = await self.worker_pool.execute_plugin_batch(
                available_plugins,
                target,
                category,
                timeout=self.profile.get("timeout", 120),
                **kwargs
            )
            
            # Process results
            investigation_result = {
                "target": target,
                "category": category,
                "investigation_type": type_name,
                "profile": self.profile_name,
                "timestamp": datetime.datetime.now().isoformat(),
                "plugin_results": results,
                "summary": self._generate_summary(results)
            }
            
            return investigation_result
            
        except Exception as e:
            self.logger.error(f"Investigation failed: {e}")
            return {"error": str(e)}
    
    def _generate_summary(self, results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics from plugin results."""
        total_tasks = len(results)
        successful_tasks = len([r for r in results.values() if r["status"] == "completed"])
        failed_tasks = len([r for r in results.values() if r["status"] == "failed"])
        timeout_tasks = len([r for r in results.values() if r["status"] == "timeout"])
        
        total_duration = sum(r.get("duration", 0) for r in results.values() if r.get("duration"))
        
        return {
            "total_tasks": total_tasks,
            "successful_tasks": successful_tasks,
            "failed_tasks": failed_tasks,
            "timeout_tasks": timeout_tasks,
            "success_rate": (successful_tasks / total_tasks * 100) if total_tasks > 0 else 0,
            "total_duration": total_duration,
            "average_duration": (total_duration / successful_tasks) if successful_tasks > 0 else 0
        }
    
    def generate_report_filename(self, target: str, category: str = None) -> str:
        """Generate a timestamped report filename."""
        # Clean target for filename (remove special characters)
        clean_target = "".join(c for c in target if c.isalnum() or c in ".-_")
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        if category:
            return f"{clean_target}_{category}_{timestamp}.txt"
        else:
            return f"{clean_target}_{timestamp}.txt"
    
    def generate_report_content(self, investigation_result: Dict[str, Any]) -> str:
        """Generate formatted report content from investigation results."""
        content = f"""DETECTIVE JOE v1.5 INVESTIGATION REPORT
=======================================
Investigation Type: {investigation_result.get('investigation_type', 'Unknown')}
Target: {investigation_result.get('target', 'Unknown')}
Category: {investigation_result.get('category', 'Unknown')}
Profile: {investigation_result.get('profile', 'Unknown')}
Date: {investigation_result.get('timestamp', 'Unknown')}
=======================================

EXECUTIVE SUMMARY
-----------------
"""
        
        summary = investigation_result.get('summary', {})
        content += f"Total Tasks Executed: {summary.get('total_tasks', 0)}\n"
        content += f"Successful Tasks: {summary.get('successful_tasks', 0)}\n"
        content += f"Failed Tasks: {summary.get('failed_tasks', 0)}\n"
        content += f"Success Rate: {summary.get('success_rate', 0):.1f}%\n"
        content += f"Total Execution Time: {summary.get('total_duration', 0):.2f} seconds\n\n"
        
        # Plugin results
        plugin_results = investigation_result.get('plugin_results', {})
        for task_id, result in plugin_results.items():
            plugin_name = result.get('plugin', 'Unknown')
            status = result.get('status', 'Unknown')
            duration = result.get('duration', 0)
            
            content += f"\n[{plugin_name.upper()}] - Status: {status.upper()}\n"
            content += "=" * 50 + "\n"
            
            if status == "completed" and result.get('result'):
                plugin_result = result['result']
                
                # Add command executed
                if 'command' in plugin_result:
                    content += f"Command: {plugin_result['command']}\n\n"
                
                # Add parsed data if available
                if 'parsed_data' in plugin_result:
                    parsed = plugin_result['parsed_data']
                    content += "STRUCTURED DATA:\n"
                    content += "-" * 20 + "\n"
                    content += self._format_parsed_data(parsed)
                
                # Add raw output
                if 'stdout' in plugin_result and plugin_result['stdout']:
                    content += "\nRAW OUTPUT:\n"
                    content += "-" * 20 + "\n"
                    content += plugin_result['stdout'][:5000]  # Limit output size
                    if len(plugin_result['stdout']) > 5000:
                        content += "\n[OUTPUT TRUNCATED - Full output available in structured data]"
            
            elif result.get('error'):
                content += f"Error: {result['error']}\n"
            
            content += f"\nExecution Time: {duration:.2f} seconds\n\n"
        
        content += "\n" + "=" * 50 + "\n"
        content += "Report generated by Detective Joe v1.5\n"
        content += f"Framework: Async execution with {summary.get('total_tasks', 0)} parallel tasks\n"
        
        return content
    
    def _format_parsed_data(self, parsed_data: Dict[str, Any]) -> str:
        """Format parsed plugin data for report display."""
        content = ""
        
        # Handle common data structures
        for key, value in parsed_data.items():
            if key == "summary":
                continue  # Skip summary as it's already shown
                
            content += f"{key.upper()}:\n"
            
            if isinstance(value, list):
                if value:
                    for item in value[:20]:  # Limit list items
                        content += f"  - {item}\n"
                    if len(value) > 20:
                        content += f"  ... and {len(value) - 20} more items\n"
                else:
                    content += "  (none found)\n"
                    
            elif isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    content += f"  {sub_key}: {sub_value}\n"
                    
            else:
                content += f"  {value}\n"
            
            content += "\n"
        
        return content
    
    def save_report(self, content: str, filename: str) -> Optional[Path]:
        """Save the investigation report to file."""
        report_path = self.reports_dir / filename
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return report_path
        except Exception as e:
            self.logger.error(f"Error saving report: {e}")
            return None
    
    async def run_cli_investigation(self, args: argparse.Namespace) -> None:
        """
        Run investigation from CLI arguments.
        
        Args:
            args: Parsed command line arguments
        """
        try:
            # Map category to investigation type
            category_map = {
                "website": "1",
                "organisation": "2", 
                "organization": "2",  # Alternative spelling
                "people": "3",
                "ip": "4",
                "server": "4",
                "ip_server": "4"
            }
            
            investigation_type = category_map.get(args.category.lower())
            if not investigation_type:
                print(f"Error: Invalid category '{args.category}'")
                print("Valid categories: website, organisation, people, ip, server")
                return
            
            print(f"[*] Starting {args.category} investigation for: {args.target}")
            print(f"[*] Using profile: {self.profile_name}")
            
            # Run investigation
            result = await self.run_investigation_async(investigation_type, args.target)
            
            if "error" in result:
                print(f"[!] Investigation failed: {result['error']}")
                return
            
            # Generate and save report
            report_content = self.generate_report_content(result)
            filename = self.generate_report_filename(args.target, args.category)
            report_path = self.save_report(report_content, filename)
            
            if report_path:
                print(f"[✓] Investigation completed successfully!")
                print(f"[✓] Report saved: {report_path}")
                
                # Print summary
                summary = result.get("summary", {})
                print(f"\nSUMMARY:")
                print(f"  Tasks executed: {summary.get('total_tasks', 0)}")
                print(f"  Success rate: {summary.get('success_rate', 0):.1f}%")
                print(f"  Total time: {summary.get('total_duration', 0):.2f}s")
            else:
                print("[!] Investigation completed but failed to save report")
                
        except Exception as e:
            self.logger.error(f"CLI investigation failed: {e}")
            print(f"[!] Investigation failed: {e}")
        finally:
            await self.worker_pool.stop()
    
    async def run_interactive(self) -> None:
        """Run interactive menu-based interface."""
        try:
            self.display_banner()
            
            while True:
                self.display_menu()
                choice = self.get_user_choice()
                target = self.get_target(choice)
                
                print(f"\n[*] Starting investigation...")
                result = await self.run_investigation_async(choice, target)
                
                if "error" in result:
                    print(f"[!] Investigation failed: {result['error']}")
                else:
                    # Generate and save report
                    report_content = self.generate_report_content(result)
                    filename = self.generate_report_filename(target)
                    report_path = self.save_report(report_content, filename)
                    
                    if report_path:
                        print(f"\n[✓] Investigation completed!")
                        print(f"[✓] Report saved: {report_path}")
                        
                        # Print summary
                        summary = result.get("summary", {})
                        print(f"\nSUMMARY:")
                        print(f"  Tasks executed: {summary.get('total_tasks', 0)}")
                        print(f"  Success rate: {summary.get('success_rate', 0):.1f}%")
                        print(f"  Total time: {summary.get('total_duration', 0):.2f}s")
                    else:
                        print("\n[!] Investigation completed but failed to save report.")
                
                # Ask if user wants to continue
                continue_choice = input("\nRun another investigation? (y/n): ").strip().lower()
                if continue_choice not in ['y', 'yes']:
                    print("\nGoodbye!")
                    break
                    
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user. Goodbye!")
        except Exception as e:
            self.logger.error(f"Interactive session failed: {e}")
            print(f"\nUnexpected error: {e}")
        finally:
            await self.worker_pool.stop()
    
    def list_profiles(self) -> None:
        """List available profiles."""
        print("\nAvailable Profiles:")
        print("=" * 50)
        
        profiles = self.config.get("profiles", {})
        for name, profile in profiles.items():
            status = "✓" if name == self.profile_name else " "
            print(f"[{status}] {name}")
            print(f"    Name: {profile.get('name', 'Unknown')}")
            print(f"    Description: {profile.get('description', 'No description')}")
            print(f"    Workers: {profile.get('parallel_workers', 4)}")
            print(f"    Timeout: {profile.get('timeout', 120)}s")
            print(f"    Categories: {', '.join(profile.get('enabled_categories', []))}")
            print()
    
    def list_plugins(self) -> None:
        """List available plugins."""
        print("\nAvailable Plugins:")
        print("=" * 50)
        
        for name, plugin in self.plugins.items():
            status = "✓" if plugin.is_available() else "✗"
            print(f"[{status}] {name}")
            metadata = plugin.get_metadata()
            print(f"    Tool: {metadata['tool_name']}")
            print(f"    Categories: {', '.join(metadata['categories'])}")
            print(f"    Required Tools: {', '.join(metadata['required_tools'])}")
            print(f"    Available: {metadata['available']}")
            print()


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser for CLI interface."""
    parser = argparse.ArgumentParser(
        description="Detective Joe v1.5 - Next-Gen Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -c website -t example.com
  %(prog)s -c organisation -t company.com -p deep  
  %(prog)s -c ip -t 192.168.1.1 -p quick
  %(prog)s --interactive
  %(prog)s --list-profiles
  %(prog)s --list-plugins
        """
    )
    
    # Main operation modes
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Run in interactive menu mode (default if no other mode specified)"
    )
    group.add_argument(
        "-c", "--category",
        choices=["website", "organisation", "organization", "people", "ip", "server"],
        help="Investigation category for CLI mode"
    )
    
    # CLI mode arguments
    parser.add_argument(
        "-t", "--target",
        help="Target for investigation (domain, IP, name, etc.)"
    )
    parser.add_argument(
        "-p", "--profile",
        default="standard",
        help="Profile to use for investigation (default: standard)"
    )
    parser.add_argument(
        "--config",
        default="profiles.yaml",
        help="Path to configuration file (default: profiles.yaml)"
    )
    
    # Information commands
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="List available investigation profiles"
    )
    parser.add_argument(
        "--list-plugins",
        action="store_true",
        help="List available plugins and their status"
    )
    
    # Advanced options
    parser.add_argument(
        "--workers",
        type=int,
        help="Override number of parallel workers"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Override default timeout in seconds"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    return parser


async def main():
    """Main entry point for Detective Joe v1.5."""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Set up logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize Detective Joe
        dj = DetectiveJoe(profile=args.profile, config_file=args.config)
        
        # Override profile settings if specified
        if args.workers:
            dj.profile["parallel_workers"] = args.workers
            dj.worker_pool = AsyncWorkerPool(max_workers=args.workers, default_timeout=dj.profile.get("timeout", 120))
        
        if args.timeout:
            dj.profile["timeout"] = args.timeout
        
        # Handle different operation modes
        if args.list_profiles:
            dj.list_profiles()
            
        elif args.list_plugins:
            dj.list_plugins()
            
        elif args.category and args.target:
            # CLI mode
            await dj.run_cli_investigation(args)
            
        else:
            # Interactive mode (default)
            await dj.run_interactive()
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Check virtual environment first
    check_virtual_environment()
    
    # Check if running on appropriate system
    if not sys.platform.startswith('linux'):
        print("Warning: Detective Joe is optimized for Linux systems. Some tools may not be available.")
    
    # Run the async main function
    asyncio.run(main())