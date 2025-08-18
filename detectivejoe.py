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
    if sys.prefix == sys.base_prefix and not os.environ.get('VIRTUAL_ENV'):
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
    from async_worker import AsyncWorkerPool, Task, TaskStatus, PLUGIN_REGISTRY
    from plugins import PluginBase, NmapPlugin, TheHarvesterPlugin, PluginDiscovery
    from intelligence import IntelligenceEngine
    from reports import ReportManager
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
        
        # Initialize plugin discovery and intelligence systems
        self.plugin_discovery = PluginDiscovery(self.plugins_dir)
        self.intelligence = IntelligenceEngine(self.state_dir)
        self.report_manager = ReportManager(self.reports_dir)
        
        # Initialize plugins using discovery system
        self.plugins = self._init_plugins()
        
        self.logger.info(f"Detective Joe v1.5 initialized with profile '{profile}'")
        
        # State management
        self.investigation_state = {
            "active": False,
            "target": None,
            "category": None,
            "start_time": None,
            "artifacts": [],
            "chained_tasks": []
        }
    
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
        """Initialize available plugins using discovery system."""
        plugins = {}
        
        try:
            # Discover and load plugins
            discovered_plugins = self.plugin_discovery.load_all_plugins()
            plugins.update(discovered_plugins)
            
            # Update global plugin registry for async worker
            PLUGIN_REGISTRY.clear()
            for name, plugin in plugins.items():
                PLUGIN_REGISTRY[name] = type(plugin)
            
            # Log available plugins
            available_plugins = [name for name, plugin in plugins.items() if plugin.is_available()]
            unavailable_plugins = [name for name, plugin in plugins.items() if not plugin.is_available()]
            
            self.logger.info(f"Available plugins: {', '.join(available_plugins) if available_plugins else 'none'}")
            if unavailable_plugins:
                self.logger.warning(f"Unavailable plugins: {', '.join(unavailable_plugins)}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize plugins: {e}")
            # Fallback to manual initialization
            try:
                plugins["nmap"] = NmapPlugin()
                plugins["theharvester"] = TheHarvesterPlugin()
                PLUGIN_REGISTRY.update({
                    "nmap": NmapPlugin,
                    "theharvester": TheHarvesterPlugin
                })
            except Exception as fallback_error:
                self.logger.error(f"Fallback plugin initialization failed: {fallback_error}")
        
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
        Run investigation asynchronously using the plugin system with intelligence and chaining.
        
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
        
        # Update investigation state
        self.investigation_state.update({
            "active": True,
            "target": target,
            "category": category,
            "start_time": datetime.datetime.now(),
            "artifacts": [],
            "chained_tasks": []
        })
        
        self.logger.info(f"Starting {type_name} for target: {target}")
        
        try:
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
                # Create detailed error message with tool installation guidance
                profile_tools = self.profile.get("tools", {}).get(category, [])
                missing_tools = []
                for tool_name in profile_tools:
                    if tool_name in self.plugins:
                        plugin = self.plugins[tool_name]
                        for required_tool in plugin.required_tools:
                            import shutil
                            if not shutil.which(required_tool):
                                missing_tools.append(required_tool)
                
                error_msg = f"No available plugins for {category} investigation."
                if missing_tools:
                    error_msg += f"\n\nMissing required tools: {', '.join(set(missing_tools))}"
                    error_msg += "\n\nTo install missing tools:"
                    if 'nmap' in missing_tools:
                        error_msg += "\n  • Ubuntu/Debian: sudo apt install nmap"
                        error_msg += "\n  • macOS: brew install nmap"
                    if 'theharvester' in missing_tools:
                        error_msg += "\n  • pip install theHarvester"
                        error_msg += "\n  • OR: git clone https://github.com/laramies/theHarvester"
                    error_msg += "\n\nAfter installation, run Detective Joe again."
                
                return {"error": error_msg}
            
            # Execute plugins asynchronously
            self.logger.info(f"Executing {len(available_plugins)} plugins: {[p.name for p in available_plugins]}")
            
            results = await self.worker_pool.execute_plugin_batch(
                available_plugins,
                target,
                category,
                timeout=self.profile.get("timeout", 120),
                **kwargs
            )
            
            # Process results through intelligence engine
            artifacts = self.intelligence.process_plugin_results(results, target, category)
            self.investigation_state["artifacts"] = artifacts
            
            # Perform artifact chaining if enabled in profile
            chained_results = {}
            if self.profile.get("enable_chaining", True) and self.profile.get("scan_depth", 1) > 1:
                chained_results = await self._perform_artifact_chaining(artifacts, category, kwargs)
            
            # Merge chained results
            if chained_results:
                results.update(chained_results)
                # Process chained artifacts
                chained_artifacts = self.intelligence.process_plugin_results(chained_results, target, category)
                artifacts.extend(chained_artifacts)
            
            # Enrich artifacts with CVE information
            self.intelligence.enrich_artifacts_with_cve(artifacts)
            
            # Save intelligence state
            self.intelligence.save_state()
            
            # Process results
            investigation_result = {
                "target": target,
                "category": category,
                "investigation_type": type_name,
                "profile": self.profile_name,
                "timestamp": datetime.datetime.now().isoformat(),
                "plugin_results": results,
                "artifacts": artifacts,
                "chained_tasks": self.investigation_state["chained_tasks"],
                "summary": self._generate_summary(results, artifacts)
            }
            
            return investigation_result
            
        except Exception as e:
            self.logger.error(f"Investigation failed: {e}")
            return {"error": str(e)}
        finally:
            # Mark investigation as inactive
            self.investigation_state["active"] = False
    
    async def _perform_artifact_chaining(self, artifacts: List[Dict[str, Any]], category: str, kwargs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Perform artifact chaining by feeding discovered targets into new plugin tasks.
        
        Args:
            artifacts: List of discovered artifacts
            category: Current investigation category
            kwargs: Additional parameters
            
        Returns:
            Results from chained plugin executions
        """
        chained_results = {}
        
        # Get chainable artifacts
        chainable = self.intelligence.get_chainable_artifacts(category)
        
        # Determine chaining depth and aggressiveness from profile
        max_depth = self.profile.get("scan_depth", 1)
        aggressiveness = self.profile.get("aggressiveness", "medium")
        
        if max_depth <= 1:
            return chained_results
        
        self.logger.info(f"Performing artifact chaining with depth {max_depth}")
        
        # Find plugins that can consume these artifacts
        for artifact_type, values in chainable.items():
            if not values:
                continue
            
            # Get plugins that can consume this artifact type
            candidates = self.plugin_discovery.get_chaining_candidates([artifact_type])
            
            # Limit candidates based on aggressiveness
            if aggressiveness == "low":
                candidates = candidates[:1]  # Only highest priority
            elif aggressiveness == "medium":
                candidates = candidates[:2]  # Top 2 priorities
            # High aggressiveness uses all candidates
            
            for plugin_name in candidates:
                if plugin_name in self.plugins and self.plugins[plugin_name].is_available():
                    plugin = self.plugins[plugin_name]
                    
                    # Chain with discovered targets (limit to prevent explosion)
                    chain_targets = values[:5] if aggressiveness == "low" else values[:10]
                    
                    for target in chain_targets:
                        try:
                            # Execute chained plugin
                            chained_result = await self.worker_pool.execute_plugin_batch(
                                [plugin],
                                target,
                                category,
                                timeout=self.profile.get("timeout", 120) // 2,  # Reduced timeout for chained tasks
                                **kwargs
                            )
                            
                            # Add to chained results with unique key
                            for task_id, result in chained_result.items():
                                chained_key = f"chained_{plugin_name}_{target}_{len(chained_results)}"
                                chained_results[chained_key] = result
                                
                                # Track chained task
                                self.investigation_state["chained_tasks"].append({
                                    "plugin": plugin_name,
                                    "target": target,
                                    "source_artifact_type": artifact_type,
                                    "status": result.get("status", "unknown")
                                })
                        
                        except Exception as e:
                            self.logger.warning(f"Chained task failed: {plugin_name} -> {target}: {e}")
        
        self.logger.info(f"Completed artifact chaining: {len(chained_results)} additional tasks")
        return chained_results
        """Generate summary statistics from plugin results."""
        total_tasks = len(results)
        successful_tasks = len([r for r in results.values() if r["status"] == "completed"])
        failed_tasks = len([r for r in results.values() if r["status"] == "failed"])
        timeout_tasks = len([r for r in results.values() if r["status"] == "timeout"])
        
        total_duration = sum(r.get("duration", 0) for r in results.values() if r.get("duration"))
        
        summary = {
            "total_tasks": total_tasks,
            "successful_tasks": successful_tasks,
            "failed_tasks": failed_tasks,
            "timeout_tasks": timeout_tasks,
            "success_rate": (successful_tasks / total_tasks * 100) if total_tasks > 0 else 0,
            "total_duration": total_duration,
            "average_duration": (total_duration / successful_tasks) if successful_tasks > 0 else 0,
            "total_artifacts": len(artifacts) if artifacts else 0,
            "chained_tasks": len(self.investigation_state.get("chained_tasks", []))
        }
        
        # Add artifact summary if available
        if artifacts:
            artifact_summary = {}
            for artifact in artifacts:
                artifact_type = artifact.type if hasattr(artifact, 'type') else 'unknown'
                artifact_summary[artifact_type] = artifact_summary.get(artifact_type, 0) + 1
            summary["artifacts_by_type"] = artifact_summary
        
        return summary
    
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
    
    def _generate_summary(self, results: Dict[str, Dict[str, Any]], artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of investigation results.
        
        Args:
            results: Plugin execution results
            artifacts: Discovered artifacts
            
        Returns:
            Summary dictionary with key statistics
        """
        total_tasks = len(results)
        successful_tasks = len([r for r in results.values() if r.get("status") == "completed"])
        failed_tasks = total_tasks - successful_tasks
        
        # Artifact type counts
        artifact_types = {}
        for artifact in artifacts:
            artifact_type = artifact.get("type", "unknown")
            artifact_types[artifact_type] = artifact_types.get(artifact_type, 0) + 1
        
        # Calculate total execution time
        total_time = sum(r.get("duration", 0) for r in results.values())
        
        return {
            "total_tasks": total_tasks,
            "successful_tasks": successful_tasks,
            "failed_tasks": failed_tasks,
            "success_rate": (successful_tasks / total_tasks * 100) if total_tasks > 0 else 0,
            "total_execution_time": round(total_time, 2),
            "total_artifacts": len(artifacts),
            "artifact_types": artifact_types
        }
    
    def save_report(self, investigation_result: Dict[str, Any], artifacts: List[Any] = None) -> Dict[str, Optional[Path]]:
        """
        Save investigation reports in multiple formats.
        
        Args:
            investigation_result: Investigation results dictionary
            artifacts: List of artifacts discovered
            
        Returns:
            Dictionary mapping format to file path
        """
        try:
            reports = self.report_manager.generate_all_reports(investigation_result, artifacts)
            return reports
        except Exception as e:
            self.logger.error(f"Error saving reports: {e}")
            return {}
    
    def generate_report_content(self, investigation_result: Dict[str, Any]) -> str:
        """Generate formatted TXT report content (legacy compatibility)."""
        artifacts = investigation_result.get("artifacts", [])
        return self.report_manager.txt_generator.generate(investigation_result, artifacts)
    
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
            
            # Generate and save reports
            reports = self.save_report(result, result.get("artifacts", []))
            
            if reports:
                print(f"[✓] Investigation completed successfully!")
                for format_type, report_path in reports.items():
                    print(f"[✓] {format_type.upper()} report saved: {report_path}")
                
                # Print summary
                summary = result.get("summary", {})
                print(f"\nSUMMARY:")
                print(f"  Tasks executed: {summary.get('total_tasks', 0)}")
                print(f"  Success rate: {summary.get('success_rate', 0):.1f}%")
                print(f"  Total time: {summary.get('total_duration', 0):.2f}s")
                print(f"  Artifacts found: {summary.get('total_artifacts', 0)}")
                if summary.get('chained_tasks', 0) > 0:
                    print(f"  Chained tasks: {summary.get('chained_tasks', 0)}")
            else:
                print("[!] Investigation completed but failed to save reports")
                
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
                    # Generate and save reports
                    reports = self.save_report(result, result.get("artifacts", []))
                    
                    if reports:
                        print(f"\n[✓] Investigation completed!")
                        for format_type, report_path in reports.items():
                            print(f"[✓] {format_type.upper()} report saved: {report_path}")
                        
                        # Print summary
                        summary = result.get("summary", {})
                        print(f"\nSUMMARY:")
                        print(f"  Tasks executed: {summary.get('total_tasks', 0)}")
                        print(f"  Success rate: {summary.get('success_rate', 0):.1f}%")
                        print(f"  Total time: {summary.get('total_duration', 0):.2f}s")
                        print(f"  Artifacts found: {summary.get('total_artifacts', 0)}")
                        if summary.get('chained_tasks', 0) > 0:
                            print(f"  Chained tasks: {summary.get('chained_tasks', 0)}")
                    else:
                        print("\n[!] Investigation completed but failed to save reports.")
                
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
        """List available plugins with enhanced information."""
        print("\nAvailable Plugins:")
        print("=" * 50)
        
        # Get plugin information from discovery system
        all_plugins_info = self.plugin_discovery.list_all_plugins()
        
        for name, info in all_plugins_info.items():
            status = "✓" if info['available'] else "✗"
            print(f"[{status}] {name} v{info['version']}")
            print(f"    Description: {info['description']}")
            print(f"    Tool: {info['tool_name']}")
            print(f"    Categories: {', '.join(info['categories'])}")
            print(f"    Required Tools: {', '.join(info['required_tools'])}")
            print(f"    Chain Priority: {info['chain_priority']}")
            print(f"    Tags: {', '.join(info['tags'])}")
            print(f"    Available: {info['available']}")
            print(f"    Loaded: {info['loaded']}")
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