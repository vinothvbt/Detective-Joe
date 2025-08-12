#!/usr/bin/env python3
"""
Detective Joe v1.5 - Plugin Base Class
Defines the base plugin interface that all reconnaissance plugins must implement.
"""

import asyncio
import subprocess
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import logging


class PluginBase(ABC):
    """
    Base class for all Detective Joe plugins.
    
    Each plugin represents a specific reconnaissance tool and provides
    a standardized interface for execution within the async framework.
    """
    
    def __init__(self, name: str, version: str = "1.0"):
        """
        Initialize the plugin.
        
        Args:
            name: Plugin name (should match tool name)
            version: Plugin version
        """
        self.name = name
        self.version = version
        self.logger = logging.getLogger(f"dj.plugin.{name}")
        self._timeout = 120  # Default timeout
        
    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Return the name of the underlying tool."""
        pass
    
    @property
    @abstractmethod
    def categories(self) -> List[str]:
        """Return list of investigation categories this plugin supports."""
        pass
    
    @property
    @abstractmethod
    def required_tools(self) -> List[str]:
        """Return list of required system tools/binaries."""
        pass
    
    @abstractmethod
    def build_command(self, target: str, category: str, **kwargs) -> str:
        """
        Build the command to execute for given target and category.
        
        Args:
            target: Target to investigate
            category: Investigation category (website, organisation, etc.)
            **kwargs: Additional parameters
            
        Returns:
            Command string to execute
        """
        pass
    
    @abstractmethod
    def parse_output(self, output: str, target: str, category: str) -> Dict[str, Any]:
        """
        Parse tool output into structured data.
        
        Args:
            output: Raw tool output
            target: Target that was investigated
            category: Investigation category
            
        Returns:
            Structured data dictionary
        """
        pass
    
    def is_available(self) -> bool:
        """
        Check if the plugin's required tools are available on the system.
        
        Returns:
            True if all required tools are available, False otherwise
        """
        import shutil
        return all(shutil.which(tool) for tool in self.required_tools)
    
    def validate_target(self, target: str, category: str) -> bool:
        """
        Validate if target is appropriate for this plugin and category.
        
        Args:
            target: Target to validate
            category: Investigation category
            
        Returns:
            True if target is valid, False otherwise
        """
        # Default implementation - override in subclasses for specific validation
        return bool(target and target.strip())
    
    async def execute(self, target: str, category: str, timeout: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        """
        Execute the plugin against the target.
        
        Args:
            target: Target to investigate
            category: Investigation category
            timeout: Execution timeout in seconds
            **kwargs: Additional parameters
            
        Returns:
            Plugin execution result
        """
        if not self.is_available():
            return {
                "status": "skipped",
                "reason": f"Required tools not available: {', '.join(self.required_tools)}",
                "plugin": self.name,
                "target": target,
                "category": category
            }
        
        if not self.validate_target(target, category):
            return {
                "status": "error",
                "reason": f"Invalid target '{target}' for category '{category}'",
                "plugin": self.name,
                "target": target,
                "category": category
            }
        
        # Use provided timeout or default
        exec_timeout = timeout or self._timeout
        
        try:
            # Build command
            command = self.build_command(target, category, **kwargs)
            self.logger.info(f"Executing: {command}")
            
            # Execute command asynchronously
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=exec_timeout
                )
                
                # Decode output
                stdout_str = stdout.decode('utf-8', errors='ignore')
                stderr_str = stderr.decode('utf-8', errors='ignore')
                
                # Parse output
                parsed_data = self.parse_output(stdout_str, target, category)
                
                return {
                    "status": "success",
                    "plugin": self.name,
                    "target": target,
                    "category": category,
                    "command": command,
                    "return_code": process.returncode,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "parsed_data": parsed_data,
                    "execution_time": execution_time
                }
                
            except asyncio.TimeoutError:
                # Kill the process if it's still running
                if process.returncode is None:
                    process.kill()
                    await process.wait()
                
                return {
                    "status": "timeout",
                    "reason": f"Command timed out after {exec_timeout} seconds",
                    "plugin": self.name,
                    "target": target,
                    "category": category,
                    "command": command
                }
                
        except Exception as e:
            self.logger.error(f"Plugin execution failed: {e}")
            return {
                "status": "error",
                "reason": str(e),
                "plugin": self.name,
                "target": target,
                "category": category
            }
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get plugin metadata.
        
        Returns:
            Plugin metadata dictionary
        """
        return {
            "name": self.name,
            "version": self.version,
            "tool_name": self.tool_name,
            "categories": self.categories,
            "required_tools": self.required_tools,
            "available": self.is_available()
        }