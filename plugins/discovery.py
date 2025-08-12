#!/usr/bin/env python3
"""
Detective Joe v1.5 - Plugin Discovery System
Auto-discovery and manifest loading for reconnaissance plugins.
"""

import os
import yaml
import importlib
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Type
from .base import PluginBase


class PluginManifest:
    """Represents a plugin manifest loaded from YAML."""
    
    def __init__(self, manifest_data: Dict[str, Any], manifest_path: Path):
        """
        Initialize plugin manifest.
        
        Args:
            manifest_data: Parsed YAML manifest data
            manifest_path: Path to the manifest file
        """
        self.data = manifest_data
        self.path = manifest_path
        self.name = manifest_data.get("name", "unknown")
        self.version = manifest_data.get("version", "1.0")
        self.description = manifest_data.get("description", "")
        self.author = manifest_data.get("author", "Unknown")
        self.tool_name = manifest_data.get("tool_name", self.name)
        self.required_tools = manifest_data.get("required_tools", [])
        self.categories = manifest_data.get("categories", [])
        self.plugin_class = manifest_data.get("plugin_class", "")
        self.module_path = manifest_data.get("module_path", "")
        self.settings = manifest_data.get("settings", {})
        self.artifacts = manifest_data.get("artifacts", {})
        self.chain_priority = manifest_data.get("chain_priority", 5)
        self.tags = manifest_data.get("tags", [])
    
    def is_valid(self) -> bool:
        """Check if manifest has required fields."""
        required_fields = ["name", "plugin_class", "module_path", "categories"]
        return all(field in self.data and self.data[field] for field in required_fields)


class PluginDiscovery:
    """Plugin auto-discovery and manifest loading system."""
    
    def __init__(self, plugins_dir: Path):
        """
        Initialize plugin discovery system.
        
        Args:
            plugins_dir: Directory containing plugins and manifests
        """
        self.plugins_dir = Path(plugins_dir)
        self.logger = logging.getLogger("dj.plugin_discovery")
        self.manifests: Dict[str, PluginManifest] = {}
        self.loaded_plugins: Dict[str, PluginBase] = {}
        
    def discover_plugins(self) -> Dict[str, PluginManifest]:
        """
        Discover plugins by scanning for YAML manifests.
        
        Returns:
            Dictionary of plugin manifests keyed by plugin name
        """
        self.manifests.clear()
        
        if not self.plugins_dir.exists():
            self.logger.warning(f"Plugins directory not found: {self.plugins_dir}")
            return self.manifests
        
        # Scan for YAML manifest files
        manifest_files = list(self.plugins_dir.glob("*.yml")) + list(self.plugins_dir.glob("*.yaml"))
        
        for manifest_file in manifest_files:
            try:
                with open(manifest_file, 'r') as f:
                    manifest_data = yaml.safe_load(f)
                
                manifest = PluginManifest(manifest_data, manifest_file)
                
                if manifest.is_valid():
                    self.manifests[manifest.name] = manifest
                    self.logger.info(f"Discovered plugin: {manifest.name} v{manifest.version}")
                else:
                    self.logger.warning(f"Invalid manifest: {manifest_file}")
                    
            except Exception as e:
                self.logger.error(f"Error loading manifest {manifest_file}: {e}")
        
        self.logger.info(f"Discovered {len(self.manifests)} plugins")
        return self.manifests
    
    def load_plugin(self, manifest: PluginManifest) -> Optional[PluginBase]:
        """
        Load a plugin from its manifest.
        
        Args:
            manifest: Plugin manifest
            
        Returns:
            Loaded plugin instance or None if loading failed
        """
        try:
            # Import the plugin module
            module_name = f"plugins.{manifest.module_path}"
            module = importlib.import_module(module_name)
            
            # Get the plugin class
            plugin_class = getattr(module, manifest.plugin_class)
            
            # Instantiate the plugin
            plugin = plugin_class()
            
            # Validate it's a proper plugin
            if not isinstance(plugin, PluginBase):
                raise TypeError(f"Plugin {manifest.name} does not inherit from PluginBase")
            
            self.logger.info(f"Loaded plugin: {manifest.name}")
            return plugin
            
        except Exception as e:
            self.logger.error(f"Error loading plugin {manifest.name}: {e}")
            return None
    
    def load_all_plugins(self) -> Dict[str, PluginBase]:
        """
        Load all discovered plugins.
        
        Returns:
            Dictionary of loaded plugins keyed by plugin name
        """
        self.loaded_plugins.clear()
        
        # First discover plugins if not already done
        if not self.manifests:
            self.discover_plugins()
        
        # Load each plugin
        for name, manifest in self.manifests.items():
            plugin = self.load_plugin(manifest)
            if plugin:
                self.loaded_plugins[name] = plugin
        
        self.logger.info(f"Loaded {len(self.loaded_plugins)} plugins successfully")
        return self.loaded_plugins
    
    def get_plugins_for_category(self, category: str) -> List[PluginBase]:
        """
        Get all plugins that support a specific category.
        
        Args:
            category: Investigation category
            
        Returns:
            List of plugins supporting the category
        """
        plugins = []
        for name, manifest in self.manifests.items():
            if category in manifest.categories:
                if name in self.loaded_plugins:
                    plugins.append(self.loaded_plugins[name])
        
        # Sort by chain priority (lower number = higher priority)
        plugins.sort(key=lambda p: self.manifests[p.name].chain_priority)
        return plugins
    
    def get_plugin_artifacts(self, plugin_name: str) -> Dict[str, List[str]]:
        """
        Get artifact information for a plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Dictionary with 'produces' and 'consumes' artifact lists
        """
        if plugin_name in self.manifests:
            return self.manifests[plugin_name].artifacts
        return {"produces": [], "consumes": []}
    
    def get_chaining_candidates(self, artifacts: List[str]) -> List[str]:
        """
        Find plugins that can consume the given artifacts.
        
        Args:
            artifacts: List of available artifacts
            
        Returns:
            List of plugin names that can consume these artifacts
        """
        candidates = []
        for name, manifest in self.manifests.items():
            consumes = manifest.artifacts.get("consumes", [])
            if any(artifact in consumes for artifact in artifacts):
                candidates.append(name)
        
        # Sort by chain priority
        candidates.sort(key=lambda name: self.manifests[name].chain_priority)
        return candidates
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive information about a plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Plugin information dictionary or None if not found
        """
        if plugin_name not in self.manifests:
            return None
        
        manifest = self.manifests[plugin_name]
        plugin = self.loaded_plugins.get(plugin_name)
        
        return {
            "name": manifest.name,
            "version": manifest.version,
            "description": manifest.description,
            "author": manifest.author,
            "tool_name": manifest.tool_name,
            "required_tools": manifest.required_tools,
            "categories": manifest.categories,
            "settings": manifest.settings,
            "artifacts": manifest.artifacts,
            "chain_priority": manifest.chain_priority,
            "tags": manifest.tags,
            "available": plugin.is_available() if plugin else False,
            "loaded": plugin is not None
        }
    
    def list_all_plugins(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about all discovered plugins.
        
        Returns:
            Dictionary mapping plugin names to their info
        """
        return {name: self.get_plugin_info(name) for name in self.manifests.keys()}