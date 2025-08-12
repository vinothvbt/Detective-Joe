#!/usr/bin/env python3
"""
Detective Joe v1.5 - Plugin Package
Plugin system for modular reconnaissance tool integration with auto-discovery.
"""

from .base import PluginBase
from .nmap_plugin import NmapPlugin
from .theharvester_plugin import TheHarvesterPlugin
from .discovery import PluginDiscovery, PluginManifest

__all__ = ['PluginBase', 'NmapPlugin', 'TheHarvesterPlugin', 'PluginDiscovery', 'PluginManifest']