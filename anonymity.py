#!/usr/bin/env python3
"""
Detective Joe v1.5 - Anonymity Layer
TOR, proxy, and User-Agent rotation support for anonymous reconnaissance.
"""

import random
import time
import subprocess
import requests
from typing import Dict, Any, List, Optional, Tuple
import logging
from pathlib import Path


class UserAgentRotator:
    """Manages User-Agent string rotation."""
    
    def __init__(self):
        """Initialize with common User-Agent strings."""
        self.user_agents = [
            # Chrome
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            
            # Firefox
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
            
            # Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            
            # Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            
            # Mobile
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
        ]
        self.current_index = 0
    
    def get_random(self) -> str:
        """Get a random User-Agent string."""
        return random.choice(self.user_agents)
    
    def get_next(self) -> str:
        """Get the next User-Agent string in rotation."""
        ua = self.user_agents[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.user_agents)
        return ua


class ProxyManager:
    """Manages proxy rotation and validation."""
    
    def __init__(self, proxy_list: List[str] = None):
        """
        Initialize proxy manager.
        
        Args:
            proxy_list: List of proxy URLs (e.g., ["http://proxy1:8080"])
        """
        self.proxy_list = proxy_list or []
        self.working_proxies = []
        self.current_index = 0
        self.logger = logging.getLogger("dj.anonymity.proxy")
    
    def add_proxy(self, proxy_url: str) -> None:
        """Add a proxy to the list."""
        if proxy_url not in self.proxy_list:
            self.proxy_list.append(proxy_url)
    
    def test_proxy(self, proxy_url: str, timeout: int = 10) -> bool:
        """
        Test if a proxy is working.
        
        Args:
            proxy_url: Proxy URL to test
            timeout: Request timeout in seconds
            
        Returns:
            True if proxy is working
        """
        try:
            proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            
            response = requests.get(
                'http://httpbin.org/ip',
                proxies=proxies,
                timeout=timeout
            )
            
            if response.status_code == 200:
                self.logger.info(f"Proxy {proxy_url} is working")
                return True
            else:
                self.logger.warning(f"Proxy {proxy_url} returned status {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.warning(f"Proxy {proxy_url} failed: {e}")
            return False
    
    def validate_proxies(self) -> List[str]:
        """
        Validate all proxies and update working proxy list.
        
        Returns:
            List of working proxy URLs
        """
        self.working_proxies = []
        
        for proxy in self.proxy_list:
            if self.test_proxy(proxy):
                self.working_proxies.append(proxy)
        
        self.logger.info(f"Validated {len(self.working_proxies)}/{len(self.proxy_list)} proxies")
        return self.working_proxies
    
    def get_random_proxy(self) -> Optional[str]:
        """Get a random working proxy."""
        if not self.working_proxies:
            return None
        return random.choice(self.working_proxies)
    
    def get_next_proxy(self) -> Optional[str]:
        """Get the next proxy in rotation."""
        if not self.working_proxies:
            return None
        
        proxy = self.working_proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.working_proxies)
        return proxy


class TorManager:
    """Manages TOR connection and circuit renewal."""
    
    def __init__(self, tor_port: int = 9050, control_port: int = 9051):
        """
        Initialize TOR manager.
        
        Args:
            tor_port: TOR SOCKS proxy port
            control_port: TOR control port
        """
        self.tor_port = tor_port
        self.control_port = control_port
        self.logger = logging.getLogger("dj.anonymity.tor")
        self.session = None
    
    def is_tor_running(self) -> bool:
        """Check if TOR is running."""
        try:
            # Test TOR SOCKS proxy
            proxies = {
                'http': f'socks5://127.0.0.1:{self.tor_port}',
                'https': f'socks5://127.0.0.1:{self.tor_port}'
            }
            
            response = requests.get(
                'http://httpbin.org/ip',
                proxies=proxies,
                timeout=10
            )
            
            if response.status_code == 200:
                return True
            return False
            
        except Exception as e:
            self.logger.debug(f"TOR check failed: {e}")
            return False
    
    def start_tor(self) -> bool:
        """
        Start TOR service.
        
        Returns:
            True if started successfully
        """
        try:
            # Try to start TOR service
            subprocess.run(['sudo', 'systemctl', 'start', 'tor'], 
                         check=True, capture_output=True)
            
            # Wait a bit for TOR to start
            time.sleep(5)
            
            if self.is_tor_running():
                self.logger.info("TOR started successfully")
                return True
            else:
                self.logger.warning("TOR service started but not responding")
                return False
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to start TOR: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error starting TOR: {e}")
            return False
    
    def renew_circuit(self) -> bool:
        """
        Renew TOR circuit to get a new IP.
        
        Returns:
            True if circuit renewed successfully
        """
        try:
            # Send NEWNYM signal to TOR control port
            subprocess.run([
                'echo', 'AUTHENTICATE ""\\nSIGNAL NEWNYM\\nQUIT'
            ], stdout=subprocess.PIPE)
            
            # Alternative method using telnet/nc
            try:
                subprocess.run([
                    'sh', '-c', 
                    f'echo -e "AUTHENTICATE \\"\\"\nSIGNAL NEWNYM\nQUIT" | nc 127.0.0.1 {self.control_port}'
                ], check=True, capture_output=True, timeout=5)
                
                self.logger.info("TOR circuit renewed")
                time.sleep(2)  # Wait for new circuit
                return True
                
            except subprocess.CalledProcessError:
                self.logger.warning("Could not renew TOR circuit via control port")
                return False
                
        except Exception as e:
            self.logger.error(f"Error renewing TOR circuit: {e}")
            return False
    
    def get_current_ip(self) -> Optional[str]:
        """
        Get current IP address through TOR.
        
        Returns:
            Current IP address or None if failed
        """
        try:
            proxies = {
                'http': f'socks5://127.0.0.1:{self.tor_port}',
                'https': f'socks5://127.0.0.1:{self.tor_port}'
            }
            
            response = requests.get(
                'http://httpbin.org/ip',
                proxies=proxies,
                timeout=10
            )
            
            if response.status_code == 200:
                ip_data = response.json()
                return ip_data.get('origin')
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting TOR IP: {e}")
            return None


class AnonymityLayer:
    """Main anonymity layer coordinating TOR, proxies, and User-Agent rotation."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize anonymity layer.
        
        Args:
            config: Anonymity configuration from profile
        """
        self.config = config
        self.logger = logging.getLogger("dj.anonymity")
        
        # Initialize components
        self.ua_rotator = UserAgentRotator()
        self.proxy_manager = ProxyManager(config.get("proxy_list", []))
        self.tor_manager = TorManager()
        
        # Settings
        self.use_tor = config.get("use_tor", False)
        self.use_proxy = config.get("use_proxy", False)
        self.user_agent_rotation = config.get("user_agent_rotation", False)
        self.request_delay = config.get("request_delay", 0)
        self.randomize_timing = config.get("randomize_timing", False)
        
        # State
        self.current_proxy = None
        self.current_ua = None
        self.request_count = 0
        
        self._initialize()
    
    def _initialize(self) -> None:
        """Initialize anonymity components."""
        if self.use_tor:
            if not self.tor_manager.is_tor_running():
                self.logger.info("TOR not running, attempting to start...")
                if not self.tor_manager.start_tor():
                    self.logger.warning("Could not start TOR, disabling TOR anonymity")
                    self.use_tor = False
            else:
                self.logger.info("TOR is running and available")
        
        if self.use_proxy and self.proxy_manager.proxy_list:
            self.logger.info("Validating proxy list...")
            working_proxies = self.proxy_manager.validate_proxies()
            if not working_proxies:
                self.logger.warning("No working proxies found, disabling proxy anonymity")
                self.use_proxy = False
            else:
                self.current_proxy = self.proxy_manager.get_next_proxy()
        
        if self.user_agent_rotation:
            self.current_ua = self.ua_rotator.get_next()
    
    def get_request_config(self) -> Dict[str, Any]:
        """
        Get configuration for anonymous requests.
        
        Returns:
            Dictionary with proxies, headers, and other request configuration
        """
        config = {}
        
        # Set up proxies
        if self.use_tor:
            config['proxies'] = {
                'http': f'socks5://127.0.0.1:{self.tor_manager.tor_port}',
                'https': f'socks5://127.0.0.1:{self.tor_manager.tor_port}'
            }
        elif self.use_proxy and self.current_proxy:
            config['proxies'] = {
                'http': self.current_proxy,
                'https': self.current_proxy
            }
        
        # Set up headers
        headers = {}
        if self.user_agent_rotation and self.current_ua:
            headers['User-Agent'] = self.current_ua
        
        if headers:
            config['headers'] = headers
        
        # Set timeout
        config['timeout'] = 30
        
        return config
    
    def rotate_identity(self) -> bool:
        """
        Rotate identity (IP, User-Agent, proxy).
        
        Returns:
            True if identity rotated successfully
        """
        success = True
        
        # Rotate TOR circuit
        if self.use_tor:
            if not self.tor_manager.renew_circuit():
                self.logger.warning("Failed to renew TOR circuit")
                success = False
        
        # Rotate proxy
        if self.use_proxy:
            new_proxy = self.proxy_manager.get_next_proxy()
            if new_proxy:
                self.current_proxy = new_proxy
                self.logger.debug(f"Rotated to proxy: {new_proxy}")
            else:
                self.logger.warning("No proxies available for rotation")
                success = False
        
        # Rotate User-Agent
        if self.user_agent_rotation:
            self.current_ua = self.ua_rotator.get_next()
            self.logger.debug(f"Rotated User-Agent")
        
        return success
    
    def apply_request_delay(self) -> None:
        """Apply request delay with optional randomization."""
        if self.request_delay > 0:
            delay = self.request_delay
            
            if self.randomize_timing:
                # Add random jitter (±50%)
                jitter = random.uniform(-0.5, 0.5) * delay
                delay = max(0.1, delay + jitter)
            
            self.logger.debug(f"Applying request delay: {delay:.2f}s")
            time.sleep(delay)
    
    def pre_request_hook(self) -> Dict[str, Any]:
        """
        Hook to call before making requests.
        
        Returns:
            Request configuration to use
        """
        self.request_count += 1
        
        # Rotate identity periodically
        if self.request_count % 10 == 0:
            self.rotate_identity()
        
        # Apply delay
        self.apply_request_delay()
        
        return self.get_request_config()
    
    def get_current_ip(self) -> Optional[str]:
        """Get current external IP address."""
        if self.use_tor:
            return self.tor_manager.get_current_ip()
        elif self.use_proxy:
            try:
                config = self.get_request_config()
                response = requests.get('http://httpbin.org/ip', **config)
                if response.status_code == 200:
                    return response.json().get('origin')
            except Exception as e:
                self.logger.error(f"Error getting IP: {e}")
        
        return None
    
    def get_status(self) -> Dict[str, Any]:
        """Get anonymity layer status."""
        return {
            "tor_enabled": self.use_tor,
            "tor_running": self.tor_manager.is_tor_running() if self.use_tor else False,
            "proxy_enabled": self.use_proxy,
            "current_proxy": self.current_proxy,
            "working_proxies": len(self.proxy_manager.working_proxies),
            "ua_rotation": self.user_agent_rotation,
            "current_ua": self.current_ua,
            "request_count": self.request_count,
            "current_ip": self.get_current_ip()
        }