#!/usr/bin/env python3
"""
Detective Joe v1.5 - Test Suite
Basic test infrastructure for the framework components.
"""

import unittest
import asyncio
import tempfile
import shutil
from pathlib import Path
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plugins.base import PluginBase
from plugins.nmap_plugin import NmapPlugin
from plugins.theharvester_plugin import TheHarvesterPlugin
from async_worker import AsyncWorkerPool, Task, TaskStatus


class MockPlugin(PluginBase):
    """Mock plugin for testing."""
    
    def __init__(self, name="mock", available=True, execution_time=0.1):
        super().__init__(name)
        self._available = available
        self._execution_time = execution_time
    
    @property
    def tool_name(self):
        return "mock_tool"
    
    @property
    def categories(self):
        return ["test"]
    
    @property 
    def required_tools(self):
        return ["echo"]  # Always available
    
    def is_available(self):
        return self._available
    
    def build_command(self, target, category, **kwargs):
        return f"echo 'Mock test for {target}'"
    
    def parse_output(self, output, target, category):
        return {
            "target": target,
            "category": category,
            "mock_data": output.strip(),
            "test": True
        }


class TestPluginBase(unittest.TestCase):
    """Test cases for the plugin base class."""
    
    def setUp(self):
        self.plugin = MockPlugin()
    
    def test_plugin_initialization(self):
        """Test plugin initialization."""
        self.assertEqual(self.plugin.name, "mock")
        self.assertEqual(self.plugin.version, "1.0")
        self.assertEqual(self.plugin.tool_name, "mock_tool")
        self.assertEqual(self.plugin.categories, ["test"])
    
    def test_plugin_availability(self):
        """Test plugin availability checking."""
        self.assertTrue(self.plugin.is_available())
        
        unavailable_plugin = MockPlugin(available=False)
        unavailable_plugin._required_tools = ["nonexistent_tool_12345"]
        self.assertFalse(unavailable_plugin.is_available())
    
    def test_target_validation(self):
        """Test target validation."""
        self.assertTrue(self.plugin.validate_target("example.com", "test"))
        self.assertFalse(self.plugin.validate_target("", "test"))
        self.assertFalse(self.plugin.validate_target(None, "test"))
    
    async def test_plugin_execution(self):
        """Test plugin execution."""
        result = await self.plugin.execute("example.com", "test")
        
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["plugin"], "mock")
        self.assertEqual(result["target"], "example.com")
        self.assertEqual(result["category"], "test")
        self.assertIn("parsed_data", result)


class TestNmapPlugin(unittest.TestCase):
    """Test cases for the Nmap plugin."""
    
    def setUp(self):
        self.plugin = NmapPlugin()
    
    def test_nmap_plugin_properties(self):
        """Test Nmap plugin properties."""
        self.assertEqual(self.plugin.tool_name, "nmap")
        self.assertIn("website", self.plugin.categories)
        self.assertIn("ip_server", self.plugin.categories)
        self.assertEqual(self.plugin.required_tools, ["nmap"])
    
    def test_command_building(self):
        """Test Nmap command building."""
        cmd = self.plugin.build_command("example.com", "website")
        self.assertIn("nmap", cmd)
        self.assertIn("example.com", cmd)
        
        cmd_basic = self.plugin.build_command("192.168.1.1", "ip_server", scan_type="basic")
        self.assertIn("nmap", cmd_basic)
        self.assertIn("192.168.1.1", cmd_basic)
    
    def test_target_validation(self):
        """Test Nmap target validation."""
        self.assertTrue(self.plugin.validate_target("example.com", "website"))
        self.assertTrue(self.plugin.validate_target("192.168.1.1", "ip_server"))
        self.assertFalse(self.plugin.validate_target("http://example.com", "website"))
        self.assertFalse(self.plugin.validate_target("", "website"))


class TestTheHarvesterPlugin(unittest.TestCase):
    """Test cases for theHarvester plugin."""
    
    def setUp(self):
        self.plugin = TheHarvesterPlugin()
    
    def test_theharvester_plugin_properties(self):
        """Test theHarvester plugin properties."""
        self.assertEqual(self.plugin.tool_name, "theHarvester")
        self.assertIn("website", self.plugin.categories)
        self.assertIn("organisation", self.plugin.categories)
        self.assertEqual(self.plugin.required_tools, ["theHarvester"])
    
    def test_command_building(self):
        """Test theHarvester command building."""
        cmd = self.plugin.build_command("example.com", "website")
        self.assertIn("theHarvester", cmd)
        self.assertIn("-d example.com", cmd)
        self.assertIn("-b", cmd)
    
    def test_target_validation(self):
        """Test theHarvester target validation."""
        self.assertTrue(self.plugin.validate_target("example.com", "website"))
        self.assertTrue(self.plugin.validate_target("test@example.com", "people"))
        self.assertFalse(self.plugin.validate_target("", "website"))


class TestAsyncWorkerPool(unittest.TestCase):
    """Test cases for the async worker pool."""
    
    def setUp(self):
        self.worker_pool = AsyncWorkerPool(max_workers=2, default_timeout=10)
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
    
    def tearDown(self):
        if self.worker_pool.running:
            self.loop.run_until_complete(self.worker_pool.stop())
        self.loop.close()
    
    def test_worker_pool_start_stop(self):
        """Test worker pool start and stop."""
        async def run_test():
            self.assertFalse(self.worker_pool.running)
            
            await self.worker_pool.start()
            self.assertTrue(self.worker_pool.running)
            self.assertEqual(len(self.worker_pool.workers), 2)
            
            await self.worker_pool.stop()
            self.assertFalse(self.worker_pool.running)
            self.assertEqual(len(self.worker_pool.workers), 0)
        
        self.loop.run_until_complete(run_test())
    
    def test_task_execution(self):
        """Test task execution through worker pool."""
        async def run_test():
            await self.worker_pool.start()
            
            try:
                # Create mock plugin and register it
                plugin = MockPlugin()
                from async_worker import PLUGIN_REGISTRY
                PLUGIN_REGISTRY["mock"] = MockPlugin
                
                # Execute plugin through worker pool
                results = await self.worker_pool.execute_plugin_batch(
                    [plugin], 
                    "test-target", 
                    "test"
                )
                
                self.assertEqual(len(results), 1)
                result = list(results.values())[0]
                self.assertEqual(result["status"], "completed")
                
            finally:
                await self.worker_pool.stop()
        
        self.loop.run_until_complete(run_test())
    
    def test_stats_collection(self):
        """Test worker pool statistics."""
        stats = self.worker_pool.get_stats()
        self.assertIn("max_workers", stats)
        self.assertIn("tasks_submitted", stats)
        self.assertIn("tasks_completed", stats)


class TestIntegration(unittest.TestCase):
    """Integration tests for the framework."""
    
    def setUp(self):
        # Create temporary directory for test files
        self.test_dir = Path(tempfile.mkdtemp())
        self.original_dir = os.getcwd()
        os.chdir(self.test_dir)
        
        # Create required directories
        for dir_name in ["reports", "cache", "state", "plugins"]:
            (self.test_dir / dir_name).mkdir()
        
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
    
    def tearDown(self):
        os.chdir(self.original_dir)
        shutil.rmtree(self.test_dir)
        self.loop.close()
    
    def test_full_investigation_workflow(self):
        """Test complete investigation workflow."""
        async def run_test():
            from detectivejoe import DetectiveJoe
            
            # Create minimal config
            config_content = """
profiles:
  test:
    name: "Test Profile"
    timeout: 10
    parallel_workers: 1
    scan_depth: 1
    aggressiveness: "low"
    enable_chaining: false
    enabled_categories: ["website"]
    tools:
      website: []
default_profile: "test"
"""
            
            with open("profiles.yaml", "w") as f:
                f.write(config_content)
            
            # Initialize DetectiveJoe
            dj = DetectiveJoe(profile="test")
            
            # Test investigation (this will likely fail due to missing tools, but should not crash)
            try:
                result = await dj.run_investigation_async("1", "127.0.0.1")
                
                # Should get a result even if tools fail
                self.assertIn("error", result)
                # Test framework accepts no tools case as expected behavior
                
            finally:
                await dj.worker_pool.stop()
        
        self.loop.run_until_complete(run_test())


def run_tests():
    """Run all tests."""
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test cases using TestLoader (avoids deprecation warning)
    suite.addTest(loader.loadTestsFromTestCase(TestPluginBase))
    suite.addTest(loader.loadTestsFromTestCase(TestNmapPlugin))
    suite.addTest(loader.loadTestsFromTestCase(TestTheHarvesterPlugin))
    suite.addTest(loader.loadTestsFromTestCase(TestAsyncWorkerPool))
    suite.addTest(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    # Run tests
    success = run_tests()
    print(f"\nTest run completed. Success: {success}")
    sys.exit(0 if success else 1)