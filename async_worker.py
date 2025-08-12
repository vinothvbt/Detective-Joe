#!/usr/bin/env python3
"""
Detective Joe v1.5 - Async Worker Pool
Provides asynchronous task execution with worker pools for efficient reconnaissance.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional, Callable, Awaitable
from dataclasses import dataclass
from enum import Enum
import time


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """Represents a reconnaissance task."""
    id: str
    plugin_name: str
    target: str
    category: str
    kwargs: Dict[str, Any]
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    
    @property
    def duration(self) -> Optional[float]:
        """Get task duration in seconds."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None


class AsyncWorkerPool:
    """
    Asynchronous worker pool for executing reconnaissance tasks.
    
    Manages concurrent execution of plugins with configurable worker limits,
    timeouts, and result aggregation.
    """
    
    def __init__(self, max_workers: int = 4, default_timeout: int = 120):
        """
        Initialize the worker pool.
        
        Args:
            max_workers: Maximum number of concurrent workers
            default_timeout: Default timeout for tasks in seconds
        """
        self.max_workers = max_workers
        self.default_timeout = default_timeout
        self.logger = logging.getLogger("dj.worker_pool")
        
        # Task management
        self.tasks: Dict[str, Task] = {}
        self.task_queue: asyncio.Queue = asyncio.Queue()
        self.results: Dict[str, Dict[str, Any]] = {}
        
        # Worker management
        self.workers: List[asyncio.Task] = []
        self.running = False
        self.semaphore = asyncio.Semaphore(max_workers)
        
        # Statistics
        self.stats = {
            "tasks_submitted": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "tasks_timeout": 0,
            "total_execution_time": 0.0
        }
    
    async def start(self) -> None:
        """Start the worker pool."""
        if self.running:
            return
        
        self.running = True
        self.logger.info(f"Starting worker pool with {self.max_workers} workers")
        
        # Create worker tasks
        for i in range(self.max_workers):
            worker = asyncio.create_task(self._worker(f"worker-{i}"))
            self.workers.append(worker)
    
    async def stop(self) -> None:
        """Stop the worker pool and wait for all tasks to complete."""
        if not self.running:
            return
        
        self.logger.info("Stopping worker pool...")
        self.running = False
        
        # Cancel all workers
        for worker in self.workers:
            worker.cancel()
        
        # Wait for workers to finish
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
        
        self.logger.info("Worker pool stopped")
    
    async def submit_task(self, task: Task) -> str:
        """
        Submit a task for execution.
        
        Args:
            task: Task to execute
            
        Returns:
            Task ID
        """
        self.tasks[task.id] = task
        await self.task_queue.put(task)
        self.stats["tasks_submitted"] += 1
        
        self.logger.debug(f"Task {task.id} submitted: {task.plugin_name} -> {task.target}")
        return task.id
    
    async def execute_plugin_batch(
        self, 
        plugins: List[Any], 
        target: str, 
        category: str, 
        timeout: Optional[int] = None,
        **kwargs
    ) -> Dict[str, Dict[str, Any]]:
        """
        Execute a batch of plugins against a target.
        
        Args:
            plugins: List of plugin instances
            target: Target to investigate
            category: Investigation category
            timeout: Execution timeout
            **kwargs: Additional plugin arguments
            
        Returns:
            Dictionary of plugin results keyed by plugin name
        """
        if not self.running:
            await self.start()
        
        # Create tasks for each plugin
        tasks = []
        for plugin in plugins:
            task_id = f"{plugin.name}_{target}_{category}_{int(time.time() * 1000)}"
            task = Task(
                id=task_id,
                plugin_name=plugin.name,
                target=target,
                category=category,
                kwargs=kwargs
            )
            tasks.append(task)
            await self.submit_task(task)
        
        # Wait for all tasks to complete
        task_ids = [task.id for task in tasks]
        results = await self.wait_for_tasks(task_ids, timeout)
        
        return results
    
    async def wait_for_tasks(
        self, 
        task_ids: List[str], 
        timeout: Optional[int] = None
    ) -> Dict[str, Dict[str, Any]]:
        """
        Wait for specific tasks to complete.
        
        Args:
            task_ids: List of task IDs to wait for
            timeout: Maximum time to wait
            
        Returns:
            Dictionary of results keyed by task ID
        """
        wait_timeout = timeout or self.default_timeout
        start_time = time.time()
        
        while time.time() - start_time < wait_timeout:
            # Check if all tasks are complete
            pending_tasks = [
                task_id for task_id in task_ids
                if task_id in self.tasks and self.tasks[task_id].status in [TaskStatus.PENDING, TaskStatus.RUNNING]
            ]
            
            if not pending_tasks:
                break
            
            # Wait a bit before checking again
            await asyncio.sleep(0.1)
        
        # Collect results
        results = {}
        for task_id in task_ids:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                results[task_id] = {
                    "task_id": task_id,
                    "plugin": task.plugin_name,
                    "status": task.status.value,
                    "result": task.result,
                    "error": task.error,
                    "duration": task.duration
                }
        
        return results
    
    async def _worker(self, worker_name: str) -> None:
        """
        Worker coroutine that processes tasks from the queue.
        
        Args:
            worker_name: Name of the worker for logging
        """
        self.logger.debug(f"Worker {worker_name} started")
        
        while self.running:
            try:
                # Get task from queue with timeout
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                
                # Execute task
                await self._execute_task(task, worker_name)
                
                # Mark task as done
                self.task_queue.task_done()
                
            except asyncio.TimeoutError:
                # No tasks available, continue
                continue
            except Exception as e:
                self.logger.error(f"Worker {worker_name} error: {e}")
        
        self.logger.debug(f"Worker {worker_name} stopped")
    
    async def _execute_task(self, task: Task, worker_name: str) -> None:
        """
        Execute a single task.
        
        Args:
            task: Task to execute
            worker_name: Name of executing worker
        """
        async with self.semaphore:
            task.status = TaskStatus.RUNNING
            task.start_time = time.time()
            
            self.logger.debug(f"Worker {worker_name} executing task {task.id}")
            
            try:
                # Import plugins here to avoid circular imports
                from plugins import NmapPlugin, TheHarvesterPlugin

                # Register plugins if not already registered
                if not PLUGIN_REGISTRY:
                    PLUGIN_REGISTRY["nmap"] = NmapPlugin
                    PLUGIN_REGISTRY["theharvester"] = TheHarvesterPlugin

                # Get plugin instance from registry
                plugin_cls = PLUGIN_REGISTRY.get(task.plugin_name)
                if not plugin_cls:
                    raise ValueError(f"Unknown plugin: {task.plugin_name}")
                plugin = plugin_cls()
                
                # Execute plugin
                result = await plugin.execute(
                    task.target, 
                    task.category, 
                    timeout=self.default_timeout,
                    **task.kwargs
                )
                
                task.result = result
                task.status = TaskStatus.COMPLETED
                self.stats["tasks_completed"] += 1
                
            except asyncio.TimeoutError:
                task.status = TaskStatus.TIMEOUT
                task.error = f"Task timed out after {self.default_timeout} seconds"
                self.stats["tasks_timeout"] += 1
                
            except Exception as e:
                task.status = TaskStatus.FAILED
                task.error = str(e)
                self.stats["tasks_failed"] += 1
                self.logger.error(f"Task {task.id} failed: {e}")
            
            finally:
                task.end_time = time.time()
                if task.duration:
                    self.stats["total_execution_time"] += task.duration
                
                self.logger.debug(
                    f"Task {task.id} completed with status {task.status.value} "
                    f"in {task.duration:.2f}s"
                )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get worker pool statistics."""
        return {
            "max_workers": self.max_workers,
            "running": self.running,
            "active_tasks": len([t for t in self.tasks.values() if t.status == TaskStatus.RUNNING]),
            "queue_size": self.task_queue.qsize(),
            **self.stats
        }
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific task."""
        if task_id not in self.tasks:
            return None
        
        task = self.tasks[task_id]
        return {
            "id": task.id,
            "plugin": task.plugin_name,
            "target": task.target,
            "category": task.category,
            "status": task.status.value,
            "duration": task.duration,
            "error": task.error
        }