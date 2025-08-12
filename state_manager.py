#!/usr/bin/env python3
"""
Detective Joe v1.5 - State Management System
Save/resume/kill functionality for investigation state persistence.
"""

import json
import signal
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging
import pickle


class InvestigationState:
    """Represents the state of an investigation."""
    
    def __init__(self):
        """Initialize investigation state."""
        self.state_id = None
        self.target = None
        self.category = None
        self.profile = None
        self.start_time = None
        self.end_time = None
        self.status = "inactive"  # inactive, running, paused, completed, failed, killed
        self.progress = 0.0
        self.completed_tasks = []
        self.pending_tasks = []
        self.failed_tasks = []
        self.artifacts = []
        self.plugin_results = {}
        self.chained_tasks = []
        self.error_log = []
        self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary for serialization."""
        return {
            "state_id": self.state_id,
            "target": self.target,
            "category": self.category,
            "profile": self.profile,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status": self.status,
            "progress": self.progress,
            "completed_tasks": self.completed_tasks,
            "pending_tasks": self.pending_tasks,
            "failed_tasks": self.failed_tasks,
            "chained_tasks": self.chained_tasks,
            "error_log": self.error_log,
            "metadata": self.metadata,
            "artifacts_count": len(self.artifacts)
        }
    
    def from_dict(self, data: Dict[str, Any]) -> None:
        """Load state from dictionary."""
        self.state_id = data.get("state_id")
        self.target = data.get("target")
        self.category = data.get("category")
        self.profile = data.get("profile")
        self.start_time = data.get("start_time")
        self.end_time = data.get("end_time")
        self.status = data.get("status", "inactive")
        self.progress = data.get("progress", 0.0)
        self.completed_tasks = data.get("completed_tasks", [])
        self.pending_tasks = data.get("pending_tasks", [])
        self.failed_tasks = data.get("failed_tasks", [])
        self.chained_tasks = data.get("chained_tasks", [])
        self.error_log = data.get("error_log", [])
        self.metadata = data.get("metadata", {})


class StateManager:
    """Manages investigation state persistence and recovery."""
    
    def __init__(self, state_dir: Path):
        """
        Initialize state manager.
        
        Args:
            state_dir: Directory for state files
        """
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger("dj.state")
        
        # Current state
        self.current_state = InvestigationState()
        self.kill_requested = False
        
        # Register signal handlers for graceful shutdown if requested
        if register_signal_handlers:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle termination signals."""
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.kill_requested = True
        
        if self.current_state.status == "running":
            self.current_state.status = "killed"
            self.save_current_state()
    
    def start_investigation(self, target: str, category: str, profile: str) -> str:
        """
        Start a new investigation and save initial state.
        
        Args:
            target: Investigation target
            category: Investigation category
            profile: Profile name
            
        Returns:
            State ID for this investigation
        """
        # Generate unique state ID
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        clean_target = "".join(c for c in target if c.isalnum() or c in ".-_")
        state_id = f"{clean_target}_{category}_{timestamp}"
        
        # Initialize state
        self.current_state = InvestigationState()
        self.current_state.state_id = state_id
        self.current_state.target = target
        self.current_state.category = category
        self.current_state.profile = profile
        self.current_state.start_time = datetime.now().isoformat()
        self.current_state.status = "running"
        
        # Save initial state
        self.save_current_state()
        
        self.logger.info(f"Started investigation {state_id}")
        return state_id
    
    def save_current_state(self) -> bool:
        """
        Save current investigation state to disk.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.current_state.state_id:
            return False
        
        try:
            # Save JSON state (human readable)
            json_path = self.state_dir / f"{self.current_state.state_id}.json"
            with open(json_path, 'w') as f:
                json.dump(self.current_state.to_dict(), f, indent=2)
            
            # Save binary state (complete with artifacts)
            pickle_path = self.state_dir / f"{self.current_state.state_id}.pkl"
            with open(pickle_path, 'wb') as f:
                pickle.dump(self.current_state, f)
            
            self.logger.debug(f"Saved state {self.current_state.state_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving state: {e}")
            return False
    
    def load_state(self, state_id: str) -> Optional[InvestigationState]:
        """
        Load investigation state from disk.
        
        Args:
            state_id: State ID to load
            
        Returns:
            Loaded investigation state or None if not found
        """
        try:
            # Try binary state first (complete)
            pickle_path = self.state_dir / f"{state_id}.pkl"
            if pickle_path.exists():
                with open(pickle_path, 'rb') as f:
                    state = pickle.load(f)
                self.logger.info(f"Loaded complete state {state_id}")
                return state
            
            # Fallback to JSON state
            json_path = self.state_dir / f"{state_id}.json"
            if json_path.exists():
                with open(json_path, 'r') as f:
                    data = json.load(f)
                
                state = InvestigationState()
                state.from_dict(data)
                self.logger.info(f"Loaded JSON state {state_id}")
                return state
            
            self.logger.warning(f"State {state_id} not found")
            return None
            
        except Exception as e:
            self.logger.error(f"Error loading state {state_id}: {e}")
            return None
    
    def resume_investigation(self, state_id: str) -> bool:
        """
        Resume a previously saved investigation.
        
        Args:
            state_id: State ID to resume
            
        Returns:
            True if resume is possible, False otherwise
        """
        state = self.load_state(state_id)
        if not state:
            return False
        
        # Check if resumable
        if state.status not in ["paused", "failed", "killed"]:
            self.logger.warning(f"Cannot resume investigation in status: {state.status}")
            return False
        
        # Set as current state
        self.current_state = state
        self.current_state.status = "running"
        self.save_current_state()
        
        self.logger.info(f"Resumed investigation {state_id}")
        return True
    
    def pause_investigation(self) -> bool:
        """
        Pause current investigation.
        
        Returns:
            True if paused successfully
        """
        if self.current_state.status != "running":
            return False
        
        self.current_state.status = "paused"
        self.save_current_state()
        
        self.logger.info(f"Paused investigation {self.current_state.state_id}")
        return True
    
    def complete_investigation(self, results: Dict[str, Any], artifacts: List[Any] = None) -> bool:
        """
        Mark investigation as completed and save final state.
        
        Args:
            results: Final investigation results
            artifacts: Discovered artifacts
            
        Returns:
            True if completed successfully
        """
        if self.current_state.status not in ["running", "paused"]:
            return False
        
        self.current_state.status = "completed"
        self.current_state.end_time = datetime.now().isoformat()
        self.current_state.progress = 100.0
        self.current_state.plugin_results = results
        if artifacts:
            self.current_state.artifacts = artifacts
        
        self.save_current_state()
        
        self.logger.info(f"Completed investigation {self.current_state.state_id}")
        return True
    
    def kill_investigation(self) -> bool:
        """
        Kill current investigation.
        
        Returns:
            True if killed successfully
        """
        if self.current_state.status not in ["running", "paused"]:
            return False
        
        self.current_state.status = "killed"
        self.current_state.end_time = datetime.now().isoformat()
        self.kill_requested = True
        self.save_current_state()
        
        self.logger.info(f"Killed investigation {self.current_state.state_id}")
        return True
    
    def update_progress(self, completed: int, total: int, current_task: str = None) -> None:
        """
        Update investigation progress.
        
        Args:
            completed: Number of completed tasks
            total: Total number of tasks
            current_task: Current task description
        """
        if total > 0:
            self.current_state.progress = (completed / total) * 100.0
        
        if current_task:
            self.current_state.metadata["current_task"] = current_task
        
        # Save progress periodically
        if completed % 5 == 0 or completed == total:
            self.save_current_state()
    
    def add_completed_task(self, task_id: str, plugin: str, status: str, duration: float) -> None:
        """Add a completed task to state."""
        task_info = {
            "task_id": task_id,
            "plugin": plugin,
            "status": status,
            "duration": duration,
            "completed_at": datetime.now().isoformat()
        }
        
        if status == "completed":
            self.current_state.completed_tasks.append(task_info)
        else:
            self.current_state.failed_tasks.append(task_info)
    
    def add_error(self, error: str, context: str = None) -> None:
        """Add an error to the error log."""
        error_info = {
            "error": error,
            "context": context,
            "timestamp": datetime.now().isoformat()
        }
        self.current_state.error_log.append(error_info)
    
    def list_saved_states(self) -> List[Dict[str, Any]]:
        """
        List all saved investigation states.
        
        Returns:
            List of state information dictionaries
        """
        states = []
        
        # Scan for JSON state files
        for json_file in self.state_dir.glob("*.json"):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                states.append({
                    "state_id": data.get("state_id"),
                    "target": data.get("target"),
                    "category": data.get("category"),
                    "profile": data.get("profile"),
                    "status": data.get("status"),
                    "start_time": data.get("start_time"),
                    "end_time": data.get("end_time"),
                    "progress": data.get("progress", 0.0),
                    "artifacts_count": data.get("artifacts_count", 0),
                    "file_path": str(json_file)
                })
                
            except Exception as e:
                self.logger.warning(f"Error reading state file {json_file}: {e}")
        
        # Sort by start time (newest first)
        states.sort(key=lambda x: x.get("start_time", ""), reverse=True)
        return states
    
    def cleanup_old_states(self, max_age_days: int = 30) -> int:
        """
        Clean up old state files.
        
        Args:
            max_age_days: Maximum age in days for state files
            
        Returns:
            Number of files cleaned up
        """
        current_time = time.time()
        max_age_seconds = max_age_days * 24 * 60 * 60
        cleaned_count = 0
        
        for state_file in self.state_dir.glob("*"):
            try:
                file_age = current_time - state_file.stat().st_mtime
                if file_age > max_age_seconds:
                    state_file.unlink()
                    cleaned_count += 1
                    self.logger.info(f"Cleaned up old state file: {state_file}")
            except Exception as e:
                self.logger.warning(f"Error cleaning up {state_file}: {e}")
        
        return cleaned_count
    
    def get_current_state_info(self) -> Dict[str, Any]:
        """Get current investigation state information."""
        return self.current_state.to_dict()
    
    def is_kill_requested(self) -> bool:
        """Check if kill has been requested."""
        return self.kill_requested