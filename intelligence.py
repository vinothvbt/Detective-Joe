#!/usr/bin/env python3
"""
Detective Joe v1.5 - Intelligence Engine
Artifact management, deduplication, CVE matching, and enrichment system.
"""

import hashlib
import json
import re
import logging
from datetime import datetime
from typing import Dict, Any, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Artifact:
    """Represents a reconnaissance artifact."""
    id: str
    type: str  # email, domain, ip, port, service, vulnerability, etc.
    value: str
    source_plugin: str
    target: str
    category: str
    confidence: float  # 0.0 to 1.0
    timestamp: str
    tags: List[str]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert artifact to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Artifact':
        """Create artifact from dictionary."""
        return cls(**data)


class ArtifactDatabase:
    """In-memory artifact database with persistence."""
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize artifact database.
        
        Args:
            storage_path: Path to persist artifacts (optional)
        """
        self.artifacts: Dict[str, Artifact] = {}
        self.artifacts_by_type: Dict[str, Set[str]] = {}
        self.artifacts_by_source: Dict[str, Set[str]] = {}
        self.storage_path = storage_path
        self.logger = logging.getLogger("dj.intelligence.db")
        
        if self.storage_path and self.storage_path.exists():
            self.load_from_disk()
    
    def add_artifact(self, artifact: Artifact) -> str:
        """
        Add artifact to database.
        
        Args:
            artifact: Artifact to add
            
        Returns:
            Artifact ID
        """
        self.artifacts[artifact.id] = artifact
        
        # Update indices
        if artifact.type not in self.artifacts_by_type:
            self.artifacts_by_type[artifact.type] = set()
        self.artifacts_by_type[artifact.type].add(artifact.id)
        
        if artifact.source_plugin not in self.artifacts_by_source:
            self.artifacts_by_source[artifact.source_plugin] = set()
        self.artifacts_by_source[artifact.source_plugin].add(artifact.id)
        
        return artifact.id
    
    def get_artifact(self, artifact_id: str) -> Optional[Artifact]:
        """Get artifact by ID."""
        return self.artifacts.get(artifact_id)
    
    def get_artifacts_by_type(self, artifact_type: str) -> List[Artifact]:
        """Get all artifacts of a specific type."""
        if artifact_type not in self.artifacts_by_type:
            return []
        
        return [self.artifacts[aid] for aid in self.artifacts_by_type[artifact_type]]
    
    def get_artifacts_by_source(self, source_plugin: str) -> List[Artifact]:
        """Get all artifacts from a specific source plugin."""
        if source_plugin not in self.artifacts_by_source:
            return []
        
        return [self.artifacts[aid] for aid in self.artifacts_by_source[source_plugin]]
    
    def find_similar_artifacts(self, artifact: Artifact, threshold: float = 0.8) -> List[Artifact]:
        """Find similar artifacts based on value and type."""
        similar = []
        for existing in self.artifacts.values():
            if (existing.type == artifact.type and 
                existing.value.lower() == artifact.value.lower() and
                existing.id != artifact.id):
                similar.append(existing)
        return similar
    
    def save_to_disk(self) -> None:
        """Save artifacts to disk."""
        if not self.storage_path:
            return
        
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                'artifacts': {aid: artifact.to_dict() for aid, artifact in self.artifacts.items()},
                'saved_at': datetime.now().isoformat()
            }
            
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            self.logger.info(f"Saved {len(self.artifacts)} artifacts to {self.storage_path}")
            
        except Exception as e:
            self.logger.error(f"Error saving artifacts: {e}")
    
    def load_from_disk(self) -> None:
        """Load artifacts from disk."""
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            
            self.artifacts.clear()
            self.artifacts_by_type.clear()
            self.artifacts_by_source.clear()
            
            for aid, artifact_data in data.get('artifacts', {}).items():
                artifact = Artifact.from_dict(artifact_data)
                self.add_artifact(artifact)
            
            self.logger.info(f"Loaded {len(self.artifacts)} artifacts from {self.storage_path}")
            
        except Exception as e:
            self.logger.error(f"Error loading artifacts: {e}")


class IntelligenceEngine:
    """Intelligence engine for artifact processing and enrichment."""
    
    def __init__(self, storage_dir: Optional[Path] = None):
        """
        Initialize intelligence engine.
        
        Args:
            storage_dir: Directory for persistent storage
        """
        self.storage_dir = storage_dir or Path("state/intelligence")
        self.artifact_db = ArtifactDatabase(self.storage_dir / "artifacts.json")
        self.logger = logging.getLogger("dj.intelligence")
        
        # CVE pattern for vulnerability matching
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        
    def process_plugin_results(self, results: Dict[str, Any], target: str, category: str) -> List[Artifact]:
        """
        Process plugin results and extract artifacts.
        
        Args:
            results: Plugin execution results
            target: Investigation target
            category: Investigation category
            
        Returns:
            List of extracted artifacts
        """
        artifacts = []
        
        for task_id, result in results.items():
            if result.get("status") != "completed" or not result.get("result"):
                continue
            
            plugin_name = result.get("plugin", "unknown")
            parsed_data = result.get("result", {}).get("parsed_data", {})
            
            # Extract artifacts from parsed data
            plugin_artifacts = self._extract_artifacts_from_parsed_data(
                parsed_data, plugin_name, target, category
            )
            
            artifacts.extend(plugin_artifacts)
        
        # Deduplicate and add to database
        deduplicated = self._deduplicate_artifacts(artifacts)
        
        for artifact in deduplicated:
            self.artifact_db.add_artifact(artifact)
        
        self.logger.info(f"Processed {len(artifacts)} artifacts, {len(deduplicated)} after deduplication")
        return deduplicated
    
    def _extract_artifacts_from_parsed_data(
        self, 
        parsed_data: Dict[str, Any], 
        plugin_name: str, 
        target: str, 
        category: str
    ) -> List[Artifact]:
        """Extract artifacts from plugin parsed data."""
        artifacts = []
        timestamp = datetime.now().isoformat()
        
        # Email extraction
        if "emails" in parsed_data:
            for email in parsed_data["emails"]:
                artifact = Artifact(
                    id=self._generate_artifact_id("email", email),
                    type="email",
                    value=email,
                    source_plugin=plugin_name,
                    target=target,
                    category=category,
                    confidence=0.8,
                    timestamp=timestamp,
                    tags=["email", "contact"],
                    metadata={"domain": email.split("@")[1] if "@" in email else ""}
                )
                artifacts.append(artifact)
        
        # Domain/host extraction
        if "hosts" in parsed_data:
            for host in parsed_data["hosts"]:
                artifact = Artifact(
                    id=self._generate_artifact_id("domain", host),
                    type="domain",
                    value=host,
                    source_plugin=plugin_name,
                    target=target,
                    category=category,
                    confidence=0.9,
                    timestamp=timestamp,
                    tags=["domain", "infrastructure"],
                    metadata={}
                )
                artifacts.append(artifact)
        
        # IP extraction
        if "ips" in parsed_data:
            for ip in parsed_data["ips"]:
                artifact = Artifact(
                    id=self._generate_artifact_id("ip", ip),
                    type="ip",
                    value=ip,
                    source_plugin=plugin_name,
                    target=target,
                    category=category,
                    confidence=0.9,
                    timestamp=timestamp,
                    tags=["ip", "infrastructure"],
                    metadata={}
                )
                artifacts.append(artifact)
        
        # Port/service extraction
        if "open_ports" in parsed_data:
            for port_info in parsed_data["open_ports"]:
                if isinstance(port_info, dict) and port_info.get("state") == "open":
                    port_value = f"{port_info.get('port', 'unknown')}/{port_info.get('protocol', 'tcp')}"
                    artifact = Artifact(
                        id=self._generate_artifact_id("port", port_value),
                        type="port",
                        value=port_value,
                        source_plugin=plugin_name,
                        target=target,
                        category=category,
                        confidence=0.95,
                        timestamp=timestamp,
                        tags=["port", "service", "network"],
                        metadata={
                            "service": port_info.get("service", ""),
                            "host": port_info.get("host", target)
                        }
                    )
                    artifacts.append(artifact)
        
        # Service extraction
        if "services" in parsed_data:
            for service_info in parsed_data["services"]:
                if isinstance(service_info, dict):
                    service_name = service_info.get("service", "unknown")
                    artifact = Artifact(
                        id=self._generate_artifact_id("service", service_name),
                        type="service",
                        value=service_name,
                        source_plugin=plugin_name,
                        target=target,
                        category=category,
                        confidence=0.85,
                        timestamp=timestamp,
                        tags=["service", "network"],
                        metadata=service_info
                    )
                    artifacts.append(artifact)
        
        # People extraction
        if "people" in parsed_data:
            for person in parsed_data["people"]:
                artifact = Artifact(
                    id=self._generate_artifact_id("person", person),
                    type="person",
                    value=person,
                    source_plugin=plugin_name,
                    target=target,
                    category=category,
                    confidence=0.7,
                    timestamp=timestamp,
                    tags=["person", "osint"],
                    metadata={}
                )
                artifacts.append(artifact)
        
        # URL extraction
        if "urls" in parsed_data:
            for url in parsed_data["urls"]:
                artifact = Artifact(
                    id=self._generate_artifact_id("url", url),
                    type="url",
                    value=url,
                    source_plugin=plugin_name,
                    target=target,
                    category=category,
                    confidence=0.8,
                    timestamp=timestamp,
                    tags=["url", "web"],
                    metadata={}
                )
                artifacts.append(artifact)
        
        return artifacts
    
    def _generate_artifact_id(self, artifact_type: str, value: str) -> str:
        """Generate unique artifact ID."""
        content = f"{artifact_type}:{value.lower()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _deduplicate_artifacts(self, artifacts: List[Artifact]) -> List[Artifact]:
        """Remove duplicate artifacts."""
        seen_ids = set()
        deduplicated = []
        
        for artifact in artifacts:
            # Check for exact duplicates
            if artifact.id in seen_ids:
                continue
            
            # Check for similar existing artifacts
            similar = self.artifact_db.find_similar_artifacts(artifact)
            if similar:
                # Merge with highest confidence similar artifact
                best_similar = max(similar, key=lambda a: a.confidence)
                if artifact.confidence > best_similar.confidence:
                    # Update existing artifact
                    best_similar.confidence = artifact.confidence
                    best_similar.tags = list(set(best_similar.tags + artifact.tags))
                    best_similar.metadata.update(artifact.metadata)
                continue
            
            seen_ids.add(artifact.id)
            deduplicated.append(artifact)
        
        return deduplicated
    
    def enrich_artifacts_with_cve(self, artifacts: List[Artifact]) -> None:
        """Enrich artifacts with CVE information."""
        for artifact in artifacts:
            if artifact.type in ["service", "port"]:
                # Look for CVE patterns in service information
                service_text = f"{artifact.value} {artifact.metadata.get('service', '')}"
                cves = self.cve_pattern.findall(service_text)
                
                if cves:
                    artifact.tags.append("vulnerability")
                    artifact.metadata["cves"] = list(set(cves))
                    self.logger.info(f"Found CVEs for {artifact.value}: {cves}")
    
    def get_chainable_artifacts(self, category: str) -> Dict[str, List[str]]:
        """
        Get artifacts suitable for chaining to new plugins.
        
        Args:
            category: Investigation category
            
        Returns:
            Dictionary mapping artifact types to values
        """
        chainable = {
            "domains": [],
            "ips": [],
            "emails": [],
            "hostnames": [],
            "organizations": [],
            "people_names": []
        }
        
        # Map artifacts to chainable types
        for artifact in self.artifact_db.artifacts.values():
            if artifact.type == "domain":
                chainable["domains"].append(artifact.value)
                chainable["hostnames"].append(artifact.value)
            elif artifact.type == "ip":
                chainable["ips"].append(artifact.value)
            elif artifact.type == "email":
                chainable["emails"].append(artifact.value)
                # Extract organization from email domain
                if "@" in artifact.value:
                    domain = artifact.value.split("@")[1]
                    chainable["organizations"].append(domain)
            elif artifact.type == "person":
                chainable["people_names"].append(artifact.value)
        
        # Remove duplicates
        for key in chainable:
            chainable[key] = list(set(chainable[key]))
        
        return chainable
    
    def tag_artifacts(self, tag: str, filter_func: callable) -> int:
        """
        Tag artifacts matching a filter function.
        
        Args:
            tag: Tag to add
            filter_func: Function that returns True for artifacts to tag
            
        Returns:
            Number of artifacts tagged
        """
        count = 0
        for artifact in self.artifact_db.artifacts.values():
            if filter_func(artifact) and tag not in artifact.tags:
                artifact.tags.append(tag)
                count += 1
        
        return count
    
    def get_artifacts_summary(self) -> Dict[str, Any]:
        """Get summary statistics of all artifacts."""
        summary = {
            "total_artifacts": len(self.artifact_db.artifacts),
            "by_type": {},
            "by_source": {},
            "by_tags": {},
            "recent_artifacts": []
        }
        
        # Count by type
        for artifact_type, artifact_ids in self.artifact_db.artifacts_by_type.items():
            summary["by_type"][artifact_type] = len(artifact_ids)
        
        # Count by source
        for source, artifact_ids in self.artifact_db.artifacts_by_source.items():
            summary["by_source"][source] = len(artifact_ids)
        
        # Count by tags
        tag_counts = {}
        for artifact in self.artifact_db.artifacts.values():
            for tag in artifact.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        summary["by_tags"] = tag_counts
        
        # Recent artifacts (last 10)
        sorted_artifacts = sorted(
            self.artifact_db.artifacts.values(),
            key=lambda a: a.timestamp,
            reverse=True
        )
        summary["recent_artifacts"] = [
            {"id": a.id, "type": a.type, "value": a.value, "source": a.source_plugin}
            for a in sorted_artifacts[:10]
        ]
        
        return summary
    
    def save_state(self) -> None:
        """Save intelligence engine state to disk."""
        self.artifact_db.save_to_disk()