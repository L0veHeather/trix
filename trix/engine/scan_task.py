"""Scan Task - Data structures for dynamic task queue.

Defines task types and priorities for the AI Agent scanning mode.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaskType(str, Enum):
    """Types of scan tasks."""
    
    PHASE = "phase"                    # Execute a complete scan phase
    PLUGIN = "plugin"                  # Execute a single plugin
    VERIFICATION = "verification"      # LLM verification task
    SUBDOMAIN = "subdomain"            # Subdomain scan
    URL = "url"                        # Scan a discovered URL
    PARAMETER = "parameter"            # Test a specific parameter
    LOGIC_ANALYSIS = "logic_analysis"  # Business logic vulnerability analysis


class TaskPriority(int, Enum):
    """Task priority levels (lower value = higher priority)."""
    
    CRITICAL = 0    # Immediate execution (e.g., confirmed vuln verification)
    HIGH = 10       # High priority (e.g., LLM verification tasks)
    NORMAL = 50     # Normal priority (e.g., standard phase execution)
    LOW = 100       # Low priority (e.g., background discovery)


@dataclass
class ScanTask:
    """A single task in the dynamic scan queue.
    
    Attributes:
        task_id: Unique identifier for this task
        scan_id: Parent scan ID
        task_type: Type of task to execute
        target: Target URL or IP
        priority: Execution priority
        phase: Phase name (for PHASE tasks)
        plugin: Plugin name (for PLUGIN tasks)
        parameters: Task-specific parameters
        parent_task_id: ID of the task that spawned this one
        depth: How deep in the task chain (for recursion limiting)
    """
    
    scan_id: str
    task_type: TaskType
    target: str
    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    priority: TaskPriority = TaskPriority.NORMAL
    
    # Task-specific fields
    phase: str | None = None
    plugin: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    
    # Lineage tracking
    parent_task_id: str | None = None
    depth: int = 0
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "task_id": self.task_id,
            "scan_id": self.scan_id,
            "task_type": self.task_type.value,
            "target": self.target,
            "priority": self.priority.value,
            "phase": self.phase,
            "plugin": self.plugin,
            "parameters": self.parameters,
            "parent_task_id": self.parent_task_id,
            "depth": self.depth,
        }
    
    @classmethod
    def create_phase_task(
        cls,
        scan_id: str,
        target: str,
        phase: str,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> ScanTask:
        """Factory method for phase tasks."""
        return cls(
            scan_id=scan_id,
            task_type=TaskType.PHASE,
            target=target,
            phase=phase,
            priority=priority,
        )
    
    @classmethod
    def create_verification_task(
        cls,
        scan_id: str,
        target: str,
        verification_payload: str,
        expected_behavior: str,
        parent_task_id: str | None = None,
        depth: int = 0,
    ) -> ScanTask:
        """Factory method for LLM verification tasks."""
        return cls(
            scan_id=scan_id,
            task_type=TaskType.VERIFICATION,
            target=target,
            priority=TaskPriority.HIGH,
            parameters={
                "verification_payload": verification_payload,
                "expected_behavior": expected_behavior,
            },
            parent_task_id=parent_task_id,
            depth=depth,
        )
    
    @classmethod
    def create_subdomain_task(
        cls,
        scan_id: str,
        subdomain: str,
        parent_task_id: str | None = None,
        depth: int = 0,
    ) -> ScanTask:
        """Factory method for subdomain discovery tasks."""
        return cls(
            scan_id=scan_id,
            task_type=TaskType.SUBDOMAIN,
            target=subdomain,
            priority=TaskPriority.NORMAL,
            parent_task_id=parent_task_id,
            depth=depth,
        )
