"""Dynamic Task Queue for AI Agent scanning mode.

Provides a priority-based async task queue that supports runtime task injection,
enabling AI agents to spawn new tasks as they discover new targets or need verification.
"""

from __future__ import annotations

import asyncio
import heapq
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from trix.engine.scan_task import ScanTask

logger = logging.getLogger(__name__)


# Configuration
DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_QUEUE_SIZE = 1000


@dataclass(order=True)
class PrioritizedTask:
    """Wrapper for priority queue ordering."""
    priority: int
    sequence: int  # For FIFO within same priority
    task: "ScanTask" = field(compare=False)


class DynamicTaskQueue:
    """Priority-based async task queue with depth limiting.
    
    Features:
    - Priority ordering (critical > high > normal > low)
    - Async put/get with proper locking
    - Depth limiting to prevent runaway recursion
    - Task deduplication by target
    
    Example:
        queue = DynamicTaskQueue()
        await queue.put(ScanTask(...))
        task = await queue.get()
    """
    
    def __init__(
        self,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_size: int = DEFAULT_MAX_QUEUE_SIZE,
    ):
        """Initialize the queue.
        
        Args:
            max_depth: Maximum task depth (prevents infinite recursion)
            max_size: Maximum queue size
        """
        self._heap: list[PrioritizedTask] = []
        self._lock = asyncio.Lock()
        self._not_empty = asyncio.Condition(self._lock)
        self._sequence = 0  # For FIFO ordering within same priority
        
        self.max_depth = max_depth
        self.max_size = max_size
        
        # Track seen targets to avoid duplicates
        self._seen_targets: set[str] = set()
        
        # Statistics
        self.stats = {
            "tasks_added": 0,
            "tasks_completed": 0,
            "tasks_rejected_depth": 0,
            "tasks_rejected_duplicate": 0,
        }
    
    async def put(self, task: "ScanTask") -> bool:
        """Add a task to the queue.
        
        Args:
            task: Task to add
            
        Returns:
            True if task was added, False if rejected
        """
        # Check depth limit
        if task.depth > self.max_depth:
            logger.warning(
                f"Task rejected: depth {task.depth} exceeds max {self.max_depth} "
                f"(task_id={task.task_id}, target={task.target})"
            )
            self.stats["tasks_rejected_depth"] += 1
            return False
        
        # Check for duplicate targets (optional, can be disabled)
        target_key = f"{task.task_type.value}:{task.target}"
        if target_key in self._seen_targets:
            logger.debug(f"Task rejected: duplicate target {target_key}")
            self.stats["tasks_rejected_duplicate"] += 1
            return False
        
        # Check queue size
        async with self._not_empty:
            if len(self._heap) >= self.max_size:
                logger.warning(f"Queue full ({self.max_size}), rejecting task")
                return False
            
            self._sequence += 1
            heapq.heappush(
                self._heap,
                PrioritizedTask(task.priority.value, self._sequence, task)
            )
            self._seen_targets.add(target_key)
            self.stats["tasks_added"] += 1
            self._not_empty.notify()
        
        logger.debug(
            f"[TaskQueue] Added task: {task.task_type.value} "
            f"priority={task.priority.name} depth={task.depth} target={task.target[:50]}"
        )
        return True
    
    async def get(self, timeout: float | None = None) -> "ScanTask":
        """Get the highest priority task.
        
        Args:
            timeout: Optional timeout in seconds
            
        Returns:
            Next task to execute
            
        Raises:
            asyncio.TimeoutError: If timeout expires with no tasks
        """
        async with self._not_empty:
            while not self._heap:
                if timeout is not None:
                    await asyncio.wait_for(
                        self._not_empty.wait(),
                        timeout=timeout,
                    )
                else:
                    await self._not_empty.wait()
            
            prioritized = heapq.heappop(self._heap)
            self.stats["tasks_completed"] += 1
            return prioritized.task
    
    def get_nowait(self) -> "ScanTask | None":
        """Get a task without waiting.
        
        Returns:
            Task or None if queue is empty
        """
        if not self._heap:
            return None
        prioritized = heapq.heappop(self._heap)
        self.stats["tasks_completed"] += 1
        return prioritized.task
    
    def empty(self) -> bool:
        """Check if queue is empty."""
        return len(self._heap) == 0
    
    def qsize(self) -> int:
        """Get queue size."""
        return len(self._heap)
    
    def clear_seen(self) -> None:
        """Clear the seen targets set (allow re-scanning)."""
        self._seen_targets.clear()
    
    def get_stats(self) -> dict[str, int]:
        """Get queue statistics."""
        return {
            **self.stats,
            "queue_size": len(self._heap),
            "seen_targets": len(self._seen_targets),
        }


class TaskQueueManager:
    """Manages task queues for multiple scans."""
    
    def __init__(self):
        self._queues: dict[str, DynamicTaskQueue] = {}
    
    def get_queue(self, scan_id: str) -> DynamicTaskQueue:
        """Get or create a queue for a scan."""
        if scan_id not in self._queues:
            self._queues[scan_id] = DynamicTaskQueue()
        return self._queues[scan_id]
    
    def remove_queue(self, scan_id: str) -> None:
        """Remove a scan's queue."""
        self._queues.pop(scan_id, None)
    
    def list_queues(self) -> list[str]:
        """List all scan IDs with active queues."""
        return list(self._queues.keys())


# Global instance
_queue_manager: TaskQueueManager | None = None


def get_queue_manager() -> TaskQueueManager:
    """Get the global queue manager."""
    global _queue_manager
    if _queue_manager is None:
        _queue_manager = TaskQueueManager()
    return _queue_manager
