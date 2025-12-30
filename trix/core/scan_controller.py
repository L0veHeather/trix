"""Scan Controller - Deterministic Flow Control for Security Scans.

This module provides the core flow control mechanism for security scans.
The ScanController is the single source of truth for:
- Task queue management
- Phase transitions
- Vulnerability reporting
- Progress tracking

The LLM does NOT control flow decisions - only the ScanController does.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from collections import deque
from typing import Any

from trix.core.scan_phase import ScanPhase, ScanTask

logger = logging.getLogger(__name__)


# Phase execution order
PHASE_ORDER = [
    ScanPhase.ENUMERATION,
    ScanPhase.PARAM_EXPANSION,
    ScanPhase.VULNERABILITY_TEST,
    ScanPhase.LLM_VERIFICATION,
    ScanPhase.DEEP_ANALYSIS,
    ScanPhase.SUMMARY,
]

# Default HTTP methods to test
DEFAULT_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]


class ScanController:
    """Deterministic scan flow controller.
    
    This class manages all scanning state and flow decisions.
    The LLM is NOT allowed to make flow decisions - it only executes
    tasks assigned by this controller.
    
    Thread-safe: All state modifications are protected by locks.
    """
    
    def __init__(
        self,
        initial_target: str,
        seed: int | None = None,
    ):
        """Initialize scan controller.
        
        Args:
            initial_target: Primary target URL
            seed: Optional random seed for reproducible scans
        """
        self._lock = threading.Lock()
        
        # Seed for reproducibility
        self._seed = seed
        if seed is not None:
            random.seed(seed)
        
        # Target info
        self._initial_target = initial_target
        
        # Phase management
        self._current_phase_index = 0
        
        # Task queue (thread-safe deque)
        self._task_queue: deque[ScanTask] = deque()
        self._completed_tasks: list[ScanTask] = []
        self._active_tasks: dict[str, float] = {}  # task_id -> start_time
        
        # Discovery tracking
        self._discovered_urls: set[str] = {initial_target}
        self._discovered_params: set[str] = set()
        
        # Vulnerability tracking
        self._suspected_vulnerabilities: list[dict[str, Any]] = []
        self._vulnerabilities: list[dict[str, Any]] = []
        
        # Progress tracking
        self._last_progress_time: float | None = None
        self._total_tasks_created = 0
        
        # HTTP methods to test
        self._http_methods = DEFAULT_HTTP_METHODS.copy()
        
        # Initialize with initial enumeration task
        self._add_initial_tasks()
        
        logger.debug(
            f"ScanController initialized: target={initial_target}, "
            f"seed={seed}, initial_tasks={len(self._task_queue)}"
        )
    
    def _add_initial_tasks(self) -> None:
        """Add initial enumeration tasks for the target."""
        initial_task = ScanTask(
            url=self._initial_target,
            method="GET",
            phase=ScanPhase.ENUMERATION,
            source="initial",
        )
        self._task_queue.append(initial_task)
        self._total_tasks_created += 1
    
    # ========== Properties ==========
    
    @property
    def current_phase(self) -> ScanPhase:
        """Get current scan phase."""
        with self._lock:
            return PHASE_ORDER[self._current_phase_index]
    
    @property
    def task_queue(self) -> list[ScanTask]:
        """Get copy of current task queue."""
        with self._lock:
            return list(self._task_queue)
    
    @property
    def http_methods(self) -> list[str]:
        """Get HTTP methods being tested."""
        return self._http_methods.copy()
    
    @property
    def discovered_urls(self) -> set[str]:
        """Get copy of discovered URLs."""
        with self._lock:
            return self._discovered_urls.copy()
    
    @property
    def discovered_params(self) -> set[str]:
        """Get copy of discovered parameters."""
        with self._lock:
            return self._discovered_params.copy()
    
    @property
    def vulnerabilities(self) -> list[dict[str, Any]]:
        """Get copy of confirmed vulnerabilities."""
        with self._lock:
            return self._vulnerabilities.copy()
    
    @property
    def active_tasks(self) -> dict[str, float]:
        """Get copy of active tasks with start times."""
        with self._lock:
            return self._active_tasks.copy()
    
    # ========== Task Management ==========
    
    def get_next_task(self) -> ScanTask | None:
        """Get next task from queue for current phase.
        
        Returns:
            Next task to execute, or None if no tasks available
        """
        with self._lock:
            current_phase = PHASE_ORDER[self._current_phase_index]
            
            # Find task matching current phase
            for i, task in enumerate(self._task_queue):
                if task.phase == current_phase:
                    # Remove and return this task
                    del self._task_queue[i]
                    return task
            
            return None
    
    def add_task(self, task: ScanTask) -> None:
        """Add a new task to the queue.
        
        Args:
            task: Task to add
        """
        with self._lock:
            # Deduplicate by signature
            existing_signatures = {t.signature() for t in self._task_queue}
            completed_signatures = {t.signature() for t in self._completed_tasks}
            
            if task.signature() not in existing_signatures and task.signature() not in completed_signatures:
                self._task_queue.append(task)
                self._total_tasks_created += 1
                logger.debug(f"Task added: {task.method} {task.url} (phase={task.phase.value})")
    
    def start_task(self, task: ScanTask) -> None:
        """Mark task as started (for heartbeat visibility).
        
        Args:
            task: Task being started
        """
        with self._lock:
            self._active_tasks[task.task_id] = time.time()
            logger.info(
                f"[TaskState] task_id={task.task_id} "
                f"state=STARTED phase={task.phase.value} "
                f"url={task.url} method={task.method}"
            )
    
    def finish_task(self, task: ScanTask) -> None:
        """Mark task as finished.
        
        Args:
            task: Task that completed
        """
        with self._lock:
            start_time = self._active_tasks.get(task.task_id)
            duration_ms = int((time.time() - start_time) * 1000) if start_time else 0
            self._active_tasks.pop(task.task_id, None)
            self._completed_tasks.append(task)
            self._last_progress_time = time.time()
            logger.info(
                f"[TaskState] task_id={task.task_id} "
                f"state=FINISHED phase={task.phase.value} "
                f"duration_ms={duration_ms}"
            )
    
    def cleanup_stuck_tasks(self, timeout_seconds: float = 300.0) -> None:
        """Clean up tasks that have been running too long.
        
        Args:
            timeout_seconds: Timeout threshold in seconds
        """
        with self._lock:
            now = time.time()
            stuck_tasks = [
                task_id for task_id, start_time in self._active_tasks.items()
                if now - start_time > timeout_seconds
            ]
            
            for task_id in stuck_tasks:
                logger.warning(f"Cleaning up stuck task: {task_id}")
                del self._active_tasks[task_id]
    
    # ========== Phase Control ==========
    
    def is_scan_complete(self) -> bool:
        """Check if scan is complete.
        
        Returns:
            True if all phases are done and no tasks remain
        """
        with self._lock:
            # Check if we're at the last phase
            if self._current_phase_index >= len(PHASE_ORDER) - 1:
                # Check if queue is empty for current phase
                current_phase = PHASE_ORDER[self._current_phase_index]
                tasks_for_phase = [t for t in self._task_queue if t.phase == current_phase]
                return len(tasks_for_phase) == 0
            return False
    
    def should_transition_phase(self) -> bool:
        """Check if should transition to next phase.
        
        Returns:
            True if current phase is complete and should move to next
        """
        with self._lock:
            current_phase = PHASE_ORDER[self._current_phase_index]
            tasks_for_phase = [t for t in self._task_queue if t.phase == current_phase]
            
            # Transition if no more tasks for current phase
            return len(tasks_for_phase) == 0
    
    def transition_to_next_phase(self) -> bool:
        """Transition to next scan phase.
        
        Returns:
            True if transitioned successfully, False if already at last phase
        """
        with self._lock:
            if self._current_phase_index >= len(PHASE_ORDER) - 1:
                return False
            
            old_phase = PHASE_ORDER[self._current_phase_index]
            self._current_phase_index += 1
            new_phase = PHASE_ORDER[self._current_phase_index]
            
            # Generate tasks for new phase if needed
            self._generate_phase_tasks(new_phase)
            
            logger.info(f"Phase transition: {old_phase.value} -> {new_phase.value}")
            return True
    
    def _generate_phase_tasks(self, phase: ScanPhase) -> None:
        """Generate tasks for a new phase.
        
        Args:
            phase: Phase to generate tasks for
        """
        if phase == ScanPhase.PARAM_EXPANSION:
            # Create param expansion tasks for discovered URLs
            for url in self._discovered_urls:
                task = ScanTask(
                    url=url,
                    method="GET",
                    phase=ScanPhase.PARAM_EXPANSION,
                    source="phase_transition",
                )
                self._task_queue.append(task)
                self._total_tasks_created += 1
        
        elif phase == ScanPhase.VULNERABILITY_TEST:
            # Create vuln test tasks for discovered URLs
            vuln_types = ["sqli", "xss", "ssrf", "lfi", "rce"]
            for url in self._discovered_urls:
                for vuln_type in vuln_types:
                    task = ScanTask(
                        url=url,
                        method="GET",
                        phase=ScanPhase.VULNERABILITY_TEST,
                        source=f"vuln_test:{vuln_type}",
                    )
                    self._task_queue.append(task)
                    self._total_tasks_created += 1
        
        elif phase == ScanPhase.LLM_VERIFICATION:
            # Create verification tasks for suspected vulnerabilities
            for vuln in self._suspected_vulnerabilities:
                task = ScanTask(
                    url=vuln.get("url", self._initial_target),
                    method=vuln.get("method", "GET"),
                    parameters=vuln.get("parameters", {}),
                    phase=ScanPhase.LLM_VERIFICATION,
                    source=f"verify:{vuln.get('type', 'unknown')}",
                )
                # Store verification context
                task.verification_context = vuln  # type: ignore
                self._task_queue.append(task)
                self._total_tasks_created += 1
        
        elif phase == ScanPhase.DEEP_ANALYSIS:
            # Create single deep analysis task
            if self._vulnerabilities:
                task = ScanTask(
                    url=self._initial_target,
                    method="ANALYSIS",
                    phase=ScanPhase.DEEP_ANALYSIS,
                    source="deep_analysis",
                )
                self._task_queue.append(task)
                self._total_tasks_created += 1
        
        elif phase == ScanPhase.SUMMARY:
            # Create single summary task
            task = ScanTask(
                url=self._initial_target,
                method="REPORT",
                phase=ScanPhase.SUMMARY,
                source="summary",
            )
            self._task_queue.append(task)
            self._total_tasks_created += 1
    
    # ========== Discovery Management ==========
    
    def add_discovered_url(self, url: str) -> bool:
        """Add a discovered URL.
        
        Args:
            url: URL to add
            
        Returns:
            True if URL was new, False if already known
        """
        with self._lock:
            if url not in self._discovered_urls:
                self._discovered_urls.add(url)
                logger.debug(f"New URL discovered: {url}")
                return True
            return False
    
    def add_discovered_param(self, param: str) -> bool:
        """Add a discovered parameter.
        
        Args:
            param: Parameter name to add
            
        Returns:
            True if param was new, False if already known
        """
        with self._lock:
            if param not in self._discovered_params:
                self._discovered_params.add(param)
                logger.debug(f"New param discovered: {param}")
                return True
            return False
    
    # ========== Vulnerability Reporting ==========
    
    def add_suspected_vulnerability(self, vuln: dict[str, Any]) -> None:
        """Add a suspected vulnerability for later verification.
        
        Args:
            vuln: Vulnerability data
        """
        with self._lock:
            self._suspected_vulnerabilities.append(vuln)
            logger.info(f"Suspected vulnerability: {vuln.get('type', 'unknown')} at {vuln.get('url', 'unknown')}")
    
    def report_vulnerability(self, vuln: dict[str, Any]) -> None:
        """Report a confirmed vulnerability.
        
        Args:
            vuln: Confirmed vulnerability data
        """
        with self._lock:
            self._vulnerabilities.append(vuln)
            logger.info(f"VULNERABILITY CONFIRMED: {vuln.get('type', 'unknown')} at {vuln.get('url', 'unknown')}")
    
    # ========== State Queries ==========
    
    def get_progress_snapshot(self) -> dict[str, Any]:
        """Get current progress snapshot.
        
        Returns:
            Dict with completed, total, remaining counts
        """
        with self._lock:
            completed = len(self._completed_tasks)
            remaining = len(self._task_queue)
            total = completed + remaining
            
            return {
                "completed": completed,
                "total": total,
                "remaining": remaining,
            }
    
    def get_heartbeat_state(self) -> dict[str, Any]:
        """Get state for heartbeat monitoring.
        
        Returns:
            Dict with task counts and timing info
        """
        with self._lock:
            return {
                "tasks_pending": len(self._task_queue),
                "tasks_running": len(self._active_tasks),
                "tasks_finished": len(self._completed_tasks),
                "last_progress_time": self._last_progress_time,
            }
    
    def get_state_snapshot(self) -> dict[str, Any]:
        """获取当前系统完整状态快照（用于调试/可观测性）。
        
        线程安全。返回可JSON序列化的字典。
        
        Returns:
            Dict with complete system state
        """
        with self._lock:
            return {
                "timestamp": time.time(),
                "current_phase": PHASE_ORDER[self._current_phase_index].value,
                "task_queue_size": len(self._task_queue),
                "active_tasks": {
                    task_id: {"start_time": start_time, "age_s": int(time.time() - start_time)}
                    for task_id, start_time in self._active_tasks.items()
                },
                "completed_tasks_count": len(self._completed_tasks),
                "discovered_urls_count": len(self._discovered_urls),
                "discovered_params_count": len(self._discovered_params),
                "vulnerabilities_count": len(self._vulnerabilities),
                "suspected_vulnerabilities_count": len(self._suspected_vulnerabilities),
            }
    
    def get_scan_summary(self) -> dict[str, Any]:
        """Get final scan summary.
        
        Returns:
            Dict with scan results summary
        """
        with self._lock:
            return {
                "target": self._initial_target,
                "seed": self._seed,
                "total_tasks": self._total_tasks_created,
                "completed_tasks": len(self._completed_tasks),
                "discovered_urls": len(self._discovered_urls),
                "discovered_params": len(self._discovered_params),
                "suspected_vulnerabilities": len(self._suspected_vulnerabilities),
                "confirmed_vulnerabilities": len(self._vulnerabilities),
                "vulnerabilities": self._vulnerabilities.copy(),
            }
