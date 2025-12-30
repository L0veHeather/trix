"""Scan Engine - Main orchestrator for security scans.

The ScanEngine coordinates all scanning activities:
- Plugin orchestration through PhaseManager
- Result collection and storage
- Event distribution
- Scan lifecycle management
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from trix.plugins.base import ScanPhase
from trix.plugins.registry import PluginRegistry, get_plugin_registry
from trix.engine.event_bus import EventBus, Event, EventType, get_event_bus
from trix.models.phase import PhaseConfig
from trix.engine.result_collector import ResultCollector
from trix.engine.scan_task import ScanTask, TaskType, TaskPriority
from trix.engine.task_queue import DynamicTaskQueue
from trix.brain.llm_judge import LLMJudge
from trix.brain.openai_judge import OpenAIJudge
from trix.core.llm_controller import ScanController as AIController
from trix.models.request import ScanTarget

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

logger = logging.getLogger(__name__)


class ScanStatus(str, Enum):
    """Status of a scan."""
    
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanConfig:
    """Configuration for a scan."""
    
    target: str
    name: str | None = None
    scan_id: str | None = None  # Optional: use existing scan_id from database
    
    # Phase configuration
    phases: list[ScanPhase] = field(default_factory=lambda: [
        ScanPhase.RECONNAISSANCE,
        ScanPhase.ENUMERATION,
        ScanPhase.VULNERABILITY_SCAN,
        ScanPhase.VALIDATION,
    ])
    
    # Plugin selection (if empty, uses all available for each phase)
    plugins: list[str] = field(default_factory=list)
    
    # Plugin-specific parameters
    plugin_params: dict[str, dict[str, Any]] = field(default_factory=dict)
    
    # Execution options
    parallel_phases: bool = False
    continue_on_error: bool = True
    timeout_seconds: int = 7200  # 2 hours
    
    # Output options
    output_dir: Path | None = None
    auto_export: bool = True
    export_formats: list[str] = field(default_factory=lambda: ["json", "markdown"])
    
    # Authentication profiles for privilege escalation testing
    # Each profile contains headers/cookies for a specific user role
    auth_profiles: list[Any] = field(default_factory=list)  # list[AuthProfile]
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "name": self.name,
            "phases": [p.value for p in self.phases],
            "plugins": self.plugins,
            "plugin_params": self.plugin_params,
            "parallel_phases": self.parallel_phases,
            "continue_on_error": self.continue_on_error,
            "timeout_seconds": self.timeout_seconds,
            "output_dir": str(self.output_dir) if self.output_dir else None,
            "auto_export": self.auto_export,
            "export_formats": self.export_formats,
        }


@dataclass
class ScanState:
    """Current state of a scan."""
    
    scan_id: str
    config: ScanConfig
    status: ScanStatus = ScanStatus.PENDING
    current_phase: ScanPhase | None = None
    progress: float = 0.0  # 0-100
    
    started_at: datetime | None = None
    completed_at: datetime | None = None
    
    error: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "config": self.config.to_dict(),
            "status": self.status.value,
            "current_phase": self.current_phase.value if self.current_phase else None,
            "progress": self.progress,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
        }


class ScanEngine:
    """Main scan engine that orchestrates security assessments.
    
    The engine manages the complete lifecycle of a scan:
    1. Initialization and validation
    2. AI-driven task loop orchestration via ScanController
    3. Result collection and aggregation
    4. Event distribution for UI updates
    5. Export and reporting
    
    Example:
        engine = ScanEngine()
        await engine.initialize()
        
        # Start a scan
        scan_id = await engine.start_scan(ScanConfig(
            target="https://example.com",
            phases=[ScanPhase.RECONNAISSANCE, ScanPhase.VULNERABILITY_SCAN]
        ))
        
        # Monitor progress
        async for event in engine.get_events(scan_id):
            print(event)
        
        # Get results
        results = engine.get_results(scan_id)
    """
    
    def __init__(
        self,
        plugin_registry: PluginRegistry | None = None,
        event_bus: EventBus | None = None,
    ):
        self._registry = plugin_registry or get_plugin_registry()
        self._event_bus = event_bus or get_event_bus()
        
        self._scans: dict[str, ScanState] = {}
        self._collectors: dict[str, ResultCollector] = {}
        self._scan_controllers: dict[str, Any] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        
        # Dynamic task queue support
        self._task_queues: dict[str, DynamicTaskQueue] = {}
        self._active_task_ids: dict[str, set[str]] = {}
        
        # LLM controller references for verification task pump
        self._llm_controllers: dict[str, Any] = {}
        self._llm_judge: LLMJudge | None = None
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the engine and plugin registry."""
        if self._initialized:
            return
        
        logger.info("Initializing scan engine...")
        
        # Initialize plugin registry
        await self._registry.initialize()
        
        # Start event bus
        await self._event_bus.start()
        
        # Initialize LLM Judge (lazily or here)
        try:
            self._llm_judge = OpenAIJudge()
        except Exception as e:
            logger.warning(f"Failed to initialize LLM Judge: {e}")
            
        self._initialized = True
        logger.info("Scan engine initialized")
    
    async def shutdown(self) -> None:
        """Shutdown the engine and cleanup resources."""
        logger.info("Shutting down scan engine...")
        
        # Cancel all running scans
        for scan_id in list(self._tasks.keys()):
            await self.cancel_scan(scan_id)
        
        # Stop event bus
        await self._event_bus.stop()
        
        self._initialized = False
        logger.info("Scan engine shutdown complete")
    
    async def start_scan(self, config: ScanConfig) -> str:
        """Start a new scan.
        
        Args:
            config: Scan configuration
            
        Returns:
            Scan ID
        """
        if not self._initialized:
            await self.initialize()
        
        # Use provided scan_id or generate new one
        scan_id = config.scan_id or str(uuid.uuid4())[:8]
        
        # Create scan state
        state = ScanState(
            scan_id=scan_id,
            config=config,
            status=ScanStatus.PENDING,
        )
        self._scans[scan_id] = state
        
        # Create result collector
        collector = ResultCollector(scan_id, config.target)
        self._collectors[scan_id] = collector
        # PhaseManager is no longer used, AI-Native flow handles orchestration via ScanController
        pass
        
        # Initialize dynamic task queue
        task_queue = DynamicTaskQueue()
        self._task_queues[scan_id] = task_queue
        self._active_task_ids[scan_id] = set()
        
        # Add initial phase tasks to queue
        for phase in config.phases:
            phase_task = ScanTask.create_phase_task(
                scan_id=scan_id,
                target=config.target,
                phase=phase.value,
            )
            await task_queue.put(phase_task)
        
        logger.info(f"Queued {len(config.phases)} phase tasks for scan {scan_id}")
        
        # Start scan task loop
        task = asyncio.create_task(self._run_scan_loop(scan_id))
        self._tasks[scan_id] = task
        
        logger.info(f"Started scan {scan_id} for target: {config.target}")
        
        return scan_id
    
    async def _run_scan(self, scan_id: str) -> None:
        """Internal method to run a scan."""
        from trix.storage import get_database, ScanStatus as DbScanStatus
        
        state = self._scans[scan_id]
        config = state.config
        collector = self._collectors[scan_id]
        phase_manager = self._phase_managers[scan_id]
        db = get_database()
        
        state.status = ScanStatus.RUNNING
        state.started_at = datetime.now(timezone.utc)
        
        # Sync to database
        db.update_scan(scan_id, status=DbScanStatus.RUNNING)
        
        # Emit scan started event
        await self._event_bus.publish(Event(
            type=EventType.SCAN_STARTED,
            scan_id=scan_id,
            data={"target": config.target, "phases": [p.value for p in config.phases]},
        ))
        
        try:
            total_phases = len(config.phases)
            completed_phases_set: set[str] = set()
            
            async for result in phase_manager.execute_all(
                config.target,
                scan_id,
                config.phases,
            ):
                # Track unique completed phases
                phase_value = result.phase.value
                if phase_value not in completed_phases_set:
                    completed_phases_set.add(phase_value)
                
                # Update state
                state.current_phase = result.phase
                completed_count = len(completed_phases_set)
                state.progress = min((completed_count / total_phases) * 100, 100)  # Cap at 100%
                
                # Sync progress to database
                db.update_scan(
                    scan_id,
                    current_phase=result.phase.value,
                    progress=state.progress,
                )
                
                # Collect findings in memory
                collector.add_findings(result.findings)
                collector.mark_phase_completed(result.phase)
                
                # Save phase result to database
                db.add_phase_result(
                    scan_id=scan_id,
                    phase=result.phase.value,
                    status=result.status.value,
                    duration_ms=result.duration_ms,
                    plugins_executed=result.plugins_executed,
                    findings_count=len(result.findings),
                    errors=result.errors,
                )
                
                # Save each finding to database
                for finding in result.findings:
                    db.add_vulnerability(
                        scan_id=scan_id,
                        title=finding.title,
                        severity=finding.severity,
                        description=finding.description,
                        url=finding.url,
                        plugin_name=finding.plugin_name,
                        cve_id=getattr(finding, 'cve_id', None),
                        evidence=getattr(finding, 'evidence', None),
                        phase=result.phase.value,
                    )
                
                # Check for cancellation
                if state.status == ScanStatus.CANCELLED:
                    break
            
            # Mark completed
            if state.status != ScanStatus.CANCELLED:
                state.status = ScanStatus.COMPLETED
            
            state.completed_at = datetime.now(timezone.utc)
            state.current_phase = None
            state.progress = 100
            
            # Sync to database
            db.update_scan(
                scan_id,
                status=DbScanStatus.COMPLETED,
                current_phase=None,
                progress=100,
                completed=True,
            )
            
            collector.mark_scan_completed()
            
            # Auto-export results
            if config.auto_export:
                await self._export_results(scan_id)
            
            # Emit scan completed event
            await self._event_bus.publish(Event(
                type=EventType.SCAN_COMPLETED,
                scan_id=scan_id,
                data=collector.get_summary().to_dict(),
            ))
            
        except asyncio.CancelledError:
            state.status = ScanStatus.CANCELLED
            db.update_scan(scan_id, status=DbScanStatus.CANCELLED)
            await self._event_bus.publish(Event(
                type=EventType.SCAN_CANCELLED,
                scan_id=scan_id,
                data={},
            ))
            
        except Exception as e:
            logger.exception(f"Scan {scan_id} failed")
            state.status = ScanStatus.FAILED
            state.error = str(e)
            
            db.update_scan(
                scan_id,
                status=DbScanStatus.FAILED,
                error_message=str(e),
            )
            
            await self._event_bus.publish(Event(
                type=EventType.SCAN_FAILED,
                scan_id=scan_id,
                data={"error": str(e)},
            ))
        
        finally:
            # Cleanup task reference
            self._tasks.pop(scan_id, None)
            self._task_queues.pop(scan_id, None)
            self._active_task_ids.pop(scan_id, None)
    
    async def _run_scan_loop(self, scan_id: str) -> None:
        """Dynamic task loop - supports runtime task injection.
        
        This replaces the linear _run_scan for AI Agent mode,
        allowing new tasks to be added during execution.
        """
        from trix.storage import get_database, ScanStatus as DbScanStatus
        
        state = self._scans[scan_id]
        config = state.config
        collector = self._collectors[scan_id]
        phase_manager = self._phase_managers[scan_id]
        task_queue = self._task_queues[scan_id]
        active_tasks = self._active_task_ids[scan_id]
        db = get_database()
        
        state.status = ScanStatus.RUNNING
        state.started_at = datetime.now(timezone.utc)
        
        db.update_scan(scan_id, status=DbScanStatus.RUNNING)
        
        await self._event_bus.publish(Event(
            type=EventType.SCAN_STARTED,
            scan_id=scan_id,
            data={"target": config.target, "phases": [p.value for p in config.phases]},
        ))
        
        completed_phases: set[str] = set()
        total_initial_tasks = task_queue.qsize()
        tasks_completed = 0
        
        total_initial_tasks = task_queue.qsize()
        tasks_completed = 0
        
        try:
            executor = None  # Safely disable legacy executor

            # Initialize AI Controller
            logger.info("[MIGRATION] Switching to AI-Native ScanController flow")
            llm_judge = self._llm_judge
            scan_controller = AIController(llm_judge=llm_judge)
            await scan_controller.__aenter__()
            
            # Dynamic task loop
            while not task_queue.empty() or active_tasks:
                # Check for cancellation
                if state.status == ScanStatus.CANCELLED:
                    break
                
                # 🔥 任务泵: 优先处理 AI 验证请求
                # 从 llm_controller 获取待处理的验证任务并注入队列
                verification_tasks = self._get_pending_verification_tasks(scan_id)
                for v_task in verification_tasks:
                    # 将 VerificationTask 转换为 ScanTask 并插队
                    ai_scan_task = ScanTask(
                        scan_id=scan_id,
                        task_type=TaskType.VERIFICATION,
                        target=v_task.target_url,
                        priority=TaskPriority.HIGH,  # 高优先级插队
                        parameters={
                            "verification_task": v_task.to_dict(),
                            "vuln_type": v_task.vuln_type,
                            "verification_payload": v_task.verification_payload,
                            "expected_behavior": v_task.expected_behavior,
                        },
                        parent_task_id=v_task.parent_task_id,
                        depth=v_task.depth + 1,
                    )
                    await task_queue.put(ai_scan_task)
                    
                    # 发射 AI_INTERVENTION 事件通知前端
                    await self._event_bus.publish(Event(
                        type=EventType.AI_INTERVENTION,
                        scan_id=scan_id,
                        data={
                            "task_id": ai_scan_task.task_id,
                            "vuln_type": v_task.vuln_type,
                            "target": v_task.target_url,
                            "message": f"🤖 AI 正在验证一个可疑的 {v_task.vuln_type}...",
                            "verification_payload": v_task.verification_payload[:50]
                                if v_task.verification_payload else "",
                        },
                    ))
                    logger.info(
                        f"[AI-Task] Injected verification task for {v_task.vuln_type}: "
                        f"{v_task.target_url[:50]}"
                    )
                
                try:
                    # Get next task with timeout
                    scan_task = await asyncio.wait_for(
                        task_queue.get(),
                        timeout=5.0,
                    )
                except asyncio.TimeoutError:
                    # No tasks available, check if we should continue
                    if not active_tasks:
                        break
                    continue
                
                # Check for cancellation
                if state.status == ScanStatus.CANCELLED:
                    break
                
                active_tasks.add(scan_task.task_id)
                
                try:
                    # Execute task
                    result, new_tasks = await self._execute_task(
                        task=scan_task,
                        default_target=config.target,
                        scan_controller=scan_controller,
                    )
                    
                    # Update progress
                    tasks_completed += 1
                    # Total estimated work = tasks_completed + current_queue_size
                    total_estimated = tasks_completed + task_queue.qsize()
                    progress = min(99, int((tasks_completed / max(1, total_estimated)) * 100))
                    state.progress = progress
                    db.update_scan(scan_id, progress=progress)
                    
                    if result:
                        # Track phase completion
                        phase_value = result.phase.value
                        if phase_value not in completed_phases:
                            completed_phases.add(phase_value)
                        
                        state.current_phase = result.phase
                        
                        db.update_scan(
                            scan_id,
                            current_phase=result.phase.value,
                            progress=state.progress,
                        )
                        
                        # Collect findings
                        collector.add_findings(result.findings)
                        collector.mark_phase_completed(result.phase)
                        
                        # Save to database
                        db.add_phase_result(
                            scan_id=scan_id,
                            phase=result.phase.value,
                            status=result.status.value,
                            duration_ms=result.duration_ms,
                            plugins_executed=result.plugins_executed,
                            findings_count=len(result.findings),
                            errors=result.errors,
                        )
                        
                        for finding in result.findings:
                            db.add_vulnerability(
                                scan_id=scan_id,
                                title=finding.title,
                                severity=finding.severity,
                                description=finding.description,
                                url=finding.url,
                                plugin_name=finding.plugin_name,
                                cve_id=getattr(finding, 'cve_id', None),
                                evidence=getattr(finding, 'evidence', None),
                                phase=result.phase.value,
                            )
                    
                    # Add newly discovered tasks to queue
                    for new_task in new_tasks:
                        added = await task_queue.put(new_task)
                        if added:
                            logger.info(
                                f"[TaskQueue] New task discovered: {new_task.task_type.value} "
                                f"-> {new_task.target[:50]}"
                            )
                
                finally:
                    active_tasks.discard(scan_task.task_id)
            
            # Mark completed
            if state.status != ScanStatus.CANCELLED:
                state.status = ScanStatus.COMPLETED
            
            state.completed_at = datetime.now(timezone.utc)
            state.current_phase = None
            state.progress = 100
            
            db.update_scan(
                scan_id,
                status=DbScanStatus.COMPLETED,
                current_phase=None,
                progress=100,
                completed=True,
            )
            
            collector.mark_scan_completed()
            
            # Log queue stats
            queue_stats = task_queue.get_stats()
            logger.info(
                f"Scan {scan_id} completed. Queue stats: "
                f"added={queue_stats['tasks_added']}, completed={queue_stats['tasks_completed']}"
            )
            
            if config.auto_export:
                await self._export_results(scan_id)
            
            await self._event_bus.publish(Event(
                type=EventType.SCAN_COMPLETED,
                scan_id=scan_id,
                data=collector.get_summary().to_dict(),
            ))
            
        except asyncio.CancelledError:
            state.status = ScanStatus.CANCELLED
            db.update_scan(scan_id, status=DbScanStatus.CANCELLED)
            await self._event_bus.publish(Event(
                type=EventType.SCAN_CANCELLED,
                scan_id=scan_id,
                data={},
            ))
            
        except Exception as e:
            logger.exception(f"Scan {scan_id} failed")
            state.status = ScanStatus.FAILED
            state.error = str(e)
            
            db.update_scan(
                scan_id,
                status=DbScanStatus.FAILED,
                error_message=str(e),
            )
            
            await self._event_bus.publish(Event(
                type=EventType.SCAN_FAILED,
                scan_id=scan_id,
                data={"error": str(e)},
            ))
        
        finally:
            if 'scan_controller' in locals():
                await scan_controller.__aexit__(None, None, None)
            if 'executor' in locals():
                await executor.__aexit__(None, None, None)
                
            self._tasks.pop(scan_id, None)
            self._task_queues.pop(scan_id, None)
            self._active_task_ids.pop(scan_id, None)
    
    async def _execute_task(
        self,
        task: ScanTask,
        default_target: str,
        scan_controller: ScanController | None = None,
    ) -> tuple[PhaseResult | None, list[ScanTask]]:
        """Execute a single task and return result + new tasks."""
        if not scan_controller:
            return None, []
        
        phase = task.phase
        # Use provided target or default to scan root target
        target_url = task.target or default_target
        
        import time
        import traceback
        
        new_tasks: list[ScanTask] = []
        result = None
        start_time = time.time()
        
        logger.debug(
            f"[Task] Executing: {task.task_type.value} "
            f"depth={task.depth} target={task.target[:50]}"
        )
        
        # 🔥 发射 TASK_STARTED 事件
        await self._event_bus.publish(Event(
            type=EventType.TASK_STARTED,
            scan_id=task.scan_id,
            data={
                "task_id": task.task_id,
                "task_type": task.task_type.value,
                "target": task.target,
                "phase": task.phase,
                "plugin": task.plugin,
                "depth": task.depth,
            },
        ))
        
        try:
            if task.task_type == TaskType.PHASE:
                # Execute full phase
                phase = ScanPhase(task.phase)
                
                # Node 2: AI Semantic Parameter Guessing (Enumeration Phase)
                if phase == ScanPhase.ENUMERATION and executor:
                    try:
                        from trix.brain.param_guesser import LLMParamGuesser
                        
                        # Fetch page content for context
                        logger.info(f"[ParamGuesser] Fetching context for {task.target}")
                        req_task = ScanTask(
                            scan_id=task.scan_id,
                            task_type=TaskType.URL,
                            target=task.target,
                            method="GET"
                        )
                        response = await executor.execute_request(req_task)
                        content = response.get("body", "")
                        
                        if content:
                            guesser = LLMParamGuesser()
                            guessed_params = await guesser.guess_parameters(
                                url=task.target,
                                method="GET",
                                page_content=content
                            )
                            
                            if guessed_params:
                                # Emit event for visibility
                                await self._event_bus.publish(Event(
                                    type=EventType.AI_INTERVENTION,
                                    scan_id=task.scan_id,
                                    data={
                                        "message": f"🤖 AI Guessed Parameters: {', '.join(guessed_params)}",
                                        "target": task.target,
                                        "params": guessed_params
                                    }
                                ))
                                
                                # Store for plugins to use (via phase specific mechanic or just log)
                                logger.info(f"[ParamGuesser] Guessed: {guessed_params}")
                                # TODO: pass to plugins via PhaseConfig updates or Shared State
                    except Exception as e:
                        logger.warning(f"AI Param Guessing failed: {e}")

                if not scan_controller:
                     raise RuntimeError("ScanController not initialized")

                # Reroute to AI Controller
                phase_config = phase_manager.get_phase_config(phase)
                active_plugins = []
                for p_name in phase_config.plugins:
                    p = self._registry.get_plugin(p_name)
                    if p: active_plugins.append(p)
                
                logger.debug(f"[AI Flow] Phase: {phase}, Config plugins: {phase_config.plugins}, Active plugins: {[p.name for p in active_plugins]}")

                findings = []
                collector = self._collectors[task.scan_id]
                
                # === [NEW FLOW] AI-Native Execution ===
                async for finding in scan_controller.scan(
                    ScanTarget(task.target),
                    plugins=active_plugins
                ):
                    # [ADAPTER] Streaming Adapter - Ensure legacy compatibility
                    
                    # Synthesize missing legacy fields
                    if not hasattr(finding, "title"):
                        finding.title = f"{finding.vuln_type.replace('_', ' ').title()}"
                    if not hasattr(finding, "severity"):
                        finding.severity = finding.risk_level.value
                    if not hasattr(finding, "description"):
                        finding.description = getattr(finding, "llm_reasoning", "No description")
                    if not hasattr(finding, "url"):
                        finding.url = finding.target
                    
                    # 1. Store in ResultCollector (Semantic Deduplication applied here)
                    logger.info(f"[🔮TRACER] 5. ✅ Vulnerability Confirmed & Stored! Type={finding.vuln_type}, Target={finding.target}")
                    collector.add_finding(finding)
                    
                    # 2. Emit Event for UI/Frontend
                    event_data = finding.to_dict()
                    # Ensure title is in event data for UI
                    if "title" not in event_data:
                        event_data["title"] = finding.title
                    if "severity" not in event_data:
                        event_data["severity"] = finding.severity
                        
                    await self._event_bus.publish(Event(
                        type=EventType.VULNERABILITY_FOUND,
                        scan_id=task.scan_id,
                        data=event_data
                    ))
                    
                    # 3. Keep for PhaseResult compatibility
                    findings.append(finding)
                # === [END NEW FLOW] ===
                
                # Construct PhaseResult manually from AI findings
                from trix.models.phase import PhaseResult, PhaseStatus
                result = PhaseResult(
                    phase=phase,
                    status=PhaseStatus.COMPLETED,
                    duration_ms=int((time.time() - start_time) * 1000),
                    plugins_executed=[p.name for p in active_plugins],
                    findings=findings
                )


                
                # Bridge: Extract AI verification tasks
                if hasattr(result, 'verification_tasks') and result.verification_tasks:
                   for v_task_dict in result.verification_tasks:
                       # Create verification task
                       v_task = ScanTask.create_verification_task(
                           scan_id=task.scan_id,
                           target=v_task_dict.get("target_url", task.target),
                           verification_payload=v_task_dict.get("verification_payload", ""),
                           expected_behavior=v_task_dict.get("expected_behavior", ""),
                           parent_task_id=task.task_id,
                           depth=task.depth + 1,
                       )
                       # Add extra metadata
                       v_task.parameters["vuln_type"] = v_task_dict.get("vuln_type")
                       
                       new_tasks.append(v_task)
                       logger.info(f"[Bridge] Scheduled verification task for {v_task_dict.get('vuln_type')}")

                # Extract new targets from result (discovered URLs, subdomains)
                if hasattr(result, 'discovered_targets') and result.discovered_targets:
                    for new_target in result.discovered_targets[:10]:  # Limit
                        new_tasks.append(ScanTask(
                            scan_id=task.scan_id,
                            task_type=TaskType.URL,
                            target=new_target,
                            priority=TaskPriority.LOW,
                            parent_task_id=task.task_id,
                            depth=task.depth + 1,
                        ))
            
            elif task.task_type == TaskType.VERIFICATION:
                # LLM verification task - handled by separate controller
                logger.info(
                    f"[Verification] Task {task.task_id}: "
                    f"payload={task.parameters.get('verification_payload', '')[:50]}..."
                )
                # TODO: Integrate with LLMController
            
            elif task.task_type in (TaskType.URL, TaskType.SUBDOMAIN):
                # Special handling for IDOR tests
                if task.parameters.get("idor_test") and executor:
                    from trix.plugins.vulns.idor import IDORPlugin
                    from trix.core.scan_phase import PhaseResult
                    
                    logger.info(f"[IDOR] Executing IDOR check for {task.target}")
                    plugin = IDORPlugin()
                    finding = await plugin.execute_check(
                        executor=executor,
                        target_url=task.target,
                        original_value=task.parameters.get("original_value", ""),
                        modified_value=task.parameters.get("modified_value", ""),
                        vuln_type=task.parameters.get("vuln_type", "idor"),
                    )
                    
                    if finding:
                        # Wrap finding in PhaseResult
                        result = PhaseResult(
                            phase=ScanPhase.VULNERABILITY_SCAN,
                            status="completed",
                            findings=[finding],
                        )
                        logger.warning(f"[IDOR] VULNERABILITY FOUND: {task.target}")
                    else:
                        result = PhaseResult(phase=ScanPhase.VULNERABILITY_SCAN, status="completed")
                        
                else:
                    # Scan new target with vulnerability phase
                    phase = ScanPhase.VULNERABILITY_SCAN
                    result = await phase_manager.execute_phase(
                        phase,
                        task.target,
                        task.scan_id,
                    )
            
            elif task.task_type == TaskType.LOGIC_ANALYSIS:
                # 🔥 Business logic vulnerability analysis
                from trix.brain.logic_agent import get_business_logic_agent, IntendedAction
                
                agent = get_business_logic_agent()
                
                # Feed collected endpoints from parameters
                endpoints = task.parameters.get("endpoints", [])
                if endpoints:
                    agent.feed_endpoints(endpoints)
                
                # Analyze and generate IDOR test tasks
                async for action in agent.analyze():
                    # Convert IntendedAction to ScanTask
                    idor_task = ScanTask(
                        scan_id=task.scan_id,
                        task_type=TaskType.URL,  # Execute as URL scan
                        target=action.path,
                        priority=TaskPriority.NORMAL,
                        parameters={
                            "idor_test": True,
                            "original_path": action.original_path,
                            "vuln_type": action.vuln_type.value,
                            "original_value": action.original_value,
                            "modified_value": action.modified_value,
                        },
                        parent_task_id=task.task_id,
                        depth=task.depth + 1,
                    )
                    new_tasks.append(idor_task)
                    
                    # Emit AI_INTERVENTION event for visibility
                    await self._event_bus.publish(Event(
                        type=EventType.AI_INTERVENTION,
                        scan_id=task.scan_id,
                        data={
                            "task_id": idor_task.task_id,
                            "vuln_type": action.vuln_type.value,
                            "target": action.path,
                            "message": f"🧠 AI 正在测试 IDOR: 将 {action.original_value} 修改为 {action.modified_value}",
                        },
                    ))
                
                logger.info(
                    f"[LogicAgent] Generated {len(new_tasks)} IDOR test tasks "
                    f"from {len(endpoints)} endpoints"
                )
            
            # 🔥 发射 TASK_FINISHED 事件
            duration_ms = int((time.time() - start_time) * 1000)
            findings_count = len(result.findings) if result and hasattr(result, 'findings') else 0
            
            await self._event_bus.publish(Event(
                type=EventType.TASK_FINISHED,
                scan_id=task.scan_id,
                data={
                    "task_id": task.task_id,
                    "task_type": task.task_type.value,
                    "status": "completed",
                    "duration_ms": duration_ms,
                    "findings_count": findings_count,
                },
            ))
            
        except Exception as e:
            # 🔥 发射 TASK_FAILED 事件
            duration_ms = int((time.time() - start_time) * 1000)
            
            await self._event_bus.publish(Event(
                type=EventType.TASK_FAILED,
                scan_id=task.scan_id,
                data={
                    "task_id": task.task_id,
                    "task_type": task.task_type.value,
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                    "duration_ms": duration_ms,
                },
            ))
            
            logger.error(f"[Task] Failed: {task.task_id} - {e}")
            # Re-raise to be handled by caller
            raise
        
        return result, new_tasks
    
    async def inject_task(self, scan_id: str, task: ScanTask) -> bool:
        """Inject a task into a running scan's queue.
        
        This can be called by LLMController or other components
        to add verification tasks or new discoveries.
        
        Returns:
            True if task was added, False if scan not found or queue full
        """
        queue = self._task_queues.get(scan_id)
        if queue is None:
            logger.warning(f"Cannot inject task: scan {scan_id} not found")
            return False
        
        return await queue.put(task)
    
    def _get_pending_verification_tasks(self, scan_id: str) -> list:
        """Get pending verification tasks from LLMController.
        
        This is called each iteration of the task loop to check for
        new verification tasks generated by the AI feedback loop.
        
        Returns:
            List of VerificationTask objects to inject into the queue
        """
        # Check if we have an LLM controller registered for this scan
        llm_controller = self._llm_controllers.get(scan_id)
        if llm_controller is None:
            return []
        
        # Get pending tasks from the controller's verification queue
        pending = []
        try:
            # Pop all pending tasks from the deque
            while llm_controller._verification_queue:
                task = llm_controller._verification_queue.popleft()
                pending.append(task)
        except (AttributeError, IndexError):
            pass
        
        return pending
    
    def register_llm_controller(self, scan_id: str, controller: Any) -> None:
        """Register an LLM controller for a scan.
        
        This allows the task loop to pull verification tasks from the controller.
        """
        if not hasattr(self, '_llm_controllers'):
            self._llm_controllers: dict[str, Any] = {}
        self._llm_controllers[scan_id] = controller
        logger.debug(f"Registered LLM controller for scan {scan_id}")
    
    def unregister_llm_controller(self, scan_id: str) -> None:
        """Unregister an LLM controller for a scan."""
        if hasattr(self, '_llm_controllers'):
            self._llm_controllers.pop(scan_id, None)
    
    async def _export_results(self, scan_id: str) -> None:
        """Export scan results to configured formats."""
        config = self._scans[scan_id].config
        collector = self._collectors[scan_id]
        
        # Determine output directory
        output_dir = config.output_dir or Path.home() / ".trix" / "scans" / scan_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        for fmt in config.export_formats:
            if fmt == "json":
                collector.export_json(output_dir / "results.json")
            elif fmt == "markdown":
                collector.export_markdown(output_dir / "report.md")
            elif fmt == "sarif":
                collector.export_sarif(output_dir / "results.sarif")
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan.
        
        Returns:
            True if cancellation was initiated
        """
        state = self._scans.get(scan_id)
        if state is None:
            return False
        
        if state.status != ScanStatus.RUNNING:
            return False
        
        state.status = ScanStatus.CANCELLED
        
        # Cancel phase manager
        phase_manager = self._phase_managers.get(scan_id)
        if phase_manager:
            phase_manager.cancel()
        
        # Cancel task
        task = self._tasks.get(scan_id)
        if task:
            task.cancel()
        
        logger.info(f"Cancelled scan {scan_id}")
        return True
    
    async def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan.
        
        Returns:
            True if scan was stopped successfully
        """
        return await self.cancel_scan(scan_id)
    
    async def pause_scan(self, scan_id: str) -> bool:
        """Pause a running scan.
        
        Returns:
            True if scan was paused successfully
        """
        from trix.storage import get_database, ScanStatus as DbScanStatus
        
        state = self._scans.get(scan_id)
        if state is None:
            # Try to get from database if not in memory
            db = get_database()
            scan = db.get_scan(scan_id)
            if scan and scan.status.value == 'running':
                db.update_scan(scan_id, status=DbScanStatus.PAUSED)
                return True
            return False
        
        if state.status != ScanStatus.RUNNING:
            return False
        
        state.status = ScanStatus.PAUSED
        
        # Update database
        db = get_database()
        db.update_scan(scan_id, status=DbScanStatus.PAUSED)
        
        # Emit pause event
        await self._event_bus.publish(Event(
            type=EventType.SCAN_PAUSED,
            scan_id=scan_id,
            data={},
        ))
        
        logger.info(f"Paused scan {scan_id}")
        return True
    
    async def resume_scan(self, scan_id: str) -> bool:
        """Resume a paused scan.
        
        Returns:
            True if scan was resumed successfully
        """
        from trix.storage import get_database, ScanStatus as DbScanStatus
        
        state = self._scans.get(scan_id)
        if state is None:
            # Try to get from database if not in memory
            db = get_database()
            scan = db.get_scan(scan_id)
            if scan and scan.status.value == 'paused':
                db.update_scan(scan_id, status=DbScanStatus.RUNNING)
                return True
            return False
        
        if state.status != ScanStatus.PAUSED:
            return False
        
        state.status = ScanStatus.RUNNING
        
        # Update database
        db = get_database()
        db.update_scan(scan_id, status=DbScanStatus.RUNNING)
        
        # Emit resume event
        await self._event_bus.publish(Event(
            type=EventType.SCAN_RESUMED,
            scan_id=scan_id,
            data={},
        ))
        
        logger.info(f"Resumed scan {scan_id}")
        return True
    
    def get_scan_state(self, scan_id: str) -> ScanState | None:
        """Get the current state of a scan."""
        return self._scans.get(scan_id)
    
    def get_results(self, scan_id: str) -> ResultCollector | None:
        """Get the result collector for a scan."""
        return self._collectors.get(scan_id)
    
    def list_scans(self) -> list[dict[str, Any]]:
        """List all scans with their states."""
        return [state.to_dict() for state in self._scans.values()]
    
    def subscribe_events(
        self,
        scan_id: str,
        handler,
    ) -> None:
        """Subscribe to events for a specific scan."""
        def filtered_handler(event: Event):
            if event.scan_id == scan_id:
                handler(event)
        
        self._event_bus.subscribe_all(filtered_handler)
    
    def get_event_bus(self) -> EventBus:
        """Get the event bus for direct subscription."""
        return self._event_bus


# Global engine instance
_engine: ScanEngine | None = None


def get_scan_engine() -> ScanEngine:
    """Get the global scan engine instance."""
    global _engine
    if _engine is None:
        _engine = ScanEngine()
    return _engine


def set_scan_engine(engine: ScanEngine) -> None:
    """Set the global scan engine instance."""
    global _engine
    _engine = engine
