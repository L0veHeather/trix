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
from trix.engine.phase_manager import PhaseManager, PhaseConfig
from trix.engine.result_collector import ResultCollector

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
    2. Phase orchestration through PhaseManager
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
        self._phase_managers: dict[str, PhaseManager] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        
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
        
        # Create phase manager
        phase_manager = PhaseManager(self._registry, self._event_bus)
        
        # Configure phases based on scan config
        for phase in config.phases:
            phase_config = PhaseConfig(
                phase=phase,
                plugins=config.plugins if config.plugins else [],
                continue_on_error=config.continue_on_error,
                parameters=config.plugin_params,
            )
            phase_manager.set_phase_config(phase_config)
        
        self._phase_managers[scan_id] = phase_manager
        
        # Start scan task
        task = asyncio.create_task(self._run_scan(scan_id))
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
