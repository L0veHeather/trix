"""Phase Manager for scan phase orchestration.

Manages the progression through scan phases and coordinates
plugin execution within each phase.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from trix.plugins.base import ScanPhase, PluginEvent, VulnerabilityFinding

if TYPE_CHECKING:
    from trix.plugins.registry import PluginRegistry
    from trix.plugins.registry import PluginRegistry
    from trix.engine.event_bus import EventBus
    from trix.brain.llm_judge import LLMJudge

from trix.models.judgment import JudgmentRequest
from trix.models.finding import ConfidenceLevel

logger = logging.getLogger(__name__)


class PhaseStatus(str, Enum):
    """Status of a scan phase."""
    
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PhaseConfig:
    """Configuration for a scan phase."""
    
    phase: ScanPhase
    enabled: bool = True
    plugins: list[str] = field(default_factory=list)
    parallel: bool = False
    timeout_seconds: int = 3600  # 1 hour default
    continue_on_error: bool = True
    parameters: dict[str, dict[str, Any]] = field(default_factory=dict)  # plugin -> params


@dataclass
class PhaseResult:
    """Result of a completed scan phase."""
    
    phase: ScanPhase
    status: PhaseStatus
    duration_ms: int
    plugins_executed: list[str] = field(default_factory=list)
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    findings: list[VulnerabilityFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    plugin_outputs: dict[str, str] = field(default_factory=dict)
    verification_tasks: list[dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "phase": self.phase.value,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "plugins_executed": self.plugins_executed,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "verification_tasks": self.verification_tasks,
        }


# Default phase configurations
DEFAULT_PHASE_CONFIGS: list[PhaseConfig] = [
    PhaseConfig(
        phase=ScanPhase.RECONNAISSANCE,
        plugins=["httpx", "katana"],
        parallel=True,
    ),
    PhaseConfig(
        phase=ScanPhase.ENUMERATION,
        plugins=["ffuf", "arjun"],
        parallel=False,
    ),
    PhaseConfig(
        phase=ScanPhase.VULNERABILITY_SCAN,
        plugins=["nuclei", "sqlmap"],
        parallel=False,
    ),
    PhaseConfig(
        phase=ScanPhase.VALIDATION,
        plugins=["nuclei"],
        parallel=False,
    ),
    PhaseConfig(
        phase=ScanPhase.REPORTING,
        plugins=[],
        parallel=False,
    ),
]


class PhaseManager:
    """Manages scan phase progression and plugin execution.
    
    The PhaseManager ensures phases execute in order and coordinates
    plugin execution within each phase.
    
    Example:
        manager = PhaseManager(registry, event_bus)
        
        # Execute all phases
        async for result in manager.execute_all(target):
            print(f"Completed: {result.phase}")
        
        # Execute single phase
        result = await manager.execute_phase(ScanPhase.RECONNAISSANCE, target)
    """
    
    def __init__(
        self,
        plugin_registry: PluginRegistry,
        event_bus: EventBus,
        llm_judge: LLMJudge | None = None,
        phase_configs: list[PhaseConfig] | None = None,
    ):
        self._registry = plugin_registry
        self._event_bus = event_bus
        self._llm_judge = llm_judge
        self._phase_configs = {
            pc.phase: pc for pc in (phase_configs or DEFAULT_PHASE_CONFIGS)
        }
        
        self._current_phase: ScanPhase | None = None
        self._phase_results: dict[ScanPhase, PhaseResult] = {}
        self._cancelled = False
        self._scan_id: str | None = None
    
    @property
    def current_phase(self) -> ScanPhase | None:
        """Get the currently executing phase."""
        return self._current_phase
    
    def get_phase_config(self, phase: ScanPhase) -> PhaseConfig:
        """Get configuration for a phase."""
        return self._phase_configs.get(phase, PhaseConfig(phase=phase))
    
    def set_phase_config(self, config: PhaseConfig) -> None:
        """Set configuration for a phase."""
        self._phase_configs[config.phase] = config
    
    def get_phase_result(self, phase: ScanPhase) -> PhaseResult | None:
        """Get the result of a completed phase."""
        return self._phase_results.get(phase)
    
    def get_all_results(self) -> list[PhaseResult]:
        """Get results of all completed phases."""
        return list(self._phase_results.values())
    
    async def execute_phase(
        self,
        phase: ScanPhase,
        target: str,
        scan_id: str,
    ) -> PhaseResult:
        """Execute a single scan phase.
        
        Args:
            phase: Phase to execute
            target: Target URL or IP
            scan_id: ID of the current scan
            
        Returns:
            PhaseResult with execution details
        """
        from trix.engine.event_bus import Event, EventType
        
        config = self.get_phase_config(phase)
        self._current_phase = phase
        self._scan_id = scan_id
        
        start_time = time.time()
        findings: list[VulnerabilityFinding] = []
        errors: list[str] = []
        plugins_executed: list[str] = []
        plugin_outputs: dict[str, str] = {}
        
        # Emit phase started event
        await self._event_bus.publish(Event(
            type=EventType.PHASE_STARTED,
            scan_id=scan_id,
            data={"phase": phase.value, "plugins": config.plugins},
        ))
        
        if not config.enabled:
            result = PhaseResult(
                phase=phase,
                status=PhaseStatus.SKIPPED,
                duration_ms=0,
            )
            await self._event_bus.publish(Event(
                type=EventType.PHASE_SKIPPED,
                scan_id=scan_id,
                data={"phase": phase.value},
            ))
            self._phase_results[phase] = result
            return result
        
        try:
            # Get plugins for this phase
            plugin_names = config.plugins or []
            
            # Also add any plugins that support this phase
            phase_plugins = self._registry.get_plugins_for_phase(phase)
            for plugin in phase_plugins:
                if plugin.name not in plugin_names:
                    plugin_names.append(plugin.name)
            
            if config.parallel:
                # Execute plugins in parallel
                tasks = []
                for plugin_name in plugin_names:
                    params = config.parameters.get(plugin_name, {})
                    tasks.append(self._execute_plugin(
                        plugin_name, target, phase, params, findings
                    ))
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(results):
                    plugin_name = plugin_names[i]
                    if isinstance(result, Exception):
                        errors.append(f"{plugin_name}: {result}")
                        if not config.continue_on_error:
                            break
                    else:
                        plugins_executed.append(plugin_name)
                        if result:
                            plugin_outputs[plugin_name] = result
            else:
                # Execute plugins sequentially
                for plugin_name in plugin_names:
                    if self._cancelled:
                        break
                    
                    params = config.parameters.get(plugin_name, {})
                    try:
                        output = await self._execute_plugin(
                            plugin_name, target, phase, params, findings
                        )
                        plugins_executed.append(plugin_name)
                        if output:
                            plugin_outputs[plugin_name] = output
                    except Exception as e:
                        errors.append(f"{plugin_name}: {e}")
                        logger.error(f"Plugin {plugin_name} error: {e}")
                        if not config.continue_on_error:
                            break
            
            status = PhaseStatus.COMPLETED if not errors else PhaseStatus.FAILED
            if self._cancelled:
                status = PhaseStatus.FAILED
            
        except asyncio.TimeoutError:
            errors.append(f"Phase timed out after {config.timeout_seconds}s")
            status = PhaseStatus.FAILED
        except Exception as e:
            errors.append(str(e))
            status = PhaseStatus.FAILED
        
        duration_ms = int((time.time() - start_time) * 1000)
        
        result = PhaseResult(
            phase=phase,
            status=status,
            duration_ms=duration_ms,
            plugins_executed=plugins_executed,
            findings=findings,
            errors=errors,
            plugin_outputs=plugin_outputs,
        )
        
        self._phase_results[phase] = result
        self._current_phase = None
        
        # Emit phase completed event
        event_type = EventType.PHASE_COMPLETED if status == PhaseStatus.COMPLETED else EventType.PHASE_FAILED
        await self._event_bus.publish(Event(
            type=event_type,
            scan_id=scan_id,
            data=result.to_dict(),
        ))
        
        return result
    
    async def _execute_plugin(
        self,
        plugin_name: str,
        target: str,
        phase: ScanPhase,
        parameters: dict[str, Any],
        findings: list[VulnerabilityFinding],
        verification_tasks: list[dict[str, Any]],
    ) -> str:
        """Execute a single plugin and collect findings."""
        from trix.engine.event_bus import Event, EventType
        from trix.plugins.base import EventType as PluginEventType
        
        output_lines: list[str] = []
        plugin_start_time = time.time()
        findings_count = 0
        
        # Emit plugin started event
        await self._event_bus.publish(Event(
            type=EventType.PLUGIN_STARTED,
            scan_id=self._scan_id,
            data={"plugin": plugin_name, "phase": phase.value},
        ))
        
        try:
            async for event in self._registry.execute(plugin_name, target, phase, parameters):
                # Convert plugin events to bus events
                if event.event_type == PluginEventType.VULNERABILITY:
                    finding = VulnerabilityFinding(
                        title=event.data.get("title", "Unknown"),
                        severity=event.data.get("severity", "info"),
                        description=event.data.get("description", ""),
                        url=event.data.get("url", target),
                        plugin_name=plugin_name,
                        phase=phase,
                        cve_id=event.data.get("cve"),
                        evidence=event.data.get("evidence"),
                    )
                    # Intercept Finding for AI Judgment
                    if self._llm_judge:
                        try:
                            # 1. Create Judgment Request
                            request = JudgmentRequest(
                                vuln_type=finding.title, # Mapping might need improvement
                                target=finding.url,
                                payload=finding.payload or "",
                                raw_request=str(event.data.get("request", "")),
                                raw_response=str(event.data.get("response", "")),
                                baseline_response="", # Plugin might need to provide this
                            )
                            
                            # 2. Judge
                            result = await self._llm_judge.judge(request)
                            
                            # 3. Decision Logic
                            if result.confidence_level == ConfidenceLevel.FALSE_POSITIVE:
                                logger.info(f"AI dismissed finding: {finding.title}")
                                continue
                                
                            elif result.confidence_level == ConfidenceLevel.SUSPECTED:
                                # Generate Verification Task
                                v_task = await self._llm_judge.generate_verification_task(
                                    request, result, task_id=f"verify-{len(verification_tasks)}"
                                )
                                if v_task:
                                    verification_tasks.append(v_task.to_dict())
                                    logger.info(f"AI generated verification task for suspected {finding.title}")
                                    continue
                                    
                            # Determine confirmed or likely -> Proceed to report
                            finding.confidence_score = result.confidence_score
                            finding.llm_reasoning = result.reasoning
                            
                        except Exception as e:
                            logger.error(f"AI Judgment failed: {e}")
                            # Fallback: process as finding but mark unverified

                    findings.append(finding)
                    findings_count += 1
                    
                    await self._event_bus.publish(Event(
                        type=EventType.VULNERABILITY_FOUND,
                        scan_id=self._scan_id,
                        data=finding.to_dict(),
                    ))
                
                elif event.event_type == PluginEventType.OUTPUT:
                    line = event.data.get("line", "")
                    output_lines.append(line)
                    
                    await self._event_bus.publish(Event(
                        type=EventType.PLUGIN_OUTPUT,
                        scan_id=self._scan_id,
                        data={"plugin": plugin_name, "line": line},
                    ))
                
                elif event.event_type == PluginEventType.PROGRESS:
                    await self._event_bus.publish(Event(
                        type=EventType.PLUGIN_PROGRESS,
                        scan_id=self._scan_id,
                        data={"plugin": plugin_name, **event.data},
                    ))
            
            # Emit plugin completed event
            duration_ms = int((time.time() - plugin_start_time) * 1000)
            await self._event_bus.publish(Event(
                type=EventType.PLUGIN_COMPLETED,
                scan_id=self._scan_id,
                data={
                    "plugin": plugin_name,
                    "phase": phase.value,
                    "findings_count": findings_count,
                    "duration_ms": duration_ms,
                },
            ))
            
        except Exception as e:
            # Emit plugin error event
            await self._event_bus.publish(Event(
                type=EventType.PLUGIN_ERROR,
                scan_id=self._scan_id,
                data={"plugin": plugin_name, "error": str(e)},
            ))
            raise
        
        return "\n".join(output_lines)
    
    async def execute_all(
        self,
        target: str,
        scan_id: str,
        phases: list[ScanPhase] | None = None,
    ):
        """Execute all scan phases in order.
        
        Args:
            target: Target URL or IP
            scan_id: ID of the current scan
            phases: Optional list of phases to execute (default: all)
            
        Yields:
            PhaseResult for each completed phase
        """
        self._cancelled = False
        
        # Determine phases to execute
        if phases is None:
            phases = [
                ScanPhase.RECONNAISSANCE,
                ScanPhase.ENUMERATION,
                ScanPhase.VULNERABILITY_SCAN,
                ScanPhase.VALIDATION,
                ScanPhase.REPORTING,
            ]
        
        for phase in phases:
            if self._cancelled:
                break
            
            result = await self.execute_phase(phase, target, scan_id)
            yield result
            
            # Stop on failure unless continue_on_error
            if result.status == PhaseStatus.FAILED:
                config = self.get_phase_config(phase)
                if not config.continue_on_error:
                    break
    
    def cancel(self) -> None:
        """Cancel the current phase execution."""
        self._cancelled = True
    
    def reset(self) -> None:
        """Reset the phase manager for a new scan."""
        self._current_phase = None
        self._phase_results.clear()
        self._cancelled = False
        self._scan_id = None
