"""Phase models for scan orchestration."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from datetime import datetime
from trix.plugins.base import ScanPhase
from trix.models.finding import VulnFinding

class PhaseStatus(Enum):
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
    timeout_seconds: int = 3600
    continue_on_error: bool = True
    parameters: dict[str, dict[str, Any]] = field(default_factory=dict)

@dataclass
class PhaseResult:
    """Result of a completed scan phase."""
    phase: ScanPhase
    status: PhaseStatus
    duration_ms: int
    plugins_executed: list[str] = field(default_factory=list)
    findings: list[VulnFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    plugin_outputs: dict[str, str] = field(default_factory=dict)
    verification_tasks: list[dict[str, Any]] = field(default_factory=list)
    started_at: datetime | None = None
    completed_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "phase": self.phase.value,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "plugins_executed": self.plugins_executed,
            "findings_count": len(self.findings),
            "errors": self.errors,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
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
        plugins=["urlfinder", "ffuf"],
        parallel=False,
    ),
    PhaseConfig(
        phase=ScanPhase.VULNERABILITY_SCAN,
        plugins=["sqli_detector", "idor_detector"],
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
