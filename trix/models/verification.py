"""Verification Task Model for Recursive Validation.

When LLM confidence is in the "uncertain" zone (50-80%), the system
generates verification tasks to further test the potential vulnerability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class VerificationPriority(str, Enum):
    """Priority level for verification tasks."""
    
    CRITICAL = "critical"   # Must verify immediately (high confidence)
    HIGH = "high"           # Verify soon (medium-high confidence)
    NORMAL = "normal"       # Standard queue priority
    LOW = "low"             # Can wait


class VerificationReason(str, Enum):
    """Reason for generating a verification task."""
    
    UNCERTAIN_CONFIDENCE = "uncertain_confidence"  # Confidence 50-80%
    TIME_DELAY_INCONCLUSIVE = "time_delay_inconclusive"  # Time-based delay unclear
    WAF_BYPASS_NEEDED = "waf_bypass_needed"  # WAF detected, need bypass
    PARTIAL_EVIDENCE = "partial_evidence"  # Some indicators but not confirmed
    MUTATION_SUGGESTED = "mutation_suggested"  # LLM suggested payload variation


@dataclass
class VerificationTask:
    """Task for recursive vulnerability verification.
    
    When the AI is uncertain about a finding, it generates a VerificationTask
    to perform additional testing with modified payloads.
    """
    
    # === Task Identification ===
    task_id: str
    
    # === Target & Payload (必需字段) ===
    target_url: str
    parameter: str
    vuln_type: str
    original_payload: str
    verification_payload: str  # New payload for verification
    
    # === Optional fields ===
    parent_task_id: str | None = None  # Links to the original task
    depth: int = 0  # Recursion depth (for loop prevention)
    
    # === Verification Context ===
    reason: VerificationReason = VerificationReason.UNCERTAIN_CONFIDENCE
    priority: VerificationPriority = VerificationPriority.HIGH
    
    # === LLM Guidance ===
    verification_instruction: str = ""  # What AI should look for
    expected_behavior: str = ""  # Expected outcome if vulnerable
    
    # === Previous Attempt Data ===
    previous_confidence: float = 0.0
    previous_reasoning: str = ""
    previous_evidence: list[str] = field(default_factory=list)
    
    # === Tracking ===
    created_at: datetime = field(default_factory=datetime.now)
    max_attempts: int = 3  # Maximum retries for this verification chain
    current_attempt: int = 1
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "task_id": self.task_id,
            "parent_task_id": self.parent_task_id,
            "depth": self.depth,
            "target_url": self.target_url,
            "parameter": self.parameter,
            "vuln_type": self.vuln_type,
            "original_payload": self.original_payload,
            "verification_payload": self.verification_payload,
            "reason": self.reason.value,
            "priority": self.priority.value,
            "verification_instruction": self.verification_instruction,
            "expected_behavior": self.expected_behavior,
            "previous_confidence": self.previous_confidence,
            "previous_reasoning": self.previous_reasoning,
            "previous_evidence": self.previous_evidence,
            "created_at": self.created_at.isoformat(),
            "max_attempts": self.max_attempts,
            "current_attempt": self.current_attempt,
        }


@dataclass
class VerificationResult:
    """Result of a verification task.
    
    Tracks whether the verification resolved the uncertainty.
    """
    
    task: VerificationTask
    resolved: bool  # Whether the ambiguity was resolved
    new_confidence: float
    is_vulnerable: bool | None  # None if still uncertain
    reasoning: str
    evidence: list[str] = field(default_factory=list)
    
    # If still uncertain, may contain next verification task
    follow_up_task: VerificationTask | None = None


# === Constants for feedback loop ===

# Confidence thresholds
CONFIDENCE_CONFIRMED = 0.80  # >= 80% is confirmed
CONFIDENCE_UNCERTAIN_HIGH = 0.80  # Upper bound of uncertainty  
CONFIDENCE_UNCERTAIN_LOW = 0.50  # Lower bound of uncertainty (< 50% is rejected)

# Maximum recursion depth to prevent infinite loops
MAX_VERIFICATION_DEPTH = 3

# Maximum total verification tasks per original finding
MAX_VERIFICATION_ATTEMPTS = 5
