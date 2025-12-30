"""Database Models for SQLite storage.

Defines all data models for the Trix storage layer using SQLAlchemy.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    Boolean,
    JSON,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def generate_uuid() -> str:
    """Generate a short UUID."""
    return str(uuid.uuid4())[:8]


def utcnow() -> datetime:
    """Get current UTC time."""
    return datetime.now(timezone.utc)


class ScanStatus(str, enum.Enum):
    """Status of a scan."""
    
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilitySeverity(str, enum.Enum):
    """Severity level of a vulnerability."""
    
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VerificationStatus(int, enum.Enum):
    """Verification status of a finding."""
    
    UNVERIFIED = 0
    VERIFIED = 1
    DISMISSED = -1


class Scan(Base):
    """Represents a security scan."""
    
    __tablename__ = "scans"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    name = Column(String(255))
    target = Column(String(2048), nullable=False)
    
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    current_phase = Column(String(50))
    progress = Column(Float, default=0.0)
    
    config = Column(JSON, default=dict)
    
    started_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime)
    
    error_message = Column(Text)
    
    # Relationships
    vulnerabilities = relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    phase_results = relationship(
        "PhaseResult",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "target": self.target,
            "status": self.status.value if self.status else None,
            "current_phase": self.current_phase,
            "progress": self.progress,
            "config": self.config,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "vulnerability_count": len(self.vulnerabilities) if self.vulnerabilities else 0,
        }


class Vulnerability(Base):
    """Represents a discovered vulnerability."""
    
    __tablename__ = "vulnerabilities"
    
    id = Column(String(16), primary_key=True, default=lambda: str(uuid.uuid4())[:16])
    scan_id = Column(String(8), ForeignKey("scans.id"), nullable=False)
    
    title = Column(String(512), nullable=False)
    severity = Column(Enum(VulnerabilitySeverity), default=VulnerabilitySeverity.INFO)
    description = Column(Text)
    
    url = Column(String(2048))
    parameter = Column(String(255))
    payload = Column(Text)
    
    # Source
    plugin_name = Column(String(100))
    template_id = Column(String(255))
    phase = Column(String(50))
    
    # Classification
    cve_id = Column(String(20))
    cwe_id = Column(String(20))
    owasp_category = Column(String(50))
    
    # AI Analysis
    risk_level = Column(String(20))
    confidence_level = Column(String(20))
    confidence_score = Column(Float)
    llm_reasoning = Column(Text)
    
    # Evidence (stored as JSON)
    evidence = Column(JSON, default=dict)
    
    # Verification
    verification_status = Column(Integer, default=0)  # 0=unverified, 1=verified, -1=dismissed
    verification_notes = Column(Text)
    
    discovered_at = Column(DateTime, default=utcnow)
    verified_at = Column(DateTime)
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "title": self.title,
            "severity": self.severity.value if self.severity else None,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "plugin_name": self.plugin_name,
            "template_id": self.template_id,
            "phase": self.phase,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "risk_level": self.risk_level,
            "confidence_level": self.confidence_level,
            "confidence_score": self.confidence_score,
            "llm_reasoning": self.llm_reasoning,
            "evidence": self.evidence,
            "verification_status": self.verification_status,
            "verification_notes": self.verification_notes,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
        }


class PhaseResult(Base):
    """Represents the result of a scan phase."""
    
    __tablename__ = "phase_results"
    
    id = Column(String(16), primary_key=True, default=lambda: str(uuid.uuid4())[:16])
    scan_id = Column(String(8), ForeignKey("scans.id"), nullable=False)
    
    phase = Column(String(50), nullable=False)
    status = Column(String(20))  # pending, running, completed, failed, skipped
    
    plugins_executed = Column(JSON, default=list)
    duration_ms = Column(Integer, default=0)
    
    findings_count = Column(Integer, default=0)
    errors = Column(JSON, default=list)
    
    raw_output = Column(Text)
    parsed_data = Column(JSON, default=dict)
    
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Relationships
    scan = relationship("Scan", back_populates="phase_results")
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "phase": self.phase,
            "status": self.status,
            "plugins_executed": self.plugins_executed,
            "duration_ms": self.duration_ms,
            "findings_count": self.findings_count,
            "errors": self.errors,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class PluginConfig(Base):
    """Stores plugin configuration."""
    
    __tablename__ = "plugin_configs"
    
    name = Column(String(100), primary_key=True)
    enabled = Column(Boolean, default=True)
    installed = Column(Boolean, default=False)
    version = Column(String(50))
    
    timeout_seconds = Column(Integer, default=300)
    max_retries = Column(Integer, default=2)
    rate_limit = Column(Integer)
    
    custom_config = Column(JSON, default=dict)
    
    installed_at = Column(DateTime)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "installed": self.installed,
            "version": self.version,
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "rate_limit": self.rate_limit,
            "custom_config": self.custom_config,
            "installed_at": self.installed_at.isoformat() if self.installed_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class ScanTemplate(Base):
    """Stores reusable scan configurations."""
    
    __tablename__ = "scan_templates"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    config = Column(JSON, nullable=False)
    
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "config": self.config,
            "is_default": self.is_default,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Setting(Base):
    """Stores application settings."""
    
    __tablename__ = "settings"
    
    key = Column(String(255), primary_key=True)
    value = Column(JSON)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class CustomPlugin(Base):
    """User-defined custom plugins/tools.
    
    Users can add their own security tools through the frontend,
    provide descriptions and use cases, and the LLM will automatically
    select appropriate plugins based on the scanning context.
    """
    
    __tablename__ = "custom_plugins"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    name = Column(String(100), unique=True, nullable=False)
    
    # Execution
    command = Column(Text, nullable=False)  # Command template with {target} placeholder
    working_dir = Column(String(512))       # Optional working directory
    plugin_dir = Column(String(100))        # Plugin directory name (in plugins/ or user_plugins/)
    
    # Description for LLM
    description = Column(Text, nullable=False)  # What this plugin does
    use_cases = Column(JSON, default=list)      # When to use this plugin
    
    # Input/Output
    input_type = Column(String(50), default="url")  # url, domain, ip, file
    output_format = Column(String(50), default="lines")  # json, lines, regex
    output_pattern = Column(String(512))  # Regex pattern for parsing output
    
    # Status
    enabled = Column(Boolean, default=True)
    installed = Column(Boolean, default=True)  # Always true for custom plugins
    
    # Plugin classification (for filtering and phase assignment)
    capabilities = Column(JSON, default=list)  # List of capability strings
    phases = Column(JSON, default=list)        # List of phase strings
    
    # Metadata
    author = Column(String(100))
    version = Column(String(50), default="1.0.0")
    icon = Column(String(10), default="🔧")
    
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "command": self.command,
            "working_dir": self.working_dir,
            "plugin_dir": self.plugin_dir,
            "description": self.description,
            "use_cases": self.use_cases or [],
            "input_type": self.input_type,
            "output_format": self.output_format,
            "output_pattern": self.output_pattern,
            "enabled": self.enabled,
            "installed": self.installed,
            "capabilities": self.capabilities or [],
            "phases": self.phases or [],
            "author": self.author,
            "version": self.version,
            "icon": self.icon,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
    
    def get_llm_description(self) -> str:
        """Generate description for LLM context."""
        cases = ", ".join(self.use_cases) if self.use_cases else "general scanning"
        return f"{self.name}: {self.description} (Use when: {cases})"

