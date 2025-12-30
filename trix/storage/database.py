"""Database Manager.

Handles SQLite database connections, sessions, and operations.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, TypeVar

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from trix.storage.models import (
    Base,
    Scan,
    Vulnerability,
    PhaseResult,
    PluginConfig,
    ScanTemplate,
    Setting,
    CustomPlugin,
    ScanStatus,
    VulnerabilitySeverity,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


class Database:
    """SQLite database manager.
    
    Provides CRUD operations for all Trix data models.
    
    Example:
        db = Database()
        
        # Create a scan
        scan = db.create_scan(target="https://example.com")
        
        # Add vulnerability
        db.add_vulnerability(
            scan_id=scan.id,
            title="SQL Injection",
            severity=VulnerabilitySeverity.HIGH,
        )
        
        # Query
        vulns = db.get_vulnerabilities(scan_id=scan.id, severity="high")
    """
    
    def __init__(self, db_path: Path | str | None = None):
        """Initialize the database.
        
        Args:
            db_path: Path to SQLite database file. If None, uses default location.
        """
        if db_path is None:
            db_path = Path.home() / ".trix" / "trix.db"
        
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            connect_args={"check_same_thread": False},
        )
        
        # Enable foreign keys
        @event.listens_for(self.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
        
        self.SessionLocal = sessionmaker(bind=self.engine)
        
        # Create tables
        Base.metadata.create_all(self.engine)
        
        logger.info(f"Database initialized at {self.db_path}")
    
    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        """Get a database session context manager."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    # ==================== Scan Operations ====================
    
    def create_scan(
        self,
        target: str,
        name: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> Scan:
        """Create a new scan."""
        with self.session() as session:
            scan = Scan(
                target=target,
                name=name or f"Scan: {target[:50]}",
                config=config or {},
            )
            session.add(scan)
            session.flush()
            session.refresh(scan)
            # Expunge from session so it can be used after session closes
            session.expunge(scan)
            return scan
    
    def get_scan(self, scan_id: str) -> Scan | None:
        """Get a scan by ID."""
        with self.session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                session.expunge(scan)
            return scan
    
    def update_scan(
        self,
        scan_id: str,
        status: ScanStatus | None = None,
        current_phase: str | None = None,
        progress: float | None = None,
        error_message: str | None = None,
        completed: bool = False,
    ) -> Scan | None:
        """Update scan status."""
        with self.session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                if status is not None:
                    scan.status = status
                if current_phase is not None:
                    scan.current_phase = current_phase
                if progress is not None:
                    scan.progress = progress
                if error_message is not None:
                    scan.error_message = error_message
                if completed:
                    scan.completed_at = datetime.now(timezone.utc)
                    scan.current_phase = None  # Clear phase on completion
                session.flush()
                session.refresh(scan)
                session.expunge(scan)
            return scan
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all related data."""
        with self.session() as session:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                session.delete(scan)
                return True
            return False
    
    def list_scans(
        self,
        status: ScanStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Scan]:
        """List scans with optional filtering."""
        with self.session() as session:
            query = session.query(Scan)
            if status:
                query = query.filter(Scan.status == status)
            query = query.order_by(Scan.started_at.desc())
            query = query.offset(offset).limit(limit)
            scans = query.all()
            for scan in scans:
                session.expunge(scan)
            return scans
    
    # ==================== Vulnerability Operations ====================
    
    def add_vulnerability(
        self,
        scan_id: str,
        title: str,
        severity: VulnerabilitySeverity | str = VulnerabilitySeverity.INFO,
        description: str | None = None,
        url: str | None = None,
        plugin_name: str | None = None,
        phase: str | None = None,
        **kwargs,
    ) -> Vulnerability:
        """Add a vulnerability finding."""
        if isinstance(severity, str):
            severity = VulnerabilitySeverity(severity.lower())
        
        with self.session() as session:
            vuln = Vulnerability(
                scan_id=scan_id,
                title=title,
                severity=severity,
                description=description,
                url=url,
                plugin_name=plugin_name,
                phase=phase,
                **kwargs,
            )
            session.add(vuln)
            session.flush()
            session.refresh(vuln)
            return vuln
    
    def get_vulnerability_count(self, scan_id: str) -> int:
        """Get count of vulnerabilities for a scan."""
        with self.session() as session:
            from sqlalchemy import func
            return session.query(func.count(Vulnerability.id)).filter(
                Vulnerability.scan_id == scan_id
            ).scalar() or 0
    
    def get_vulnerability(self, vuln_id: str) -> Vulnerability | None:
        """Get a vulnerability by ID."""
        with self.session() as session:
            return session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    
    def get_vulnerabilities(
        self,
        scan_id: str | None = None,
        severity: str | None = None,
        plugin: str | None = None,
        verified_only: bool = False,
        exclude_dismissed: bool = True,
    ) -> list[Vulnerability]:
        """Get vulnerabilities with filtering."""
        with self.session() as session:
            query = session.query(Vulnerability)
            
            if scan_id:
                query = query.filter(Vulnerability.scan_id == scan_id)
            if severity:
                query = query.filter(Vulnerability.severity == VulnerabilitySeverity(severity))
            if plugin:
                query = query.filter(Vulnerability.plugin_name == plugin)
            if verified_only:
                query = query.filter(Vulnerability.verification_status == 1)
            if exclude_dismissed:
                query = query.filter(Vulnerability.verification_status != -1)
            
            return query.all()
    
    def verify_vulnerability(
        self,
        vuln_id: str,
        status: int,
        notes: str | None = None,
    ) -> Vulnerability | None:
        """Update vulnerability verification status."""
        with self.session() as session:
            vuln = session.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
            if vuln:
                vuln.verification_status = status
                if notes:
                    vuln.verification_notes = notes
                if status != 0:
                    vuln.verified_at = datetime.now(timezone.utc)
                session.flush()
                session.refresh(vuln)
            return vuln
    
    def get_vulnerability_stats(self, scan_id: str) -> dict[str, Any]:
        """Get vulnerability statistics for a scan."""
        with self.session() as session:
            vulns = session.query(Vulnerability).filter(
                Vulnerability.scan_id == scan_id
            ).all()
            
            stats = {
                "total": 0,
                "by_severity": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                "verified": 0,
                "dismissed": 0,
            }
            
            for vuln in vulns:
                if vuln.verification_status == -1:
                    stats["dismissed"] += 1
                    continue
                
                stats["total"] += 1
                if vuln.severity:
                    stats["by_severity"][vuln.severity.value] += 1
                if vuln.verification_status == 1:
                    stats["verified"] += 1
            
            return stats
    
    # ==================== Phase Result Operations ====================
    
    def add_phase_result(
        self,
        scan_id: str,
        phase: str,
        status: str,
        plugins_executed: list[str] | None = None,
        duration_ms: int = 0,
        findings_count: int = 0,
        errors: list[str] | None = None,
    ) -> PhaseResult:
        """Add a phase result."""
        with self.session() as session:
            result = PhaseResult(
                scan_id=scan_id,
                phase=phase,
                status=status,
                plugins_executed=plugins_executed or [],
                duration_ms=duration_ms,
                findings_count=findings_count,
                errors=errors or [],
                completed_at=datetime.now(timezone.utc),
            )
            session.add(result)
            session.flush()
            session.refresh(result)
            return result
    
    def get_phase_results(self, scan_id: str) -> list[dict]:
        """Get all phase results for a scan as dictionaries."""
        with self.session() as session:
            results = session.query(PhaseResult).filter(
                PhaseResult.scan_id == scan_id
            ).all()
            # Convert to dict inside session to avoid DetachedInstanceError
            return [r.to_dict() for r in results]
    
    # ==================== Plugin Config Operations ====================
    
    def get_plugin_config(self, plugin_name: str) -> PluginConfig | None:
        """Get plugin configuration."""
        with self.session() as session:
            return session.query(PluginConfig).filter(
                PluginConfig.name == plugin_name
            ).first()
    
    def save_plugin_config(
        self,
        plugin_name: str,
        **kwargs,
    ) -> PluginConfig:
        """Save or update plugin configuration."""
        with self.session() as session:
            config = session.query(PluginConfig).filter(
                PluginConfig.name == plugin_name
            ).first()
            
            if config is None:
                config = PluginConfig(name=plugin_name)
                session.add(config)
            
            for key, value in kwargs.items():
                if hasattr(config, key):
                    setattr(config, key, value)
            
            session.flush()
            session.refresh(config)
            return config
    
    def list_plugin_configs(self) -> list[PluginConfig]:
        """List all plugin configurations."""
        with self.session() as session:
            return session.query(PluginConfig).all()
    
    # ==================== Settings Operations ====================
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a setting value."""
        with self.session() as session:
            setting = session.query(Setting).filter(Setting.key == key).first()
            return setting.value if setting else default
    
    def set_setting(self, key: str, value: Any) -> Setting:
        """Set a setting value."""
        with self.session() as session:
            setting = session.query(Setting).filter(Setting.key == key).first()
            if setting is None:
                setting = Setting(key=key)
                session.add(setting)
            setting.value = value
            session.flush()
            session.refresh(setting)
            return setting
    
    # ==================== Scan Template Operations ====================
    
    def create_template(
        self,
        name: str,
        config: dict[str, Any],
        description: str | None = None,
    ) -> ScanTemplate:
        """Create a scan template."""
        with self.session() as session:
            template = ScanTemplate(
                name=name,
                config=config,
                description=description,
            )
            session.add(template)
            session.flush()
            session.refresh(template)
            return template
    
    def get_template(self, template_id: str) -> ScanTemplate | None:
        """Get a scan template by ID."""
        with self.session() as session:
            return session.query(ScanTemplate).filter(
                ScanTemplate.id == template_id
            ).first()
    
    def list_templates(self) -> list[ScanTemplate]:
        """List all scan templates."""
        with self.session() as session:
            return session.query(ScanTemplate).all()
    
    # ==================== Custom Plugin Operations ====================
    
    def create_custom_plugin(
        self,
        name: str,
        command: str,
        description: str,
        use_cases: list[str] | None = None,
        capabilities: list[str] | None = None,
        phases: list[str] | None = None,
        plugin_dir: str | None = None,
        input_type: str = "url",
        output_format: str = "lines",
        output_pattern: str | None = None,
        author: str | None = None,
        icon: str = "🔧",
    ) -> CustomPlugin:
        """Create a new custom plugin."""
        with self.session() as session:
            plugin = CustomPlugin(
                name=name,
                command=command,
                description=description,
                use_cases=use_cases or [],
                capabilities=capabilities or [],
                phases=phases or [],
                plugin_dir=plugin_dir,
                input_type=input_type,
                output_format=output_format,
                output_pattern=output_pattern,
                author=author,
                icon=icon,
            )
            session.add(plugin)
            session.flush()
            session.refresh(plugin)
            return plugin
    
    def get_custom_plugin(self, plugin_id: str) -> CustomPlugin | None:
        """Get a custom plugin by ID."""
        with self.session() as session:
            return session.query(CustomPlugin).filter(
                CustomPlugin.id == plugin_id
            ).first()
    
    def get_custom_plugin_by_name(self, name: str) -> CustomPlugin | None:
        """Get a custom plugin by name."""
        with self.session() as session:
            return session.query(CustomPlugin).filter(
                CustomPlugin.name == name
            ).first()
    
    def list_custom_plugins(self, enabled_only: bool = False) -> list[CustomPlugin]:
        """List all custom plugins."""
        with self.session() as session:
            query = session.query(CustomPlugin)
            if enabled_only:
                query = query.filter(CustomPlugin.enabled == True)
            return query.order_by(CustomPlugin.created_at.desc()).all()
    
    def update_custom_plugin(
        self,
        plugin_id: str,
        **kwargs,
    ) -> CustomPlugin | None:
        """Update a custom plugin."""
        with self.session() as session:
            plugin = session.query(CustomPlugin).filter(
                CustomPlugin.id == plugin_id
            ).first()
            if plugin:
                for key, value in kwargs.items():
                    if hasattr(plugin, key) and value is not None:
                        setattr(plugin, key, value)
                session.flush()
                session.refresh(plugin)
            return plugin
    
    def delete_custom_plugin(self, plugin_id: str) -> bool:
        """Delete a custom plugin."""
        with self.session() as session:
            plugin = session.query(CustomPlugin).filter(
                CustomPlugin.id == plugin_id
            ).first()
            if plugin:
                session.delete(plugin)
                return True
            return False
    
    def get_custom_plugins_for_llm(self) -> list[str]:
        """Get custom plugin descriptions for LLM context."""
        plugins = self.list_custom_plugins(enabled_only=True)
        return [p.get_llm_description() for p in plugins]


# Global database instance
_database: Database | None = None


def get_database() -> Database:
    """Get the global database instance."""
    global _database
    if _database is None:
        _database = Database()
    return _database


def set_database(db: Database) -> None:
    """Set the global database instance."""
    global _database
    _database = db
