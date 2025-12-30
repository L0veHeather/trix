"""Result Collector for aggregating scan results.

Collects and stores findings from all plugins and phases,
providing aggregation and filtering capabilities.
"""

from __future__ import annotations

import json
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trix.plugins.base import ScanPhase, VulnerabilityFinding

logger = logging.getLogger(__name__)


@dataclass
class ScanSummary:
    """Summary statistics for a scan."""
    
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    verified_count: int = 0
    dismissed_count: int = 0
    
    plugins_used: list[str] = field(default_factory=list)
    phases_completed: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "verified_count": self.verified_count,
            "dismissed_count": self.dismissed_count,
            "plugins_used": self.plugins_used,
            "phases_completed": self.phases_completed,
        }


class ResultCollector:
    """Collects and manages scan results.
    
    Provides:
    - Finding storage and retrieval
    - Filtering by severity, plugin, phase
    - Verification status tracking
    - Export to various formats
    
    Example:
        collector = ResultCollector(scan_id="scan-123")
        
        # Add findings
        collector.add_finding(finding)
        
        # Query findings
        critical = collector.get_findings(severity="critical")
        
        # Export
        collector.export_json(Path("report.json"))
    """
    
    def __init__(self, scan_id: str, target: str):
        self.scan_id = scan_id
        self.target = target
        self.started_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None
        
        self._findings: list[VulnerabilityFinding] = []
        self._verification_status: dict[str, int] = {}  # finding_id -> status (1=verified, -1=dismissed)
        self._plugins_used: set[str] = set()
        self._phases_completed: set[ScanPhase] = set()
        self._fingerprints: set[str] = set()  # Deduplication fingerprints
    
    def add_finding(self, finding: VulnerabilityFinding) -> str:
        """Add a finding to the collection.
        
        Returns:
            Finding ID
        """
        # Semantic Deduplication
        # Create a fingerprint unique to this specific vulnerability instance
        fp_components = [
            finding.target,
            finding.plugin_name,
            finding.title,
            finding.parameter or "",
            finding.payload or ""
        ]
        fingerprint = hashlib.sha256("|".join(fp_components).encode()).hexdigest()
        
        if fingerprint in self._fingerprints:
            logger.debug(f"Duplicate finding ignored: {finding.title} @ {finding.target}")
            return ""  # Return empty or None to indicate ignored
            
        self._fingerprints.add(fingerprint)

        # Generate ID if not present
        finding_id = f"{self.scan_id}-{len(self._findings)}"
        self._findings.append(finding)
        self._plugins_used.add(finding.plugin_name)
        
        logger.debug(f"Added finding: {finding.title} ({finding.severity})")
        return finding_id
    
    def add_findings(self, findings: list[VulnerabilityFinding]) -> None:
        """Add multiple findings."""
        for finding in findings:
            self.add_finding(finding)
    
    def mark_phase_completed(self, phase: ScanPhase) -> None:
        """Mark a phase as completed."""
        self._phases_completed.add(phase)
    
    def mark_scan_completed(self) -> None:
        """Mark the scan as completed."""
        self.completed_at = datetime.now(timezone.utc)
    
    def verify_finding(self, index: int, status: int) -> bool:
        """Set verification status for a finding.
        
        Args:
            index: Finding index
            status: 1 for verified, -1 for dismissed, 0 to clear
            
        Returns:
            True if successful
        """
        if 0 <= index < len(self._findings):
            finding_id = f"{self.scan_id}-{index}"
            if status == 0:
                self._verification_status.pop(finding_id, None)
            else:
                self._verification_status[finding_id] = status
            return True
        return False
    
    def get_finding(self, index: int) -> VulnerabilityFinding | None:
        """Get a finding by index."""
        if 0 <= index < len(self._findings):
            return self._findings[index]
        return None
    
    def get_findings(
        self,
        severity: str | None = None,
        plugin: str | None = None,
        phase: ScanPhase | None = None,
        verified_only: bool = False,
        exclude_dismissed: bool = True,
    ) -> list[VulnerabilityFinding]:
        """Get findings with optional filtering.
        
        Args:
            severity: Filter by severity level
            plugin: Filter by plugin name
            phase: Filter by scan phase
            verified_only: Only return verified findings
            exclude_dismissed: Exclude dismissed findings
            
        Returns:
            List of matching findings
        """
        results = []
        
        for i, finding in enumerate(self._findings):
            finding_id = f"{self.scan_id}-{i}"
            verification = self._verification_status.get(finding_id, 0)
            
            # Apply filters
            if severity and finding.severity != severity:
                continue
            if plugin and finding.plugin_name != plugin:
                continue
            if phase and finding.phase != phase:
                continue
            if verified_only and verification != 1:
                continue
            if exclude_dismissed and verification == -1:
                continue
            
            results.append(finding)
        
        return results
    
    def get_summary(self) -> ScanSummary:
        """Get summary statistics for the scan."""
        summary = ScanSummary()
        
        for i, finding in enumerate(self._findings):
            finding_id = f"{self.scan_id}-{i}"
            verification = self._verification_status.get(finding_id, 0)
            
            # Skip dismissed
            if verification == -1:
                summary.dismissed_count += 1
                continue
            
            summary.total_findings += 1
            
            if verification == 1:
                summary.verified_count += 1
            
            # Count by severity
            severity = finding.severity.lower()
            if severity == "critical":
                summary.critical_count += 1
            elif severity == "high":
                summary.high_count += 1
            elif severity == "medium":
                summary.medium_count += 1
            elif severity == "low":
                summary.low_count += 1
            else:
                summary.info_count += 1
        
        summary.plugins_used = list(self._plugins_used)
        summary.phases_completed = [p.value for p in self._phases_completed]
        
        return summary
    
    def to_dict(self) -> dict[str, Any]:
        """Convert all results to a dictionary."""
        findings_with_status = []
        for i, finding in enumerate(self._findings):
            finding_id = f"{self.scan_id}-{i}"
            finding_dict = finding.to_dict()
            finding_dict["id"] = finding_id
            finding_dict["verification_status"] = self._verification_status.get(finding_id, 0)
            findings_with_status.append(finding_dict)
        
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "summary": self.get_summary().to_dict(),
            "findings": findings_with_status,
        }
    
    def export_json(self, path: Path) -> None:
        """Export results to JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"Exported results to {path}")
    
    def export_markdown(self, path: Path) -> None:
        """Export results to Markdown file."""
        summary = self.get_summary()
        
        lines = [
            f"# Security Scan Report",
            f"",
            f"**Target:** {self.target}",
            f"**Scan ID:** {self.scan_id}",
            f"**Started:** {self.started_at.isoformat()}",
            f"**Completed:** {self.completed_at.isoformat() if self.completed_at else 'In Progress'}",
            f"",
            f"## Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| Critical | {summary.critical_count} |",
            f"| High | {summary.high_count} |",
            f"| Medium | {summary.medium_count} |",
            f"| Low | {summary.low_count} |",
            f"| Info | {summary.info_count} |",
            f"| **Total** | **{summary.total_findings}** |",
            f"",
            f"## Findings",
            f"",
        ]
        
        # Group by severity
        for severity in ["critical", "high", "medium", "low", "info"]:
            findings = self.get_findings(severity=severity)
            if findings:
                lines.append(f"### {severity.title()} ({len(findings)})")
                lines.append("")
                
                for finding in findings:
                    lines.append(f"#### {finding.title}")
                    lines.append(f"")
                    lines.append(f"- **URL:** {finding.url}")
                    lines.append(f"- **Plugin:** {finding.plugin_name}")
                    if finding.cve_id:
                        lines.append(f"- **CVE:** {finding.cve_id}")
                    lines.append(f"")
                    lines.append(finding.description)
                    lines.append(f"")
        
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        logger.info(f"Exported report to {path}")
    
    def export_sarif(self, path: Path) -> None:
        """Export results in SARIF format (for GitHub/IDE integration)."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Trix",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/usestrix/strix",
                        }
                    },
                    "results": [],
                }
            ],
        }
        
        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none",
        }
        
        for finding in self._findings:
            result = {
                "ruleId": finding.template_id or finding.plugin_name,
                "level": severity_map.get(finding.severity.lower(), "note"),
                "message": {
                    "text": finding.description or finding.title,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.url,
                            }
                        }
                    }
                ],
            }
            sarif["runs"][0]["results"].append(result)
        
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2)
        logger.info(f"Exported SARIF to {path}")
