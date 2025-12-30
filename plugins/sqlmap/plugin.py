"""Sqlmap Plugin Implementation.

Automatic SQL injection and database takeover tool.
"""

from __future__ import annotations

import asyncio
import re
import logging
import shutil
from pathlib import Path
from typing import Any, AsyncGenerator

from trix.plugins.base import (
    BasePlugin,
    PluginResult,
    PluginEvent,
    ScanPhase,
    PluginCapability,
    PluginStatus,
)
from trix.models.finding import VulnFinding, ConfidenceLevel, RiskLevel

logger = logging.getLogger(__name__)


class SqlmapPlugin(BasePlugin):
    """Sqlmap SQL injection plugin.
    
    Sqlmap is an open source penetration testing tool that automates
    the process of detecting and exploiting SQL injection flaws and
    taking over database servers.
    """
    
    name = "sqlmap"
    version = "1.7"
    description = "Automatic SQL injection detection and exploitation"
    author = "sqlmapproject"
    homepage = "https://github.com/sqlmapproject/sqlmap"
    
    phases = [ScanPhase.EXPLOITATION, ScanPhase.VULNERABILITY_SCAN]
    capabilities = [
        PluginCapability.SQL_INJECTION,
        PluginCapability.DATABASE_EXPLOITATION,
        PluginCapability.VULNERABILITY_DETECTION,
    ]
    
    # Patterns for parsing sqlmap output
    PARAM_PATTERN = re.compile(r"Parameter: (.+)")
    TYPE_PATTERN = re.compile(r"Type: (.+)")
    PAYLOAD_PATTERN = re.compile(r"Payload: (.+)")
    DBMS_PATTERN = re.compile(r"back-end DBMS: (.+)")
    INJECTABLE_PATTERN = re.compile(r"(\w+) parameter '([^']+)' is injectable")
    VULN_FOUND_PATTERN = re.compile(r"\[INFO\] .+ parameter '([^']+)' is (injectable|vulnerable)")
    
    async def check_installed(self) -> bool:
        """Check if sqlmap is installed."""
        if shutil.which("sqlmap"):
            return True
        
        common_paths = [
            Path.home() / ".local" / "bin" / "sqlmap",
            Path("/usr/local/bin/sqlmap"),
            Path("/usr/bin/sqlmap"),
            Path("/opt/homebrew/bin/sqlmap"),
        ]
        
        for path in common_paths:
            if path.exists():
                self._executable_path = str(path)
                return True
        
        return False
    
    async def install(self) -> bool:
        """Install sqlmap using pipx."""
        try:
            # Try pipx first
            if shutil.which("pipx"):
                process = await asyncio.create_subprocess_exec(
                    "pipx", "install", "sqlmap",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                
                if process.returncode == 0:
                    return True
                logger.warning(f"pipx install failed: {stderr.decode()}")
            
            # Try pip
            if shutil.which("pip3") or shutil.which("pip"):
                pip_cmd = "pip3" if shutil.which("pip3") else "pip"
                process = await asyncio.create_subprocess_exec(
                    pip_cmd, "install", "--user", "sqlmap",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await process.communicate()
                
                if process.returncode == 0:
                    return True
                logger.warning(f"pip install failed: {stderr.decode()}")
            
            # Try brew on macOS
            if shutil.which("brew"):
                process = await asyncio.create_subprocess_exec(
                    "brew", "install", "sqlmap",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await process.communicate()
                
                if process.returncode == 0:
                    return True
            
            logger.error("Failed to install sqlmap")
            return False
            
        except Exception as e:
            logger.exception(f"Failed to install sqlmap: {e}")
            return False
    
    async def update(self) -> bool:
        """Update sqlmap."""
        sqlmap_path = self._get_executable()
        if not sqlmap_path:
            return False
        
        try:
            process = await asyncio.create_subprocess_exec(
                sqlmap_path, "--update",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            # Try reinstall
            return await self.install()
    
    def _get_executable(self) -> str | None:
        """Get the sqlmap executable path."""
        if hasattr(self, "_executable_path"):
            return self._executable_path
        
        path = shutil.which("sqlmap")
        if path:
            return path
        
        local_bin = Path.home() / ".local" / "bin" / "sqlmap"
        if local_bin.exists():
            return str(local_bin)
        
        return None
    
    def build_command(self, params: dict[str, Any]) -> list[str]:
        """Build sqlmap command line."""
        sqlmap_path = self._get_executable()
        if not sqlmap_path:
            raise RuntimeError("Sqlmap not found")
        
        cmd = [sqlmap_path]
        
        # Target
        url = params.get("url")
        request_file = params.get("request_file")
        
        if request_file:
            cmd.extend(["-r", request_file])
        elif url:
            cmd.extend(["-u", url])
        
        # POST data
        data = params.get("data")
        if data:
            cmd.extend(["--data", data])
        
        # Cookie
        cookie = params.get("cookie")
        if cookie:
            cmd.extend(["--cookie", cookie])
        
        # Level and risk
        level = params.get("level", 1)
        cmd.extend(["--level", str(level)])
        
        risk = params.get("risk", 1)
        cmd.extend(["--risk", str(risk)])
        
        # Threads
        threads = params.get("threads", 1)
        cmd.extend(["--threads", str(threads)])
        
        # Timeout
        timeout = params.get("timeout", 30)
        cmd.extend(["--timeout", str(timeout)])
        
        # Retries
        retries = params.get("retries", 3)
        cmd.extend(["--retries", str(retries)])
        
        # DBMS
        dbms = params.get("dbms")
        if dbms:
            cmd.extend(["--dbms", dbms])
        
        # Technique
        technique = params.get("technique", "BEUSTQ")
        cmd.extend(["--technique", technique])
        
        # Tamper
        tamper = params.get("tamper")
        if tamper:
            cmd.extend(["--tamper", tamper])
        
        # Random agent
        if params.get("random_agent", True):
            cmd.append("--random-agent")
        
        # Forms
        if params.get("forms", False):
            cmd.append("--forms")
        
        # Crawl
        crawl = params.get("crawl", 0)
        if crawl > 0:
            cmd.extend(["--crawl", str(crawl)])
        
        # Batch mode (non-interactive)
        cmd.append("--batch")
        
        # Flush session to ensure fresh test
        cmd.append("--flush-session")
        
        return cmd
    
    async def execute(
        self,
        target: str,
        phase: ScanPhase,
        params: dict[str, Any],
    ) -> AsyncGenerator[PluginEvent, None]:
        """Execute sqlmap scan."""
        from trix.plugins.base import EventType as PluginEventType
        
        if "url" not in params:
            params["url"] = target
        
        try:
            cmd = self.build_command(params)
            url = params.get("url", target)
            
            yield PluginEvent(
                event_type=PluginEventType.STARTED,
                message=f"Starting sqlmap scan on {url}",
                data={"command": " ".join(cmd)},
            )
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            
            findings = []
            current_param = None
            current_type = None
            current_payload = None
            dbms = None
            
            async for line in process.stdout:
                line = line.decode().strip()
                if not line:
                    continue
                
                # Parse parameter
                param_match = self.PARAM_PATTERN.search(line)
                if param_match:
                    current_param = param_match.group(1)
                
                # Parse injection type
                type_match = self.TYPE_PATTERN.search(line)
                if type_match:
                    current_type = type_match.group(1)
                
                # Parse payload
                payload_match = self.PAYLOAD_PATTERN.search(line)
                if payload_match:
                    current_payload = payload_match.group(1)
                
                # Parse DBMS
                dbms_match = self.DBMS_PATTERN.search(line)
                if dbms_match:
                    dbms = dbms_match.group(1)
                
                # Check for injectable parameter
                injectable_match = self.INJECTABLE_PATTERN.search(line)
                vuln_match = self.VULN_FOUND_PATTERN.search(line)
                
                if injectable_match or vuln_match:
                    param = injectable_match.group(2) if injectable_match else vuln_match.group(1)
                    
                    finding = VulnFinding(
                        target=params.get("url", target),
                        vuln_type="SQL Injection",
                        payload=current_payload or "Tool discovery",
                        raw_request="",
                        raw_response="",
                        llm_reasoning=f"SQL injection vulnerability found in {param} parameter. DBMS: {dbms}",
                        confidence_score=1.0,
                        confidence_level=ConfidenceLevel.CONFIRMED,
                        risk_level=RiskLevel.CRITICAL,
                        parameter=param,
                        plugin_name=self.name,
                        scan_id="",
                    )
                    # Legacy compatibility fields
                    finding.title = f"SQL Injection in parameter: {param}"
                    finding.severity = "critical"
                    finding.description = finding.llm_reasoning
                    finding.url = finding.target
                    finding.cwe_id = "CWE-89"
                    finding.owasp_category = "A03:2021 Injection"
                    finding.evidence = [f"DBMS: {dbms}", f"Type: {current_type}"]
                    
                    findings.append(finding)
                    
                    yield PluginEvent(
                        event_type=PluginEventType.VULNERABILITY,
                        message=f"SQL Injection found: {param}",
                        data=finding.to_dict(),
                    )
                
                # Progress updates
                if "[INFO]" in line or "[WARNING]" in line:
                    yield PluginEvent(
                        event_type=PluginEventType.PROGRESS,
                        message=line,
                        data={"raw": line},
                    )
            
            await process.wait()
            
            yield PluginEvent(
                event_type=PluginEventType.COMPLETED,
                message=f"Sqlmap completed. Found {len(findings)} SQL injection(s).",
                data={
                    "findings_count": len(findings),
                    "dbms": dbms,
                    "exit_code": process.returncode,
                },
            )
            
        except Exception as e:
            logger.exception(f"Sqlmap execution error: {e}")
            yield PluginEvent(
                event_type=PluginEventType.ERROR,
                message=str(e),
                data={"error": str(e)},
            )
    
    def parse_output(self, line: str) -> VulnFinding | None:
        """Parse sqlmap output line."""
        injectable_match = self.INJECTABLE_PATTERN.search(line)
        if injectable_match:
            param = injectable_match.group(2)
            finding = VulnFinding(
                target="", # Unknown from single line
                vuln_type="SQL Injection",
                payload="",
                raw_request="",
                raw_response="",
                llm_reasoning=f"SQL injection in {param}",
                confidence_score=0.9,
                confidence_level=ConfidenceLevel.SUSPECTED,
                risk_level=RiskLevel.CRITICAL,
                parameter=param,
                plugin_name=self.name,
                scan_id="",
            )
            finding.title = f"SQL Injection: {param}"
            finding.severity = "critical"
            return finding
        return None


# Plugin instance for auto-discovery
plugin = SqlmapPlugin()
