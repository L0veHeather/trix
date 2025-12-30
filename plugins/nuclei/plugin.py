"""Nuclei Plugin Implementation.

Fast and customizable vulnerability scanner based on YAML templates.
"""

from __future__ import annotations

import asyncio
import json
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


class NucleiPlugin(BasePlugin):
    """Nuclei vulnerability scanner plugin.
    
    Nuclei is a fast and customizable vulnerability scanner based on
    simple YAML templates. It can be used to discover various types
    of vulnerabilities including CVEs, misconfigurations, and exposed
    sensitive data.
    """
    
    name = "nuclei"
    version = "3.0"
    description = "Fast template-based vulnerability scanner"
    author = "ProjectDiscovery"
    homepage = "https://github.com/projectdiscovery/nuclei"
    
    phases = [ScanPhase.VULNERABILITY_SCAN, ScanPhase.VALIDATION]
    capabilities = [
        PluginCapability.VULNERABILITY_DETECTION,
        PluginCapability.CVE_SCANNING,
        PluginCapability.TEMPLATE_BASED,
    ]
    
    async def check_installed(self) -> bool:
        """Check if nuclei is installed."""
        # Check in PATH
        if shutil.which("nuclei"):
            return True
        
        # Check common locations
        common_paths = [
            Path.home() / "go" / "bin" / "nuclei",
            Path("/usr/local/bin/nuclei"),
            Path("/opt/homebrew/bin/nuclei"),
        ]
        
        for path in common_paths:
            if path.exists():
                self._executable_path = str(path)
                return True
        
        return False
    
    async def install(self) -> bool:
        """Install nuclei using go install."""
        try:
            # Check if Go is available
            if not shutil.which("go"):
                logger.error("Go is required to install nuclei")
                return False
            
            process = await asyncio.create_subprocess_exec(
                "go", "install",
                "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            _, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Failed to install nuclei: {stderr.decode()}")
                return False
            
            # Update nuclei templates
            await self._update_templates()
            
            return True
        except Exception as e:
            logger.exception(f"Failed to install nuclei: {e}")
            return False
    
    async def update(self) -> bool:
        """Update nuclei and templates."""
        # Update binary
        await self.install()
        
        # Update templates
        await self._update_templates()
        
        return True
    
    async def _update_templates(self) -> bool:
        """Update nuclei templates."""
        try:
            nuclei_path = self._get_executable()
            if not nuclei_path:
                return False
            
            process = await asyncio.create_subprocess_exec(
                nuclei_path, "-update-templates",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False
    
    def _get_executable(self) -> str | None:
        """Get the nuclei executable path."""
        if hasattr(self, "_executable_path"):
            return self._executable_path
        
        # Check PATH
        path = shutil.which("nuclei")
        if path:
            return path
        
        # Check go bin
        go_bin = Path.home() / "go" / "bin" / "nuclei"
        if go_bin.exists():
            return str(go_bin)
        
        return None
    
    def build_command(self, params: dict[str, Any]) -> list[str]:
        """Build nuclei command line."""
        nuclei_path = self._get_executable()
        if not nuclei_path:
            raise RuntimeError("Nuclei not found")
        
        cmd = [nuclei_path]
        
        # Target
        target = params.get("target")
        if target:
            cmd.extend(["-u", target])
        
        # Templates
        templates = params.get("templates")
        if templates:
            cmd.extend(["-t", templates])
        
        # Tags
        tags = params.get("tags", "cve,sqli,xss,rce,lfi,ssrf")
        if tags:
            cmd.extend(["-tags", tags])
        
        # Severity
        severity = params.get("severity", "critical,high,medium")
        if severity:
            cmd.extend(["-severity", severity])
        
        # Rate limiting
        rate_limit = params.get("rate_limit", 150)
        cmd.extend(["-rate-limit", str(rate_limit)])
        
        # Concurrency
        concurrency = params.get("concurrency", 25)
        cmd.extend(["-concurrency", str(concurrency)])
        
        # Timeout
        timeout = params.get("timeout", 10)
        cmd.extend(["-timeout", str(timeout)])
        
        # Output format - JSONL for parsing
        cmd.append("-jsonl")
        
        # Silent and no color for clean output
        cmd.extend(["-silent", "-no-color"])
        
        return cmd
    
    async def execute(
        self,
        target: str,
        phase: ScanPhase,
        params: dict[str, Any],
    ) -> AsyncGenerator[PluginEvent, None]:
        """Execute nuclei scan."""
        from trix.plugins.base import EventType as PluginEventType
        
        # Ensure target is in params
        if "target" not in params:
            params["target"] = target
        
        try:
            cmd = self.build_command(params)
            
            yield PluginEvent(
                event_type=PluginEventType.STARTED,
                message=f"Starting nuclei scan on {target}",
                data={"command": " ".join(cmd)},
            )
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            findings_count = 0
            
            # Read output line by line
            async for line in process.stdout:
                line = line.decode().strip()
                if not line:
                    continue
                
                # Parse JSONL output
                finding = self.parse_output(line)
                if finding:
                    findings_count += 1
                    yield PluginEvent(
                        event_type=PluginEventType.VULNERABILITY,
                        message=f"Found: {finding.title}",
                        data=finding.to_dict(),
                    )
            
            await process.wait()
            
            yield PluginEvent(
                event_type=PluginEventType.COMPLETED,
                message=f"Nuclei scan completed. Found {findings_count} issues.",
                data={
                    "findings_count": findings_count,
                    "exit_code": process.returncode,
                },
            )
            
        except Exception as e:
            logger.exception(f"Nuclei execution error: {e}")
            yield PluginEvent(
                event_type=PluginEventType.ERROR,
                message=str(e),
                data={"error": str(e)},
            )
    
    def parse_output(self, line: str) -> VulnFinding | None:
        """Parse nuclei JSONL output."""
        try:
            data = json.loads(line)
            
            # Extract info
            info = data.get("info", {})
            classification = info.get("classification", {})
            
            # Map severity
            severity_map = {
                "critical": RiskLevel.CRITICAL,
                "high": RiskLevel.HIGH,
                "medium": RiskLevel.MEDIUM,
                "low": RiskLevel.LOW,
                "info": RiskLevel.INFO,
            }
            risk_level = severity_map.get(
                info.get("severity", "").lower(),
                RiskLevel.INFO
            )
            
            # Build finding
            finding = VulnFinding(
                target=data.get("matched-at", data.get("host", "")),
                vuln_type=info.get("name", data.get("template-id", "Unknown")),
                payload=data.get("curl-command", "Template execution"),
                raw_request="",
                raw_response="",
                llm_reasoning=info.get("description", "No description provided"),
                confidence_score=1.0,
                confidence_level=ConfidenceLevel.CONFIRMED,
                risk_level=risk_level,
                plugin_name=self.name,
                scan_id="",
            )
            # Legacy compatibility fields
            finding.title = finding.vuln_type
            finding.severity = risk_level.value
            finding.description = finding.llm_reasoning
            finding.url = finding.target
            finding.template_id = data.get("template-id")
            finding.cve_id = classification.get("cve-id")
            finding.cwe_id = classification.get("cwe-id")
            finding.evidence = [
                f"Matcher: {data.get('matcher-name')}",
                f"Extract: {data.get('extracted-results')}",
                f"Tags: {info.get('tags', [])}"
            ]
            
            return finding
            
        except json.JSONDecodeError:
            # Not JSON, might be status message
            logger.debug(f"Non-JSON nuclei output: {line}")
            return None
        except Exception as e:
            logger.error(f"Failed to parse nuclei output: {e}")
            return None


# Plugin instance for auto-discovery
plugin = NucleiPlugin()
