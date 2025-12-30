"""Httpx Plugin Implementation.

Fast and multi-purpose HTTP toolkit for web reconnaissance.
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


class HttpxPlugin(BasePlugin):
    """Httpx web probe plugin.
    
    Httpx is a fast and multi-purpose HTTP toolkit that allows probing
    web servers and detecting technologies, status codes, titles, and
    other useful information for reconnaissance.
    """
    
    name = "httpx"
    version = "1.3"
    description = "Fast HTTP probe for web reconnaissance"
    author = "ProjectDiscovery"
    homepage = "https://github.com/projectdiscovery/httpx"
    
    phases = [ScanPhase.RECONNAISSANCE]
    capabilities = [
        PluginCapability.WEB_PROBE,
        PluginCapability.TECHNOLOGY_DETECTION,
        PluginCapability.SERVICE_ENUMERATION,
    ]
    
    async def check_installed(self) -> bool:
        """Check if httpx is installed."""
        if shutil.which("httpx"):
            return True
        
        common_paths = [
            Path.home() / "go" / "bin" / "httpx",
            Path("/usr/local/bin/httpx"),
            Path("/opt/homebrew/bin/httpx"),
        ]
        
        for path in common_paths:
            if path.exists():
                self._executable_path = str(path)
                return True
        
        return False
    
    async def install(self) -> bool:
        """Install httpx using go install."""
        try:
            if not shutil.which("go"):
                logger.error("Go is required to install httpx")
                return False
            
            process = await asyncio.create_subprocess_exec(
                "go", "install",
                "github.com/projectdiscovery/httpx/cmd/httpx@latest",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            _, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Failed to install httpx: {stderr.decode()}")
                return False
            
            return True
        except Exception as e:
            logger.exception(f"Failed to install httpx: {e}")
            return False
    
    async def update(self) -> bool:
        """Update httpx."""
        return await self.install()
    
    def _get_executable(self) -> str | None:
        """Get the httpx executable path."""
        if hasattr(self, "_executable_path"):
            return self._executable_path
        
        # Check known paths first to avoid conflict with python-httpx
        common_paths = [
            Path.home() / "go" / "bin" / "httpx",
            Path("/usr/local/bin/httpx"),
            Path("/opt/homebrew/bin/httpx"),
        ]
        
        for path in common_paths:
            if path.exists():
                return str(path)
        
        # Fallback to PATH
        path = shutil.which("httpx")
        if path:
            return path
        
        return None
    
    def build_command(self, params: dict[str, Any]) -> list[str]:
        """Build httpx command line."""
        httpx_path = self._get_executable()
        if not httpx_path:
            raise RuntimeError("Httpx not found")
        
        cmd = [httpx_path]
        
        # Target
        target = params.get("target")
        target_list = params.get("target_list")
        
        if target_list:
            cmd.extend(["-l", target_list])
        elif target:
            cmd.extend(["-u", target])
        
        # Threads
        threads = params.get("threads", 50)
        cmd.extend(["-threads", str(threads)])
        
        # Timeout
        timeout = params.get("timeout", 15)
        cmd.extend(["-timeout", str(timeout)])
        
        # Retries
        retries = params.get("retries", 2)
        cmd.extend(["-retries", str(retries)])
        
        # Options
        if params.get("follow_redirects", True):
            cmd.append("-follow-redirects")
        
        if params.get("tech_detect", True):
            cmd.append("-tech-detect")
        
        if params.get("status_code", True):
            cmd.append("-status-code")
        
        if params.get("content_length", True):
            cmd.append("-content-length")
        
        if params.get("title", True):
            cmd.append("-title")
        
        if params.get("web_server", True):
            cmd.append("-web-server")
        
        # JSON output
        cmd.append("-json")
        
        # Silent
        cmd.append("-silent")
        
        return cmd
    
    async def execute(
        self,
        target: str,
        phase: ScanPhase,
        params: dict[str, Any],
    ) -> AsyncGenerator[PluginEvent, None]:
        """Execute httpx probe."""
        from trix.plugins.base import EventType as PluginEventType
        
        # Add target to params if not already there
        if "target" not in params:
            params["target"] = target
        
        try:
            cmd = self.build_command(params)
            
            yield PluginEvent(
                event_type=PluginEventType.STARTED,
                message=f"Starting httpx probe on {target}",
                data={"command": " ".join(cmd)},
            )
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            results_count = 0
            technologies_found = set()
            
            async for line in process.stdout:
                line = line.decode().strip()
                if not line:
                    continue
                
                result = self._parse_result(line)
                if result:
                    results_count += 1
                    
                    # Track technologies
                    techs = result.get("technologies", [])
                    technologies_found.update(techs)
                    
                    yield PluginEvent(
                        event_type=PluginEventType.OUTPUT,
                        message=f"Probed: {result.get('url', 'unknown')}",
                        data=result,
                    )
            
            await process.wait()
            
            yield PluginEvent(
                event_type=PluginEventType.COMPLETED,
                message=f"Httpx probe completed. Found {results_count} hosts.",
                data={
                    "results_count": results_count,
                    "technologies": list(technologies_found),
                    "exit_code": process.returncode,
                },
            )
            
        except Exception as e:
            logger.exception(f"Httpx execution error: {e}")
            yield PluginEvent(
                event_type=PluginEventType.ERROR,
                message=str(e),
                data={"error": str(e)},
            )
    
    def _parse_result(self, line: str) -> dict[str, Any] | None:
        """Parse httpx JSON output."""
        try:
            data = json.loads(line)
            
            return {
                "url": data.get("url"),
                "host": data.get("host"),
                "status_code": data.get("status_code"),
                "title": data.get("title"),
                "web_server": data.get("webserver"),
                "technologies": data.get("tech", []),
                "content_length": data.get("content_length"),
                "content_type": data.get("content_type"),
                "response_time": data.get("response_time"),
                "lines": data.get("lines"),
                "words": data.get("words"),
                "cdn": data.get("cdn"),
                "scheme": data.get("scheme"),
            }
        except json.JSONDecodeError:
            return None
    
    def parse_output(self, line: str) -> VulnFinding | None:
        """Parse output - httpx doesn't produce vulnerabilities directly."""
        # Httpx is for reconnaissance, not vulnerability detection
        # It produces host information, not findings
        return None


# Plugin instance for auto-discovery
plugin = HttpxPlugin()
