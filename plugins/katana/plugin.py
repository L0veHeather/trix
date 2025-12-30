"""Katana Plugin Implementation.

Next-generation crawling and spidering framework.
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


class KatanaPlugin(BasePlugin):
    """Katana web crawler plugin.
    
    Katana is a next-generation crawling and spidering framework that
    can discover URLs, endpoints, and JavaScript files. It supports
    both standard and headless browser modes.
    """
    
    name = "katana"
    version = "1.0"
    description = "Next-generation web crawling framework"
    author = "ProjectDiscovery"
    homepage = "https://github.com/projectdiscovery/katana"
    
    phases = [ScanPhase.ENUMERATION, ScanPhase.RECONNAISSANCE]
    capabilities = [
        PluginCapability.WEB_CRAWLING,
        PluginCapability.ENDPOINT_ENUMERATION,
        PluginCapability.JS_CRAWLING,
    ]
    
    async def check_installed(self) -> bool:
        """Check if katana is installed."""
        if shutil.which("katana"):
            return True
        
        common_paths = [
            Path.home() / "go" / "bin" / "katana",
            Path("/usr/local/bin/katana"),
            Path("/opt/homebrew/bin/katana"),
        ]
        
        for path in common_paths:
            if path.exists():
                self._executable_path = str(path)
                return True
        
        return False
    
    async def install(self) -> bool:
        """Install katana using go install."""
        try:
            if not shutil.which("go"):
                logger.error("Go is required to install katana")
                return False
            
            process = await asyncio.create_subprocess_exec(
                "go", "install",
                "github.com/projectdiscovery/katana/cmd/katana@latest",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            _, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Failed to install katana: {stderr.decode()}")
                return False
            
            return True
        except Exception as e:
            logger.exception(f"Failed to install katana: {e}")
            return False
    
    async def update(self) -> bool:
        """Update katana."""
        return await self.install()
    
    def _get_executable(self) -> str | None:
        """Get the katana executable path."""
        if hasattr(self, "_executable_path"):
            return self._executable_path
        # Check known paths first
        common_paths = [
            Path.home() / "go" / "bin" / "katana",
            Path("/usr/local/bin/katana"),
            Path("/opt/homebrew/bin/katana"),
        ]
        
        for path in common_paths:
            if path.exists():
                return str(path)
        
        # Fallback to PATH
        path = shutil.which("katana")
        if path:
            return path
        
        return None
    
    def build_command(self, params: dict[str, Any]) -> list[str]:
        """Build katana command line."""
        katana_path = self._get_executable()
        if not katana_path:
            raise RuntimeError("Katana not found")
        
        cmd = [katana_path]
        
        # Target
        target = params.get("target")
        target_list = params.get("target_list")
        
        if target_list:
            cmd.extend(["-list", target_list])
        elif target:
            cmd.extend(["-u", target])
        
        # Depth
        depth = params.get("depth", 3)
        cmd.extend(["-d", str(depth)])
        
        # Headless mode
        if params.get("headless", False):
            cmd.append("-headless")
        
        # JS crawling
        if params.get("js_crawl", True):
            cmd.append("-js-crawl")
        
        # Timeout
        timeout = params.get("timeout", 15)
        cmd.extend(["-timeout", str(timeout)])
        
        # Concurrency
        concurrency = params.get("concurrency", 10)
        cmd.extend(["-c", str(concurrency)])
        
        # Parallelism
        parallelism = params.get("parallelism", 10)
        cmd.extend(["-p", str(parallelism)])
        
        # Delay
        delay = params.get("delay", 0)
        if delay > 0:
            cmd.extend(["-delay", str(delay)])
        
        # Scope
        scope = params.get("scope", "rdn")
        cmd.extend(["-field-scope", scope])
        
        # Form filling
        if params.get("form_fill", True):
            cmd.append("-automatic-form-fill")
        
        # Known files
        if params.get("known_files", True):
            cmd.append("-known-files")
        
        # Extension filter
        ext_filter = params.get("extension_filter")
        if ext_filter:
            cmd.extend(["-extension-filter", ext_filter])
        
        # JSON output
        cmd.append("-jsonl")
        
        # Silent
        cmd.append("-silent")
        
        return cmd
    
    async def execute(
        self,
        target: str,
        phase: ScanPhase,
        params: dict[str, Any],
    ) -> AsyncGenerator[PluginEvent, None]:
        """Execute katana crawling."""
        from trix.plugins.base import EventType as PluginEventType
        
        if "target" not in params:
            params["target"] = target
        
        try:
            cmd = self.build_command(params)
            
            yield PluginEvent(
                event_type=PluginEventType.STARTED,
                message=f"Starting katana crawl on {target}",
                data={"command": " ".join(cmd)},
            )
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            urls_found = set()
            js_files = set()
            forms = []
            
            async for line in process.stdout:
                line = line.decode().strip()
                if not line:
                    continue
                
                result = self._parse_result(line)
                if result:
                    url = result.get("url", "")
                    
                    # Track unique URLs
                    if url not in urls_found:
                        urls_found.add(url)
                        
                        # Track JS files
                        if url.endswith(".js"):
                            js_files.add(url)
                        
                        # Track forms
                        if result.get("tag") == "form":
                            forms.append(result)
                        
                        yield PluginEvent(
                            event_type=PluginEventType.OUTPUT,
                            message=f"Discovered: {url}",
                            data=result,
                        )
            
            await process.wait()
            
            yield PluginEvent(
                event_type=PluginEventType.COMPLETED,
                message=f"Katana completed. Found {len(urls_found)} URLs.",
                data={
                    "urls_count": len(urls_found),
                    "js_files_count": len(js_files),
                    "forms_count": len(forms),
                    "js_files": list(js_files),
                    "exit_code": process.returncode,
                },
            )
            
        except Exception as e:
            logger.exception(f"Katana execution error: {e}")
            yield PluginEvent(
                event_type=PluginEventType.ERROR,
                message=str(e),
                data={"error": str(e)},
            )
    
    def _parse_result(self, line: str) -> dict[str, Any] | None:
        """Parse katana JSON output."""
        try:
            data = json.loads(line)
            
            request = data.get("request", {})
            response = data.get("response", {})
            
            return {
                "url": request.get("endpoint"),
                "method": request.get("method", "GET"),
                "tag": request.get("tag"),
                "attribute": request.get("attribute"),
                "status_code": response.get("status_code"),
                "source": request.get("source"),
            }
        except json.JSONDecodeError:
            # Plain URL output
            if line.startswith("http"):
                return {"url": line, "method": "GET"}
            return None
    
    def parse_output(self, line: str) -> VulnFinding | None:
        """Parse output - katana produces URLs, not vulnerabilities."""
        return None


# Plugin instance for auto-discovery
plugin = KatanaPlugin()
