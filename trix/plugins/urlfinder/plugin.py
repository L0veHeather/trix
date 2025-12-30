"""URLFinder Plugin Implementation.

Integrates URLFinder-x (or compatible) for passive URL discovery.
Includes Host Binding and AI Sensitivity Analysis.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import json
import logging
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, AsyncGenerator

from trix.plugins.base import (
    BasePlugin,
    PluginEvent,
    ScanPhase,
    PluginCapability,
    BasePlugin,
    PluginEvent,
    ScanPhase,
    PluginCapability,
    VulnerabilityFinding,
)
from trix.storage.models import VulnerabilitySeverity
from trix.engine.event_bus import EventType
from trix.llm.llm import LLM
from trix.llm.config import LLMConfig

logger = logging.getLogger(__name__)


class URLFinderPlugin(BasePlugin):
    """URLFinder plugin for passive URL discovery."""
    
    name = "urlfinder"
    version = "0.1.0"
    description = "Passive URL discovery with host binding and sensitivity analysis"
    author = "Strix Team"
    
    phases = [ScanPhase.RECONNAISSANCE]
    capabilities = [PluginCapability.ENDPOINT_ENUMERATION, PluginCapability.WEB_CRAWLING]
    
    # Critical keywords for sensitivity analysis
    SENSITIVE_KEYWORDS = [
        r"api_key", r"access_token", r"secret", r"admin", r"config",
        r"password", r"credential", r"auth", r"jwt", r"bearer",
        r"private", r"backup", r"\.env", r"\.git", r"aws_key"
    ]
    
    async def check_installed(self) -> bool:
        """Check if URLFinder is installed."""
        return self._get_executable() is not None
        
    def _get_executable(self) -> str | None:
        """Find URLFinder executable."""
        # Check specific names
        for name in ["URLFinder-x", "urlfinder-x", "URLFinder", "urlfinder"]:
            path = shutil.which(name)
            if path:
                return path
                
        # Check known paths
        home = Path.home()
        paths = [
            # User provided path in root plugins dir
            Path(__file__).parent.parent.parent.parent / "plugins" / "URLFinder-x-macos-arm64",
            
            home / "go" / "bin" / "urlfinder",
            home / "go" / "bin" / "URLFinder-x",
            Path("/usr/local/bin/urlfinder"),
            Path("/opt/homebrew/bin/urlfinder"),
        ]
        
        for p in paths:
            if p.exists():
                return str(p)
                
        return None

    def build_command(self, params: dict[str, Any]) -> list[str]:
        """Build command line arguments."""
        exe = self._get_executable()
        if not exe:
            raise RuntimeError("URLFinder executable not found")
            
        target = params.get("target")
        if not target:
            raise ValueError("Target is required")
            
        # Basic args based on pingc0y/URLFinder usage
        # -u <url> -m <mode> -o cli (or json)
        cmd = [exe, "-u", target]
        
        mode = str(params.get("mode", "2"))
        cmd.extend(["-m", mode])
        
        # Output to stdout/cli for parsing, or json if supported
        # We'll use -o cli and parse lines, or -j if avail.
        # User requested N-Next/URLFinder-x which might output differently.
        # Safest is usually parsing stdout lines or using -f for file.
        # Using -o cli implies printing to stdout.
        # Note: pingc0y/URLFinder default outputs to a file unless configured?
        # Let's try to capture stdout.
        
        # Timeout
        timeout = str(params.get("timeout", 10))
        cmd.extend(["-time", timeout]) # pingc0y uses -time
        
        return cmd

    async def execute(
        self,
        target: str,
        phase: ScanPhase,
        params: dict[str, Any],
    ) -> AsyncGenerator[PluginEvent, None]:
        """Execute URLFinder."""
        from trix.plugins.base import EventType as PluginEventType

        if "target" not in params:
            params["target"] = target
            
        target_domain = urlparse(target).netloc
        if not target_domain:
            target_domain = target # fallback

        try:
            cmd = self.build_command(params)
            
            yield PluginEvent(
                event_type=PluginEventType.STARTED,
                message=f"Starting URLFinder on {target}",
                data={"command": " ".join(cmd)}
            )
            
            # Run process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            urls_found = set()
            
            # Read stdout line by line
            async for line_bytes in process.stdout:
                line = line_bytes.decode(errors="replace").strip()
                if not line:
                    continue
                
                # Check if line looks like a URL
                # Output format usually contains status code, size, url
                # e.g. "200 1234 http://example.com/foo" or just url
                
                # Simple extraction: find string starting with http
                match = re.search(r'(https?://[^\s]+)', line)
                if match:
                    url = match.group(1)
                    parsed_url = urlparse(url)
                    
                    # 1. Host Binding Logic (Scope Check)
                    if not self._is_in_scope(parsed_url.netloc, target_domain):
                        continue
                        
                    if url not in urls_found:
                        urls_found.add(url)
                        
                        yield PluginEvent(
                            event_type=PluginEventType.OUTPUT,
                            message=f"Found: {url}",
                            data={"url": url, "source": "urlfinder"}
                        )
                        
                        # 2. AI Sensitivity Analysis
                        if await self._analyze_sensitivity(url, line):
                            yield PluginEvent(
                                event_type=PluginEventType.FINDING,
                                message=f"Sensitive Info: {url}",
                                data=VulnerabilityFinding(
                                    title="Potential Sensitive Information Exposed",
                                    severity=VulnerabilitySeverity.HIGH,
                                    description=f"URLFinder discovered a potentially sensitive URL: {url}\nContext: {line}",
                                    url=url,
                                    plugin_name=self.name,
                                    phase=phase.value,
                                    evidence=line
                                ).to_dict()
                            )

            await process.wait()
            
            if process.returncode != 0:
                _, stderr = await process.communicate()
                logger.warning(f"URLFinder exited with code {process.returncode}: {stderr.decode()}")

            # Node 1: AI API Analysis
            inferred_apis = await self.analyze_source_for_hidden_apis(list(urls_found))
            for api in inferred_apis:
                yield PluginEvent(
                    event_type=PluginEventType.FINDING,
                    message=f"AI Inferred API: {api}",
                    data=VulnerabilityFinding(
                        title="AI Inferred Hidden API Endpoint",
                        severity=VulnerabilitySeverity.INFO,
                        description=f"AI inferred potential API endpoint based on URL patterns: {api}",
                        url=api,
                        plugin_name=self.name,
                        phase=phase.value
                    ).to_dict()
                )

            yield PluginEvent(
                event_type=PluginEventType.COMPLETED,
                message=f"URLFinder completed. Found {len(urls_found)} URLs. AI inferred {len(inferred_apis)} hidden APIs.",
                data={"count": len(urls_found), "inferred": len(inferred_apis)}
            )

        except Exception as e:
            logger.exception("URLFinder execution failed")
            yield PluginEvent(
                event_type=PluginEventType.ERROR,
                message=str(e),
                data={"error": str(e)}
            )

    def _is_in_scope(self, url_host: str, target_host: str) -> bool:
        """Check if URL host matches target host (subdomain bindings)."""
        if not url_host or not target_host:
            return False
            
        # Remove port if present
        url_host = url_host.split(':')[0]
        target_host = target_host.split(':')[0]
        
        return url_host == target_host or url_host.endswith("." + target_host)

    async def install(self) -> tuple[bool, str]:
        """Install URLFinder (Manual installation required)."""
        if await self.check_installed():
            return True, "Already installed"
        return False, "Please install URLFinder manually to plugins/ or system path"

    async def update(self) -> tuple[bool, str]:
        """Update URLFinder."""
        return True, "Manual update required"

    def parse_output(self, raw_output: str) -> list[VulnerabilityFinding]:
        """Parse raw output (not used as we stream events)."""
        return []
    
    async def _analyze_sensitivity(self, url: str, context: str) -> bool:
        """Analyze if URL contains sensitive info using heuristics + LLM."""
        
        # 1. Heuristic Check
        is_suspicious = False
        for pattern in self.SENSITIVE_KEYWORDS:
            if re.search(pattern, url, re.IGNORECASE):
                is_suspicious = True
                break
                
        if not is_suspicious:
            return False
            
        # 2. LLM Judgment
        try:
             # Initialize LLM Client (using default config or env vars)
             llm = LLM(config=LLMConfig())
             
             prompt = f"""
             You are a security analyst. Analyze the following URL and context for SENSITIVE information exposure.
             
             URL: {url}
             Context: {context}
             
             Keywords matched: {', '.join([p for p in self.SENSITIVE_KEYWORDS if re.search(p, url, re.IGNORECASE)])}
             
             Determine if this is truly a sensitive exposure (e.g. API key, credentials, internal admin path) vs a false positive (e.g. public API docs, css file).
             
             Return JSON:
             {{
                "is_sensitive": boolean,
                "confidence": "high|medium|low",
                "reason": "explanation"
             }}
             """
             
             response = await llm.generate([{"role": "user", "content": prompt}])
             content = response.content
             
             # Simple JSON parsing (in production use robust parser)
             if "true" in content.lower() and '"is_sensitive": true' in content.lower():
                 return True
                 
        except Exception as e:
            logger.warning(f"LLM analysis failed: {e}")
            # Fallback to heuristic result if LLM fails
            return True
        
        return False

    async def analyze_source_for_hidden_apis(self, urls: list[str]) -> list[str]:
        """Node 1: Analyze valid URLs to infer hidden API structure using AI."""
        if not urls:
            return []

        try:
            llm = LLM(config=LLMConfig())
            
            prompt = f"""
            You are an API Reconnaissance Agent. Analyze the following discovered URLs from a target:
            
            {json.dumps(urls[:50], indent=2)}  # Limit to 50 for token saving
            
            1. Identify API patterns (e.g. /api/v1/user/1 -> /api/v1/user/{{id}})
            2. Infer 3-5 POTENTIAL hidden API endpoints that might exist but were not found (e.g. if POST /login exists, maybe POST /register or POST /reset-password exists).
            3. Must be plausible based on REST/GraphQL conventions.
            
            Return ONLY a raw JSON list of strings of inferred URLs. Example: ["/api/v1/admin", "/api/v1/users"]
            """
            
            response = await llm.generate([{"role": "user", "content": prompt}])
            content = response.content
            
            # extract json list
            match = re.search(r'\[.*\]', content, re.DOTALL)
            if match:
                inferred = json.loads(match.group(0))
                return [u for u in inferred if isinstance(u, str)]
                
        except Exception as e:
            logger.warning(f"AI API Analysis failed: {e}")
            
        return []
