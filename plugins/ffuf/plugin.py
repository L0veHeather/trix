"""Ffuf Plugin Implementation.

Fast web fuzzer for content discovery and endpoint enumeration.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import tempfile
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


# Common wordlist locations
DEFAULT_WORDLISTS = [
    Path.home() / ".trix" / "wordlists" / "common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]


class FfufPlugin(BasePlugin):
    """Ffuf web fuzzer plugin.
    
    Ffuf is a fast web fuzzer written in Go that allows typical directory
    discovery, virtual host discovery (without DNS records), and parameter
    fuzzing.
    """
    
    name = "ffuf"
    version = "2.1"
    description = "Fast web fuzzer for content discovery"
    author = "joohoi"
    homepage = "https://github.com/ffuf/ffuf"
    
    phases = [ScanPhase.ENUMERATION]
    capabilities = [
        PluginCapability.CONTENT_DISCOVERY,
        PluginCapability.FUZZING,
        PluginCapability.ENDPOINT_ENUMERATION,
    ]
    
    async def check_installed(self) -> bool:
        """Check if ffuf is installed."""
        if shutil.which("ffuf"):
            return True
        
        common_paths = [
            Path.home() / "go" / "bin" / "ffuf",
            Path("/usr/local/bin/ffuf"),
            Path("/opt/homebrew/bin/ffuf"),
        ]
        
        for path in common_paths:
            if path.exists():
                self._executable_path = str(path)
                return True
        
        return False
    
    async def install(self) -> bool:
        """Install ffuf using go install."""
        try:
            if not shutil.which("go"):
                logger.error("Go is required to install ffuf")
                return False
            
            process = await asyncio.create_subprocess_exec(
                "go", "install",
                "github.com/ffuf/ffuf/v2@latest",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            _, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Failed to install ffuf: {stderr.decode()}")
                return False
            
            # Install default wordlist if none exists
            await self._ensure_wordlist()
            
            return True
        except Exception as e:
            logger.exception(f"Failed to install ffuf: {e}")
            return False
    
    async def update(self) -> bool:
        """Update ffuf."""
        return await self.install()
    
    async def _ensure_wordlist(self) -> None:
        """Ensure a default wordlist exists."""
        wordlist_dir = Path.home() / ".trix" / "wordlists"
        wordlist_path = wordlist_dir / "common.txt"
        
        if wordlist_path.exists():
            return
        
        # Check if any default wordlist exists
        for wl in DEFAULT_WORDLISTS:
            if Path(wl).exists():
                return
        
        # Download a basic wordlist
        try:
            wordlist_dir.mkdir(parents=True, exist_ok=True)
            
            # Basic common paths
            common_words = [
                "admin", "login", "wp-admin", "administrator", "phpmyadmin",
                "dashboard", "api", "v1", "v2", "user", "users", "config",
                "backup", "test", "dev", "staging", "uploads", "images",
                "css", "js", "static", "assets", "files", "download",
                "robots.txt", "sitemap.xml", ".git", ".env", "wp-config.php",
                "index.php", "index.html", "admin.php", "login.php",
            ]
            
            wordlist_path.write_text("\n".join(common_words))
            logger.info(f"Created basic wordlist at {wordlist_path}")
        except Exception as e:
            logger.warning(f"Could not create wordlist: {e}")
    
    def _get_executable(self) -> str | None:
        """Get the ffuf executable path."""
        if hasattr(self, "_executable_path"):
            return self._executable_path
        
        path = shutil.which("ffuf")
        if path:
            return path
        
        go_bin = Path.home() / "go" / "bin" / "ffuf"
        if go_bin.exists():
            return str(go_bin)
        
        return None
    
    def _find_wordlist(self, wordlist: str | None) -> str | None:
        """Find a valid wordlist path. Returns None if not found."""
        if wordlist and Path(wordlist).exists():
            return wordlist
        
        for wl in DEFAULT_WORDLISTS:
            if Path(wl).exists():
                return str(wl)
        
        # Return None instead of raising - will be handled gracefully in execute()
        return None
    
    def build_command(self, params: dict[str, Any]) -> list[str]:
        """Build ffuf command line."""
        ffuf_path = self._get_executable()
        if not ffuf_path:
            raise RuntimeError("Ffuf not found")
        
        cmd = [ffuf_path]
        
        # URL with FUZZ placeholder
        url = params.get("url")
        if url:
            # Ensure FUZZ placeholder exists
            if "FUZZ" not in url:
                url = url.rstrip("/") + "/FUZZ"
            cmd.extend(["-u", url])
        
        # Wordlist
        wordlist = self._find_wordlist(params.get("wordlist"))
        if not wordlist:
            raise RuntimeError("No wordlist found. Please install SecLists or specify a wordlist path.")
        cmd.extend(["-w", wordlist])
        
        # Method
        method = params.get("method", "GET")
        cmd.extend(["-X", method])
        
        # Threads
        threads = params.get("threads", 40)
        cmd.extend(["-t", str(threads)])
        
        # Rate limit
        rate = params.get("rate", 0)
        if rate > 0:
            cmd.extend(["-rate", str(rate)])
        
        # Timeout
        timeout = params.get("timeout", 10)
        cmd.extend(["-timeout", str(timeout)])
        
        # Filters
        filter_code = params.get("filter_code", "404")
        if filter_code:
            cmd.extend(["-fc", filter_code])
        
        match_code = params.get("match_code")
        if match_code:
            cmd.extend(["-mc", match_code])
        
        filter_size = params.get("filter_size")
        if filter_size:
            cmd.extend(["-fs", str(filter_size)])
        
        filter_words = params.get("filter_words")
        if filter_words:
            cmd.extend(["-fw", str(filter_words)])
        
        filter_lines = params.get("filter_lines")
        if filter_lines:
            cmd.extend(["-fl", str(filter_lines)])
        
        # Extensions
        extensions = params.get("extensions")
        if extensions:
            cmd.extend(["-e", extensions])
        
        # Follow redirects
        if params.get("follow_redirects", False):
            cmd.append("-r")
        
        # Headers
        headers = params.get("headers", [])
        if isinstance(headers, str):
            headers = [headers]
        for header in headers:
            cmd.extend(["-H", header])
        
        # POST data
        data = params.get("data")
        if data:
            cmd.extend(["-d", data])
        
        # Recursion
        if params.get("recursion", False):
            cmd.append("-recursion")
            depth = params.get("recursion_depth", 2)
            cmd.extend(["-recursion-depth", str(depth)])
        
        # Output format
        cmd.extend(["-of", "json"])
        
        # Silent mode
        cmd.append("-s")
        
        return cmd
    
    async def execute(
        self,
        target: str,
        phase: ScanPhase,
        params: dict[str, Any],
    ) -> AsyncGenerator[PluginEvent, None]:
        """Execute ffuf fuzzing."""
        from trix.plugins.base import EventType as PluginEventType
        
        # Ensure url is set
        if "url" not in params:
            params["url"] = target
        
        try:
            cmd = self.build_command(params)
            url = params.get("url", target)
            
            # Create temp file for output
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".json",
                delete=False
            ) as f:
                output_file = f.name
            
            cmd.extend(["-o", output_file])
            
            yield PluginEvent(
                event_type=PluginEventType.STARTED,
                message=f"Starting ffuf fuzzing on {url}",
                data={"command": " ".join(cmd)},
            )
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            # Wait for completion
            _, stderr = await process.communicate()
            
            # Parse results from output file
            results = []
            try:
                output_path = Path(output_file)
                if output_path.exists():
                    data = json.loads(output_path.read_text())
                    results = data.get("results", [])
                    output_path.unlink()  # Clean up
            except Exception as e:
                logger.warning(f"Failed to parse ffuf output: {e}")
            
            # Yield results
            for result in results:
                yield PluginEvent(
                    event_type=PluginEventType.OUTPUT,
                    message=f"Found: {result.get('url', 'unknown')}",
                    data={
                        "url": result.get("url"),
                        "status_code": result.get("status"),
                        "content_length": result.get("length"),
                        "words": result.get("words"),
                        "lines": result.get("lines"),
                        "content_type": result.get("content-type"),
                        "redirect_location": result.get("redirectlocation"),
                        "fuzz_value": result.get("input", {}).get("FUZZ"),
                    },
                )
            
            yield PluginEvent(
                event_type=PluginEventType.COMPLETED,
                message=f"Ffuf completed. Found {len(results)} endpoints.",
                data={
                    "results_count": len(results),
                    "exit_code": process.returncode,
                },
            )
            
        except Exception as e:
            logger.exception(f"Ffuf execution error: {e}")
            yield PluginEvent(
                event_type=PluginEventType.ERROR,
                message=str(e),
                data={"error": str(e)},
            )
    
    def parse_output(self, line: str) -> VulnFinding | None:
        """Parse output - ffuf produces endpoints, not vulnerabilities."""
        return None


# Plugin instance for auto-discovery
plugin = FfufPlugin()
