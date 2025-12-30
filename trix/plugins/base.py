"""Plugin Base Classes and Types.

This module defines the core abstractions for the Trix plugin system.
All security tool plugins must inherit from BasePlugin and implement
the required methods.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Callable

from trix.llm.llm import LLM
from trix.llm.config import LLMConfig
from trix.models.finding import VulnFinding

logger = logging.getLogger(__name__)


class ScanPhase(str, Enum):
    """Phases of a security scan."""
    
    RECONNAISSANCE = "reconnaissance"
    ENUMERATION = "enumeration"
    VULNERABILITY_SCAN = "vulnerability_scan"
    EXPLOITATION = "exploitation"
    VALIDATION = "validation"
    REPORTING = "reporting"


class PluginStatus(str, Enum):
    """Plugin installation/runtime status."""
    
    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    UPDATE_AVAILABLE = "update_available"
    RUNNING = "running"
    ERROR = "error"
    DISABLED = "disabled"


class PluginCapability(str, Enum):
    """Capabilities a plugin can provide."""
    
    WEB_SCANNING = "web_scanning"
    API_TESTING = "api_testing"
    SUBDOMAIN_ENUM = "subdomain_enum"
    PORT_SCANNING = "port_scanning"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    SQL_INJECTION = "sql_injection"
    XSS_DETECTION = "xss_detection"
    DIRECTORY_BRUTEFORCE = "directory_bruteforce"
    FUZZING = "fuzzing"
    CRAWLING = "crawling"
    TECHNOLOGY_DETECTION = "technology_detection"
    SECRET_SCANNING = "secret_scanning"
    CONFIGURATION_AUDIT = "configuration_audit"
    # Capabilities for built-in plugins
    DATABASE_EXPLOITATION = "database_exploitation"
    CONTENT_DISCOVERY = "content_discovery"
    CVE_SCANNING = "cve_scanning"
    WEB_PROBE = "web_probe"
    WEB_CRAWLING = "web_crawling"
    TEMPLATE_BASED = "template_based"
    ENDPOINT_ENUMERATION = "endpoint_enumeration"
    SERVICE_ENUMERATION = "service_enumeration"
    JS_CRAWLING = "js_crawling"


class EventType(str, Enum):
    """Types of events emitted during plugin execution."""
    
    STARTED = "started"
    PROGRESS = "progress"
    OUTPUT = "output"
    VULNERABILITY = "vulnerability"
    FINDING = "finding"
    WARNING = "warning"
    ERROR = "error"
    COMPLETED = "completed"


@dataclass
class PluginEvent:
    """Event emitted during plugin execution.
    
    Used for real-time updates to the UI during scanning.
    """
    
    event_type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    plugin_name: str = ""
    phase: ScanPhase | None = None
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_type": self.event_type.value,
            "message": self.message,
            "plugin_name": self.plugin_name,
            "phase": self.phase.value if self.phase else None,
            "data": self.data,
            "timestamp": self.timestamp,
        }


@dataclass
class PluginResult:
    """Final result of plugin execution."""
    
    success: bool
    plugin_name: str
    phase: ScanPhase
    duration_ms: int
    
    raw_output: str = ""
    findings: list[VulnFinding] = field(default_factory=list)
    parsed_data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "plugin_name": self.plugin_name,
            "phase": self.phase.value,
            "duration_ms": self.duration_ms,
            "raw_output": self.raw_output,
            "findings": [f.to_dict() for f in self.findings],
            "parsed_data": self.parsed_data,
            "error": self.error,
        }


@dataclass
class PluginConfig:
    """Configuration for a plugin instance."""
    
    enabled: bool = True
    timeout_seconds: int = 300
    max_retries: int = 2
    rate_limit: int | None = None
    custom_args: dict[str, Any] = field(default_factory=dict)


class BasePlugin(ABC):
    """Abstract base class for all Trix plugins.
    
    All security tool plugins must inherit from this class and implement
    the required abstract methods. The plugin system handles:
    - Installation and updates
    - Configuration management
    - Execution lifecycle
    - Output parsing
    - Event streaming
    
    Example:
        class MyPlugin(BasePlugin):
            name = "my_plugin"
            version = "1.0.0"
            display_name = "My Security Plugin"
            description = "Does security things"
            phases = [ScanPhase.VULNERABILITY_SCAN]
            capabilities = [PluginCapability.WEB_SCANNING]
            
            async def check_installed(self):
                # Check if tool is installed
                ...
            
            async def execute(self, target, phase, parameters):
                # Run the tool
                ...
    """
    
    # Required class attributes
    name: str
    version: str
    display_name: str
    description: str
    
    # Supported phases and capabilities
    phases: list[ScanPhase]
    capabilities: list[PluginCapability]
    
    # Optional attributes
    author: str = "Trix"
    homepage: str = ""
    icon: str = "🔧"
    color: str = "#6366f1"
    
    def __init__(self, config: PluginConfig | None = None):
        """Initialize the plugin with optional configuration."""
        self.config = config or PluginConfig()
        self.status = PluginStatus.NOT_INSTALLED
        self._event_handlers: list[Callable[[PluginEvent], None]] = []
        self._cancel_event = asyncio.Event()
    
    # ==================== Abstract Methods ====================
    
    @abstractmethod
    async def check_installed(self) -> tuple[bool, str]:
        """Check if the tool is installed and get version.
        
        Returns:
            Tuple of (is_installed, version_or_error_message)
        """
        raise NotImplementedError
    
    @abstractmethod
    async def install(self) -> tuple[bool, str]:
        """Install the tool.
        
        Returns:
            Tuple of (success, message)
        """
        raise NotImplementedError
    
    @abstractmethod
    async def update(self) -> tuple[bool, str]:
        """Update the tool and any templates/rules.
        
        Returns:
            Tuple of (success, message)
        """
        raise NotImplementedError
    
    @abstractmethod
    async def execute(
        self,
        target: str,
        phase: ScanPhase,
        parameters: dict[str, Any],
    ) -> AsyncIterator[PluginEvent]:
        """Execute the plugin against a target.
        
        This is a generator that yields PluginEvent objects for real-time
        updates. The final event should be of type COMPLETED.
        
        Args:
            target: Target URL or IP
            phase: Current scan phase
            parameters: Plugin-specific parameters
            
        Yields:
            PluginEvent objects for progress, findings, etc.
        """
        raise NotImplementedError
        yield  # Make this a generator
    
    @abstractmethod
    def parse_output(self, raw_output: str) -> list[VulnFinding]:
        """Parse raw tool output into vulnerability findings.
        
        Args:
            raw_output: Raw output from the tool
            
        Returns:
            List of VulnFinding objects
        """
        raise NotImplementedError
    
    # ==================== Optional Override Methods ====================
    
    def get_default_parameters(self, phase: ScanPhase) -> dict[str, Any]:
        """Get default parameters for a specific phase.
        
        Override this to provide phase-specific defaults.
        """
        return {}
    
    def validate_parameters(self, parameters: dict[str, Any]) -> tuple[bool, str]:
        """Validate parameters before execution.
        
        Override this to add custom validation logic.
        
        Returns:
            Tuple of (is_valid, error_message_if_invalid)
        """
        return True, ""
    
    def get_ui_schema(self) -> dict[str, Any]:
        """Get UI schema for parameter configuration.
        
        Override this to define the parameter form in the UI.
        
        Returns:
            JSON Schema-like dict for form generation
        """
        return {}
    
    async def cleanup(self) -> None:
        """Clean up any resources after execution.
        
        Override this to clean up temp files, kill processes, etc.
        """
        pass
    
    # ==================== Helper Methods ====================
    
    def emit_event(
        self,
        event_type: EventType,
        phase: ScanPhase,
        data: dict[str, Any],
    ) -> PluginEvent:
        """Create and emit a plugin event."""
        event = PluginEvent(
            event_type=event_type,
            plugin_name=self.name,
            phase=phase,
            data=data,
        )
        for handler in self._event_handlers:
            try:
                handler(event)
            except Exception as e:
                logger.warning(f"Event handler error: {e}")
        return event
    
    def add_event_handler(self, handler: Callable[[PluginEvent], None]) -> None:
        """Add an event handler for real-time updates."""
        self._event_handlers.append(handler)
    
    def remove_event_handler(self, handler: Callable[[PluginEvent], None]) -> None:
        """Remove an event handler."""
        if handler in self._event_handlers:
            self._event_handlers.remove(handler)
    
    async def cancel(self) -> None:
        """Request cancellation of the current execution."""
        self._cancel_event.set()
    
    def is_cancelled(self) -> bool:
        """Check if cancellation has been requested."""
        return self._cancel_event.is_set()
    
    def reset_cancellation(self) -> None:
        """Reset the cancellation state for a new execution."""
        self._cancel_event.clear()
    
    async def run_command(
        self,
        cmd: list[str],
        timeout: int | None = None,
        env: dict[str, str] | None = None,
    ) -> tuple[int, str, str]:
        """Helper to run a command asynchronously.
        
        Args:
            cmd: Command and arguments as list
            timeout: Timeout in seconds (uses config default if None)
            env: Additional environment variables
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        import os
        
        timeout = timeout or self.config.timeout_seconds
        
        # Merge environment
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=full_env,
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
            
            return (
                proc.returncode or 0,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
            )
            
        except asyncio.TimeoutError:
            if proc:
                proc.kill()
            return -1, "", f"Command timed out after {timeout}s"
        except FileNotFoundError:
            return -1, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return -1, "", str(e)
    
    async def stream_command(
        self,
        cmd: list[str],
        phase: ScanPhase,
        line_parser: Callable[[str], PluginEvent | None] | None = None,
        env: dict[str, str] | None = None,
    ) -> AsyncIterator[PluginEvent]:
        """Stream command output as events.
        
        Args:
            cmd: Command and arguments
            phase: Current scan phase
            line_parser: Optional function to parse each output line
            env: Additional environment variables
            
        Yields:
            PluginEvent for each meaningful output line
        """
        import os
        
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=full_env,
            )
            
            yield self.emit_event(EventType.STARTED, phase, {"command": " ".join(cmd)})
            
            # Read stdout line by line
            async for line in proc.stdout:
                if self.is_cancelled():
                    proc.kill()
                    yield self.emit_event(EventType.WARNING, phase, {"message": "Cancelled"})
                    break
                
                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    continue
                
                if line_parser:
                    event = line_parser(line_str)
                    if event:
                        yield event
                else:
                    yield self.emit_event(EventType.OUTPUT, phase, {"line": line_str})
            
            await proc.wait()
            
            yield self.emit_event(
                EventType.COMPLETED,
                phase,
                {"return_code": proc.returncode},
            )
            
        except Exception as e:
            yield self.emit_event(EventType.ERROR, phase, {"error": str(e)})
    
    async def mutate_payload_with_ai(
        self,
        payload: str,
        tech_stack: list[str],
        context: str = ""
    ) -> str:
        """Node 3: Mutate payload based on target technology using AI.
        
        Args:
            payload: Original payload (e.g. ' OR 1=1 --)
            tech_stack: Detected technologies (e.g. ['PostgreSQL', 'Nginx'])
            context: Additional context
            
        Returns:
            Mutated payload optimized for the stack
        """
        if not tech_stack:
            return payload
            
        try:
            llm = LLM(config=LLMConfig())
            
            prompt = f"""
            You are an Exploit Payload Specialist.
            
            Task: Optimize the following security payload for the specific technology stack.
            
            Original Payload: {payload}
            Target Stack: {', '.join(tech_stack)}
            Context: {context}
            
            Instructions:
            1. Adapt syntax for the specific database/server (e.g. MySQL # vs PostgreSQL --).
            2. Apply WAF evasion techniques relevant to this stack if typically needed.
            3. Return ONLY the raw mutated payload string. No quotes, no explanations.
            """
            
            response = await llm.generate([{"role": "user", "content": prompt}])
            mutated = response.content.strip()
            
            # Basic validation to ensure we didn't get a chatty response
            if len(mutated) > len(payload) * 5 or " " in mutated and "\n" in mutated:
                # If response looks like a sentence, fallback
                if "here is" in mutated.lower():
                     return payload
            
            return mutated
            
        except Exception as e:
            logger.warning(f"AI Payload Mutation failed: {e}")
            return payload
    
    def to_dict(self) -> dict[str, Any]:
        """Convert plugin info to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "display_name": getattr(self, 'display_name', self.name),
            "description": self.description,
            "author": self.author,
            "homepage": self.homepage,
            "icon": getattr(self, 'icon', '🔧'),
            "color": getattr(self, 'color', '#6366f1'),
            "phases": [p.value for p in self.phases],
            "capabilities": [c.value for c in self.capabilities],
            "status": self.status.value,
            "config": {
                "enabled": self.config.enabled,
                "timeout_seconds": self.config.timeout_seconds,
                "max_retries": self.config.max_retries,
                "rate_limit": self.config.rate_limit,
            },
        }
    
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name}, version={self.version})>"
