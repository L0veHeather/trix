"""Plugin Registry.

Central registry for managing plugin instances and their lifecycle.
Provides a high-level API for plugin discovery, loading, and execution.
"""

from __future__ import annotations

import asyncio
import logging
import traceback
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from trix.plugins.base import (
    BasePlugin,
    PluginCapability,
    PluginConfig,
    PluginEvent,
    PluginStatus,
    ScanPhase,
)
from trix.plugins.loader import PluginLoader, get_plugin_loader
from trix.plugins.manifest import PluginManifest

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

logger = logging.getLogger(__name__)


@dataclass
class PluginLoadResult:
    """插件加载结果.
    
    Attributes:
        valid: 成功加载的插件名称列表
        invalid: 加载失败的插件信息列表，每项包含 name, error, traceback
    """
    valid: list[str] = field(default_factory=list)
    invalid: list[dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """转换为可序列化的字典."""
        return {"valid": self.valid, "invalid": self.invalid}


class PluginRegistry:
    """Central registry for all plugins.
    
    The registry manages:
    - Plugin discovery and loading
    - Plugin lifecycle (install, update, enable/disable)
    - Plugin execution coordination
    - Event distribution
    
    Example:
        registry = get_plugin_registry()
        
        # List available plugins
        plugins = registry.list_plugins()
        
        # Get and configure a plugin
        nuclei = registry.get_plugin("nuclei")
        nuclei.config.timeout_seconds = 600
        
        # Execute plugin
        async for event in registry.execute("nuclei", target, phase, params):
            print(event)
    """
    
    def __init__(self, loader: PluginLoader | None = None):
        """Initialize the registry.
        
        Args:
            loader: Plugin loader instance (uses global if None)
        """
        self._loader = loader or get_plugin_loader()
        self._plugins: dict[str, BasePlugin] = {}
        self._global_event_handlers: list[Callable[[PluginEvent], None]] = []
        self._initialized = False
    
    async def initialize(self) -> PluginLoadResult:
        """Initialize the registry by discovering and loading all plugins.
        
        Returns:
            PluginLoadResult with lists of valid and invalid plugins
        """
        if self._initialized:
            return PluginLoadResult(valid=list(self._plugins.keys()))
        
        logger.info("Initializing plugin registry...")
        result = PluginLoadResult()
        
        # Discover plugins
        plugin_names = self._loader.discover_plugins()
        logger.info(f"Discovered {len(plugin_names)} plugins: {plugin_names}")
        
        # Load each plugin with safe error handling
        for name in plugin_names:
            try:
                await self.load_plugin(name)
                result.valid.append(name)
            except Exception as e:
                error_log = {
                    "name": name,
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                }
                result.invalid.append(error_log)
                logger.error(f"[PluginLoadError] {name}: {e}")
        
        self._initialized = True
        self._load_result = result  # Store for later query
        
        # Log summary
        logger.info(f"Registry initialized with {len(self._plugins)} plugins")
        if result.invalid:
            logger.warning(
                f"Failed to load {len(result.invalid)} plugins: "
                f"{[p['name'] for p in result.invalid]}"
            )
        
        return result
    
    async def load_plugin(
        self,
        plugin_name: str,
        config: PluginConfig | None = None,
    ) -> BasePlugin:
        """Load a plugin into the registry.
        
        Args:
            plugin_name: Name of the plugin to load
            config: Optional configuration for the plugin
            
        Returns:
            Loaded plugin instance
        """
        if plugin_name in self._plugins:
            logger.debug(f"Plugin {plugin_name} already loaded")
            return self._plugins[plugin_name]
        
        # Create plugin instance
        plugin = self._loader.create_plugin(plugin_name, config)
        
        # Check installation status - handle both bool and tuple[bool, str] return
        try:
            result = await plugin.check_installed()
            if isinstance(result, tuple):
                is_installed, version = result
            else:
                is_installed = result
                version = "unknown" if result else "not installed"
            
            if is_installed:
                plugin.status = PluginStatus.INSTALLED
                logger.info(f"Plugin {plugin_name} is installed (version: {version})")
            else:
                plugin.status = PluginStatus.NOT_INSTALLED
                logger.info(f"Plugin {plugin_name} is not installed: {version}")
        except Exception as e:
            plugin.status = PluginStatus.NOT_INSTALLED
            logger.warning(f"Plugin {plugin_name} check_installed failed: {e}")
        
        # Register global event handlers
        for handler in self._global_event_handlers:
            plugin.add_event_handler(handler)
        
        self._plugins[plugin_name] = plugin
        return plugin
    
    def get_plugin(self, plugin_name: str) -> BasePlugin | None:
        """Get a loaded plugin by name."""
        return self._plugins.get(plugin_name)
    
    def list_plugins(self) -> list[dict[str, Any]]:
        """List all loaded plugins with their info as dicts."""
        return [plugin.to_dict() for plugin in self._plugins.values()]
    
    def get_loaded_plugins(self) -> list[BasePlugin]:
        """Get all loaded plugin objects."""
        return list(self._plugins.values())
    
    def list_available_plugins(self) -> list[str]:
        """List all available (discoverable) plugins."""
        return self._loader.discover_plugins()
    
    def get_plugins_for_phase(self, phase: ScanPhase) -> list[BasePlugin]:
        """Get all plugins that support a specific scan phase."""
        return [
            plugin for plugin in self._plugins.values()
            if phase in plugin.phases and plugin.config.enabled
        ]
    
    def get_plugins_with_capability(
        self,
        capability: PluginCapability,
    ) -> list[BasePlugin]:
        """Get all plugins with a specific capability."""
        return [
            plugin for plugin in self._plugins.values()
            if capability in plugin.capabilities and plugin.config.enabled
        ]
    
    async def install_plugin(self, plugin_name: str) -> tuple[bool, str]:
        """Install a plugin's underlying tool.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Tuple of (success, message)
        """
        plugin = self.get_plugin(plugin_name)
        if plugin is None:
            # Try to load it first
            plugin = await self.load_plugin(plugin_name)
        
        success, message = await plugin.install()
        if success:
            plugin.status = PluginStatus.INSTALLED
        
        return success, message
    
    async def update_plugin(self, plugin_name: str) -> tuple[bool, str]:
        """Update a plugin and its templates/rules.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Tuple of (success, message)
        """
        plugin = self.get_plugin(plugin_name)
        if plugin is None:
            return False, f"Plugin not found: {plugin_name}"
        
        return await plugin.update()
    
    async def update_all_plugins(self) -> dict[str, tuple[bool, str]]:
        """Update all installed plugins.
        
        Returns:
            Dictionary mapping plugin names to (success, message) tuples
        """
        results = {}
        for name, plugin in self._plugins.items():
            if plugin.status == PluginStatus.INSTALLED:
                results[name] = await plugin.update()
        return results
    
    def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin."""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.config.enabled = True
            return True
        return False
    
    def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin."""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            plugin.config.enabled = False
            return True
        return False
    
    def configure_plugin(
        self,
        plugin_name: str,
        config: dict[str, Any],
    ) -> bool:
        """Update a plugin's configuration.
        
        Args:
            plugin_name: Name of the plugin
            config: Configuration dictionary
            
        Returns:
            True if successful
        """
        plugin = self.get_plugin(plugin_name)
        if plugin is None:
            return False
        
        if "enabled" in config:
            plugin.config.enabled = config["enabled"]
        if "timeout_seconds" in config:
            plugin.config.timeout_seconds = config["timeout_seconds"]
        if "max_retries" in config:
            plugin.config.max_retries = config["max_retries"]
        if "rate_limit" in config:
            plugin.config.rate_limit = config["rate_limit"]
        if "custom_args" in config:
            plugin.config.custom_args.update(config["custom_args"])
        
        return True
    
    async def execute(
        self,
        plugin_name: str,
        target: str,
        phase: ScanPhase,
        parameters: dict[str, Any] | None = None,
    ) -> AsyncIterator[PluginEvent]:
        """Execute a plugin.
        
        Args:
            plugin_name: Name of the plugin to execute
            target: Target URL or IP
            phase: Current scan phase
            parameters: Plugin-specific parameters
            
        Yields:
            PluginEvent objects during execution
        """
        plugin = self.get_plugin(plugin_name)
        if plugin is None:
            raise ValueError(f"Plugin not found: {plugin_name}")
        
        if not plugin.config.enabled:
            raise ValueError(f"Plugin is disabled: {plugin_name}")
        
        if plugin.status != PluginStatus.INSTALLED:
            raise ValueError(f"Plugin not installed: {plugin_name}")
        
        # Validate parameters
        params = parameters or {}
        is_valid, error = plugin.validate_parameters(params)
        if not is_valid:
            raise ValueError(f"Invalid parameters: {error}")
        
        # Reset cancellation state
        plugin.reset_cancellation()
        plugin.status = PluginStatus.RUNNING
        
        try:
            async for event in plugin.execute(target, phase, params):
                yield event
        except Exception as e:
            # 构造详细错误信息
            error_detail = {
                "plugin": plugin_name,
                "error": str(e),
                "type": type(e).__name__,
                "traceback": traceback.format_exc(),
                "target": target,
                "phase": phase.value,
            }
            logger.error(f"[PluginExecutionError] {plugin_name}: {e}")
            
            # 发布错误事件到 EventBus 供前端订阅
            try:
                from trix.engine.event_bus import get_event_bus, Event, EventType
                bus = get_event_bus()
                await bus.publish(Event(
                    type=EventType.PLUGIN_ERROR,
                    data=error_detail,
                ))
            except Exception:
                pass  # 事件发布失败不影响主流程
            
            raise  # 重新抛出让调用方处理
        finally:
            plugin.status = PluginStatus.INSTALLED
            await plugin.cleanup()
    
    async def execute_multiple(
        self,
        plugin_names: list[str],
        target: str,
        phase: ScanPhase,
        parameters: dict[str, dict[str, Any]] | None = None,
        parallel: bool = False,
    ) -> AsyncIterator[PluginEvent]:
        """Execute multiple plugins.
        
        Args:
            plugin_names: List of plugin names to execute
            target: Target URL or IP
            phase: Current scan phase
            parameters: Dictionary mapping plugin names to their parameters
            parallel: Whether to run plugins in parallel
            
        Yields:
            PluginEvent objects from all plugins
        """
        params = parameters or {}
        
        if parallel:
            # Run all plugins in parallel
            async def run_plugin(name: str) -> list[PluginEvent]:
                events = []
                async for event in self.execute(name, target, phase, params.get(name)):
                    events.append(event)
                return events
            
            tasks = [run_plugin(name) for name in plugin_names]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Plugin execution error: {result}")
                else:
                    for event in result:
                        yield event
        else:
            # Run plugins sequentially
            for name in plugin_names:
                try:
                    async for event in self.execute(name, target, phase, params.get(name)):
                        yield event
                except Exception as e:
                    logger.error(f"Plugin {name} execution error: {e}")
    
    async def cancel_plugin(self, plugin_name: str) -> bool:
        """Cancel a running plugin.
        
        Args:
            plugin_name: Name of the plugin to cancel
            
        Returns:
            True if cancellation was requested
        """
        plugin = self.get_plugin(plugin_name)
        if plugin and plugin.status == PluginStatus.RUNNING:
            await plugin.cancel()
            return True
        return False
    
    async def cancel_all(self) -> None:
        """Cancel all running plugins."""
        for plugin in self._plugins.values():
            if plugin.status == PluginStatus.RUNNING:
                await plugin.cancel()
    
    def add_event_handler(self, handler: Callable[[PluginEvent], None]) -> None:
        """Add a global event handler for all plugins."""
        self._global_event_handlers.append(handler)
        # Add to existing plugins
        for plugin in self._plugins.values():
            plugin.add_event_handler(handler)
    
    def remove_event_handler(self, handler: Callable[[PluginEvent], None]) -> None:
        """Remove a global event handler."""
        if handler in self._global_event_handlers:
            self._global_event_handlers.remove(handler)
        for plugin in self._plugins.values():
            plugin.remove_event_handler(handler)
    
    def get_manifest(self, plugin_name: str) -> PluginManifest | None:
        """Get the manifest for a plugin."""
        try:
            return self._loader.load_manifest(plugin_name)
        except Exception:
            return None
    
    def get_ui_schema(self, plugin_name: str) -> dict[str, Any]:
        """Get the UI schema for a plugin's parameters."""
        plugin = self.get_plugin(plugin_name)
        if plugin:
            return plugin.get_ui_schema()
        
        # Try from manifest
        manifest = self.get_manifest(plugin_name)
        if manifest:
            return manifest.get_json_schema()
        
        return {}


# Global registry instance
_registry: PluginRegistry | None = None


def get_plugin_registry() -> PluginRegistry:
    """Get the global plugin registry instance."""
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
    return _registry


def set_plugin_registry(registry: PluginRegistry) -> None:
    """Set the global plugin registry instance."""
    global _registry
    _registry = registry
