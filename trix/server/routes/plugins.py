"""Plugin API Routes.

REST API endpoints for managing plugins.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from trix.storage import get_database
from trix.server.app import get_plugin_registry
from trix.plugins import ScanPhase, PluginStatus

logger = logging.getLogger(__name__)
router = APIRouter()


# ==================== Request/Response Models ====================

class PluginInfo(BaseModel):
    """Response model for plugin information."""
    
    name: str
    version: str
    description: str | None
    author: str | None
    phases: list[str]
    capabilities: list[str]
    status: str
    installed: bool
    enabled: bool


class PluginListResponse(BaseModel):
    """Response model for plugin list."""
    
    plugins: list[PluginInfo]
    total: int


class PluginConfigRequest(BaseModel):
    """Request model for plugin configuration."""
    
    enabled: bool | None = None
    timeout_seconds: int | None = None
    max_retries: int | None = None
    rate_limit: int | None = None
    custom_config: dict[str, Any] | None = None


class InstallPluginRequest(BaseModel):
    """Request model for installing a plugin."""
    
    name: str
    force: bool = False


# ==================== Endpoints ====================

@router.get("", response_model=PluginListResponse)
async def list_plugins(
    phase: str | None = None,
    installed_only: bool = False,
    enabled_only: bool = False,
):
    """List all available plugins."""
    registry = get_plugin_registry()
    db = get_database()
    
    plugins = []
    
    for plugin in registry.get_loaded_plugins():
        # Filter by phase
        if phase and phase.upper() not in [p.name for p in plugin.phases]:
            continue
        
        # Get config from database
        config = db.get_plugin_config(plugin.name)
        
        # Filter by installed/enabled
        installed = await plugin.check_installed()
        enabled = config.enabled if config else True
        
        if installed_only and not installed:
            continue
        if enabled_only and not enabled:
            continue
        
        plugins.append(PluginInfo(
            name=plugin.name,
            version=plugin.version,
            description=plugin.description,
            author=plugin.author,
            phases=[p.name for p in plugin.phases],
            capabilities=[c.name for c in plugin.capabilities],
            status=plugin.status.name,
            installed=installed,
            enabled=enabled,
        ))
    
    return PluginListResponse(plugins=plugins, total=len(plugins))


@router.get("/load-status")
async def get_plugin_load_status():
    """获取插件加载状态，包含失败的插件列表.
    
    Returns:
        loaded: 成功加载的插件数量
        failed: 加载失败的插件详情列表
    """
    from trix.plugins.registry import PluginLoadResult
    registry = get_plugin_registry()
    
    # 获取存储的加载结果
    load_result = getattr(registry, '_load_result', PluginLoadResult())
    
    return {
        "loaded": len(registry.list_plugins()),
        "valid": load_result.valid,
        "failed": load_result.invalid,
    }


@router.get("/{plugin_name}")
async def get_plugin(plugin_name: str):
    """Get details of a specific plugin."""
    registry = get_plugin_registry()
    db = get_database()
    
    plugin = registry.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    config = db.get_plugin_config(plugin_name)
    installed = await plugin.check_installed()
    
    return {
        "name": plugin.name,
        "version": plugin.version,
        "description": plugin.description,
        "author": plugin.author,
        "homepage": plugin.homepage,
        "phases": [p.name for p in plugin.phases],
        "capabilities": [c.name for c in plugin.capabilities],
        "status": plugin.status.name,
        "installed": installed,
        "config": config.to_dict() if config else None,
        "parameters": [
            {
                "name": p.name,
                "description": p.description,
                "type": p.param_type,
                "required": p.required,
                "default": p.default,
            }
            for p in plugin.parameters
        ],
    }


@router.post("/{plugin_name}/install")
async def install_plugin(
    plugin_name: str,
    request: InstallPluginRequest | None = None,
    background_tasks: BackgroundTasks = None,
):
    """Install a plugin."""
    registry = get_plugin_registry()
    db = get_database()
    
    plugin = registry.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    # Check if already installed
    if await plugin.check_installed() and not (request and request.force):
        return {
            "status": "already_installed",
            "plugin": plugin_name,
            "version": plugin.version,
        }
    
    # Install plugin
    try:
        success = await plugin.install()
        if success:
            # Update database
            db.save_plugin_config(
                plugin_name,
                installed=True,
                version=plugin.version,
            )
            logger.info(f"Installed plugin: {plugin_name}")
            return {
                "status": "installed",
                "plugin": plugin_name,
                "version": plugin.version,
            }
        else:
            raise HTTPException(status_code=500, detail="Installation failed")
    except Exception as e:
        logger.exception(f"Failed to install {plugin_name}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{plugin_name}/update")
async def update_plugin(plugin_name: str):
    """Update a plugin to the latest version."""
    registry = get_plugin_registry()
    db = get_database()
    
    plugin = registry.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    try:
        success = await plugin.update()
        if success:
            db.save_plugin_config(
                plugin_name,
                version=plugin.version,
            )
            logger.info(f"Updated plugin: {plugin_name}")
            return {
                "status": "updated",
                "plugin": plugin_name,
                "version": plugin.version,
            }
        else:
            return {
                "status": "no_update",
                "plugin": plugin_name,
                "message": "Already at latest version",
            }
    except Exception as e:
        logger.exception(f"Failed to update {plugin_name}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{plugin_name}/config")
async def update_plugin_config(plugin_name: str, request: PluginConfigRequest):
    """Update plugin configuration."""
    registry = get_plugin_registry()
    db = get_database()
    
    plugin = registry.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    # Build update dict
    updates = {}
    if request.enabled is not None:
        updates["enabled"] = request.enabled
    if request.timeout_seconds is not None:
        updates["timeout_seconds"] = request.timeout_seconds
    if request.max_retries is not None:
        updates["max_retries"] = request.max_retries
    if request.rate_limit is not None:
        updates["rate_limit"] = request.rate_limit
    if request.custom_config is not None:
        updates["custom_config"] = request.custom_config
    
    config = db.save_plugin_config(plugin_name, **updates)
    
    return {
        "status": "updated",
        "plugin": plugin_name,
        "config": config.to_dict(),
    }


@router.post("/{plugin_name}/enable")
async def enable_plugin(plugin_name: str):
    """Enable a plugin."""
    registry = get_plugin_registry()
    db = get_database()
    
    plugin = registry.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    db.save_plugin_config(plugin_name, enabled=True)
    
    return {"status": "enabled", "plugin": plugin_name}


@router.post("/{plugin_name}/disable")
async def disable_plugin(plugin_name: str):
    """Disable a plugin."""
    registry = get_plugin_registry()
    db = get_database()
    
    plugin = registry.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    db.save_plugin_config(plugin_name, enabled=False)
    
    return {"status": "disabled", "plugin": plugin_name}


@router.get("/phases/available")
async def list_phases():
    """List all available scan phases."""
    return {
        "phases": [
            {
                "name": phase.name,
                "value": phase.value,
                "description": _get_phase_description(phase),
            }
            for phase in ScanPhase
        ]
    }


@router.get("/phases/{phase}/plugins")
async def get_phase_plugins(phase: str):
    """Get all plugins for a specific phase."""
    registry = get_plugin_registry()
    
    try:
        scan_phase = ScanPhase[phase.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Invalid phase: {phase}")
    
    plugins = registry.get_plugins_for_phase(scan_phase)
    
    return {
        "phase": phase,
        "plugins": [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
            }
            for p in plugins
        ],
    }


def _get_phase_description(phase: ScanPhase) -> str:
    """Get description for a scan phase."""
    descriptions = {
        ScanPhase.RECONNAISSANCE: "Information gathering and target discovery",
        ScanPhase.ENUMERATION: "Service enumeration and content discovery",
        ScanPhase.VULNERABILITY_SCAN: "Automated vulnerability scanning",
        ScanPhase.EXPLOITATION: "Vulnerability exploitation and verification",
        ScanPhase.POST_EXPLOITATION: "Post-exploitation analysis",
        ScanPhase.VALIDATION: "Finding validation and verification",
        ScanPhase.REPORTING: "Report generation and export",
    }
    return descriptions.get(phase, "")
