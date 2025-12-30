"""FastAPI Application.

Main FastAPI application with all routes and middleware.
"""

from __future__ import annotations

import asyncio
import logging
import traceback
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from trix.storage import get_database
from trix.plugins import PluginRegistry
from trix.engine import ScanEngine, EventBus

logger = logging.getLogger(__name__)


# Global instances
_event_bus: EventBus | None = None
_plugin_registry: PluginRegistry | None = None
_scan_engine: ScanEngine | None = None


def get_event_bus() -> EventBus:
    """Get the global event bus."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


def get_plugin_registry() -> PluginRegistry:
    """Get the global plugin registry."""
    global _plugin_registry
    if _plugin_registry is None:
        _plugin_registry = PluginRegistry()
    return _plugin_registry


def get_scan_engine() -> ScanEngine:
    """Get the global scan engine."""
    global _scan_engine
    if _scan_engine is None:
        _scan_engine = ScanEngine(
            plugin_registry=get_plugin_registry(),
            event_bus=get_event_bus(),
        )
    return _scan_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    logger.info("Starting Trix server...")
    
    # Initialize database
    db = get_database()
    logger.info(f"Database ready at {db.db_path}")
    
    # Initialize plugin registry (don't fail if plugins can't load)
    try:
        registry = get_plugin_registry()
        await registry.initialize()
        logger.info(f"Loaded {len(registry.list_plugins())} plugins")
    except Exception as e:
        logger.warning(f"Plugin initialization failed: {e}")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Trix server...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="Trix Security Scanner",
        description="AI-powered web application security scanner",
        version="2.0.0",
        lifespan=lifespan,
    )
    
    # CORS middleware for desktop app
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Tauri app
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Global exception handler with structured error response
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.exception(f"Unhandled error: {exc}")
        
        # 构造标准化错误响应
        error_response = {
            "status": "error",
            "code": 500,
            "message": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(),
            "path": str(request.url.path),
        }
        
        # 通过 EventBus 推送错误到前端
        try:
            from trix.engine.event_bus import Event, EventType
            event_bus = get_event_bus()
            await event_bus.publish(Event(
                type=EventType.ERROR,
                data=error_response,
            ))
        except Exception:
            pass  # 推送失败不影响响应
        
        return JSONResponse(
            status_code=500,
            content=error_response,
        )
    
    # Register routes
    from trix.server.routes import scans, plugins, results, websocket, settings, custom_plugins, auth
    
    app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
    app.include_router(plugins.router, prefix="/api/plugins", tags=["plugins"])
    app.include_router(custom_plugins.router, prefix="/api/custom-plugins", tags=["custom-plugins"])
    app.include_router(results.router, prefix="/api/results", tags=["results"])
    app.include_router(settings.router, prefix="/api", tags=["settings"])
    app.include_router(auth.router, prefix="/api/login", tags=["auth"])  # Browser login assistant
    app.include_router(websocket.router, prefix="/ws", tags=["websocket"])
    
    # Health check
    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "version": "2.0.0",
        }
    
    # API info
    @app.get("/api")
    async def api_info():
        registry = get_plugin_registry()
        engine = get_scan_engine()
        
        return {
            "name": "Trix Security Scanner",
            "version": "2.0.0",
            "plugins_loaded": len(registry.list_plugins()),
            "active_scans": len(engine._tasks),
        }
    
    return app


# Create the default app instance
app = create_app()
