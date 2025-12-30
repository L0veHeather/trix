"""WebSocket API.

Real-time communication with the frontend via WebSocket.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from trix.server.app import get_event_bus
from trix.engine import EventType

logger = logging.getLogger(__name__)
router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections."""
    
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}
        self.scan_subscriptions: dict[str, set[str]] = {}  # scan_id -> connection_ids
        self._event_handlers: dict[str, Callable] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"Client {client_id} connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, client_id: str):
        """Handle client disconnection."""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        
        # Remove from all subscriptions
        for scan_id, subscribers in list(self.scan_subscriptions.items()):
            subscribers.discard(client_id)
            if not subscribers:
                del self.scan_subscriptions[scan_id]
        
        logger.info(f"Client {client_id} disconnected. Total: {len(self.active_connections)}")
    
    def subscribe_to_scan(self, client_id: str, scan_id: str):
        """Subscribe client to scan updates."""
        if scan_id not in self.scan_subscriptions:
            self.scan_subscriptions[scan_id] = set()
        self.scan_subscriptions[scan_id].add(client_id)
        logger.debug(f"Client {client_id} subscribed to scan {scan_id}")
    
    def unsubscribe_from_scan(self, client_id: str, scan_id: str):
        """Unsubscribe client from scan updates."""
        if scan_id in self.scan_subscriptions:
            self.scan_subscriptions[scan_id].discard(client_id)
    
    async def send_personal(self, client_id: str, message: dict[str, Any]):
        """Send message to specific client."""
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json(message)
            except Exception as e:
                logger.error(f"Failed to send to {client_id}: {e}")
    
    async def broadcast(self, message: dict[str, Any]):
        """Broadcast message to all connected clients."""
        for client_id, websocket in list(self.active_connections.items()):
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Failed to broadcast to {client_id}: {e}")
    
    async def broadcast_to_scan(self, scan_id: str, message: dict[str, Any]):
        """Broadcast message to all clients subscribed to a scan."""
        subscribers = self.scan_subscriptions.get(scan_id, set())
        for client_id in subscribers:
            await self.send_personal(client_id, message)


# Global connection manager
manager = ConnectionManager()


def setup_event_bus_handlers():
    """Set up handlers to forward event bus events to WebSocket clients."""
    from trix.engine.event_bus import Event
    event_bus = get_event_bus()
    
    async def handle_scan_started(event: Event):
        await manager.broadcast({
            "type": "scan.started",
            "data": event.data,
        })
    
    async def handle_scan_progress(event: Event):
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "scan.progress",
                "data": event.data,
            })
    
    async def handle_phase_started(event: Event):
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "phase.started",
                "data": event.data,
            })
    
    async def handle_phase_completed(event: Event):
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "phase.completed",
                "data": event.data,
            })
    
    async def handle_vulnerability_found(event: Event):
        scan_id = event.scan_id or event.data.get("scan_id")
        # Broadcast to scan subscribers
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "vulnerability.found",
                "data": event.data,
            })
        # Also broadcast globally for dashboard updates
        await manager.broadcast({
            "type": "vulnerability.new",
            "data": {
                "scan_id": scan_id,
                "severity": event.data.get("severity"),
                "title": event.data.get("title"),
            },
        })
    
    async def handle_scan_completed(event: Event):
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "scan.completed",
                "data": event.data,
            })
        await manager.broadcast({
            "type": "scan.finished",
            "data": {"scan_id": scan_id},
        })
    
    async def handle_scan_error(event: Event):
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "scan.error",
                "data": event.data,
            })
    
    async def handle_plugin_started(event: Event):
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "plugin.started",
                "data": event.data,
            })
    
    async def handle_plugin_completed(event: Event):
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "plugin.completed",
                "data": event.data,
            })

    async def handle_plugin_error(event: Event):
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "scan.error",
                "data": event.data,
            })

    async def handle_plugin_output(event: Event):
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "plugin.output",
                "data": event.data,
            })
    
    async def handle_llm_response(event: Event):
        """Forward LLM judgment results with reasoning_trace for AI visualization."""
        scan_id = event.scan_id or event.data.get("scan_id")
        # Broadcast to scan subscribers with full reasoning data
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "llm.response",
                "data": {
                    "scan_id": scan_id,
                    "vuln_type": event.data.get("vuln_type", ""),
                    "is_vulnerable": event.data.get("is_vulnerable", False),
                    "confidence_score": event.data.get("confidence_score", 0.0),
                    "reasoning": event.data.get("reasoning", ""),
                    "reasoning_trace": event.data.get("reasoning_trace", ""),
                    "evidence": event.data.get("evidence", []),
                    "evidence_snippet": event.data.get("evidence_snippet", ""),
                    "waf_detected": event.data.get("waf_detected", False),
                    "waf_type": event.data.get("waf_type", ""),
                },
            })
    
    async def handle_verification_created(event: Event):
        """Forward verification task creation events."""
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "verification.created",
                "data": {
                    "scan_id": scan_id,
                    "task_id": event.data.get("task_id", ""),
                    "verification_payload": event.data.get("verification_payload", ""),
                    "reason": event.data.get("reason", ""),
                    "depth": event.data.get("depth", 0),
                },
            })
    
    # 🔥 Task events for fine-grained progress tracking
    async def handle_task_started(event: Event):
        """Forward task started events to task log panel."""
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "task.started",
                "data": event.data,
            })
    
    async def handle_task_finished(event: Event):
        """Forward task finished events."""
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "task.finished",
                "data": event.data,
            })
    
    async def handle_task_failed(event: Event):
        """Forward task failed events - frontend should display in task log, not popup."""
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "task.failed",
                "data": event.data,
            })
    
    # Subscribe to events
    event_bus.subscribe(EventType.SCAN_STARTED, handle_scan_started)
    event_bus.subscribe(EventType.SCAN_PROGRESS, handle_scan_progress)
    event_bus.subscribe(EventType.PHASE_STARTED, handle_phase_started)
    event_bus.subscribe(EventType.PHASE_COMPLETED, handle_phase_completed)
    event_bus.subscribe(EventType.VULNERABILITY_FOUND, handle_vulnerability_found)
    event_bus.subscribe(EventType.SCAN_COMPLETED, handle_scan_completed)
    event_bus.subscribe(EventType.SCAN_ERROR, handle_scan_error)
    event_bus.subscribe(EventType.PLUGIN_STARTED, handle_plugin_started)
    event_bus.subscribe(EventType.PLUGIN_COMPLETED, handle_plugin_completed)
    event_bus.subscribe(EventType.PLUGIN_ERROR, handle_plugin_error)
    event_bus.subscribe(EventType.PLUGIN_OUTPUT, handle_plugin_output)
    event_bus.subscribe(EventType.LLM_RESPONSE, handle_llm_response)
    
    # Task events (细粒度)
    event_bus.subscribe(EventType.TASK_STARTED, handle_task_started)
    event_bus.subscribe(EventType.TASK_FINISHED, handle_task_finished)
    event_bus.subscribe(EventType.TASK_FAILED, handle_task_failed)
    
    # 🔥 AI events - 通知前端 AI 干预状态
    async def handle_ai_intervention(event: Event):
        """Forward AI intervention events to show user: 🤖 AI is verifying..."""
        scan_id = event.scan_id or event.data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "ai.intervention",
                "data": event.data,
            })
        # Also broadcast globally for dashboard visibility
        await manager.broadcast({
            "type": "ai.activity",
            "data": {
                "scan_id": scan_id,
                "message": event.data.get("message", "🤖 AI verifying..."),
            },
        })
    
    event_bus.subscribe(EventType.AI_INTERVENTION, handle_ai_intervention)


# Initialize event handlers
setup_event_bus_handlers()


@router.websocket("/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket, client_id)
    
    try:
        while True:
            # Receive messages from client
            data = await websocket.receive_json()
            
            action = data.get("action")
            
            if action == "subscribe":
                scan_id = data.get("scan_id")
                if scan_id:
                    manager.subscribe_to_scan(client_id, scan_id)
                    await manager.send_personal(client_id, {
                        "type": "subscribed",
                        "scan_id": scan_id,
                    })
            
            elif action == "unsubscribe":
                scan_id = data.get("scan_id")
                if scan_id:
                    manager.unsubscribe_from_scan(client_id, scan_id)
                    await manager.send_personal(client_id, {
                        "type": "unsubscribed",
                        "scan_id": scan_id,
                    })
            
            elif action == "ping":
                await manager.send_personal(client_id, {"type": "pong"})
            
            else:
                await manager.send_personal(client_id, {
                    "type": "error",
                    "message": f"Unknown action: {action}",
                })
    
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.exception(f"WebSocket error for {client_id}")
        manager.disconnect(client_id)
