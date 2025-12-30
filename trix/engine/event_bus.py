"""Event Bus for real-time communication.

Provides a pub/sub system for distributing events across
the application, enabling real-time UI updates.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine
from collections import defaultdict

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Types of events in the system."""
    
    # Scan lifecycle
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"
    SCAN_PAUSED = "scan.paused"
    SCAN_RESUMED = "scan.resumed"
    SCAN_ERROR = "scan.error"
    
    # Phase lifecycle
    PHASE_STARTED = "phase.started"
    PHASE_COMPLETED = "phase.completed"
    PHASE_FAILED = "phase.failed"
    PHASE_SKIPPED = "phase.skipped"
    
    # Plugin events
    PLUGIN_STARTED = "plugin.started"
    PLUGIN_PROGRESS = "plugin.progress"
    PLUGIN_OUTPUT = "plugin.output"
    PLUGIN_COMPLETED = "plugin.completed"
    PLUGIN_ERROR = "plugin.error"
    
    # Findings
    VULNERABILITY_FOUND = "vulnerability.found"
    FINDING_VERIFIED = "finding.verified"
    FINDING_DISMISSED = "finding.dismissed"
    
    # LLM events
    LLM_REQUEST = "llm.request"
    LLM_RESPONSE = "llm.response"
    LLM_ERROR = "llm.error"
    
    # System events
    PLUGIN_INSTALLED = "plugin.installed"
    PLUGIN_UPDATED = "plugin.updated"
    PLUGIN_ENABLED = "plugin.enabled"
    PLUGIN_DISABLED = "plugin.disabled"
    
    # Task events (细粒度任务状态)
    TASK_STARTED = "task.started"      # {task_id, task_type, target, plugin_name}
    TASK_FINISHED = "task.finished"    # {task_id, status, duration_ms, findings_count}
    TASK_FAILED = "task.failed"        # {task_id, error, traceback}
    TASK_QUEUED = "task.queued"        # {task_id, queue_size}
    
    # AI events (AI 干预状态)
    AI_INTERVENTION = "ai.intervention"  # {task_id, vuln_type, target, message}
    AI_BYPASS_STARTED = "ai.bypass_started"  # AI 开始生成绕过 payload
    AI_BYPASS_RESULT = "ai.bypass_result"    # AI bypass 结果
    
    # Generic
    LOG = "log"
    ERROR = "error"


@dataclass
class Event:
    """An event in the system."""
    
    type: EventType
    data: dict[str, Any]
    scan_id: str | None = None
    timestamp: float = field(default_factory=lambda: asyncio.get_event_loop().time())
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.type.value,
            "data": self.data,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
        }


# Type alias for event handlers
EventHandler = Callable[[Event], Coroutine[Any, Any, None] | None]


class EventBus:
    """Central event bus for the application.
    
    Supports both synchronous and asynchronous handlers.
    Handlers can subscribe to specific event types or all events.
    
    Example:
        bus = EventBus()
        
        # Subscribe to specific event
        async def on_vuln(event):
            print(f"Found: {event.data}")
        bus.subscribe(EventType.VULNERABILITY_FOUND, on_vuln)
        
        # Subscribe to all events
        bus.subscribe_all(lambda e: print(e.type))
        
        # Publish event
        await bus.publish(Event(
            type=EventType.VULNERABILITY_FOUND,
            data={"title": "SQL Injection"}
        ))
    """
    
    def __init__(self):
        self._handlers: dict[EventType, list[EventHandler]] = defaultdict(list)
        self._global_handlers: list[EventHandler] = []
        self._event_queue: asyncio.Queue[Event] = asyncio.Queue()
        self._running = False
        self._task: asyncio.Task | None = None
    
    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Subscribe to a specific event type."""
        self._handlers[event_type].append(handler)
    
    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Unsubscribe from a specific event type."""
        if handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
    
    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe to all events."""
        self._global_handlers.append(handler)
    
    def unsubscribe_all(self, handler: EventHandler) -> None:
        """Unsubscribe from all events."""
        if handler in self._global_handlers:
            self._global_handlers.remove(handler)
    
    async def emit(self, event: Event) -> None:
        """Alias for publish (for compatibility with checklist)."""
        await self.publish(event)

    def emit_sync(self, event: Event) -> None:
        """Alias for publish_sync."""
        self.publish_sync(event)

    async def publish(self, event: Event) -> None:
        """Publish an event to all subscribers.
        
        This is async and will notify handlers immediately.
        """
        # Notify specific handlers
        handlers = self._handlers.get(event.type, [])
        for handler in handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(f"Event handler error for {event.type}: {e}")
        
        # Notify global handlers
        for handler in self._global_handlers:
            try:
                result = handler(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(f"Global event handler error: {e}")
    
    def publish_sync(self, event: Event) -> None:
        """Queue an event for async publishing.
        
        Use this when you can't await the publish.
        """
        try:
            self._event_queue.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("Event queue full, dropping event")
    
    async def start(self) -> None:
        """Start the event processing loop."""
        if self._running:
            return
        
        self._running = True
        self._task = asyncio.create_task(self._process_events())
    
    async def stop(self) -> None:
        """Stop the event processing loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
    
    async def _process_events(self) -> None:
        """Process events from the queue."""
        while self._running:
            try:
                event = await asyncio.wait_for(
                    self._event_queue.get(),
                    timeout=0.1,
                )
                await self.publish(event)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Event processing error: {e}")
    
    def clear_handlers(self) -> None:
        """Remove all handlers."""
        self._handlers.clear()
        self._global_handlers.clear()


# Global event bus instance
_event_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


def set_event_bus(bus: EventBus) -> None:
    """Set the global event bus instance."""
    global _event_bus
    _event_bus = bus
