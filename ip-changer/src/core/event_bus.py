"""Thread-safe Event Bus for IP Changer application.

Enables decoupled communication across UI, background workers, and services.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)

# Core Event Type Constants
SETTINGS_CHANGED = "settings_changed"
PROFILE_ADDED = "profile_added"
PROFILE_REMOVED = "profile_removed"
PROFILE_UPDATED = "profile_updated"
ROTATION_STATE_CHANGED = "rotation_state_changed"
ROTATION_COMPLETED = "rotation_completed"
CONNECTION_STATUS_CHANGED = "connection_status_changed"
IP_VERIFIED = "ip_verified"
KILL_SWITCH_TOGGLED = "kill_switch_toggled"
DIAGNOSTIC_COMPLETED = "diagnostic_completed"


class EventBus:
    """Thread-safe publisher/subscriber event bus."""

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[Callable[[Any], None]]] = {}
        self._lock = threading.RLock()

    def subscribe(self, event_type: str, callback: Callable[[Any], None]) -> None:
        """Register a callback for an event type.

        Args:
            event_type: Identifier of the event to listen for.
            callback: Callable accepting event payload.
        """
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            if callback not in self._subscribers[event_type]:
                self._subscribers[event_type].append(callback)
                logger.debug("Subscribed %s to %s", callback.__name__, event_type)

    def unsubscribe(self, event_type: str, callback: Callable[[Any], None]) -> None:
        """Remove a callback for an event type.

        Args:
            event_type: Identifier of the event.
            callback: Callable to deregister.
        """
        with self._lock:
            if event_type in self._subscribers:
                try:
                    self._subscribers[event_type].remove(callback)
                    logger.debug("Unsubscribed %s from %s", callback.__name__, event_type)
                    if not self._subscribers[event_type]:
                        del self._subscribers[event_type]
                except ValueError:
                    pass

    def emit(self, event_type: str, data: Any = None) -> None:
        """Emit an event to all subscribers synchronously in a thread-safe manner.

        Args:
            event_type: Identifier of the event being emitted.
            data: Payload passed to subscriber callbacks.
        """
        with self._lock:
            subscribers_snapshot = list(self._subscribers.get(event_type, []))

        for callback in subscribers_snapshot:
            try:
                callback(data)
            except Exception as exc:  # pylint: disable=broad-except
                logger.exception("Error executing subscriber %s for event '%s': %s", callback, event_type, exc)

    def clear(self) -> None:
        """Remove all subscribers."""
        with self._lock:
            self._subscribers.clear()


# Default singleton instance
default_event_bus = EventBus()
