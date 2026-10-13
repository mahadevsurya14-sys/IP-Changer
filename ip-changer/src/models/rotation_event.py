"""Rotation state, outcome, event, and history tracking models.

Maintains an auditable, thread-safe history of public IP transitions
and rotation performance statistics.
"""

from __future__ import annotations

import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional



class RotationState(str, Enum):
    """Finite state machine states during IP rotation cycles."""
    IDLE = "idle"
    VALIDATING = "validating"
    CONNECTING = "connecting"
    VERIFYING = "verifying"
    ROTATING = "rotating"
    PAUSED = "paused"
    CONNECTION_FAILED = "connection_failed"
    VERIFICATION_FAILED = "verification_failed"
    UNSUPPORTED_METHOD = "unsupported_method"
    SAFETY_BLOCKED = "safety_blocked"
    STOPPING = "stopping"


class RotationResult(str, Enum):
    """Categorized result of an individual rotation attempt."""
    SUCCESS_IP_CHANGED = "success_ip_changed"
    SUCCESS_IP_UNCHANGED = "success_ip_unchanged"
    FAILED_CONNECTION = "failed_connection"
    FAILED_VERIFICATION = "failed_verification"
    FAILED_TIMEOUT = "failed_timeout"
    FAILED_SAFETY = "failed_safety"
    CANCELLED = "cancelled"
    PROVIDER_LIMIT = "provider_limit"


def sanitize_sensitive_text(text: Optional[str]) -> Optional[str]:
    """Scrub sensitive credentials, tokens, and basic authorization strings.

    Args:
        text: Raw error or status message.

    Returns:
        Sanitized message with sensitive tokens masked.
    """
    if not text:
        return text

    # Mask Basic auth / Bearer headers
    sanitized = re.sub(
        r"(Bearer\s+)[A-Za-z0-9\-\._~\+\/]+=*",
        r"\1[REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    # Mask user:pass in URLs
    sanitized = re.sub(
        r"(https?|socks5?|socks5h)://([^:]+):([^@]+)@",
        r"\1://\2:[REDACTED]@",
        sanitized,
        flags=re.IGNORECASE,
    )
    # Mask password / token / secret key params
    sanitized = re.sub(
        r"(password|token|secret|auth|api_key)=([^\s&,;]+)",
        r"\1=[REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )
    return sanitized


@dataclass
class RotationEvent:
    """Record of an executed rotation attempt and observed IP delta."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    profile_name: str = ""
    method_type: str = ""
    previous_ip: Optional[str] = None
    new_ip: Optional[str] = None
    ip_changed: bool = False
    result: RotationResult = RotationResult.SUCCESS_IP_CHANGED
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    rotation_number: int = 0

    def __post_init__(self) -> None:
        """Sanitize error message upon instantiation."""
        if self.error_message:
            self.error_message = sanitize_sensitive_text(self.error_message)

    def to_dict(self) -> Dict[str, Any]:
        """Convert rotation event to dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "profile_name": self.profile_name,
            "method_type": self.method_type,
            "previous_ip": self.previous_ip,
            "new_ip": self.new_ip,
            "ip_changed": self.ip_changed,
            "result": self.result.value if isinstance(self.result, RotationResult) else self.result,
            "duration_seconds": round(self.duration_seconds, 3),
            "error_message": self.error_message,
            "rotation_number": self.rotation_number,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RotationEvent:
        """Deserialize rotation event from dictionary."""
        res_raw = data.get("result", RotationResult.SUCCESS_IP_CHANGED.value)
        result = RotationResult(res_raw) if isinstance(res_raw, str) else res_raw

        return cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            profile_name=data.get("profile_name", ""),
            method_type=data.get("method_type", ""),
            previous_ip=data.get("previous_ip"),
            new_ip=data.get("new_ip"),
            ip_changed=bool(data.get("ip_changed", False)),
            result=result,
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            error_message=sanitize_sensitive_text(data.get("error_message")),
            rotation_number=int(data.get("rotation_number", 0)),
        )


class RotationHistory:
    """Thread-safe historical ledger of rotation events with aggregation helpers."""

    def __init__(self, max_history_size: int = 1000) -> None:
        self._max_history_size = max(10, max_history_size)
        self._events: List[RotationEvent] = []
        self._lock = threading.RLock()

    @property
    def max_history_size(self) -> int:
        """Get maximum historical event capacity."""
        return self._max_history_size

    @max_history_size.setter
    def max_history_size(self, size: int) -> None:
        """Update maximum capacity, truncating older items if necessary."""
        with self._lock:
            self._max_history_size = max(10, size)
            if len(self._events) > self._max_history_size:
                self._events = self._events[-self._max_history_size:]

    def add(self, event: RotationEvent) -> None:
        """Append a new rotation event, maintaining size ceiling.

        Args:
            event: RotationEvent instance to store.
        """
        with self._lock:
            self._events.append(event)
            if len(self._events) > self._max_history_size:
                self._events.pop(0)

    def clear(self) -> None:
        """Purge all recorded events."""
        with self._lock:
            self._events.clear()

    def get_events(self, limit: Optional[int] = None) -> List[RotationEvent]:
        """Retrieve a shallow copy of stored events, newest last.

        Args:
            limit: Maximum number of recent events to return.
        """
        with self._lock:
            if limit is not None and limit > 0:
                return list(self._events[-limit:])
            return list(self._events)

    def get_stats(self) -> Dict[str, Any]:
        """Calculate summary statistics over the recorded events.

        Returns:
            Dict containing total, success count, failure count, IP change count,
            and average rotation duration in seconds.
        """
        with self._lock:
            total = len(self._events)
            if total == 0:
                return {
                    "total": 0,
                    "success_count": 0,
                    "fail_count": 0,
                    "ip_changed_count": 0,
                    "ip_unchanged_count": 0,
                    "avg_duration_seconds": 0.0,
                }

            success_results = {
                RotationResult.SUCCESS_IP_CHANGED,
                RotationResult.SUCCESS_IP_UNCHANGED,
            }
            success_count = sum(1 for e in self._events if e.result in success_results)
            fail_count = total - success_count
            ip_changed_count = sum(1 for e in self._events if e.ip_changed)
            ip_unchanged_count = sum(1 for e in self._events if not e.ip_changed and e.result in success_results)
            avg_duration = sum(e.duration_seconds for e in self._events) / total

            return {
                "total": total,
                "success_count": success_count,
                "fail_count": fail_count,
                "ip_changed_count": ip_changed_count,
                "ip_unchanged_count": ip_unchanged_count,
                "avg_duration_seconds": round(avg_duration, 3),
            }

    def export_to_dicts(self) -> List[Dict[str, Any]]:
        """Export all events as list of dictionaries."""
        with self._lock:
            return [e.to_dict() for e in self._events]
