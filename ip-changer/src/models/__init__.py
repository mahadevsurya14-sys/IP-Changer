"""Domain data models for IP Changer."""

from src.models.app_settings import PRESET_INTERVALS, AppSettings, ThemeMode
from src.models.connection_profile import (
    ConnectionCapabilities,
    ConnectionProfile,
    ConnectionStatus,
    ConnectionTestResult,
    ConnectionType,
    TrafficScope,
)
from src.models.rotation_event import (
    RotationEvent,
    RotationHistory,
    RotationResult,
    RotationState,
    sanitize_sensitive_text,
)

__all__ = [
    "ConnectionType",
    "ConnectionStatus",
    "TrafficScope",
    "ConnectionCapabilities",
    "ConnectionProfile",
    "ConnectionTestResult",
    "RotationState",
    "RotationResult",
    "RotationEvent",
    "RotationHistory",
    "sanitize_sensitive_text",
    "ThemeMode",
    "AppSettings",
    "PRESET_INTERVALS",
]
