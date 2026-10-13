"""Core infrastructure and business logic for IP Changer."""

from src.core.capability_registry import CapabilityRegistry, MethodCapability
from src.core.connection_manager import ConnectionManager
from src.core.event_bus import (
    CONNECTION_STATUS_CHANGED,
    DIAGNOSTIC_COMPLETED,
    IP_VERIFIED,
    KILL_SWITCH_TOGGLED,
    PROFILE_ADDED,
    PROFILE_REMOVED,
    PROFILE_UPDATED,
    ROTATION_COMPLETED,
    ROTATION_STATE_CHANGED,
    SETTINGS_CHANGED,
    EventBus,
    default_event_bus,
)
from src.core.ip_verifier import IPVerificationResult, IPVerifier
from src.core.method_selector import MethodSelector, SelectionResult
from src.core.rotation_controller import RotationController
from src.core.safety_manager import SafetyManager, SafetyStatus

__all__ = [
    # Event Bus
    "EventBus",
    "default_event_bus",
    "SETTINGS_CHANGED",
    "PROFILE_ADDED",
    "PROFILE_REMOVED",
    "PROFILE_UPDATED",
    "ROTATION_STATE_CHANGED",
    "ROTATION_COMPLETED",
    "CONNECTION_STATUS_CHANGED",
    "IP_VERIFIED",
    "KILL_SWITCH_TOGGLED",
    "DIAGNOSTIC_COMPLETED",
    # Verification & Capabilities
    "IPVerifier",
    "IPVerificationResult",
    "CapabilityRegistry",
    "MethodCapability",
    # Selection & Connection
    "MethodSelector",
    "SelectionResult",
    "ConnectionManager",
    # Rotation & Safety
    "RotationController",
    "SafetyManager",
    "SafetyStatus",
]
