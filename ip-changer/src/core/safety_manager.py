"""Safety manager ensuring traffic leak prevention and kill switch enforcement.

Provides baseline IP detection, leak verification, firewall kill-switch toggling,
pre-rotation sanity checks, and safe network state restoration.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.core.event_bus import EventBus, KILL_SWITCH_TOGGLED
from src.core.ip_verifier import IPVerifier
from src.models.app_settings import AppSettings
from src.models.connection_profile import ConnectionProfile, TrafficScope

logger = logging.getLogger(__name__)


@dataclass
class SafetyStatus:
    """Current posture of safety protections and network guardrails."""
    kill_switch_active: bool
    is_protected: bool
    can_guarantee_protection: bool
    active_protections: List[str] = field(default_factory=list)
    warnings: List[Tuple[str, str] | str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert safety status to dictionary."""
        return asdict(self)


class SafetyManager:
    """Manages kill switch enforcement and leak protection guardrails."""

    def __init__(self, event_bus: EventBus, settings: AppSettings) -> None:
        """Initialize SafetyManager.

        Args:
            event_bus: System event bus.
            settings: Master application settings.
        """
        self._event_bus = event_bus
        self._settings = settings

        self._kill_switch_active: bool = settings.kill_switch_enabled
        self._baseline_direct_ip: Optional[str] = None
        self._lock = threading.RLock()

    @property
    def kill_switch_active(self) -> bool:
        """Check if kill switch is currently enabled."""
        with self._lock:
            return self._kill_switch_active

    @property
    def baseline_direct_ip(self) -> Optional[str]:
        """Get initial baseline direct public IP."""
        with self._lock:
            return self._baseline_direct_ip

    def establish_baseline_ip(self, ip_verifier: IPVerifier) -> Optional[str]:
        """Record the initial direct (unproxied) public IP as baseline for leak checks.

        Args:
            ip_verifier: IPVerifier instance.

        Returns:
            Discovered direct public IP string or None.
        """
        result = ip_verifier.verify_ip(proxy_config=None)
        with self._lock:
            if result.is_valid and result.ip_address:
                self._baseline_direct_ip = result.ip_address
                logger.info("Recorded direct baseline public IP: %s", self._baseline_direct_ip)
            return self._baseline_direct_ip

    def enable_kill_switch(self, adapter: Optional[Any] = None) -> Tuple[bool, str]:
        """Enable kill switch to prevent unencrypted/unproxied traffic leaks.

        Args:
            adapter: Optional platform firewall or network adapter.

        Returns:
            Tuple of (success: bool, status_message: str).
        """
        with self._lock:
            success = True
            message = "Kill switch enabled."

            if adapter and hasattr(adapter, "enable_kill_switch"):
                try:
                    success, message = adapter.enable_kill_switch()
                except Exception as exc:
                    logger.exception("Failed to engage platform kill switch: %s", exc)
                    return False, f"Firewall adapter error: {exc}"

            if success:
                self._kill_switch_active = True
                self._settings.kill_switch_enabled = True
                logger.info("Kill switch active: %s", message)
                self._event_bus.emit(
                    KILL_SWITCH_TOGGLED,
                    {"kill_switch_active": True, "message": message},
                )
                return True, message

            return False, message

    def disable_kill_switch(self, adapter: Optional[Any] = None) -> Tuple[bool, str]:
        """Disable kill switch and restore normal network communication.

        Args:
            adapter: Optional platform firewall adapter.

        Returns:
            Tuple of (success: bool, status_message: str).
        """
        with self._lock:
            success = True
            message = "Kill switch disabled."

            if adapter and hasattr(adapter, "disable_kill_switch"):
                try:
                    success, message = adapter.disable_kill_switch()
                except Exception as exc:
                    logger.exception("Failed to disable platform kill switch: %s", exc)
                    return False, f"Firewall adapter error: {exc}"

            self._kill_switch_active = False
            self._settings.kill_switch_enabled = False
            logger.info("Kill switch deactivated: %s", message)
            self._event_bus.emit(
                KILL_SWITCH_TOGGLED,
                {"kill_switch_active": False, "message": message},
            )
            return success, message

    def check_direct_fallback(self, ip_verifier: IPVerifier) -> bool:
        """Check if network traffic has leaked or silently fallen back to the direct route.

        Args:
            ip_verifier: IPVerifier instance.

        Returns:
            True if traffic is leaking to the direct baseline IP, False otherwise.
        """
        with self._lock:
            baseline = self._baseline_direct_ip

        if not baseline:
            # Baseline unknown, obtain it now
            baseline = self.establish_baseline_ip(ip_verifier)
            if not baseline:
                return False

        # Check current egress IP
        current_result = ip_verifier.verify_ip()
        if not current_result.is_valid or not current_result.ip_address:
            return False

        is_leaking = (current_result.ip_address == baseline)
        if is_leaking:
            logger.warning(
                "Direct fallback detected! Current IP (%s) matches baseline direct IP (%s)",
                current_result.ip_address,
                baseline,
            )
        return is_leaking

    def verify_tunnel_active(self, adapter: Optional[Any] = None) -> bool:
        """Check whether platform tunnel/VPN connection is actively engaged.

        Args:
            adapter: Optional network adapter.

        Returns:
            True if tunnel is verified active, False otherwise.
        """
        if adapter and hasattr(adapter, "is_tunnel_active"):
            try:
                return bool(adapter.is_tunnel_active())
            except Exception as exc:
                logger.error("Error querying tunnel status from adapter: %s", exc)
                return False
        return False

    def restore_network_config(self, adapter: Optional[Any] = None) -> bool:
        """Safely restore system network routing and firewall rules to pristine state.

        Args:
            adapter: Optional platform adapter.

        Returns:
            True if restoration succeeded, False otherwise.
        """
        with self._lock:
            success = True
            if adapter and hasattr(adapter, "restore_network_config"):
                try:
                    success = bool(adapter.restore_network_config())
                except Exception as exc:
                    logger.error("Failed restoring adapter network config: %s", exc)
                    success = False

            self._kill_switch_active = False
            logger.info("Restored network configuration safely")
            return success

    def pre_rotation_safety_check(
        self,
        profile: Optional[ConnectionProfile],
        scope: TrafficScope,
    ) -> Tuple[bool, str]:
        """Perform pre-flight safety audit before initiating rotation cycle.

        Args:
            profile: Connection profile targeted for rotation.
            scope: Requested traffic routing scope.

        Returns:
            Tuple of (passed: bool, message: str).
        """
        if not profile:
            return False, "Safety check failed: No profile selected."

        if not profile.enabled:
            return False, f"Safety check failed: Profile '{profile.name}' is disabled."

        if scope == TrafficScope.SYSTEM_WIDE and not profile.capabilities.supports_system_wide:
            return (
                False,
                f"Safety check failed: System-wide scope requested but profile "
                f"'{profile.name}' does not support system routing.",
            )

        with self._lock:
            if self._kill_switch_active and scope != TrafficScope.SYSTEM_WIDE:
                logger.warning(
                    "Kill switch is active with application-level proxy profile '%s'",
                    profile.name,
                )

        return True, "Pre-rotation safety checks passed."

    def get_status(self) -> SafetyStatus:
        """Obtain current safety status and protections summary.

        Returns:
            SafetyStatus instance describing active protections and warnings.
        """
        with self._lock:
            protections: List[str] = []
            warnings: List[str] = []

            if self._kill_switch_active:
                protections.append("Firewall Kill Switch Active")
            else:
                warnings.append("Kill switch is inactive; direct network fallback possible on tunnel drop.")

            if self._baseline_direct_ip:
                protections.append(f"Baseline IP Monitored ({self._baseline_direct_ip})")
            else:
                warnings.append("Baseline direct IP has not been calibrated.")

            can_guarantee = self._kill_switch_active
            is_protected = self._kill_switch_active or (self._baseline_direct_ip is not None)

            return SafetyStatus(
                kill_switch_active=self._kill_switch_active,
                is_protected=is_protected,
                can_guarantee_protection=can_guarantee,
                active_protections=protections,
                warnings=warnings,
            )
