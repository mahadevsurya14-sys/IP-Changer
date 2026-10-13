"""Capability registry for connection methods and protocols in IP Changer.

Defines operational limits, system-wide traffic routing capability, minimum rotation
intervals, dependency requirements, and feasibility analysis for connection profiles.
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple

from src.models.connection_profile import ConnectionProfile, ConnectionType, TrafficScope

logger = logging.getLogger(__name__)


@dataclass
class MethodCapability:
    """Operational attributes and system constraints for a connection method."""
    connection_type: ConnectionType
    supports_rotation: bool
    min_rotation_interval: int
    supports_system_wide: bool
    requires_admin: bool
    requires_optional_deps: bool
    optional_dep_name: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert capability definition to dictionary."""
        data = asdict(self)
        data["connection_type"] = self.connection_type.value
        return data


class CapabilityRegistry:
    """Central registry tracking capabilities, limits, and runtime requirements."""

    def __init__(self) -> None:
        """Initialize the capability registry with known defaults."""
        self._capabilities: Dict[ConnectionType, MethodCapability] = {}
        self._register_default_capabilities()

    def _register_default_capabilities(self) -> None:
        """Populate initial baseline specifications for all connection types."""
        self.register(
            MethodCapability(
                connection_type=ConnectionType.HTTP_PROXY,
                supports_rotation=True,
                min_rotation_interval=5,
                supports_system_wide=False,
                requires_admin=False,
                requires_optional_deps=False,
                optional_dep_name=None,
                notes="Standard HTTP proxy supporting application-level forwarding.",
            )
        )
        self.register(
            MethodCapability(
                connection_type=ConnectionType.HTTPS_PROXY,
                supports_rotation=True,
                min_rotation_interval=5,
                supports_system_wide=False,
                requires_admin=False,
                requires_optional_deps=False,
                optional_dep_name=None,
                notes="Secure HTTPS/SSL proxy supporting application-level forwarding.",
            )
        )
        self.register(
            MethodCapability(
                connection_type=ConnectionType.SOCKS5_PROXY,
                supports_rotation=True,
                min_rotation_interval=5,
                supports_system_wide=False,
                requires_admin=False,
                requires_optional_deps=True,
                optional_dep_name="PySocks",
                notes="SOCKS5 proxy protocol with optional authentication (requires PySocks).",
            )
        )
        self.register(
            MethodCapability(
                connection_type=ConnectionType.VPN_OPENVPN,
                supports_rotation=True,
                min_rotation_interval=30,
                supports_system_wide=True,
                requires_admin=True,
                requires_optional_deps=False,
                optional_dep_name=None,
                notes="OpenVPN system-level tunnel interface; requires administrative rights.",
            )
        )
        self.register(
            MethodCapability(
                connection_type=ConnectionType.VPN_WIREGUARD,
                supports_rotation=True,
                min_rotation_interval=15,
                supports_system_wide=True,
                requires_admin=True,
                requires_optional_deps=False,
                optional_dep_name=None,
                notes="WireGuard kernel/user-space network tunnel; requires administrative rights.",
            )
        )
        self.register(
            MethodCapability(
                connection_type=ConnectionType.VPN_SYSTEM,
                supports_rotation=True,
                min_rotation_interval=20,
                supports_system_wide=True,
                requires_admin=True,
                requires_optional_deps=False,
                optional_dep_name=None,
                notes="Operating system native VPN connection (Windows rasdial / Linux nmcli).",
            )
        )
        self.register(
            MethodCapability(
                connection_type=ConnectionType.ROTATION_GATEWAY,
                supports_rotation=True,
                min_rotation_interval=5,
                supports_system_wide=False,
                requires_admin=False,
                requires_optional_deps=False,
                optional_dep_name=None,
                notes="Managed rotating proxy backconnect gateway (dynamic exit IPs).",
            )
        )

    def register(self, capability: MethodCapability) -> None:
        """Register or override capability for a connection type.

        Args:
            capability: MethodCapability instance.
        """
        self._capabilities[capability.connection_type] = capability
        logger.debug("Registered capabilities for %s", capability.connection_type.value)

    def check_socks5_available(self) -> bool:
        """Determine if PySocks library is installed and importable.

        Returns:
            True if PySocks is available, False otherwise.
        """
        try:
            import socks  # type: ignore # pylint: disable=unused-import
            return True
        except ImportError:
            return False

    def get_capabilities(self, conn_type: ConnectionType) -> MethodCapability:
        """Retrieve capability metadata for a connection type.

        Args:
            conn_type: Target ConnectionType.

        Returns:
            MethodCapability instance. Defaults to conservative settings if unknown.
        """
        if conn_type in self._capabilities:
            return self._capabilities[conn_type]

        # Fallback conservative capability
        return MethodCapability(
            connection_type=conn_type,
            supports_rotation=False,
            min_rotation_interval=60,
            supports_system_wide=False,
            requires_admin=False,
            requires_optional_deps=False,
            notes="Unknown connection method; conservative restrictions applied.",
        )

    def get_all_capabilities(self) -> Dict[ConnectionType, MethodCapability]:
        """Get copy of all registered capabilities mapped by connection type."""
        return dict(self._capabilities)

    def is_feasible(
        self,
        profile: ConnectionProfile,
        interval: int,
        scope: TrafficScope,
    ) -> Tuple[bool, str]:
        """Validate whether a profile can satisfy the desired rotation interval and scope.

        Args:
            profile: Profile to evaluate.
            interval: Desired rotation frequency in seconds.
            scope: Desired traffic routing scope (application vs system-wide).

        Returns:
            Tuple of (is_feasible: bool, reason_description: str).
        """
        # Validate profile integrity
        if not profile.is_valid():
            return False, f"Profile '{profile.name}' has invalid configuration parameters."

        method_cap = self.get_capabilities(profile.connection_type)

        # Check rotation capability
        if not (profile.capabilities.supports_rotation and method_cap.supports_rotation):
            return False, f"Connection type '{profile.connection_type.value}' does not support rotation."

        # Check rotation interval ceiling
        effective_min_interval = max(
            method_cap.min_rotation_interval,
            profile.capabilities.min_rotation_interval_seconds,
        )
        if interval < effective_min_interval:
            return (
                False,
                f"Requested interval ({interval}s) is shorter than minimum allowed "
                f"({effective_min_interval}s) for '{profile.name}'.",
            )

        # Check traffic scope feasibility
        if scope == TrafficScope.SYSTEM_WIDE:
            if not (method_cap.supports_system_wide or profile.capabilities.supports_system_wide):
                return (
                    False,
                    f"Profile '{profile.name}' ({profile.connection_type.value}) does not support "
                    f"system-wide traffic routing.",
                )

        # Check optional library dependencies (e.g. SOCKS5)
        if profile.connection_type == ConnectionType.SOCKS5_PROXY:
            if not self.check_socks5_available():
                return (
                    False,
                    "SOCKS5 proxy requires the 'PySocks' library, which is currently not installed.",
                )

        return True, f"Profile '{profile.name}' meets all capability requirements."
