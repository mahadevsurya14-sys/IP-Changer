"""Connection profile and capability models for IP Changer.

Manages connection endpoints, proxy/VPN types, capabilities, validation,
and test result tracking.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional



class ConnectionType(str, Enum):
    """Supported network connection protocols and methods."""
    HTTP_PROXY = "http_proxy"
    HTTPS_PROXY = "https_proxy"
    SOCKS5_PROXY = "socks5_proxy"
    VPN_OPENVPN = "vpn_openvpn"
    VPN_WIREGUARD = "vpn_wireguard"
    VPN_SYSTEM = "vpn_system"
    ROTATION_GATEWAY = "rotation_gateway"


class ConnectionStatus(str, Enum):
    """Runtime status of a connection profile."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    ERROR = "error"
    UNKNOWN = "unknown"


class TrafficScope(str, Enum):
    """Scope of network traffic routing."""
    APPLICATION_LEVEL = "application_level"
    SYSTEM_WIDE = "system_wide"


@dataclass
class ConnectionCapabilities:
    """Feature flags and operating limits supported by a profile."""
    supports_rotation: bool = True
    supports_system_wide: bool = False
    min_rotation_interval_seconds: int = 5
    max_concurrent: int = 1
    supports_ipv6: bool = False
    requires_admin: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert capabilities to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> ConnectionCapabilities:
        """Create ConnectionCapabilities instance from dictionary."""
        if not data:
            return cls()
        return cls(
            supports_rotation=bool(data.get("supports_rotation", True)),
            supports_system_wide=bool(data.get("supports_system_wide", False)),
            min_rotation_interval_seconds=int(data.get("min_rotation_interval_seconds", 5)),
            max_concurrent=int(data.get("max_concurrent", 1)),
            supports_ipv6=bool(data.get("supports_ipv6", False)),
            requires_admin=bool(data.get("requires_admin", False)),
        )


@dataclass
class ConnectionProfile:
    """Configuration profile for a proxy endpoint or VPN tunnel."""
    name: str
    connection_type: ConnectionType
    host: str
    port: int
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    username: Optional[str] = None
    auth_token_key: Optional[str] = None  # Reference key in secure OS keyring; never actual secret
    enabled: bool = True
    priority: int = 0
    traffic_scope: TrafficScope = TrafficScope.APPLICATION_LEVEL
    capabilities: ConnectionCapabilities = field(default_factory=ConnectionCapabilities)
    provider_name: str = ""
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def validate(self) -> None:
        """Validate profile parameters.

        Raises:
            ValueError: If profile attributes fail structural validation.
        """
        if not self.name or not self.name.strip():
            raise ValueError("Profile name cannot be empty.")

        if not self.host or not self.host.strip():
            raise ValueError("Host cannot be empty.")

        # Port validation (0 allowed only for system VPN relying on native adapter naming)
        if self.connection_type != ConnectionType.VPN_SYSTEM:
            if not (1 <= self.port <= 65535):
                raise ValueError(f"Port must be between 1 and 65535, got {self.port}.")
        else:
            if self.port < 0 or self.port > 65535:
                raise ValueError(f"Port must be between 0 and 65535 for VPN_SYSTEM, got {self.port}.")

        # Basic Host format validation (IPv4, IPv6, or domain name)
        host_str = self.host.strip()
        if " " in host_str:
            raise ValueError(f"Host '{host_str}' contains invalid characters.")

        if self.capabilities.min_rotation_interval_seconds < 1:
            raise ValueError("Minimum rotation interval must be at least 1 second.")

    def is_valid(self) -> bool:
        """Check if profile is valid without raising exception."""
        try:
            self.validate()
            return True
        except ValueError:
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize profile to JSON-compatible dictionary.

        Excludes any raw passwords or sensitive credentials.
        Only stores the keyring reference key `auth_token_key`.
        """
        return {
            "id": self.id,
            "name": self.name,
            "connection_type": self.connection_type.value,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "auth_token_key": self.auth_token_key,
            "enabled": self.enabled,
            "priority": self.priority,
            "traffic_scope": self.traffic_scope.value,
            "capabilities": self.capabilities.to_dict(),
            "provider_name": self.provider_name,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ConnectionProfile:
        """Deserialize profile from dictionary."""
        conn_type_raw = data.get("connection_type", ConnectionType.HTTP_PROXY.value)
        conn_type = ConnectionType(conn_type_raw) if isinstance(conn_type_raw, str) else conn_type_raw

        traffic_scope_raw = data.get("traffic_scope", TrafficScope.APPLICATION_LEVEL.value)
        traffic_scope = TrafficScope(traffic_scope_raw) if isinstance(traffic_scope_raw, str) else traffic_scope_raw

        capabilities_data = data.get("capabilities", {})
        capabilities = (
            capabilities_data
            if isinstance(capabilities_data, ConnectionCapabilities)
            else ConnectionCapabilities.from_dict(capabilities_data)
        )

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", ""),
            connection_type=conn_type,
            host=data.get("host", ""),
            port=int(data.get("port", 8080)),
            username=data.get("username"),
            auth_token_key=data.get("auth_token_key"),
            enabled=bool(data.get("enabled", True)),
            priority=int(data.get("priority", 0)),
            traffic_scope=traffic_scope,
            capabilities=capabilities,
            provider_name=data.get("provider_name", ""),
            notes=data.get("notes", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class ConnectionTestResult:
    """Outcome of an endpoint health and connectivity verification probe."""
    profile_id: str
    success: bool
    latency_ms: float
    observed_ip: Optional[str] = None
    error_message: Optional[str] = None
    tested_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert test result to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ConnectionTestResult:
        """Construct test result from dictionary."""
        return cls(
            profile_id=data.get("profile_id", ""),
            success=bool(data.get("success", False)),
            latency_ms=float(data.get("latency_ms", 0.0)),
            observed_ip=data.get("observed_ip"),
            error_message=data.get("error_message"),
            tested_at=data.get("tested_at", datetime.now(timezone.utc).isoformat()),
        )
