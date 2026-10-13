"""Connection manager orchestrating proxy configurations and network adapters.

Provides adapter registration, thread-safe connection lifecycle transitions,
requests-compatible proxy configuration construction, and health probes.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any, Dict, Optional

import requests

from src.core.capability_registry import CapabilityRegistry
from src.core.event_bus import CONNECTION_STATUS_CHANGED, EventBus
from src.models.connection_profile import (
    ConnectionProfile,
    ConnectionStatus,
    ConnectionTestResult,
    ConnectionType,
)
from src.models.rotation_event import sanitize_sensitive_text

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active network connections, proxy endpoints, and adapter delegation."""

    def __init__(
        self,
        event_bus: EventBus,
        capability_registry: CapabilityRegistry,
    ) -> None:
        """Initialize connection manager.

        Args:
            event_bus: System event bus.
            capability_registry: Registry of method capabilities.
        """
        self._event_bus = event_bus
        self._capabilities = capability_registry
        self._adapters: Dict[ConnectionType, Any] = {}
        self._status_cache: Dict[str, ConnectionStatus] = {}
        self._lock = threading.RLock()

    def register_adapter(self, conn_type: ConnectionType, adapter: Any) -> None:
        """Register a platform-specific network adapter.

        Args:
            conn_type: Associated connection type.
            adapter: Adapter instance implementing connect, disconnect, test, get_status.
        """
        with self._lock:
            self._adapters[conn_type] = adapter
            logger.info("Registered adapter %s for connection type %s", type(adapter).__name__, conn_type.value)

    def _get_adapter(self, conn_type: ConnectionType) -> Optional[Any]:
        """Retrieve registered adapter for connection type.

        Args:
            conn_type: Target ConnectionType.

        Returns:
            Registered adapter instance or None if not registered.
        """
        with self._lock:
            return self._adapters.get(conn_type)

    def _get_secret(self, auth_token_key: Optional[str]) -> Optional[str]:
        """Retrieve secret authentication token from OS keyring if available.

        Args:
            auth_token_key: Identifier key in the keyring.

        Returns:
            Password/token string if found, None otherwise.
        """
        if not auth_token_key:
            return None
        try:
            import keyring  # type: ignore # pylint: disable=import-outside-toplevel
            return keyring.get_password("ip_changer", auth_token_key)
        except Exception as exc:
            logger.debug("Keyring access unavailable or secret not found for key '%s': %s", auth_token_key, exc)
            return None

    def get_proxy_config(self, profile: ConnectionProfile) -> Optional[Dict[str, str]]:
        """Construct requests-compatible proxy configuration dictionary.

        Args:
            profile: Target connection profile.

        Returns:
            Dict containing 'http' and 'https' proxy URLs, or None for VPN types.
        """
        proxy_types = {
            ConnectionType.HTTP_PROXY,
            ConnectionType.HTTPS_PROXY,
            ConnectionType.SOCKS5_PROXY,
            ConnectionType.ROTATION_GATEWAY,
        }

        if profile.connection_type not in proxy_types:
            return None

        # Resolve credentials if configured
        auth_part = ""
        password = self._get_secret(profile.auth_token_key)
        if profile.username:
            if password:
                auth_part = f"{profile.username}:{password}@"
            else:
                auth_part = f"{profile.username}@"

        host_port = f"{profile.host}:{profile.port}"

        if profile.connection_type == ConnectionType.SOCKS5_PROXY:
            # Use socks5h for remote DNS resolution
            url = f"socks5h://{auth_part}{host_port}"
            return {"http": url, "https": url}

        # HTTP, HTTPS, and ROTATION_GATEWAY
        url = f"http://{auth_part}{host_port}"
        return {"http": url, "https": url}

    def _update_status(self, profile: ConnectionProfile, new_status: ConnectionStatus) -> None:
        """Update connection status in cache and emit notification.

        Args:
            profile: Profile undergoing transition.
            new_status: New ConnectionStatus.
        """
        with self._lock:
            previous_status = self._status_cache.get(profile.id, ConnectionStatus.DISCONNECTED)
            self._status_cache[profile.id] = new_status

        if previous_status != new_status:
            logger.info("Connection status for '%s': %s -> %s", profile.name, previous_status.value, new_status.value)
            payload = {
                "profile_id": profile.id,
                "profile_name": profile.name,
                "status": new_status,
                "previous_status": previous_status,
            }
            self._event_bus.emit(CONNECTION_STATUS_CHANGED, payload)

    def get_status(self, profile: ConnectionProfile) -> ConnectionStatus:
        """Get current status of profile connection.

        Args:
            profile: ConnectionProfile to inspect.

        Returns:
            ConnectionStatus enum value.
        """
        adapter = self._get_adapter(profile.connection_type)
        if adapter and hasattr(adapter, "get_status"):
            try:
                status = adapter.get_status(profile)
                with self._lock:
                    self._status_cache[profile.id] = status
                return status
            except Exception as exc:
                logger.error("Adapter failed getting status for '%s': %s", profile.name, exc)

        with self._lock:
            return self._status_cache.get(profile.id, ConnectionStatus.DISCONNECTED)

    def connect(self, profile: ConnectionProfile) -> ConnectionTestResult:
        """Establish connection or activate proxy routing for profile.

        Args:
            profile: Target ConnectionProfile.

        Returns:
            ConnectionTestResult indicating success or failure.
        """
        self._update_status(profile, ConnectionStatus.CONNECTING)

        adapter = self._get_adapter(profile.connection_type)
        if adapter and hasattr(adapter, "connect"):
            try:
                result = adapter.connect(profile)
                status = ConnectionStatus.CONNECTED if result.success else ConnectionStatus.ERROR
                self._update_status(profile, status)
                return result
            except Exception as exc:
                sanitized = sanitize_sensitive_text(str(exc)) or "Connection failed"
                logger.exception("Adapter connect failed for '%s': %s", profile.name, sanitized)
                self._update_status(profile, ConnectionStatus.ERROR)
                return ConnectionTestResult(
                    profile_id=profile.id,
                    success=False,
                    latency_ms=0.0,
                    error_message=sanitized,
                )

        # For proxy types without platform adapter, perform TCP handshake check
        result = self.test_connection(profile)
        status = ConnectionStatus.CONNECTED if result.success else ConnectionStatus.ERROR
        self._update_status(profile, status)
        return result

    def disconnect(self, profile: ConnectionProfile) -> bool:
        """Terminate active connection for profile.

        Args:
            profile: Profile to disconnect.

        Returns:
            True if disconnect succeeded, False otherwise.
        """
        self._update_status(profile, ConnectionStatus.DISCONNECTING)

        adapter = self._get_adapter(profile.connection_type)
        success = True
        if adapter and hasattr(adapter, "disconnect"):
            try:
                success = bool(adapter.disconnect(profile))
            except Exception as exc:
                logger.error("Adapter disconnect failed for '%s': %s", profile.name, exc)
                success = False

        self._update_status(profile, ConnectionStatus.DISCONNECTED)
        return success

    def test_connection(self, profile: ConnectionProfile) -> ConnectionTestResult:
        """Run connectivity and latency test on the given profile endpoint.

        Args:
            profile: Connection profile to probe.

        Returns:
            ConnectionTestResult containing probe outcome, latency, and observed IP if any.
        """
        adapter = self._get_adapter(profile.connection_type)
        if adapter and hasattr(adapter, "test_connection"):
            try:
                return adapter.test_connection(profile)
            except Exception as exc:
                sanitized = sanitize_sensitive_text(str(exc))
                return ConnectionTestResult(
                    profile_id=profile.id,
                    success=False,
                    latency_ms=0.0,
                    error_message=sanitized,
                )

        # Built-in proxy and socket probe
        start_time = time.perf_counter()
        proxy_config = self.get_proxy_config(profile)

        if proxy_config:
            # Probe via HTTP GET through proxy
            try:
                resp = requests.get(
                    "https://api.ipify.org",
                    proxies=proxy_config,
                    timeout=8,
                    headers={"User-Agent": "Mozilla/5.0 IP-Changer-Probe/1.0"},
                )
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                if resp.status_code == 200:
                    observed_ip = resp.text.strip()
                    return ConnectionTestResult(
                        profile_id=profile.id,
                        success=True,
                        latency_ms=round(elapsed_ms, 2),
                        observed_ip=observed_ip,
                    )
                return ConnectionTestResult(
                    profile_id=profile.id,
                    success=False,
                    latency_ms=round(elapsed_ms, 2),
                    error_message=f"HTTP probe returned status {resp.status_code}",
                )
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                sanitized_err = sanitize_sensitive_text(str(exc))
                return ConnectionTestResult(
                    profile_id=profile.id,
                    success=False,
                    latency_ms=round(elapsed_ms, 2),
                    error_message=sanitized_err,
                )

        # Direct TCP socket ping for endpoints without HTTP proxy config
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect((profile.host, profile.port))
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            sock.close()
            return ConnectionTestResult(
                profile_id=profile.id,
                success=True,
                latency_ms=round(elapsed_ms, 2),
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            sanitized_err = sanitize_sensitive_text(str(exc))
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=round(elapsed_ms, 2),
                error_message=sanitized_err,
            )
