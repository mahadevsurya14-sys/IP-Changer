"""Proxy adapter implementation for HTTP, HTTPS, and SOCKS5 proxies.

Provides connectivity testing, socket reachability checks, and requests-compatible
proxy configuration dictionaries without exposing or logging credentials.
"""

from __future__ import annotations

import logging
import socket
import time
import urllib.parse
from typing import Any, Dict, Optional

import requests

from src.adapters.base_adapter import BaseAdapter
from src.models.connection_profile import (
    ConnectionProfile,
    ConnectionStatus,
    ConnectionTestResult,
    ConnectionType,
)

logger = logging.getLogger(__name__)

# Verification endpoints used for health testing proxy egress
DEFAULT_PROBE_URLS = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
]


class ProxyAdapter(BaseAdapter):
    """Adapter for handling HTTP, HTTPS, and SOCKS5 proxy connections."""

    def __init__(
        self,
        secret_store: Optional[Any] = None,
        default_timeout: float = 10.0,
    ) -> None:
        """Initialize the ProxyAdapter.

        Args:
            secret_store: Optional SecretStore instance to resolve authentication credentials.
            default_timeout: Socket and HTTP timeout in seconds.
        """
        self._secret_store = secret_store
        self._default_timeout = default_timeout
        self._active_profiles: Dict[str, ConnectionStatus] = {}

    def _resolve_password(self, profile: ConnectionProfile) -> Optional[str]:
        """Safely fetch password for the profile from secret store if configured."""
        if not profile.auth_token_key or self._secret_store is None:
            return None
        try:
            return self._secret_store.get_secret(profile.id, "password")
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Could not retrieve credentials for profile %s: %s", profile.id, exc)
            return None

    @staticmethod
    def is_socks5_supported() -> bool:
        """Check if SOCKS5 proxy dependencies (PySocks) are installed."""
        try:
            import socks  # noqa: F401 pylint: disable=import-outside-toplevel
            return True
        except ImportError:
            return False

    def is_socket_reachable(self, host: str, port: int, timeout: Optional[float] = None) -> bool:
        """Verify TCP socket reachability for the proxy host and port.

        Args:
            host: Proxy server IP or domain.
            port: Proxy server port.
            timeout: Socket connection timeout in seconds.

        Returns:
            True if socket handshake succeeded, False otherwise.
        """
        sock_timeout = timeout or self._default_timeout
        try:
            with socket.create_connection((host, port), timeout=sock_timeout):
                return True
        except (socket.timeout, socket.error, OSError) as exc:
            logger.debug("Socket check failed for %s:%d - %s", host, port, exc)
            return False

    def get_proxy_config(self, profile: ConnectionProfile) -> Optional[Dict[str, str]]:
        """Construct requests-compatible proxies dictionary.

        Args:
            profile: ConnectionProfile containing host, port, and credentials.

        Returns:
            Dict containing 'http' and 'https' keys with sanitized proxy URLs, or None.
        """
        if profile.connection_type not in (
            ConnectionType.HTTP_PROXY,
            ConnectionType.HTTPS_PROXY,
            ConnectionType.SOCKS5_PROXY,
        ):
            return None

        # Build scheme
        if profile.connection_type == ConnectionType.SOCKS5_PROXY:
            # socks5h:// causes DNS resolution to happen through the proxy (prevents DNS leaks)
            scheme = "socks5h"
        else:
            scheme = "http"

        password = self._resolve_password(profile)

        # Assemble auth credentials if present
        auth_part = ""
        if profile.username:
            user_quoted = urllib.parse.quote(profile.username, safe="")
            if password:
                pwd_quoted = urllib.parse.quote(password, safe="")
                auth_part = f"{user_quoted}:{pwd_quoted}@"
            else:
                auth_part = f"{user_quoted}@"

        proxy_url = f"{scheme}://{auth_part}{profile.host}:{profile.port}"

        return {
            "http": proxy_url,
            "https": proxy_url,
        }

    def test(self, profile: ConnectionProfile) -> ConnectionTestResult:
        """Probe proxy reachability and measure latency to public verification service.

        Args:
            profile: Target connection profile.

        Returns:
            ConnectionTestResult with latency and public IP if successful.
        """
        if profile.connection_type == ConnectionType.SOCKS5_PROXY and not self.is_socks5_supported():
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message="SOCKS5 support is unavailable. Please install PySocks ('pip install PySocks').",
            )

        # 1. Quick TCP socket probe
        start_time = time.perf_counter()
        if not self.is_socket_reachable(profile.host, profile.port, timeout=min(5.0, self._default_timeout)):
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message=f"Proxy endpoint {profile.host}:{profile.port} is unreachable via TCP.",
            )

        proxy_config = self.get_proxy_config(profile)
        if not proxy_config:
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message=f"Unsupported connection type '{profile.connection_type}' for ProxyAdapter.",
            )

        # 2. HTTP probe through proxy
        last_error = "Unknown error"
        for probe_url in DEFAULT_PROBE_URLS:
            try:
                probe_start = time.perf_counter()
                session = requests.Session()
                session.proxies = proxy_config
                response = session.get(
                    probe_url,
                    timeout=self._default_timeout,
                    headers={"User-Agent": "IP-Changer-Probe/1.0"},
                )
                latency_ms = (time.perf_counter() - probe_start) * 1000.0

                if response.status_code == 200:
                    observed_ip: Optional[str] = None
                    try:
                        data = response.json()
                        observed_ip = data.get("ip") or data.get("ip_addr")
                    except Exception:
                        text_body = response.text.strip()
                        if text_body:
                            observed_ip = text_body.splitlines()[0].strip()

                    return ConnectionTestResult(
                        profile_id=profile.id,
                        success=True,
                        latency_ms=round(latency_ms, 2),
                        observed_ip=observed_ip,
                        error_message=None,
                    )
                last_error = f"Probe to {probe_url} returned HTTP {response.status_code}."
            except requests.exceptions.ProxyError as exc:
                last_error = f"Proxy error connecting through {profile.host}:{profile.port}."
                logger.debug("Proxy error during test: %s", exc)
                break  # Likely auth or gateway failure; subsequent URLs won't help
            except requests.exceptions.ConnectTimeout:
                last_error = f"Connection timed out through proxy {profile.host}:{profile.port}."
            except requests.exceptions.RequestException as exc:
                last_error = f"Request failed through proxy: {exc.__class__.__name__}"
                logger.debug("Request probe exception: %s", exc)

        return ConnectionTestResult(
            profile_id=profile.id,
            success=False,
            latency_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
            error_message=last_error,
        )

    def connect(self, profile: ConnectionProfile) -> ConnectionTestResult:
        """Validate proxy connectivity and mark profile as active.

        Args:
            profile: Target connection profile.

        Returns:
            ConnectionTestResult indicating whether proxy is functional.
        """
        self._active_profiles[profile.id] = ConnectionStatus.CONNECTING
        logger.info("Connecting to proxy profile: %s (%s:%d)", profile.name, profile.host, profile.port)

        test_result = self.test(profile)
        if test_result.success:
            self._active_profiles[profile.id] = ConnectionStatus.CONNECTED
            logger.info("Proxy profile '%s' connected successfully. Observed IP: %s", profile.name, test_result.observed_ip)
        else:
            self._active_profiles[profile.id] = ConnectionStatus.ERROR
            logger.warning("Failed to connect proxy profile '%s': %s", profile.name, test_result.error_message)

        return test_result

    def disconnect(self, profile: ConnectionProfile) -> bool:
        """Deactivate proxy profile.

        Args:
            profile: Connection profile to deactivate.

        Returns:
            True upon successful deactivation.
        """
        logger.info("Disconnecting proxy profile: %s", profile.name)
        self._active_profiles[profile.id] = ConnectionStatus.DISCONNECTED
        return True

    def get_status(self, profile: ConnectionProfile) -> ConnectionStatus:
        """Return cached or checked connection status for profile."""
        return self._active_profiles.get(profile.id, ConnectionStatus.DISCONNECTED)
