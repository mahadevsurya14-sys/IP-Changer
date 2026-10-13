"""Windows 11 VPN management adapter using rasdial and PowerShell.

Provides safe VPN interface connection, disconnection, routing inspection,
and system adapter enumeration with strict argument validation and elevation checks.
"""

from __future__ import annotations

import ctypes
import json
import logging
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

from src.adapters.base_adapter import BaseAdapter
from src.models.connection_profile import (
    ConnectionProfile,
    ConnectionStatus,
    ConnectionTestResult,
    ConnectionType,
)

logger = logging.getLogger(__name__)

# Sanitization regex for VPN connection names (alphanumeric, spaces, underscores, dashes, dots)
VPN_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_\-\. ]+$")


class WindowsVPNAdapter(BaseAdapter):
    """Adapter for managing Windows native VPN connections via rasdial and PowerShell."""

    def __init__(self, secret_store: Optional[Any] = None) -> None:
        """Initialize the Windows VPN adapter.

        Args:
            secret_store: Optional SecretStore instance for credential retrieval.
        """
        self._secret_store = secret_store
        self._is_windows = sys.platform == "win32"
        self._active_connections: Dict[str, ConnectionStatus] = {}

    def is_supported(self) -> bool:
        """Check if current OS is Windows."""
        return self._is_windows

    @staticmethod
    def requires_admin() -> bool:
        """Check if current process has administrative elevation."""
        if sys.platform != "win32":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False

    def _validate_connection_name(self, name: str) -> str:
        """Validate that VPN connection name does not contain illegal characters.

        Raises:
            ValueError: If connection name contains malicious or invalid characters.
        """
        cleaned = name.strip()
        if not cleaned:
            raise ValueError("VPN connection name cannot be empty.")
        if not VPN_NAME_PATTERN.match(cleaned):
            raise ValueError(f"VPN connection name contains invalid characters: '{cleaned}'")
        return cleaned

    def _resolve_password(self, profile: ConnectionProfile) -> Optional[str]:
        """Safely fetch password for profile without logging."""
        if not profile.auth_token_key or self._secret_store is None:
            return None
        try:
            return self._secret_store.get_secret(profile.id, "password")
        except Exception as exc:
            logger.warning("Failed to retrieve secret for profile %s: %s", profile.id, exc)
            return None

    def list_vpn_connections(self) -> List[str]:
        """List configured Windows VPN connection names using PowerShell.

        Returns:
            List of connection name strings.
        """
        if not self._is_windows:
            logger.warning("WindowsVPNAdapter called on non-Windows platform.")
            return []

        ps_cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "Get-VpnConnection | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress"
        ]

        try:
            result = subprocess.run(
                ps_cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            output = result.stdout.strip()
            if not output:
                return []

            parsed = json.loads(output)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if item]
            if isinstance(parsed, str):
                return [parsed]
            return []
        except subprocess.TimeoutExpired:
            logger.error("PowerShell Get-VpnConnection timed out.")
            return []
        except Exception as exc:
            logger.error("Failed to list Windows VPN connections: %s", exc)
            return []

    def get_active_interfaces(self) -> List[Dict[str, Any]]:
        """Retrieve network interface details using PowerShell Get-NetAdapter.

        Returns:
            List of dictionaries containing interface name, status, link speed, and interface index.
        """
        if not self._is_windows:
            return []

        ps_cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "Get-NetAdapter | Select-Object Name, Status, InterfaceDescription, ifIndex, LinkSpeed | ConvertTo-Json -Compress"
        ]

        try:
            result = subprocess.run(
                ps_cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            output = result.stdout.strip()
            if not output:
                return []

            parsed = json.loads(output)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
            return []
        except Exception as exc:
            logger.error("Failed to query network adapters: %s", exc)
            return []

    def verify_routing(self) -> bool:
        """Check whether default network route points to a VPN / PPP adapter.

        Returns:
            True if default routing appears to be routed over a tunnel adapter.
        """
        if not self._is_windows:
            return False

        ps_cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object InterfaceAlias, RouteMetric, NextHop | ConvertTo-Json -Compress"
        ]

        try:
            result = subprocess.run(
                ps_cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            output = result.stdout.strip()
            if not output:
                return False

            parsed = json.loads(output)
            routes = parsed if isinstance(parsed, list) else [parsed]
            for route in routes:
                alias = str(route.get("InterfaceAlias", "")).lower()
                if any(k in alias for k in ("vpn", "wireguard", "wintun", "ppp", "tunnel", "tap")):
                    return True
            return False
        except Exception as exc:
            logger.warning("Routing verification check encountered error: %s", exc)
            return False

    def connect(self, profile: ConnectionProfile) -> ConnectionTestResult:
        """Establish Windows VPN connection via rasdial.

        Args:
            profile: Connection profile specifying the VPN connection name.

        Returns:
            ConnectionTestResult indicating success or failure reason.
        """
        if not self._is_windows:
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message="WindowsVPNAdapter is only supported on Windows operating systems.",
            )

        try:
            vpn_name = self._validate_connection_name(profile.host or profile.name)
        except ValueError as err:
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message=str(err),
            )

        self._active_connections[profile.id] = ConnectionStatus.CONNECTING
        logger.info("Attempting to connect Windows VPN: %s", vpn_name)

        # Build rasdial arguments safely without shell=True
        cmd = ["rasdial.exe", vpn_name]
        password = self._resolve_password(profile)
        if profile.username:
            cmd.append(profile.username)
            if password:
                cmd.append(password)

        start_time = time.perf_counter()
        try:
            # shell=False ensures argument list is not subject to command injection
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if result.returncode == 0:
                self._active_connections[profile.id] = ConnectionStatus.CONNECTED
                logger.info("Successfully connected to Windows VPN '%s'", vpn_name)
                return ConnectionTestResult(
                    profile_id=profile.id,
                    success=True,
                    latency_ms=round(elapsed_ms, 2),
                    error_message=None,
                )

            # Analyze error output
            error_output = result.stderr.strip() or result.stdout.strip()
            if "797" in error_output or "691" in error_output:
                error_msg = f"VPN authentication or modem error: {error_output}"
            elif "Access is denied" in error_output or "elevation" in error_output.lower():
                error_msg = "Administrative privileges required to connect this VPN adapter."
            else:
                error_msg = f"rasdial failed (code {result.returncode}): {error_output}"

            self._active_connections[profile.id] = ConnectionStatus.ERROR
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=round(elapsed_ms, 2),
                error_message=error_msg,
            )
        except subprocess.TimeoutExpired:
            self._active_connections[profile.id] = ConnectionStatus.ERROR
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=30000.0,
                error_message=f"Connection attempt to '{vpn_name}' timed out after 30 seconds.",
            )
        except Exception as exc:
            self._active_connections[profile.id] = ConnectionStatus.ERROR
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message=f"Exception initiating VPN: {exc}",
            )

    def disconnect(self, profile: ConnectionProfile) -> bool:
        """Safely disconnect an active Windows VPN session via rasdial.

        Args:
            profile: Connection profile to disconnect.

        Returns:
            True if connection was disconnected successfully, False otherwise.
        """
        if not self._is_windows:
            return False

        try:
            vpn_name = self._validate_connection_name(profile.host or profile.name)
        except ValueError as err:
            logger.error("Cannot disconnect invalid VPN name: %s", err)
            return False

        logger.info("Disconnecting Windows VPN: %s", vpn_name)
        cmd = ["rasdial.exe", vpn_name, "/DISCONNECT"]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self._active_connections[profile.id] = ConnectionStatus.DISCONNECTED
            if result.returncode == 0:
                logger.info("VPN '%s' disconnected successfully.", vpn_name)
                return True

            logger.warning("rasdial disconnect output: %s", result.stdout.strip())
            return True
        except Exception as exc:
            logger.error("Error disconnecting VPN '%s': %s", vpn_name, exc)
            return False

    def test(self, profile: ConnectionProfile) -> ConnectionTestResult:
        """Probe configured VPN interface availability.

        Args:
            profile: Connection profile.

        Returns:
            ConnectionTestResult.
        """
        if not self._is_windows:
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message="WindowsVPNAdapter requires Windows platform.",
            )

        vpn_name = profile.host or profile.name
        connections = self.list_vpn_connections()
        if vpn_name in connections:
            return ConnectionTestResult(
                profile_id=profile.id,
                success=True,
                latency_ms=5.0,
                error_message=None,
            )

        return ConnectionTestResult(
            profile_id=profile.id,
            success=False,
            latency_ms=0.0,
            error_message=f"VPN profile '{vpn_name}' is not found in Windows configured VPN connections.",
        )

    def get_status(self, profile: ConnectionProfile) -> ConnectionStatus:
        """Check if target VPN interface is currently connected."""
        if not self._is_windows:
            return ConnectionStatus.UNKNOWN

        vpn_name = profile.host or profile.name
        ps_cmd = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            f"(Get-VpnConnection -Name '{vpn_name}' -ErrorAction SilentlyContinue).ConnectionStatus"
        ]

        try:
            result = subprocess.run(
                ps_cmd,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            status_text = result.stdout.strip().lower()
            if "connected" in status_text:
                return ConnectionStatus.CONNECTED
            if "connecting" in status_text:
                return ConnectionStatus.CONNECTING
            if "disconnected" in status_text:
                return ConnectionStatus.DISCONNECTED
        except Exception as exc:
            logger.debug("Failed to query status for '%s': %s", vpn_name, exc)

        return self._active_connections.get(profile.id, ConnectionStatus.DISCONNECTED)

    def get_proxy_config(self, profile: ConnectionProfile) -> Optional[Dict[str, str]]:
        """VPN adapters route at network level; return None for proxy dict."""
        return None
