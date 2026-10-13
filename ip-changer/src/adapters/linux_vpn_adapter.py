"""Linux / Kali VPN management adapter for OpenVPN and WireGuard.

Provides secure process management, tunnel interface monitoring, routing table inspection,
and DNS configuration parsing with strict argument validation and privilege checks.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.adapters.base_adapter import BaseAdapter
from src.models.connection_profile import (
    ConnectionProfile,
    ConnectionStatus,
    ConnectionTestResult,
    ConnectionType,
)

logger = logging.getLogger(__name__)

INTERFACE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_\-\.]{1,15}$")


class LinuxVPNAdapter(BaseAdapter):
    """Adapter for managing Linux/Kali VPN connections via WireGuard and OpenVPN."""

    def __init__(self) -> None:
        """Initialize the Linux VPN adapter."""
        self._is_linux = sys.platform.startswith("linux")
        self._active_connections: Dict[str, ConnectionStatus] = {}

    def is_supported(self) -> bool:
        """Check if current OS is Linux."""
        return self._is_linux

    @staticmethod
    def requires_admin() -> bool:
        """Check if current process has root privileges."""
        if not sys.platform.startswith("linux"):
            return False
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            return False

    def _validate_identifier(self, identifier: str) -> str:
        """Sanitize and validate an interface or profile configuration name."""
        cleaned = identifier.strip()
        if not cleaned:
            raise ValueError("VPN identifier or interface name cannot be empty.")
        if not INTERFACE_NAME_PATTERN.match(cleaned):
            raise ValueError(f"VPN identifier '{cleaned}' contains invalid characters or exceeds 15 chars.")
        return cleaned

    def list_tunnel_interfaces(self) -> List[str]:
        """List active network tunnel interfaces (tun*, tap*, wg*).

        Returns:
            List of interface names.
        """
        if not self._is_linux:
            return []

        tunnels: List[str] = []
        sys_net = Path("/sys/class/net")
        if sys_net.exists():
            for iface in sys_net.iterdir():
                name = iface.name
                if any(name.startswith(prefix) for prefix in ("tun", "tap", "wg", "ppp")):
                    tunnels.append(name)
            return sorted(tunnels)

        # Fallback to ip link
        try:
            res = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in res.stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    iface_name = parts[1].strip().split("@")[0]
                    if any(iface_name.startswith(p) for p in ("tun", "tap", "wg", "ppp")):
                        tunnels.append(iface_name)
        except Exception as exc:
            logger.warning("Failed to list tunnel interfaces: %s", exc)

        return sorted(tunnels)

    def check_routing_table(self) -> List[Dict[str, str]]:
        """Inspect and parse the Linux routing table.

        Returns:
            List of route entries with keys: destination, gateway, interface, metric.
        """
        if not self._is_linux:
            return []

        routes: List[Dict[str, str]] = []
        try:
            res = subprocess.run(
                ["ip", "route", "show"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            for line in res.stdout.splitlines():
                parts = line.strip().split()
                if not parts:
                    continue
                route: Dict[str, str] = {"destination": parts[0]}
                for i, token in enumerate(parts):
                    if token == "via" and i + 1 < len(parts):
                        route["gateway"] = parts[i + 1]
                    elif token == "dev" and i + 1 < len(parts):
                        route["interface"] = parts[i + 1]
                    elif token == "metric" and i + 1 < len(parts):
                        route["metric"] = parts[i + 1]
                routes.append(route)
        except Exception as exc:
            logger.error("Failed to parse routing table: %s", exc)

        return routes

    def check_dns_config(self) -> Dict[str, Any]:
        """Read DNS nameservers and search domains from system configuration.

        Returns:
            Dict containing nameservers and search_domains.
        """
        config: Dict[str, Any] = {"nameservers": [], "search_domains": []}
        if not self._is_linux:
            return config

        resolv_path = Path("/etc/resolv.conf")
        if resolv_path.exists():
            try:
                content = resolv_path.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("nameserver "):
                        ns = line.split(None, 1)[1].strip()
                        config["nameservers"].append(ns)
                    elif line.startswith("search ") or line.startswith("domain "):
                        domain = line.split(None, 1)[1].strip()
                        config["search_domains"].append(domain)
            except Exception as exc:
                logger.error("Failed to read /etc/resolv.conf: %s", exc)

        return config

    def verify_routing(self) -> bool:
        """Verify whether default gateway routes via a tunnel interface."""
        if not self._is_linux:
            return False

        routes = self.check_routing_table()
        for route in routes:
            if route.get("destination") == "default":
                iface = route.get("interface", "")
                if any(iface.startswith(prefix) for prefix in ("tun", "tap", "wg", "ppp")):
                    return True
        return False

    def connect(self, profile: ConnectionProfile) -> ConnectionTestResult:
        """Establish Linux VPN connection using WireGuard or OpenVPN.

        Args:
            profile: Connection profile specifying connection type and config file or interface name.

        Returns:
            ConnectionTestResult.
        """
        if not self._is_linux:
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message="LinuxVPNAdapter is only supported on Linux operating systems.",
            )

        if not self.requires_admin():
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message="Root privileges (sudo/root) required to manage Linux VPN interfaces.",
            )

        try:
            target_name = self._validate_identifier(profile.host or profile.name)
        except ValueError as err:
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message=str(err),
            )

        self._active_connections[profile.id] = ConnectionStatus.CONNECTING
        start_time = time.perf_counter()

        # WireGuard connection
        if profile.connection_type == ConnectionType.VPN_WIREGUARD:
            if not shutil.which("wg-quick"):
                self._active_connections[profile.id] = ConnectionStatus.ERROR
                return ConnectionTestResult(
                    profile_id=profile.id,
                    success=False,
                    latency_ms=0.0,
                    error_message="'wg-quick' utility is not installed. Install wireguard-tools.",
                )

            cmd = ["wg-quick", "up", target_name]
        # OpenVPN connection
        elif profile.connection_type == ConnectionType.VPN_OPENVPN:
            # Check if systemctl openvpn is available or raw openvpn binary
            if shutil.which("systemctl"):
                cmd = ["systemctl", "start", f"openvpn-client@{target_name}"]
            elif shutil.which("openvpn"):
                cmd = ["openvpn", "--config", f"/etc/openvpn/{target_name}.conf", "--daemon"]
            else:
                self._active_connections[profile.id] = ConnectionStatus.ERROR
                return ConnectionTestResult(
                    profile_id=profile.id,
                    success=False,
                    latency_ms=0.0,
                    error_message="Neither systemctl nor openvpn binary was found on this system.",
                )
        else:
            self._active_connections[profile.id] = ConnectionStatus.ERROR
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message=f"Unsupported Linux VPN connection type: {profile.connection_type}",
            )

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if res.returncode == 0:
                self._active_connections[profile.id] = ConnectionStatus.CONNECTED
                logger.info("Successfully started Linux VPN: %s", target_name)
                return ConnectionTestResult(
                    profile_id=profile.id,
                    success=True,
                    latency_ms=round(elapsed_ms, 2),
                    error_message=None,
                )

            err = res.stderr.strip() or res.stdout.strip()
            self._active_connections[profile.id] = ConnectionStatus.ERROR
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=round(elapsed_ms, 2),
                error_message=f"Failed to start VPN ({res.returncode}): {err}",
            )
        except subprocess.TimeoutExpired:
            self._active_connections[profile.id] = ConnectionStatus.ERROR
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=30000.0,
                error_message="VPN connection command timed out.",
            )
        except Exception as exc:
            self._active_connections[profile.id] = ConnectionStatus.ERROR
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message=f"Execution error: {exc}",
            )

    def disconnect(self, profile: ConnectionProfile) -> bool:
        """Safely disconnect a Linux VPN session.

        Args:
            profile: Connection profile.

        Returns:
            True if stopped successfully.
        """
        if not self._is_linux or not self.requires_admin():
            logger.warning("LinuxVPNAdapter disconnect requires Linux root privileges.")
            return False

        try:
            target_name = self._validate_identifier(profile.host or profile.name)
        except ValueError as err:
            logger.error("Cannot disconnect invalid identifier: %s", err)
            return False

        if profile.connection_type == ConnectionType.VPN_WIREGUARD:
            cmd = ["wg-quick", "down", target_name]
        elif profile.connection_type == ConnectionType.VPN_OPENVPN:
            if shutil.which("systemctl"):
                cmd = ["systemctl", "stop", f"openvpn-client@{target_name}"]
            else:
                cmd = ["killall", "openvpn"]
        else:
            return False

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self._active_connections[profile.id] = ConnectionStatus.DISCONNECTED
            return res.returncode == 0
        except Exception as exc:
            logger.error("Failed to disconnect VPN '%s': %s", target_name, exc)
            return False

    def test(self, profile: ConnectionProfile) -> ConnectionTestResult:
        """Probe interface status and presence."""
        if not self._is_linux:
            return ConnectionTestResult(
                profile_id=profile.id,
                success=False,
                latency_ms=0.0,
                error_message="LinuxVPNAdapter requires Linux platform.",
            )

        target = profile.host or profile.name
        tunnels = self.list_tunnel_interfaces()
        is_active = any(target in t for t in tunnels)

        return ConnectionTestResult(
            profile_id=profile.id,
            success=is_active,
            latency_ms=1.0,
            error_message=None if is_active else f"Tunnel interface '{target}' is not active.",
        )

    def get_status(self, profile: ConnectionProfile) -> ConnectionStatus:
        """Check status of tunnel interface."""
        if not self._is_linux:
            return ConnectionStatus.UNKNOWN

        target = profile.host or profile.name
        tunnels = self.list_tunnel_interfaces()
        if any(target in t for t in tunnels):
            return ConnectionStatus.CONNECTED

        return self._active_connections.get(profile.id, ConnectionStatus.DISCONNECTED)

    def get_proxy_config(self, profile: ConnectionProfile) -> Optional[Dict[str, str]]:
        """VPN routes at OS level; return None."""
        return None
