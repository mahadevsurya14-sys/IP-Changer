"""System diagnostics and health check service for IP Changer.

Conducts read-only diagnostic inspections of internet reachability, proxy health,
VPN tunnels, IPv4/IPv6 egress, DNS leak resilience, and firewall kill-switch status.
"""

from __future__ import annotations

import logging
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import requests

from src.core.event_bus import DIAGNOSTIC_COMPLETED, EventBus
from src.models.app_settings import AppSettings
from src.models.connection_profile import ConnectionProfile, ConnectionType

logger = logging.getLogger(__name__)


class DiagnosticStatus(str, Enum):
    """Execution status of an individual diagnostic check."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    UNKNOWN = "UNKNOWN"


class DiagnosticSeverity(str, Enum):
    """Severity classification of check failure or warning."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class DiagnosticCheck:
    """Individual diagnostic probe outcome."""
    name: str
    status: DiagnosticStatus
    severity: DiagnosticSeverity
    message: str
    remediation: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize diagnostic check to dictionary."""
        return {
            "name": self.name,
            "status": self.status.value if isinstance(self.status, DiagnosticStatus) else str(self.status),
            "severity": self.severity.value if isinstance(self.severity, DiagnosticSeverity) else str(self.severity),
            "message": self.message,
            "remediation": self.remediation,
            "details": self.details or {},
            "timestamp": self.timestamp,
        }


class DiagnosticsService:
    """Comprehensive read-only diagnostics service for network and security stack."""

    def __init__(
        self,
        ip_verifier: Optional[Any] = None,
        connection_manager: Optional[Any] = None,
        safety_manager: Optional[Any] = None,
        settings: Optional[AppSettings] = None,
        event_bus: Optional[EventBus] = None,
    ) -> None:
        """Initialize the DiagnosticsService.

        Args:
            ip_verifier: Service responsible for determining observed public IP.
            connection_manager: Service managing active proxies and VPN adapters.
            safety_manager: Service governing kill switches and safety boundaries.
            settings: Current application settings.
            event_bus: Application event dispatcher.
        """
        self.ip_verifier = ip_verifier
        self.connection_manager = connection_manager
        self.safety_manager = safety_manager
        self.settings = settings or AppSettings()
        self.event_bus = event_bus

    def check_internet(self) -> DiagnosticCheck:
        """Probe general internet connectivity via DNS and HTTP reachability."""
        start = time.perf_counter()
        # 1. DNS check for reliable root server or public resolver
        dns_ok = False
        try:
            socket.gethostbyname("one.one.one.one")
            dns_ok = True
        except socket.error:
            pass

        # 2. HTTP check
        http_ok = False
        latency = 0.0
        try:
            res = requests.get("https://1.1.1.1", timeout=5.0)
            if res.status_code == 200:
                http_ok = True
                latency = (time.perf_counter() - start) * 1000.0
        except Exception:
            pass

        if dns_ok and http_ok:
            return DiagnosticCheck(
                name="Internet Connectivity",
                status=DiagnosticStatus.PASS,
                severity=DiagnosticSeverity.INFO,
                message=f"Internet connection is active (latency: {latency:.1f}ms).",
                details={"latency_ms": round(latency, 1), "dns_resolving": True},
            )
        elif not dns_ok and http_ok:
            return DiagnosticCheck(
                name="Internet Connectivity",
                status=DiagnosticStatus.WARNING,
                severity=DiagnosticSeverity.WARNING,
                message="HTTP connection works via direct IP, but domain name resolution failed.",
                remediation="Check your system DNS server settings or router connection.",
                details={"latency_ms": round(latency, 1), "dns_resolving": False},
            )
        else:
            return DiagnosticCheck(
                name="Internet Connectivity",
                status=DiagnosticStatus.FAIL,
                severity=DiagnosticSeverity.CRITICAL,
                message="No internet connectivity detected.",
                remediation="Check your physical network adapter, Wi-Fi link, or gateway connection.",
                details={"latency_ms": 0.0, "dns_resolving": dns_ok},
            )

    def check_proxy(self, profile: Optional[ConnectionProfile] = None) -> DiagnosticCheck:
        """Probe the specified or currently active proxy profile."""
        target_profile = profile
        if target_profile is None and self.connection_manager is not None:
            target_profile = getattr(self.connection_manager, "current_profile", None)

        if not target_profile:
            return DiagnosticCheck(
                name="Proxy Connectivity",
                status=DiagnosticStatus.UNKNOWN,
                severity=DiagnosticSeverity.INFO,
                message="No proxy profile selected to test.",
                remediation="Select a configured proxy profile to test.",
            )

        start = time.perf_counter()
        try:
            with socket.create_connection((target_profile.host, target_profile.port), timeout=5.0):
                sock_ok = True
        except (socket.error, socket.timeout) as exc:
            return DiagnosticCheck(
                name=f"Proxy Connectivity ({target_profile.name})",
                status=DiagnosticStatus.FAIL,
                severity=DiagnosticSeverity.ERROR,
                message=f"Proxy host {target_profile.host}:{target_profile.port} is unreachable via TCP: {exc}",
                remediation="Verify proxy server address, port, and ensure remote host is online.",
                details={"host": target_profile.host, "port": target_profile.port},
            )

        latency = (time.perf_counter() - start) * 1000.0
        return DiagnosticCheck(
            name=f"Proxy Connectivity ({target_profile.name})",
            status=DiagnosticStatus.PASS,
            severity=DiagnosticSeverity.INFO,
            message=f"Proxy endpoint {target_profile.host}:{target_profile.port} is reachable ({latency:.1f}ms).",
            details={"host": target_profile.host, "port": target_profile.port, "latency_ms": round(latency, 1)},
        )

    def check_vpn_tunnel(self) -> DiagnosticCheck:
        """Verify whether an active VPN tunnel interface is operational."""
        is_windows = sys.platform == "win32"
        is_linux = sys.platform.startswith("linux")

        if is_windows:
            from src.adapters.windows_vpn_adapter import WindowsVPNAdapter
            adapter = WindowsVPNAdapter()
            is_routed = adapter.verify_routing()
            active_ifaces = adapter.get_active_interfaces()
            vpn_ifaces = [
                iface.get("Name", "")
                for iface in active_ifaces
                if any(k in str(iface.get("InterfaceDescription", "")).lower() for k in ("vpn", "wireguard", "tap", "tunnel"))
            ]
            if is_routed or vpn_ifaces:
                return DiagnosticCheck(
                    name="VPN Tunnel Interface",
                    status=DiagnosticStatus.PASS,
                    severity=DiagnosticSeverity.INFO,
                    message=f"VPN tunnel is active. Adapters detected: {', '.join(vpn_ifaces) or 'Default VPN Route'}.",
                    details={"interfaces": vpn_ifaces, "routing_verified": is_routed},
                )
            return DiagnosticCheck(
                name="VPN Tunnel Interface",
                status=DiagnosticStatus.WARNING,
                severity=DiagnosticSeverity.WARNING,
                message="No active VPN tunnel interface or default tunnel route detected.",
                remediation="Ensure Windows VPN or WireGuard tunnel is connected.",
            )

        elif is_linux:
            from src.adapters.linux_vpn_adapter import LinuxVPNAdapter
            adapter = LinuxVPNAdapter()
            tunnels = adapter.list_tunnel_interfaces()
            is_routed = adapter.verify_routing()
            if tunnels:
                return DiagnosticCheck(
                    name="VPN Tunnel Interface",
                    status=DiagnosticStatus.PASS,
                    severity=DiagnosticSeverity.INFO,
                    message=f"Active Linux tunnel interface(s): {', '.join(tunnels)}.",
                    details={"tunnels": tunnels, "routing_verified": is_routed},
                )
            return DiagnosticCheck(
                name="VPN Tunnel Interface",
                status=DiagnosticStatus.WARNING,
                severity=DiagnosticSeverity.WARNING,
                message="No active tunnel interfaces (tun*, wg*, tap*) detected.",
                remediation="Start your OpenVPN or WireGuard service using wg-quick or systemctl.",
            )

        return DiagnosticCheck(
            name="VPN Tunnel Interface",
            status=DiagnosticStatus.UNKNOWN,
            severity=DiagnosticSeverity.INFO,
            message=f"Platform {sys.platform} not supported for tunnel probing.",
        )

    def check_public_ipv4(self) -> DiagnosticCheck:
        """Determine observed public IPv4 address and query latency."""
        endpoints = ["https://api.ipify.org?format=json", "https://ifconfig.me/ip"]
        for ep in endpoints:
            try:
                start = time.perf_counter()
                res = requests.get(ep, timeout=self.settings.verification_timeout_seconds)
                latency = (time.perf_counter() - start) * 1000.0
                if res.status_code == 200:
                    ip = res.json().get("ip") if ep.endswith("json") else res.text.strip()
                    return DiagnosticCheck(
                        name="Public IPv4 Probe",
                        status=DiagnosticStatus.PASS,
                        severity=DiagnosticSeverity.INFO,
                        message=f"Public IPv4 observed: {ip} ({latency:.1f}ms)",
                        details={"ipv4": ip, "latency_ms": round(latency, 1)},
                    )
            except Exception:
                continue

        return DiagnosticCheck(
            name="Public IPv4 Probe",
            status=DiagnosticStatus.FAIL,
            severity=DiagnosticSeverity.ERROR,
            message="Failed to discover public IPv4 address from probe endpoints.",
            remediation="Check proxy egress rules, firewall filters, or internet connection.",
        )

    def check_public_ipv6(self) -> DiagnosticCheck:
        """Determine observed public IPv6 address or verify absence."""
        try:
            start = time.perf_counter()
            res = requests.get("https://api64.ipify.org?format=json", timeout=5.0)
            latency = (time.perf_counter() - start) * 1000.0
            if res.status_code == 200:
                ip = res.json().get("ip", "")
                if ":" in ip:
                    return DiagnosticCheck(
                        name="Public IPv6 Probe",
                        status=DiagnosticStatus.PASS,
                        severity=DiagnosticSeverity.INFO,
                        message=f"Public IPv6 observed: {ip}",
                        details={"ipv6": ip, "latency_ms": round(latency, 1)},
                    )
                return DiagnosticCheck(
                    name="Public IPv6 Probe",
                    status=DiagnosticStatus.PASS,
                    severity=DiagnosticSeverity.INFO,
                    message="IPv6 is not active or ISP only routes IPv4.",
                    details={"ipv4_fallback": ip},
                )
        except Exception as exc:
            logger.debug("IPv6 probe failed: %s", exc)

        return DiagnosticCheck(
            name="Public IPv6 Probe",
            status=DiagnosticStatus.PASS,
            severity=DiagnosticSeverity.INFO,
            message="No IPv6 connectivity detected (IPv4 only or blocked).",
            details={"ipv6_available": False},
        )

    def check_dns(self) -> DiagnosticCheck:
        """Check system DNS server configuration for potential leaks."""
        if sys.platform.startswith("linux"):
            from src.adapters.linux_vpn_adapter import LinuxVPNAdapter
            adapter = LinuxVPNAdapter()
            dns_info = adapter.check_dns_config()
            nameservers = dns_info.get("nameservers", [])
            if any(ns in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9") for ns in nameservers):
                return DiagnosticCheck(
                    name="DNS Configuration",
                    status=DiagnosticStatus.PASS,
                    severity=DiagnosticSeverity.INFO,
                    message=f"Secure public DNS resolvers active: {', '.join(nameservers)}",
                    details=dns_info,
                )
            return DiagnosticCheck(
                name="DNS Configuration",
                status=DiagnosticStatus.WARNING,
                severity=DiagnosticSeverity.WARNING,
                message=f"Nameservers in use: {', '.join(nameservers)}. ISP DNS leak possible.",
                remediation="Configure static secure DNS (e.g. 1.1.1.1 or 9.9.9.9) or enable VPN DNS override.",
                details=dns_info,
            )

        # Standard resolution test for Windows
        try:
            start = time.perf_counter()
            _, _, ips = socket.gethostbyname_ex("one.one.one.one")
            latency = (time.perf_counter() - start) * 1000.0
            return DiagnosticCheck(
                name="DNS Resolution",
                status=DiagnosticStatus.PASS,
                severity=DiagnosticSeverity.INFO,
                message=f"DNS resolution operational ({latency:.1f}ms). Resolved IPs: {', '.join(ips)}",
                details={"resolved_ips": ips, "latency_ms": round(latency, 1)},
            )
        except Exception as exc:
            return DiagnosticCheck(
                name="DNS Resolution",
                status=DiagnosticStatus.FAIL,
                severity=DiagnosticSeverity.ERROR,
                message=f"DNS resolution failure: {exc}",
                remediation="Verify adapter DNS configuration or flush DNS cache ('ipconfig /flushdns').",
            )

    def check_routing(self) -> DiagnosticCheck:
        """Inspect platform-specific routing table."""
        if sys.platform == "win32":
            from src.adapters.windows_vpn_adapter import WindowsVPNAdapter
            adapter = WindowsVPNAdapter()
            is_routed = adapter.verify_routing()
            return DiagnosticCheck(
                name="Routing Configuration",
                status=DiagnosticStatus.PASS if is_routed else DiagnosticStatus.WARNING,
                severity=DiagnosticSeverity.INFO if is_routed else DiagnosticSeverity.WARNING,
                message="Default traffic is routed through VPN tunnel adapter." if is_routed else "Default routing points to standard physical gateway.",
                details={"vpn_routed": is_routed},
            )
        elif sys.platform.startswith("linux"):
            from src.adapters.linux_vpn_adapter import LinuxVPNAdapter
            adapter = LinuxVPNAdapter()
            routes = adapter.check_routing_table()
            is_routed = adapter.verify_routing()
            return DiagnosticCheck(
                name="Routing Configuration",
                status=DiagnosticStatus.PASS if is_routed else DiagnosticStatus.WARNING,
                severity=DiagnosticSeverity.INFO if is_routed else DiagnosticSeverity.WARNING,
                message="Default route directs traffic into tunnel interface." if is_routed else "Default route points to local gateway.",
                details={"route_count": len(routes), "vpn_routed": is_routed},
            )

        return DiagnosticCheck(
            name="Routing Configuration",
            status=DiagnosticStatus.UNKNOWN,
            severity=DiagnosticSeverity.INFO,
            message=f"Routing check unsupported on platform {sys.platform}.",
        )

    def check_kill_switch(self) -> DiagnosticCheck:
        """Check whether firewall kill switch is supported and currently armed."""
        from src.adapters.firewall_adapter import FirewallAdapter
        is_elevated = FirewallAdapter.requires_admin()
        kill_switch_active = False

        if self.safety_manager is not None:
            kill_switch_active = bool(getattr(self.safety_manager, "kill_switch_active", False))

        if not is_elevated:
            return DiagnosticCheck(
                name="Firewall Kill-Switch Capability",
                status=DiagnosticStatus.WARNING,
                severity=DiagnosticSeverity.WARNING,
                message="Firewall kill switch cannot be engaged without Administrator/root privileges.",
                remediation="Run the application as Administrator to enable leak-proof kill-switch protection.",
                details={"elevated": False, "active": kill_switch_active},
            )

        return DiagnosticCheck(
            name="Firewall Kill-Switch Capability",
            status=DiagnosticStatus.PASS,
            severity=DiagnosticSeverity.INFO,
            message=f"Firewall kill switch is available (status: {'ENGAGED' if kill_switch_active else 'DISENGAGED'}).",
            details={"elevated": True, "active": kill_switch_active},
        )

    def check_direct_fallback(self) -> DiagnosticCheck:
        """Check policy configuration for direct internet fallback."""
        if self.settings.direct_fallback_allowed:
            return DiagnosticCheck(
                name="Direct Fallback Safety",
                status=DiagnosticStatus.WARNING,
                severity=DiagnosticSeverity.WARNING,
                message="Direct internet fallback is ALLOWED. Your real IP may be exposed if proxy disconnects.",
                remediation="Disable 'direct_fallback_allowed' in safety settings to prevent unmasked exposure.",
                details={"allowed": True},
            )

        return DiagnosticCheck(
            name="Direct Fallback Safety",
            status=DiagnosticStatus.PASS,
            severity=DiagnosticSeverity.INFO,
            message="Direct internet fallback is BLOCKED. Traffic will stop if proxy fails.",
            details={"allowed": False},
        )

    def check_provider_rotation_support(self, profile: Optional[ConnectionProfile] = None) -> DiagnosticCheck:
        """Check if target profile supports automatic rotation."""
        target = profile
        if target is None and self.connection_manager is not None:
            target = getattr(self.connection_manager, "current_profile", None)

        if not target:
            return DiagnosticCheck(
                name="Provider Rotation Support",
                status=DiagnosticStatus.UNKNOWN,
                severity=DiagnosticSeverity.INFO,
                message="No profile selected to inspect for rotation capabilities.",
            )

        if not target.capabilities.supports_rotation:
            return DiagnosticCheck(
                name=f"Provider Rotation Support ({target.name})",
                status=DiagnosticStatus.WARNING,
                severity=DiagnosticSeverity.WARNING,
                message=f"Profile '{target.name}' is marked as non-rotatable.",
                remediation="Use a rotation gateway, multi-node pool, or change profile capabilities.",
                details={"supports_rotation": False},
            )

        return DiagnosticCheck(
            name=f"Provider Rotation Support ({target.name})",
            status=DiagnosticStatus.PASS,
            severity=DiagnosticSeverity.INFO,
            message=f"Profile supports automated rotation (min interval: {target.capabilities.min_rotation_interval_seconds}s).",
            details={"supports_rotation": True, "min_interval": target.capabilities.min_rotation_interval_seconds},
        )

    def run_all_checks(self, profile: Optional[ConnectionProfile] = None) -> List[DiagnosticCheck]:
        """Execute all diagnostics sequentially and broadcast event.

        Args:
            profile: Optional specific profile to inspect.

        Returns:
            List of DiagnosticCheck results.
        """
        logger.info("Executing full diagnostic suite...")
        checks: List[DiagnosticCheck] = [
            self.check_internet(),
            self.check_public_ipv4(),
            self.check_public_ipv6(),
            self.check_dns(),
            self.check_routing(),
            self.check_kill_switch(),
            self.check_direct_fallback(),
            self.check_vpn_tunnel(),
            self.check_proxy(profile),
            self.check_provider_rotation_support(profile),
        ]

        # Broadcast via EventBus
        if self.event_bus is not None:
            try:
                self.event_bus.emit(DIAGNOSTIC_COMPLETED, [c.to_dict() for c in checks])
            except Exception as exc:
                logger.error("Failed to emit DIAGNOSTIC_COMPLETED event: %s", exc)

        logger.info("Diagnostic suite finished. Total checks: %d", len(checks))
        return checks
