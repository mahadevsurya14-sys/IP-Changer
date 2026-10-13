"""Unit tests for MethodSelector in IP Changer.

Tests profile evaluation, manual override selection, priority ranking,
interval and scope feasibility checks, and explanation formatting.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.core.capability_registry import CapabilityRegistry
from src.core.event_bus import EventBus
from src.core.method_selector import MethodSelector
from src.models.app_settings import AppSettings
from src.models.connection_profile import (
    ConnectionCapabilities,
    ConnectionProfile,
    ConnectionType,
    TrafficScope,
)


@pytest.fixture
def mock_dependencies() -> tuple[CapabilityRegistry, AppSettings, EventBus]:
    """Provide real or mocked dependencies for MethodSelector."""
    caps = CapabilityRegistry()
    settings = AppSettings()
    event_bus = EventBus()
    return caps, settings, event_bus


def test_select_manual_override(mock_dependencies: tuple[CapabilityRegistry, AppSettings, EventBus]) -> None:
    """Test that a viable manual override profile takes precedence."""
    caps, settings, event_bus = mock_dependencies
    selector = MethodSelector(caps, settings, event_bus)

    profile_a = ConnectionProfile(
        id="prof-a",
        name="Profile Alpha",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.1",
        port=8080,
        priority=100,  # High priority
    )
    profile_b = ConnectionProfile(
        id="prof-b",
        name="Profile Beta",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.2",
        port=8080,
        priority=1,  # Low priority, but manually requested
    )

    result = selector.select(
        profiles=[profile_a, profile_b],
        interval=30,
        scope=TrafficScope.APPLICATION_LEVEL,
        manual_override_id="prof-b",
    )

    assert result.selected_profile is not None
    assert result.selected_profile.id == "prof-b"
    assert "Manual override" in result.selection_policy


def test_select_highest_priority(mock_dependencies: tuple[CapabilityRegistry, AppSettings, EventBus]) -> None:
    """Test that the candidate with the highest priority is selected."""
    caps, settings, event_bus = mock_dependencies
    selector = MethodSelector(caps, settings, event_bus)

    p_low = ConnectionProfile(
        id="p1",
        name="Low Priority",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.1",
        port=8080,
        priority=5,
    )
    p_high = ConnectionProfile(
        id="p2",
        name="High Priority",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.2",
        port=8080,
        priority=50,
    )
    p_med = ConnectionProfile(
        id="p3",
        name="Medium Priority",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.3",
        port=8080,
        priority=20,
    )

    result = selector.select(
        profiles=[p_low, p_high, p_med],
        interval=30,
        scope=TrafficScope.APPLICATION_LEVEL,
    )

    assert result.selected_profile is not None
    assert result.selected_profile.id == "p2"
    assert result.selected_profile.priority == 50


def test_reject_disabled_profile(mock_dependencies: tuple[CapabilityRegistry, AppSettings, EventBus]) -> None:
    """Test that disabled profiles are rejected and not selected."""
    caps, settings, event_bus = mock_dependencies
    selector = MethodSelector(caps, settings, event_bus)

    p_disabled = ConnectionProfile(
        id="p-disabled",
        name="Disabled High Priority",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.1",
        port=8080,
        priority=100,
        enabled=False,
    )
    p_enabled = ConnectionProfile(
        id="p-enabled",
        name="Enabled Low Priority",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.2",
        port=8080,
        priority=10,
        enabled=True,
    )

    result = selector.select(
        profiles=[p_disabled, p_enabled],
        interval=30,
        scope=TrafficScope.APPLICATION_LEVEL,
    )

    assert result.selected_profile is not None
    assert result.selected_profile.id == "p-enabled"
    # p-disabled should be recorded in rejected list
    rejected_ids = [p.id for p, _ in result.rejected_profiles]
    assert "p-disabled" in rejected_ids


def test_reject_infeasible_interval(mock_dependencies: tuple[CapabilityRegistry, AppSettings, EventBus]) -> None:
    """Test that profiles with higher minimum intervals than requested are rejected."""
    caps, settings, event_bus = mock_dependencies
    selector = MethodSelector(caps, settings, event_bus)

    # OpenVPN default min interval is 30s in capability registry
    vpn_profile = ConnectionProfile(
        id="vpn-1",
        name="OpenVPN Profile",
        connection_type=ConnectionType.VPN_OPENVPN,
        host="vpn.example.com",
        port=1194,
        priority=10,
    )

    # Request rotation every 10s (too fast for OpenVPN)
    result = selector.select(
        profiles=[vpn_profile],
        interval=10,
        scope=TrafficScope.APPLICATION_LEVEL,
    )

    assert result.selected_profile is None
    assert len(result.rejected_profiles) == 1
    assert "shorter than minimum allowed" in result.rejected_profiles[0][1]


def test_prefer_vpn_for_system_wide(mock_dependencies: tuple[CapabilityRegistry, AppSettings, EventBus]) -> None:
    """Test that VPN profiles supporting system routing are preferred when SYSTEM_WIDE is requested."""
    caps, settings, event_bus = mock_dependencies
    selector = MethodSelector(caps, settings, event_bus)

    proxy_profile = ConnectionProfile(
        id="proxy-1",
        name="HTTP Proxy",
        connection_type=ConnectionType.HTTP_PROXY,
        host="proxy.example.com",
        port=8080,
        priority=100,  # Higher priority, but lacks system_wide support
    )
    vpn_profile = ConnectionProfile(
        id="vpn-1",
        name="WireGuard VPN",
        connection_type=ConnectionType.VPN_WIREGUARD,
        host="wg.example.com",
        port=51820,
        priority=10,
        capabilities=ConnectionCapabilities(supports_system_wide=True),
    )

    result = selector.select(
        profiles=[proxy_profile, vpn_profile],
        interval=30,
        scope=TrafficScope.SYSTEM_WIDE,
    )

    # Proxy profile should be rejected due to lack of system_wide support
    assert result.selected_profile is not None
    assert result.selected_profile.id == "vpn-1"
    assert result.selected_profile.connection_type == ConnectionType.VPN_WIREGUARD


def test_no_profiles_available(mock_dependencies: tuple[CapabilityRegistry, AppSettings, EventBus]) -> None:
    """Test selection result when an empty profile list is passed."""
    caps, settings, event_bus = mock_dependencies
    selector = MethodSelector(caps, settings, event_bus)

    result = selector.select(
        profiles=[],
        interval=30,
        scope=TrafficScope.APPLICATION_LEVEL,
    )

    assert result.selected_profile is None
    assert "No enabled connection profiles" in result.reason
    assert len(result.rejected_profiles) == 0


def test_all_profiles_rejected(mock_dependencies: tuple[CapabilityRegistry, AppSettings, EventBus]) -> None:
    """Test selection result when all profiles are disabled or invalid."""
    caps, settings, event_bus = mock_dependencies
    selector = MethodSelector(caps, settings, event_bus)

    p1 = ConnectionProfile(
        id="p1",
        name="Disabled 1",
        connection_type=ConnectionType.HTTP_PROXY,
        host="1.1.1.1",
        port=8080,
        enabled=False,
    )
    p2 = ConnectionProfile(
        id="p2",
        name="Disabled 2",
        connection_type=ConnectionType.HTTP_PROXY,
        host="2.2.2.2",
        port=8080,
        enabled=False,
    )

    result = selector.select(
        profiles=[p1, p2],
        interval=30,
        scope=TrafficScope.APPLICATION_LEVEL,
    )

    assert result.selected_profile is None
    assert len(result.rejected_profiles) == 2


def test_selection_explanation(mock_dependencies: tuple[CapabilityRegistry, AppSettings, EventBus]) -> None:
    """Test human-readable selection explanation string generation."""
    caps, settings, event_bus = mock_dependencies
    selector = MethodSelector(caps, settings, event_bus)

    p1 = ConnectionProfile(
        id="p1",
        name="Active HTTP Proxy",
        connection_type=ConnectionType.HTTP_PROXY,
        host="proxy.test.com",
        port=8080,
        priority=10,
    )
    p2 = ConnectionProfile(
        id="p2",
        name="Disabled Proxy",
        connection_type=ConnectionType.HTTP_PROXY,
        host="disabled.test.com",
        port=8080,
        enabled=False,
    )

    result = selector.select(
        profiles=[p1, p2],
        interval=30,
        scope=TrafficScope.APPLICATION_LEVEL,
    )

    explanation = selector.get_selection_explanation(result)
    assert "Selection Policy:" in explanation
    assert "Active Profile: 'Active HTTP Proxy'" in explanation
    assert "Rejected Profiles (1):" in explanation
    assert "Disabled Proxy" in explanation
