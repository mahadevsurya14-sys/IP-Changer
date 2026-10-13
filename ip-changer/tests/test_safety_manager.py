"""Unit tests for SafetyManager in IP Changer.

Tests kill-switch toggling, safety status auditing, pre-rotation safety checks,
direct fallback detection, and network restoration with mock firewall adapter.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.core.event_bus import EventBus
from src.core.ip_verifier import IPVerificationResult, IPVerifier
from src.core.safety_manager import SafetyManager
from src.models.app_settings import AppSettings
from src.models.connection_profile import (
    ConnectionCapabilities,
    ConnectionProfile,
    ConnectionType,
    TrafficScope,
)


@pytest.fixture
def safety_fixture() -> tuple[SafetyManager, EventBus, AppSettings, MagicMock]:
    """Provide SafetyManager configured with mock firewall adapter."""
    event_bus = EventBus()
    settings = AppSettings(kill_switch_enabled=False)
    manager = SafetyManager(event_bus=event_bus, settings=settings)

    mock_firewall = MagicMock()
    mock_firewall.enable_kill_switch.return_value = (True, "Rules applied")
    mock_firewall.disable_kill_switch.return_value = (True, "Rules removed")
    mock_firewall.restore_network_config.return_value = True

    return manager, event_bus, settings, mock_firewall


def test_kill_switch_enable_disable(
    safety_fixture: tuple[SafetyManager, EventBus, AppSettings, MagicMock]
) -> None:
    """Test engaging and disengaging the firewall kill switch."""
    manager, _, settings, mock_firewall = safety_fixture

    assert manager.kill_switch_active is False

    # Enable
    success, msg = manager.enable_kill_switch(adapter=mock_firewall)
    assert success is True
    assert manager.kill_switch_active is True
    assert settings.kill_switch_enabled is True
    mock_firewall.enable_kill_switch.assert_called_once()

    # Disable
    success, msg = manager.disable_kill_switch(adapter=mock_firewall)
    assert success is True
    assert manager.kill_switch_active is False
    assert settings.kill_switch_enabled is False
    mock_firewall.disable_kill_switch.assert_called_once()


def test_safety_status(
    safety_fixture: tuple[SafetyManager, EventBus, AppSettings, MagicMock]
) -> None:
    """Test safety posture diagnostic reporting."""
    manager, _, _, _ = safety_fixture

    # Initial status (kill switch inactive, baseline uncalibrated)
    status = manager.get_status()
    assert status.kill_switch_active is False
    assert status.can_guarantee_protection is False
    assert len(status.warnings) >= 1

    # Calibrate baseline direct IP
    mock_verifier = MagicMock(spec=IPVerifier)
    mock_verifier.verify_ip.return_value = IPVerificationResult(
        ip_address="198.51.100.5",
        is_valid=True,
        service_used="https://api.ipify.org",
    )
    manager.establish_baseline_ip(mock_verifier)

    status_with_baseline = manager.get_status()
    assert status_with_baseline.is_protected is True
    assert any("Baseline IP Monitored" in p for p in status_with_baseline.active_protections)


def test_pre_rotation_check_no_kill_switch(
    safety_fixture: tuple[SafetyManager, EventBus, AppSettings, MagicMock]
) -> None:
    """Test pre-rotation checks when kill switch is disabled."""
    manager, _, _, _ = safety_fixture

    profile = ConnectionProfile(
        name="Standard Proxy",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.1",
        port=8080,
    )

    passed, reason = manager.pre_rotation_safety_check(
        profile=profile,
        scope=TrafficScope.APPLICATION_LEVEL,
    )
    assert passed is True
    assert "passed" in reason.lower()

    # Disabled profile must fail
    profile.enabled = False
    passed, reason = manager.pre_rotation_safety_check(
        profile=profile,
        scope=TrafficScope.APPLICATION_LEVEL,
    )
    assert passed is False
    assert "disabled" in reason.lower()


def test_pre_rotation_check_with_kill_switch(
    safety_fixture: tuple[SafetyManager, EventBus, AppSettings, MagicMock]
) -> None:
    """Test pre-rotation checks when system-wide scope is requested."""
    manager, _, _, mock_firewall = safety_fixture
    manager.enable_kill_switch(adapter=mock_firewall)

    # Profile without system-wide capability requested for SYSTEM_WIDE scope
    proxy_profile = ConnectionProfile(
        name="Non-System Proxy",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.1",
        port=8080,
        capabilities=ConnectionCapabilities(supports_system_wide=False),
    )

    passed, reason = manager.pre_rotation_safety_check(
        profile=proxy_profile,
        scope=TrafficScope.SYSTEM_WIDE,
    )
    assert passed is False
    assert "does not support system routing" in reason


def test_direct_fallback_detection(
    safety_fixture: tuple[SafetyManager, EventBus, AppSettings, MagicMock]
) -> None:
    """Test detection of silent direct IP leakage against baseline."""
    manager, _, _, _ = safety_fixture

    mock_verifier = MagicMock(spec=IPVerifier)

    # 1. Establish baseline IP as 198.51.100.99
    mock_verifier.verify_ip.return_value = IPVerificationResult(
        ip_address="198.51.100.99",
        is_valid=True,
        service_used="https://api.ipify.org",
    )
    manager.establish_baseline_ip(mock_verifier)

    # 2. Check fallback when current IP matches baseline (leak occurring)
    mock_verifier.verify_ip.return_value = IPVerificationResult(
        ip_address="198.51.100.99",
        is_valid=True,
        service_used="https://api.ipify.org",
    )
    is_leaking = manager.check_direct_fallback(mock_verifier)
    assert is_leaking is True

    # 3. Check fallback when current IP is different (proxied/protected)
    mock_verifier.verify_ip.return_value = IPVerificationResult(
        ip_address="203.0.113.10",
        is_valid=True,
        service_used="https://api.ipify.org",
    )
    is_leaking_protected = manager.check_direct_fallback(mock_verifier)
    assert is_leaking_protected is False


def test_restore_network_config(
    safety_fixture: tuple[SafetyManager, EventBus, AppSettings, MagicMock]
) -> None:
    """Test restoring system network configuration safely."""
    manager, _, _, mock_firewall = safety_fixture
    manager.enable_kill_switch(adapter=mock_firewall)

    assert manager.kill_switch_active is True

    success = manager.restore_network_config(adapter=mock_firewall)
    assert success is True
    assert manager.kill_switch_active is False
    mock_firewall.restore_network_config.assert_called_once()
