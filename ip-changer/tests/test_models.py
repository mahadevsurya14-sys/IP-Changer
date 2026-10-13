"""Unit tests for data models in IP Changer.

Tests ConnectionProfile, ConnectionCapabilities, AppSettings, RotationEvent,
and RotationHistory models for validation, serialization, and aggregation.
"""

from __future__ import annotations

import pytest

from src.models.app_settings import AppSettings, ThemeMode
from src.models.connection_profile import (
    ConnectionCapabilities,
    ConnectionProfile,
    ConnectionType,
    TrafficScope,
)
from src.models.rotation_event import (
    RotationEvent,
    RotationHistory,
    RotationResult,
    sanitize_sensitive_text,
)


def test_connection_profile_validation() -> None:
    """Test validation constraints on ConnectionProfile."""
    # Valid profile
    profile = ConnectionProfile(
        name="Valid HTTP Proxy",
        connection_type=ConnectionType.HTTP_PROXY,
        host="192.168.1.100",
        port=8080,
    )
    profile.validate()
    assert profile.is_valid() is True

    # Empty name
    with pytest.raises(ValueError, match="Profile name cannot be empty"):
        ConnectionProfile(
            name="   ",
            connection_type=ConnectionType.HTTP_PROXY,
            host="192.168.1.100",
            port=8080,
        ).validate()

    # Empty host
    with pytest.raises(ValueError, match="Host cannot be empty"):
        ConnectionProfile(
            name="Bad Host",
            connection_type=ConnectionType.HTTP_PROXY,
            host="",
            port=8080,
        ).validate()

    # Invalid port (out of bounds)
    with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
        ConnectionProfile(
            name="Bad Port",
            connection_type=ConnectionType.HTTP_PROXY,
            host="192.168.1.100",
            port=70000,
        ).validate()

    # Port 0 for HTTP proxy should fail
    with pytest.raises(ValueError, match="Port must be between 1 and 65535"):
        ConnectionProfile(
            name="Bad Port Zero",
            connection_type=ConnectionType.HTTP_PROXY,
            host="192.168.1.100",
            port=0,
        ).validate()

    # Host with whitespace
    with pytest.raises(ValueError, match="contains invalid characters"):
        ConnectionProfile(
            name="Whitespace Host",
            connection_type=ConnectionType.HTTP_PROXY,
            host="192.168. 1.100",
            port=8080,
        ).validate()

    # Invalid min rotation interval in capabilities
    with pytest.raises(ValueError, match="Minimum rotation interval must be at least 1 second"):
        ConnectionProfile(
            name="Bad Capabilities",
            connection_type=ConnectionType.HTTP_PROXY,
            host="192.168.1.100",
            port=8080,
            capabilities=ConnectionCapabilities(min_rotation_interval_seconds=0),
        ).validate()


def test_connection_profile_serialization() -> None:
    """Test serialization to and from dictionary for ConnectionProfile."""
    caps = ConnectionCapabilities(
        supports_rotation=True,
        supports_system_wide=True,
        min_rotation_interval_seconds=15,
        max_concurrent=2,
        supports_ipv6=True,
        requires_admin=True,
    )
    original = ConnectionProfile(
        id="profile-test-123",
        name="WireGuard US East",
        connection_type=ConnectionType.VPN_WIREGUARD,
        host="us-east.vpn.example.com",
        port=51820,
        username="testuser",
        auth_token_key="keyring_ref_test",
        enabled=True,
        priority=10,
        traffic_scope=TrafficScope.SYSTEM_WIDE,
        capabilities=caps,
        provider_name="TestVPN",
        notes="Testing profile notes",
    )

    data = original.to_dict()
    assert data["id"] == "profile-test-123"
    assert data["connection_type"] == "vpn_wireguard"
    assert data["traffic_scope"] == "system_wide"
    assert data["capabilities"]["supports_system_wide"] is True

    # Roundtrip deserialization
    reconstructed = ConnectionProfile.from_dict(data)
    assert reconstructed.id == original.id
    assert reconstructed.name == original.name
    assert reconstructed.connection_type == original.connection_type
    assert reconstructed.host == original.host
    assert reconstructed.port == original.port
    assert reconstructed.username == original.username
    assert reconstructed.auth_token_key == original.auth_token_key
    assert reconstructed.priority == original.priority
    assert reconstructed.traffic_scope == original.traffic_scope
    assert reconstructed.capabilities.min_rotation_interval_seconds == 15
    assert reconstructed.provider_name == original.provider_name


def test_rotation_event_creation() -> None:
    """Test RotationEvent initialization and sensitive data sanitization."""
    raw_error = "Connection failed: http://admin:supersecret@10.0.0.1:8080 Bearer abc123456789"
    event = RotationEvent(
        profile_name="Proxy A",
        method_type="http_proxy",
        previous_ip="1.1.1.1",
        new_ip="2.2.2.2",
        ip_changed=True,
        result=RotationResult.SUCCESS_IP_CHANGED,
        duration_seconds=1.452,
        error_message=raw_error,
        rotation_number=1,
    )

    assert event.ip_changed is True
    assert event.result == RotationResult.SUCCESS_IP_CHANGED
    # Sensitive tokens should be sanitized
    assert "supersecret" not in (event.error_message or "")
    assert "abc123456789" not in (event.error_message or "")

    event_dict = event.to_dict()
    assert event_dict["ip_changed"] is True
    assert event_dict["result"] == "success_ip_changed"
    assert event_dict["duration_seconds"] == 1.452

    deserialized = RotationEvent.from_dict(event_dict)
    assert deserialized.profile_name == event.profile_name
    assert deserialized.result == event.result
    assert deserialized.previous_ip == "1.1.1.1"
    assert deserialized.new_ip == "2.2.2.2"


def test_rotation_history_stats() -> None:
    """Test statistical aggregation computed by RotationHistory."""
    history = RotationHistory(max_history_size=100)

    # Empty stats
    empty_stats = history.get_stats()
    assert empty_stats["total"] == 0
    assert empty_stats["success_count"] == 0
    assert empty_stats["fail_count"] == 0
    assert empty_stats["avg_duration_seconds"] == 0.0

    # Add 1 successful changed event
    history.add(
        RotationEvent(
            profile_name="P1",
            result=RotationResult.SUCCESS_IP_CHANGED,
            ip_changed=True,
            duration_seconds=2.0,
        )
    )
    # Add 1 successful unchanged event
    history.add(
        RotationEvent(
            profile_name="P2",
            result=RotationResult.SUCCESS_IP_UNCHANGED,
            ip_changed=False,
            duration_seconds=4.0,
        )
    )
    # Add 1 failed connection event
    history.add(
        RotationEvent(
            profile_name="P3",
            result=RotationResult.FAILED_CONNECTION,
            ip_changed=False,
            duration_seconds=3.0,
        )
    )

    stats = history.get_stats()
    assert stats["total"] == 3
    assert stats["success_count"] == 2
    assert stats["fail_count"] == 1
    assert stats["ip_changed_count"] == 1
    assert stats["ip_unchanged_count"] == 1
    assert stats["avg_duration_seconds"] == 3.0  # (2.0 + 4.0 + 3.0) / 3


def test_rotation_history_max_size() -> None:
    """Test ceiling enforcement and FIFO eviction in RotationHistory."""
    history = RotationHistory(max_history_size=10)

    for i in range(15):
        history.add(
            RotationEvent(
                profile_name=f"Profile_{i}",
                rotation_number=i,
            )
        )

    events = history.get_events()
    assert len(events) == 10
    # First 5 items (0..4) should have been evicted; remaining are 5..14
    assert events[0].rotation_number == 5
    assert events[-1].rotation_number == 14

    # Test limit parameter
    subset = history.get_events(limit=3)
    assert len(subset) == 3
    assert subset[-1].rotation_number == 14


def test_app_settings_validation() -> None:
    """Test validation boundaries of AppSettings."""
    settings = AppSettings()
    settings.validate()  # Defaults must pass

    # Interval < 5 seconds
    settings.default_rotation_interval_seconds = 4
    with pytest.raises(ValueError, match="default_rotation_interval_seconds must be >= 5 seconds"):
        settings.validate()
    settings.default_rotation_interval_seconds = 30

    # Connection timeout < 1 second
    settings.connection_timeout_seconds = 0
    with pytest.raises(ValueError, match="connection_timeout_seconds must be >= 1 second"):
        settings.validate()
    settings.connection_timeout_seconds = 15

    # Verification timeout < 1 second
    settings.verification_timeout_seconds = 0
    with pytest.raises(ValueError, match="verification_timeout_seconds must be >= 1 second"):
        settings.validate()
    settings.verification_timeout_seconds = 10

    # Log retention < 1 day
    settings.log_retention_days = 0
    with pytest.raises(ValueError, match="log_retention_days must be >= 1 day"):
        settings.validate()
    settings.log_retention_days = 7

    # Max retries < 0
    settings.max_retries = -1
    with pytest.raises(ValueError, match="max_retries must be >= 0"):
        settings.validate()
    settings.max_retries = 3

    # Retry backoff < 1.0
    settings.retry_backoff_factor = 0.9
    with pytest.raises(ValueError, match="retry_backoff_factor must be >= 1.0"):
        settings.validate()
    settings.retry_backoff_factor = 1.5

    # Max history size < 10
    settings.max_history_size = 5
    with pytest.raises(ValueError, match="max_history_size must be >= 10 entries"):
        settings.validate()
    settings.max_history_size = 500

    # Empty verification urls
    settings.verification_urls = []
    with pytest.raises(ValueError, match="At least one.*verification"):
        settings.validate()


def test_app_settings_serialization() -> None:
    """Test dictionary serialization and roundtrip of AppSettings."""
    settings = AppSettings(
        default_rotation_interval_seconds=45,
        default_connection_method="socks5_proxy",
        auto_rotate_enabled=False,
        preferred_profile_id="pref-id-1",
        connection_timeout_seconds=20,
        max_retries=5,
        retry_backoff_factor=2.0,
        kill_switch_enabled=True,
        theme="light",
        log_retention_days=14,
        max_history_size=250,
        start_minimized=True,
        check_ipv6=True,
    )

    data = settings.to_dict()
    assert data["default_rotation_interval_seconds"] == 45
    assert data["theme"] == "light"
    assert data["kill_switch_enabled"] is True

    loaded = AppSettings.from_dict(data)
    assert loaded.default_rotation_interval_seconds == 45
    assert loaded.default_connection_method == "socks5_proxy"
    assert loaded.auto_rotate_enabled is False
    assert loaded.preferred_profile_id == "pref-id-1"
    assert loaded.connection_timeout_seconds == 20
    assert loaded.max_retries == 5
    assert loaded.retry_backoff_factor == 2.0
    assert loaded.kill_switch_enabled is True
    assert loaded.theme == "light"
    assert loaded.log_retention_days == 14
    assert loaded.max_history_size == 250
    assert loaded.start_minimized is True
    assert loaded.check_ipv6 is True
