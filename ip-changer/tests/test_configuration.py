"""Unit tests for AppSettings and ConfigurationService in IP Changer.

Tests default settings, interval and timeout constraints, atomic saving/loading,
profile CRUD operations, and invalid profile rejection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.event_bus import EventBus
from src.models.app_settings import AppSettings
from src.models.connection_profile import ConnectionProfile, ConnectionType
from src.services.configuration_service import ConfigurationService


def test_default_settings() -> None:
    """Test that default settings instantiate with expected baseline parameters."""
    settings = AppSettings()
    assert settings.default_rotation_interval_seconds == 60
    assert settings.connection_timeout_seconds == 15
    assert settings.max_retries == 3
    assert settings.retry_backoff_factor == 1.5
    assert settings.kill_switch_enabled is False
    assert settings.theme == "dark"
    assert len(settings.verification_urls) >= 2


def test_interval_validation() -> None:
    """Test rotation interval threshold validation."""
    settings = AppSettings()

    # Valid intervals
    settings.default_rotation_interval_seconds = 5
    settings.validate()

    settings.default_rotation_interval_seconds = 60
    settings.validate()

    # Infeasible intervals < 5s
    settings.default_rotation_interval_seconds = 4
    with pytest.raises(ValueError, match="default_rotation_interval_seconds must be >= 5"):
        settings.validate()


def test_timeout_validation() -> None:
    """Test connection timeout boundary validation."""
    settings = AppSettings()

    # Valid timeout
    settings.connection_timeout_seconds = 1
    settings.validate()

    # Invalid timeout <= 0
    settings.connection_timeout_seconds = 0
    with pytest.raises(ValueError, match="connection_timeout_seconds must be >= 1"):
        settings.validate()


def test_save_load_settings(tmp_path: Path) -> None:
    """Test saving and loading settings to disk atomically."""
    settings_path = tmp_path / "test_settings.json"

    original = AppSettings(
        default_rotation_interval_seconds=40,
        connection_timeout_seconds=25,
        theme="light",
        kill_switch_enabled=True,
    )
    original.save_to_file(settings_path)

    assert settings_path.exists()

    loaded = AppSettings.load_from_file(settings_path)
    assert loaded.default_rotation_interval_seconds == 40
    assert loaded.connection_timeout_seconds == 25
    assert loaded.theme == "light"
    assert loaded.kill_switch_enabled is True


def test_profile_crud(tmp_path: Path) -> None:
    """Test full CRUD operations on ConnectionProfile within ConfigurationService."""
    event_bus = EventBus()
    service = ConfigurationService(config_dir=tmp_path, event_bus=event_bus)

    # 1. Create / Add
    profile1 = ConnectionProfile(
        id="test-p1",
        name="Proxy Alpha",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.1",
        port=8080,
        priority=10,
    )
    added = service.add_profile(profile1)
    assert added.id == "test-p1"

    # 2. Read / List
    retrieved = service.get_profile("test-p1")
    assert retrieved is not None
    assert retrieved.name == "Proxy Alpha"

    all_profiles = service.list_profiles()
    assert len(all_profiles) == 1
    assert all_profiles[0].id == "test-p1"

    # 3. Update
    retrieved.name = "Proxy Alpha Updated"
    retrieved.priority = 25
    updated = service.update_profile(retrieved)
    assert updated.name == "Proxy Alpha Updated"
    assert updated.priority == 25

    # Verify update persisted
    reloaded_profile = service.get_profile("test-p1")
    assert reloaded_profile is not None
    assert reloaded_profile.name == "Proxy Alpha Updated"

    # 4. Delete
    removed = service.remove_profile("test-p1")
    assert removed is True
    assert service.get_profile("test-p1") is None
    assert len(service.list_profiles()) == 0


def test_invalid_profile_rejected(tmp_path: Path) -> None:
    """Test that invalid profiles are rejected by ConfigurationService."""
    event_bus = EventBus()
    service = ConfigurationService(config_dir=tmp_path, event_bus=event_bus)

    # Empty name
    invalid_profile = ConnectionProfile(
        id="bad-p",
        name="",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.1",
        port=8080,
    )

    with pytest.raises(ValueError, match="Profile name cannot be empty"):
        service.add_profile(invalid_profile)

    # Duplicate ID
    valid_p = ConnectionProfile(
        id="duplicate-id",
        name="Valid First",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.1",
        port=8080,
    )
    service.add_profile(valid_p)

    duplicate_p = ConnectionProfile(
        id="duplicate-id",
        name="Valid Second",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.2",
        port=8080,
    )
    with pytest.raises(ValueError, match="already exists"):
        service.add_profile(duplicate_p)


def test_settings_to_dict_roundtrip() -> None:
    """Test roundtrip conversion of AppSettings to dictionary and back."""
    settings = AppSettings(
        default_rotation_interval_seconds=15,
        default_connection_method="https_proxy",
        auto_rotate_enabled=True,
        theme="dark",
    )
    data = settings.to_dict()
    assert isinstance(data, dict)
    assert data["default_rotation_interval_seconds"] == 15
    assert data["theme"] == "dark"

    deserialized = AppSettings.from_dict(data)
    assert deserialized.default_rotation_interval_seconds == settings.default_rotation_interval_seconds
    assert deserialized.default_connection_method == settings.default_connection_method
    assert deserialized.auto_rotate_enabled == settings.auto_rotate_enabled
    assert deserialized.theme == settings.theme
