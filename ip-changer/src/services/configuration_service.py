"""Configuration and profile persistence service for IP Changer.

Coordinates application configuration, connection profile lifecycle,
atomic file serialization, and event bus notification broadcasts.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.core.event_bus import (
    PROFILE_ADDED,
    PROFILE_REMOVED,
    PROFILE_UPDATED,
    SETTINGS_CHANGED,
    EventBus,
    default_event_bus,
)
from src.models.app_settings import AppSettings
from src.models.connection_profile import ConnectionProfile

logger = logging.getLogger(__name__)


class ConfigurationService:
    """Service for managing AppSettings and ConnectionProfiles with atomic file persistence."""

    def __init__(
        self,
        config_dir: Optional[Union[str, Path]] = None,
        event_bus: Optional[EventBus] = None,
    ) -> None:
        """Initialize configuration service.

        Args:
            config_dir: Custom configuration directory, defaults to project config/.
            event_bus: EventBus instance for notifications, defaults to singleton.
        """
        self._lock = threading.RLock()
        self._event_bus = event_bus or default_event_bus

        if config_dir is not None:
            self._config_dir = Path(config_dir).resolve()
        else:
            # Default to <project_root>/config directory
            project_root = Path(__file__).resolve().parent.parent.parent
            self._config_dir = project_root / "config"

        self._ensure_config_dir()

        self._settings_file = self._config_dir / "settings.json"
        self._profiles_file = self._config_dir / "profiles.json"

        self._settings: AppSettings = self._load_settings()
        self._profiles: Dict[str, ConnectionProfile] = self._load_profiles()

    def get_config_dir(self) -> Path:
        """Return the configuration directory path, ensuring it exists."""
        self._ensure_config_dir()
        return self._config_dir

    def _ensure_config_dir(self) -> None:
        """Create configuration directory if it doesn't already exist."""
        try:
            self._config_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.error("Failed to create configuration directory at %s: %s", self._config_dir, exc)
            raise

    # -------------------------------------------------------------------------
    # AppSettings Management
    # -------------------------------------------------------------------------

    def _load_settings(self) -> AppSettings:
        """Load settings from disk or initialize default instance."""
        with self._lock:
            if not self._settings_file.exists():
                logger.info("Settings file not found; initializing new AppSettings.")
                settings = AppSettings()
                self._save_settings_atomic(settings)
                return settings

            try:
                settings = AppSettings.load_from_file(self._settings_file)
                return settings
            except Exception as exc:
                logger.error("Failed to read settings from %s (%s). Using defaults.", self._settings_file, exc)
                return AppSettings()

    def _save_settings_atomic(self, settings: AppSettings) -> None:
        """Atomically persist settings to disk."""
        settings.validate()
        self._atomic_write_json(self._settings_file, settings.to_dict())

    def get_settings(self) -> AppSettings:
        """Get current application settings."""
        with self._lock:
            return self._settings

    def update_settings(self, new_settings: AppSettings) -> None:
        """Update and persist application settings, notifying listeners.

        Args:
            new_settings: Validated AppSettings instance.
        """
        new_settings.validate()
        with self._lock:
            self._settings = new_settings
            self._save_settings_atomic(self._settings)

        logger.info("Application settings updated successfully.")
        self._event_bus.emit(SETTINGS_CHANGED, self._settings)

    # -------------------------------------------------------------------------
    # ConnectionProfile Management
    # -------------------------------------------------------------------------

    def _load_profiles(self) -> Dict[str, ConnectionProfile]:
        """Load profiles from JSON file."""
        with self._lock:
            if not self._profiles_file.exists():
                logger.info("Profiles file not found at %s. Initializing empty profiles.", self._profiles_file)
                self._save_profiles_atomic({})
                return {}

            try:
                with open(self._profiles_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                profiles: Dict[str, ConnectionProfile] = {}
                profile_items = data if isinstance(data, list) else data.get("profiles", [])

                for item in profile_items:
                    try:
                        profile = ConnectionProfile.from_dict(item)
                        profile.validate()
                        profiles[profile.id] = profile
                    except Exception as err:
                        logger.warning("Skipping invalid profile entry in %s: %s", self._profiles_file, err)

                return profiles
            except Exception as exc:
                logger.error("Error reading profiles file %s: %s", self._profiles_file, exc)
                return {}

    def _save_profiles_atomic(self, profiles: Dict[str, ConnectionProfile]) -> None:
        """Atomically persist sanitized profile list to JSON."""
        # Ensure credentials/secrets are NEVER written to disk
        payload = [profile.to_dict() for profile in profiles.values()]
        self._atomic_write_json(self._profiles_file, payload)

    def list_profiles(self, enabled_only: bool = False) -> List[ConnectionProfile]:
        """Return list of profiles, optionally filtered by enabled state.

        Args:
            enabled_only: If True, only returns profiles with enabled=True.

        Returns:
            List of ConnectionProfile instances sorted by priority (descending).
        """
        with self._lock:
            profiles = list(self._profiles.values())

        if enabled_only:
            profiles = [p for p in profiles if p.enabled]

        # Sort primarily by priority (higher priority first), then by name
        return sorted(profiles, key=lambda p: (-p.priority, p.name.lower()))

    def get_profile(self, profile_id: str) -> Optional[ConnectionProfile]:
        """Retrieve a connection profile by its unique ID.

        Args:
            profile_id: UUID string of the profile.

        Returns:
            ConnectionProfile if found, else None.
        """
        with self._lock:
            return self._profiles.get(profile_id)

    def add_profile(self, profile: ConnectionProfile) -> ConnectionProfile:
        """Validate and add a new connection profile.

        Args:
            profile: Profile to register.

        Returns:
            The registered ConnectionProfile.

        Raises:
            ValueError: If profile data is invalid or duplicate ID exists.
        """
        profile.validate()

        with self._lock:
            if profile.id in self._profiles:
                raise ValueError(f"Profile with ID '{profile.id}' already exists.")

            self._profiles[profile.id] = profile
            self._save_profiles_atomic(self._profiles)

        logger.info("Added profile '%s' (ID: %s)", profile.name, profile.id)
        self._event_bus.emit(PROFILE_ADDED, profile)
        return profile

    def update_profile(self, profile: ConnectionProfile) -> ConnectionProfile:
        """Validate and update an existing connection profile.

        Args:
            profile: Modified profile.

        Returns:
            The updated ConnectionProfile.

        Raises:
            KeyError: If profile does not exist.
            ValueError: If profile validation fails.
        """
        profile.validate()

        with self._lock:
            if profile.id not in self._profiles:
                raise KeyError(f"Profile with ID '{profile.id}' does not exist.")

            self._profiles[profile.id] = profile
            self._save_profiles_atomic(self._profiles)

        logger.info("Updated profile '%s' (ID: %s)", profile.name, profile.id)
        self._event_bus.emit(PROFILE_UPDATED, profile)
        return profile

    def remove_profile(self, profile_id: str) -> bool:
        """Remove a connection profile by ID.

        Args:
            profile_id: Unique ID of the profile to remove.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            profile = self._profiles.pop(profile_id, None)
            if profile is None:
                return False

            self._save_profiles_atomic(self._profiles)

        logger.info("Removed profile '%s' (ID: %s)", profile.name, profile_id)
        self._event_bus.emit(PROFILE_REMOVED, profile_id)
        return True

    # -------------------------------------------------------------------------
    # Internal Storage Utilities
    # -------------------------------------------------------------------------

    def _atomic_write_json(self, target_path: Path, data: Any) -> None:
        """Write JSON atomically to disk using a temporary file.

        Args:
            target_path: Destination file path.
            data: Object to serialize as JSON.
        """
        self._ensure_config_dir()
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                dir=str(target_path.parent),
                delete=False,
                encoding="utf-8",
                suffix=".tmp",
            ) as f:
                temp_file = Path(f.name)
                json.dump(data, f, indent=4)
                f.flush()
                os.fsync(f.fileno())

            temp_file.replace(target_path)
            logger.debug("Atomically wrote configuration file: %s", target_path)
        except Exception as exc:
            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass
            logger.error("Failed atomic JSON write to %s: %s", target_path, exc)
            raise
