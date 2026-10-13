"""Application configuration settings model for IP Changer.

Maintains user preferences, network safety policies, log retention,
and rotation timing configurations.
"""

from __future__ import annotations

import enum
import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class ThemeMode(enum.Enum):
    """Supported UI theme modes."""
    LIGHT = "light"
    DARK = "dark"
    SYSTEM = "system"


# Preset rotation interval options in seconds.
PRESET_INTERVALS: List[int] = [5, 10, 30, 60]


@dataclass
class AppSettings:
    """Persistent user preferences and runtime operational settings."""
    # Network and Rotation
    default_rotation_interval_seconds: int = 60
    auto_rotate_enabled: bool = False
    connection_timeout_seconds: int = 15
    verification_timeout_seconds: int = 10
    verification_urls: List[str] = field(default_factory=lambda: [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/all.json",
        "https://icanhazip.com",
    ])

    # Retry and history
    max_retries: int = 3
    retry_backoff_factor: float = 1.5
    max_history_size: int = 1000

    # IPv6 support
    check_ipv6: bool = False
    ipv6_verification_url: str = "https://api6.ipify.org"

    # Profile preference defaults
    default_connection_method: Optional[str] = None
    preferred_profile_id: Optional[str] = None

    # Safety and Kill Switch
    kill_switch_enabled: bool = False
    dns_leak_protection: bool = True
    direct_fallback_allowed: bool = False
    trusted_direct_ips: List[str] = field(default_factory=list)
    blocked_regions: List[str] = field(default_factory=list)

    # Logging and Diagnostics
    log_level: str = "INFO"
    log_directory: str = "logs"
    max_log_size_bytes: int = 10 * 1024 * 1024  # 10 MB
    log_retention_days: int = 7
    log_backup_count: int = 5

    # Security
    use_system_keyring: bool = True

    # UI Preferences
    theme: str = "dark"
    start_minimized: bool = False
    minimize_to_tray: bool = True
    show_notifications: bool = True

    def __post_init__(self) -> None:
        """Normalize attributes upon initialization."""
        if isinstance(self.theme, ThemeMode):
            self.theme = self.theme.value
        elif hasattr(self.theme, "value"):
            self.theme = str(self.theme.value)
        else:
            self.theme = str(self.theme)

    # Backward compatibility properties
    @property
    def default_rotation_interval(self) -> int:
        """Alias for default_rotation_interval_seconds."""
        return self.default_rotation_interval_seconds

    @default_rotation_interval.setter
    def default_rotation_interval(self, value: int) -> None:
        self.default_rotation_interval_seconds = value

    @property
    def connection_timeout(self) -> int:
        """Alias for connection_timeout_seconds."""
        return self.connection_timeout_seconds

    @connection_timeout.setter
    def connection_timeout(self, value: int) -> None:
        self.connection_timeout_seconds = value

    @property
    def verification_timeout(self) -> int:
        """Alias for verification_timeout_seconds."""
        return self.verification_timeout_seconds

    @verification_timeout.setter
    def verification_timeout(self, value: int) -> None:
        self.verification_timeout_seconds = value

    @property
    def verification_services(self) -> List[str]:
        """Alias for verification_urls."""
        return self.verification_urls

    @verification_services.setter
    def verification_services(self, value: List[str]) -> None:
        self.verification_urls = value

    @property
    def ipv6_verification_service(self) -> str:
        """Alias for ipv6_verification_url."""
        return self.ipv6_verification_url

    @ipv6_verification_service.setter
    def ipv6_verification_service(self, value: str) -> None:
        self.ipv6_verification_url = value

    @property
    def auto_mode(self) -> bool:
        """Alias for auto_rotate_enabled."""
        return self.auto_rotate_enabled

    @auto_mode.setter
    def auto_mode(self, value: bool) -> None:
        self.auto_rotate_enabled = value

    def validate(self) -> None:
        """Validate configuration settings.

        Raises:
            ValueError: If any setting fails validation constraints.
        """
        if self.default_rotation_interval_seconds < 5:
            raise ValueError("default_rotation_interval_seconds must be >= 5 seconds")

        if self.connection_timeout_seconds < 1:
            raise ValueError("connection_timeout_seconds must be >= 1 second")

        if self.verification_timeout_seconds < 1:
            raise ValueError("verification_timeout_seconds must be >= 1 second")

        if self.log_retention_days < 1:
            raise ValueError("log_retention_days must be >= 1 day")

        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")

        if self.retry_backoff_factor < 1.0:
            raise ValueError("retry_backoff_factor must be >= 1.0")

        if self.max_history_size < 10:
            raise ValueError("max_history_size must be >= 10 entries")

        if not self.verification_urls:
            raise ValueError("At least one IPv4 verification service/URL must be configured.")

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> AppSettings:
        """Construct AppSettings from dictionary."""
        if not data:
            return cls()

        theme_val = data.get("theme", "dark")
        if isinstance(theme_val, ThemeMode):
            theme_val = theme_val.value

        rot_interval = data.get(
            "default_rotation_interval_seconds",
            data.get("default_rotation_interval", 60),
        )
        conn_timeout = data.get(
            "connection_timeout_seconds",
            data.get("connection_timeout", 15),
        )
        verif_timeout = data.get(
            "verification_timeout_seconds",
            data.get("verification_timeout", 10),
        )
        verif_urls = data.get(
            "verification_urls",
            data.get("verification_services", [
                "https://api.ipify.org?format=json",
                "https://ifconfig.me/all.json",
                "https://icanhazip.com",
            ]),
        )
        ipv6_url = data.get(
            "ipv6_verification_url",
            data.get("ipv6_verification_service", "https://api6.ipify.org"),
        )
        auto_rotate = data.get(
            "auto_rotate_enabled",
            data.get("auto_mode", False),
        )
        log_retention = data.get(
            "log_retention_days",
            data.get("log_retention", 7),
        )

        return cls(
            default_rotation_interval_seconds=int(rot_interval),
            auto_rotate_enabled=bool(auto_rotate),
            connection_timeout_seconds=int(conn_timeout),
            verification_timeout_seconds=int(verif_timeout),
            verification_urls=list(verif_urls),
            max_retries=int(data.get("max_retries", 3)),
            retry_backoff_factor=float(data.get("retry_backoff_factor", 1.5)),
            max_history_size=int(data.get("max_history_size", 1000)),
            check_ipv6=bool(data.get("check_ipv6", False)),
            ipv6_verification_url=str(ipv6_url),
            default_connection_method=data.get("default_connection_method"),
            preferred_profile_id=data.get("preferred_profile_id"),
            kill_switch_enabled=bool(data.get("kill_switch_enabled", False)),
            dns_leak_protection=bool(data.get("dns_leak_protection", True)),
            direct_fallback_allowed=bool(data.get("direct_fallback_allowed", False)),
            trusted_direct_ips=list(data.get("trusted_direct_ips", [])),
            blocked_regions=list(data.get("blocked_regions", [])),
            log_level=str(data.get("log_level", "INFO")),
            log_directory=str(data.get("log_directory", "logs")),
            max_log_size_bytes=int(data.get("max_log_size_bytes", 10 * 1024 * 1024)),
            log_retention_days=int(log_retention),
            log_backup_count=int(data.get("log_backup_count", 5)),
            use_system_keyring=bool(data.get("use_system_keyring", True)),
            theme=str(theme_val),
            start_minimized=bool(data.get("start_minimized", False)),
            minimize_to_tray=bool(data.get("minimize_to_tray", True)),
            show_notifications=bool(data.get("show_notifications", True)),
        )

    def save_to_file(self, file_path: Union[str, Path]) -> None:
        """Atomically persist settings to JSON file.

        Args:
            file_path: Target JSON file path.
        """
        self.validate()
        path = Path(file_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                dir=str(path.parent),
                delete=False,
                encoding="utf-8",
                suffix=".tmp",
            ) as f:
                temp_file = Path(f.name)
                json.dump(self.to_dict(), f, indent=4)
                f.flush()
                os.fsync(f.fileno())

            temp_file.replace(path)
        except Exception:
            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass
            raise

    @classmethod
    def load_from_file(cls, file_path: Union[str, Path]) -> AppSettings:
        """Load settings from JSON file.

        Args:
            file_path: Target JSON file path.

        Returns:
            Loaded AppSettings instance.
        """
        path = Path(file_path).resolve()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
