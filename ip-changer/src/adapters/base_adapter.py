"""Abstract base class for network adapters in IP Changer.

Defines the lifecycle and operational interface for proxy and VPN adapters.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from src.models.connection_profile import ConnectionProfile, ConnectionStatus, ConnectionTestResult


class BaseAdapter(ABC):
    """Abstract base adapter defining standard network operations."""

    @abstractmethod
    def connect(self, profile: ConnectionProfile) -> ConnectionTestResult:
        """Establish or activate connection to the profile endpoint.

        Args:
            profile: Target connection profile.

        Returns:
            ConnectionTestResult indicating success, latency, and observed public IP.
        """
        raise NotImplementedError

    @abstractmethod
    def disconnect(self, profile: ConnectionProfile) -> bool:
        """Tear down or disconnect from the profile endpoint.

        Args:
            profile: Target connection profile to disconnect.

        Returns:
            True if successfully disconnected or already inactive, False otherwise.
        """
        raise NotImplementedError

    @abstractmethod
    def test(self, profile: ConnectionProfile) -> ConnectionTestResult:
        """Probe connectivity and measure latency to the endpoint without state change.

        Args:
            profile: Target connection profile.

        Returns:
            ConnectionTestResult containing probe outcome.
        """
        raise NotImplementedError

    @abstractmethod
    def get_status(self, profile: ConnectionProfile) -> ConnectionStatus:
        """Retrieve current connection status for the given profile.

        Args:
            profile: Target connection profile.

        Returns:
            ConnectionStatus enum value.
        """
        raise NotImplementedError

    @abstractmethod
    def get_proxy_config(self, profile: ConnectionProfile) -> Optional[Dict[str, str]]:
        """Generate requests-compatible proxy dictionary configuration.

        Args:
            profile: Target connection profile.

        Returns:
            Dictionary with 'http' and 'https' proxy URLs, or None if not applicable.
        """
        raise NotImplementedError
