"""Public IP address verification service for IP Changer.

Provides robust verification of external IPv4 and IPv6 addresses across
configured verification endpoints, supporting optional proxy forwarding,
latency measurement, and cross-verification.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

import requests
from requests.exceptions import RequestException

from src.core.event_bus import EventBus, IP_VERIFIED
from src.models.app_settings import AppSettings
from src.models.rotation_event import sanitize_sensitive_text


logger = logging.getLogger(__name__)


@dataclass
class IPVerificationResult:
    """Outcome of an external IP address verification request."""
    ip_address: Optional[str]
    is_valid: bool
    service_used: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    latency_ms: float = 0.0
    error: Optional[str] = None
    is_ipv6: bool = False

    def __post_init__(self) -> None:
        """Sanitize error messages to eliminate sensitive strings."""
        if self.error:
            self.error = sanitize_sensitive_text(self.error)

    def to_dict(self) -> Dict[str, Any]:
        """Convert verification result to dictionary."""
        return asdict(self)


class IPVerifier:
    """Verifies public IP connectivity and address changes."""

    def __init__(self, settings: AppSettings, event_bus: EventBus) -> None:
        """Initialize the IP verifier.

        Args:
            settings: Application configuration settings.
            event_bus: System event bus for dispatching verification events.
        """
        self._settings = settings
        self._event_bus = event_bus

    @staticmethod
    def _validate_ip_address(ip_str: str) -> bool:
        """Validate if a string is a valid IPv4 or IPv6 address.

        Args:
            ip_str: Candidate IP address string.

        Returns:
            True if string is a valid IPv4/IPv6 address, False otherwise.
        """
        if not ip_str or not isinstance(ip_str, str):
            return False
        clean_ip = ip_str.strip()
        try:
            ipaddress.ip_address(clean_ip)
            return True
        except ValueError:
            return False

    def _fetch_ip(
        self,
        url: str,
        proxies: Optional[Dict[str, str]] = None,
        timeout: int = 10,
    ) -> IPVerificationResult:
        """Execute HTTP GET to an IP echo endpoint.

        Args:
            url: Endpoint URL returning plain text or simple IP string.
            proxies: Optional requests proxy configuration mapping.
            timeout: Network request timeout in seconds.

        Returns:
            IPVerificationResult containing the verified IP or error details.
        """
        start_time = time.perf_counter()
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; IP-Changer/1.0)",
            "Accept": "text/plain",
        }

        # Safe logging: mask credentials in proxies
        safe_proxy_repr = "none"
        if proxies:
            safe_proxy_repr = sanitize_sensitive_text(str(proxies)) or "configured"
        logger.debug("Querying IP service %s (proxies: %s)", url, safe_proxy_repr)

        try:
            response = requests.get(
                url,
                headers=headers,
                proxies=proxies,
                timeout=timeout,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            if response.status_code != 200:
                err_msg = f"HTTP {response.status_code} returned by service"
                logger.warning("Verification failure on %s: %s", url, err_msg)
                return IPVerificationResult(
                    ip_address=None,
                    is_valid=False,
                    service_used=url,
                    latency_ms=round(elapsed_ms, 2),
                    error=err_msg,
                )

            raw_body = response.text.strip()
            # If JSON response was returned with 'ip' key, try extracting it
            candidate_ip = raw_body
            if candidate_ip.startswith("{") and candidate_ip.endswith("}"):
                try:
                    candidate_ip = response.json().get("ip", candidate_ip)
                except Exception:
                    pass

            candidate_ip = candidate_ip.strip()

            if not self._validate_ip_address(candidate_ip):
                err_msg = f"Invalid IP response received: '{candidate_ip[:60]}'"
                logger.warning("Invalid response from %s: %s", url, err_msg)
                return IPVerificationResult(
                    ip_address=None,
                    is_valid=False,
                    service_used=url,
                    latency_ms=round(elapsed_ms, 2),
                    error=err_msg,
                )

            parsed_obj = ipaddress.ip_address(candidate_ip)
            is_ipv6 = parsed_obj.version == 6

            return IPVerificationResult(
                ip_address=candidate_ip,
                is_valid=True,
                service_used=url,
                latency_ms=round(elapsed_ms, 2),
                error=None,
                is_ipv6=is_ipv6,
            )

        except RequestException as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            sanitized_err = sanitize_sensitive_text(str(exc)) or "Connection error"
            logger.warning("Failed request to %s: %s", url, sanitized_err)
            return IPVerificationResult(
                ip_address=None,
                is_valid=False,
                service_used=url,
                latency_ms=round(elapsed_ms, 2),
                error=sanitized_err,
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            sanitized_err = sanitize_sensitive_text(str(exc)) or "Unexpected error"
            logger.exception("Unexpected exception verifying IP against %s: %s", url, sanitized_err)
            return IPVerificationResult(
                ip_address=None,
                is_valid=False,
                service_used=url,
                latency_ms=round(elapsed_ms, 2),
                error=sanitized_err,
            )

    def _get_connection_timeout(self) -> int:
        """Get configured connection timeout in seconds."""
        return getattr(
            self._settings,
            "connection_timeout_seconds",
            getattr(self._settings, "connection_timeout", 15),
        )

    def _get_verification_urls(self) -> list[str]:
        """Get configured verification URLs."""
        urls = getattr(
            self._settings,
            "verification_urls",
            getattr(self._settings, "verification_services", None),
        )
        return urls or ["https://api.ipify.org"]

    def _get_ipv6_url(self) -> str:
        """Get configured IPv6 verification URL."""
        return getattr(
            self._settings,
            "ipv6_verification_url",
            getattr(self._settings, "ipv6_verification_service", "https://api6.ipify.org"),
        )

    def verify_ip(
        self,
        proxy_config: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> IPVerificationResult:
        """Fetch the public IPv4 address using configured verification services.

        Attempts configured endpoints sequentially until a valid response is obtained.

        Args:
            proxy_config: Optional requests proxy configuration mapping.
            timeout: Optional override for request timeout in seconds.

        Returns:
            IPVerificationResult representing the outcome.
        """
        req_timeout = timeout if timeout is not None else self._get_connection_timeout()
        services = self._get_verification_urls()

        last_result: Optional[IPVerificationResult] = None
        for service_url in services:
            result = self._fetch_ip(service_url, proxies=proxy_config, timeout=req_timeout)
            if result.is_valid:
                self._event_bus.emit(IP_VERIFIED, result)
                return result
            last_result = result

        # All services failed
        final_result = last_result or IPVerificationResult(
            ip_address=None,
            is_valid=False,
            service_used="none",
            error="No verification services configured",
        )
        self._event_bus.emit(IP_VERIFIED, final_result)
        return final_result

    def verify_ipv6(
        self,
        proxy_config: Optional[Dict[str, str]] = None,
    ) -> IPVerificationResult:
        """Fetch the public IPv6 address using the configured IPv6 service.

        Args:
            proxy_config: Optional requests proxy configuration mapping.

        Returns:
            IPVerificationResult for the IPv6 endpoint.
        """
        url = self._get_ipv6_url()
        timeout = self._get_connection_timeout()
        result = self._fetch_ip(url, proxies=proxy_config, timeout=timeout)
        self._event_bus.emit(IP_VERIFIED, result)
        return result

    def cross_verify(
        self,
        proxy_config: Optional[Dict[str, str]] = None,
    ) -> Tuple[IPVerificationResult, Optional[IPVerificationResult]]:
        """Verify the public IP using two distinct services to prevent spoofing/caching.

        Args:
            proxy_config: Optional requests proxy configuration mapping.

        Returns:
            A tuple of (primary_result, secondary_result). Secondary may be None
            if only one service is configured.
        """
        services = self._get_verification_urls()
        timeout = self._get_connection_timeout()

        primary_url = services[0]
        primary_result = self._fetch_ip(primary_url, proxies=proxy_config, timeout=timeout)

        secondary_result: Optional[IPVerificationResult] = None
        if len(services) > 1:
            secondary_url = services[1]
            secondary_result = self._fetch_ip(secondary_url, proxies=proxy_config, timeout=timeout)

        # Emit the most authoritative valid result
        effective_result = primary_result if primary_result.is_valid else (secondary_result or primary_result)
        self._event_bus.emit(IP_VERIFIED, effective_result)

        return primary_result, secondary_result
