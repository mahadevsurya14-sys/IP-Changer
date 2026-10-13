"""Unit tests for IPVerifier in IP Changer.

Tests public IPv4 and IPv6 lookup, response validation, timeout handling,
DNS/HTTP errors, cross-verification, and proxy credential masking.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from src.core.event_bus import EventBus
from src.core.ip_verifier import IPVerificationResult, IPVerifier
from src.models.app_settings import AppSettings


@pytest.fixture
def ip_verifier_setup() -> tuple[IPVerifier, AppSettings, EventBus]:
    """Fixture providing IPVerifier instance and its dependencies."""
    settings = AppSettings(
        connection_timeout_seconds=5,
        verification_urls=["https://api.ipify.org", "https://ifconfig.me/ip"],
        ipv6_verification_url="https://api6.ipify.org",
    )
    event_bus = EventBus()
    verifier = IPVerifier(settings, event_bus)
    return verifier, settings, event_bus


def test_valid_ipv4_verification(ip_verifier_setup: tuple[IPVerifier, AppSettings, EventBus]) -> None:
    """Test successful verification of a valid IPv4 address."""
    verifier, _, _ = ip_verifier_setup

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "203.0.113.195\n"
        mock_get.return_value = mock_response

        result = verifier.verify_ip()

        assert result.is_valid is True
        assert result.ip_address == "203.0.113.195"
        assert result.is_ipv6 is False
        assert result.error is None
        mock_get.assert_called_once()


def test_valid_ipv6_verification(ip_verifier_setup: tuple[IPVerifier, AppSettings, EventBus]) -> None:
    """Test successful verification of a valid IPv6 address."""
    verifier, _, _ = ip_verifier_setup

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        mock_get.return_value = mock_response

        result = verifier.verify_ipv6()

        assert result.is_valid is True
        assert result.ip_address == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        assert result.is_ipv6 is True
        assert result.error is None


def test_invalid_ip_response(ip_verifier_setup: tuple[IPVerifier, AppSettings, EventBus]) -> None:
    """Test handling when verification endpoint returns invalid IP data (e.g. HTML error page)."""
    verifier, _, _ = ip_verifier_setup

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>502 Bad Gateway</body></html>"
        mock_get.return_value = mock_response

        result = verifier.verify_ip()

        assert result.is_valid is False
        assert result.ip_address is None
        assert result.error is not None
        assert "Invalid IP response" in result.error


def test_timeout_handling(ip_verifier_setup: tuple[IPVerifier, AppSettings, EventBus]) -> None:
    """Test handling of request timeout during verification."""
    verifier, _, _ = ip_verifier_setup

    with patch("requests.get", side_effect=requests.exceptions.ConnectTimeout("Connection timed out")):
        result = verifier.verify_ip()

        assert result.is_valid is False
        assert result.ip_address is None
        assert result.error is not None
        assert "timed out" in result.error.lower() or "connection" in result.error.lower()


def test_dns_failure(ip_verifier_setup: tuple[IPVerifier, AppSettings, EventBus]) -> None:
    """Test handling of DNS resolution failure."""
    verifier, _, _ = ip_verifier_setup

    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Failed to resolve host")):
        result = verifier.verify_ip()

        assert result.is_valid is False
        assert result.ip_address is None
        assert result.error is not None


def test_http_error(ip_verifier_setup: tuple[IPVerifier, AppSettings, EventBus]) -> None:
    """Test handling when service returns non-200 HTTP status code."""
    verifier, _, _ = ip_verifier_setup

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        result = verifier.verify_ip()

        assert result.is_valid is False
        assert result.ip_address is None
        assert result.error is not None
        assert "HTTP 500" in result.error


def test_cross_verification(ip_verifier_setup: tuple[IPVerifier, AppSettings, EventBus]) -> None:
    """Test cross verification querying primary and secondary endpoints."""
    verifier, _, _ = ip_verifier_setup

    with patch("requests.get") as mock_get:
        resp1 = MagicMock()
        resp1.status_code = 200
        resp1.text = "198.51.100.1"

        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.text = "198.51.100.1"

        mock_get.side_effect = [resp1, resp2]

        res_primary, res_secondary = verifier.cross_verify()

        assert res_primary.is_valid is True
        assert res_primary.ip_address == "198.51.100.1"
        assert res_secondary is not None
        assert res_secondary.is_valid is True
        assert res_secondary.ip_address == "198.51.100.1"
        assert mock_get.call_count == 2


def test_proxy_config_passed(ip_verifier_setup: tuple[IPVerifier, AppSettings, EventBus]) -> None:
    """Test that proxy dictionary configuration is passed down to requests.get."""
    verifier, _, _ = ip_verifier_setup

    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "192.0.2.1"
        mock_get.return_value = mock_response

        result = verifier.verify_ip(proxy_config=proxies)

        assert result.is_valid is True
        assert result.ip_address == "192.0.2.1"
        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        assert kwargs["proxies"] == proxies


def test_credentials_not_logged(ip_verifier_setup: tuple[IPVerifier, AppSettings, EventBus]) -> None:
    """Test that proxy credentials embedded in URLs are sanitized from logs and error results."""
    verifier, _, _ = ip_verifier_setup

    sensitive_proxy = {"http": "http://admin:secret123@proxy.example.com:8080"}

    with patch("requests.get", side_effect=requests.exceptions.RequestException("Auth failed: http://admin:secret123@proxy.example.com:8080")):
        result = verifier.verify_ip(proxy_config=sensitive_proxy)

        assert result.is_valid is False
        assert "secret123" not in (result.error or "")
        assert "[REDACTED]" in (result.error or "")
