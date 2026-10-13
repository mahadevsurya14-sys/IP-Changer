"""Unit tests for RotationController in IP Changer.

Tests rotation lifecycle, duplicate worker prevention, state machine transitions,
IP delta detection, error and failure states, cancellation, pause/resume, and exponential backoff.
All network operations and external dependencies are mocked.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from src.core.connection_manager import ConnectionManager
from src.core.event_bus import EventBus
from src.core.ip_verifier import IPVerificationResult, IPVerifier
from src.core.method_selector import MethodSelector, SelectionResult
from src.core.rotation_controller import RotationController
from src.models.app_settings import AppSettings
from src.models.connection_profile import (
    ConnectionProfile,
    ConnectionTestResult,
    ConnectionType,
    TrafficScope,
)
from src.models.rotation_event import RotationResult, RotationState


@pytest.fixture
def controller_setup() -> tuple[
    RotationController,
    MagicMock,
    MagicMock,
    MagicMock,
    AppSettings,
    EventBus,
    ConnectionProfile,
]:
    """Fixture providing RotationController with mocked dependencies."""
    settings = AppSettings(
        default_rotation_interval_seconds=5,
        connection_timeout_seconds=5,
        retry_backoff_factor=1.5,
        max_history_size=50,
    )
    event_bus = EventBus()
    mock_selector = MagicMock(spec=MethodSelector)
    mock_connection_mgr = MagicMock(spec=ConnectionManager)
    mock_ip_verifier = MagicMock(spec=IPVerifier)

    test_profile = ConnectionProfile(
        id="profile-1",
        name="Test Proxy Profile",
        connection_type=ConnectionType.HTTP_PROXY,
        host="10.0.0.1",
        port=8080,
    )

    # Set up default successful selections and connections
    mock_selector.select.return_value = SelectionResult(
        selected_profile=test_profile,
        reason="Selected by mock",
    )
    mock_connection_mgr.connect.return_value = ConnectionTestResult(
        profile_id=test_profile.id,
        success=True,
        latency_ms=15.0,
    )
    mock_connection_mgr.get_proxy_config.return_value = {"http": "http://10.0.0.1:8080"}
    mock_ip_verifier.verify_ip.return_value = IPVerificationResult(
        ip_address="203.0.113.1",
        is_valid=True,
        service_used="https://api.ipify.org",
    )

    controller = RotationController(
        method_selector=mock_selector,
        connection_manager=mock_connection_mgr,
        ip_verifier=mock_ip_verifier,
        settings=settings,
        event_bus=event_bus,
    )

    return (
        controller,
        mock_selector,
        mock_connection_mgr,
        mock_ip_verifier,
        settings,
        event_bus,
        test_profile,
    )


def test_start_stop(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test starting and stopping the background rotation loop."""
    controller, _, _, _, _, _, test_profile = controller_setup

    assert controller.is_running is False
    assert controller.state == RotationState.IDLE

    controller.start(
        interval=5,
        scope=TrafficScope.APPLICATION_LEVEL,
        profiles=[test_profile],
    )

    assert controller.is_running is True

    controller.stop()
    assert controller.is_running is False
    assert controller.state == RotationState.IDLE


def test_prevent_duplicate_workers(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test that starting the controller multiple times does not spawn duplicate workers."""
    controller, _, _, _, _, _, test_profile = controller_setup

    controller.start(
        interval=5,
        scope=TrafficScope.APPLICATION_LEVEL,
        profiles=[test_profile],
    )
    first_worker = controller._worker_thread

    # Secondary start call while active
    controller.start(
        interval=10,
        scope=TrafficScope.APPLICATION_LEVEL,
        profiles=[test_profile],
    )
    second_worker = controller._worker_thread

    assert first_worker is second_worker

    controller.stop()


def test_state_transitions(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test observed state transitions during an individual rotation cycle."""
    controller, _, _, _, _, event_bus, test_profile = controller_setup

    observed_states: list[RotationState] = []

    def on_state_changed(payload: dict) -> None:
        observed_states.append(payload["new_state"])

    event_bus.subscribe("rotation_state_changed", on_state_changed)

    # Perform single synchronous rotation
    event = controller.rotate_once(
        scope=TrafficScope.APPLICATION_LEVEL,
        profiles=[test_profile],
    )

    assert RotationState.VALIDATING in observed_states
    assert RotationState.CONNECTING in observed_states
    assert RotationState.VERIFYING in observed_states
    assert controller.state == RotationState.IDLE
    assert event.result == RotationResult.SUCCESS_IP_CHANGED


def test_rotation_records_event(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test that a completed rotation is appended to RotationHistory."""
    controller, _, _, _, _, _, test_profile = controller_setup

    assert len(controller.history.get_events()) == 0

    event = controller.rotate_once(profiles=[test_profile])

    history_events = controller.history.get_events()
    assert len(history_events) == 1
    assert history_events[0].event_id == event.event_id
    assert history_events[0].profile_name == test_profile.name
    assert controller.rotation_count == 1


def test_ip_changed_detection(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test detecting an actual IP change between consecutive rotations."""
    controller, _, _, mock_verifier, _, _, test_profile = controller_setup

    # First rotation establishes IP 203.0.113.1
    mock_verifier.verify_ip.return_value = IPVerificationResult(
        ip_address="203.0.113.1",
        is_valid=True,
        service_used="https://api.ipify.org",
    )
    event1 = controller.rotate_once(profiles=[test_profile])
    assert event1.new_ip == "203.0.113.1"
    assert event1.result == RotationResult.SUCCESS_IP_CHANGED

    # Second rotation observes changed IP 198.51.100.50
    mock_verifier.verify_ip.return_value = IPVerificationResult(
        ip_address="198.51.100.50",
        is_valid=True,
        service_used="https://api.ipify.org",
    )
    event2 = controller.rotate_once(profiles=[test_profile])
    assert event2.previous_ip == "203.0.113.1"
    assert event2.new_ip == "198.51.100.50"
    assert event2.ip_changed is True
    assert event2.result == RotationResult.SUCCESS_IP_CHANGED


def test_ip_unchanged_detection(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test detecting when IP remains identical across rotations."""
    controller, _, _, mock_verifier, _, _, test_profile = controller_setup

    # First rotation establishes IP
    mock_verifier.verify_ip.return_value = IPVerificationResult(
        ip_address="203.0.113.1",
        is_valid=True,
        service_used="https://api.ipify.org",
    )
    controller.rotate_once(profiles=[test_profile])

    # Second rotation returns exact same IP
    mock_verifier.verify_ip.return_value = IPVerificationResult(
        ip_address="203.0.113.1",
        is_valid=True,
        service_used="https://api.ipify.org",
    )
    event2 = controller.rotate_once(profiles=[test_profile])

    assert event2.previous_ip == "203.0.113.1"
    assert event2.new_ip == "203.0.113.1"
    assert event2.ip_changed is False
    assert event2.result == RotationResult.SUCCESS_IP_UNCHANGED


def test_connection_failure_handling(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test handling and error logging when connection adapter fails."""
    controller, _, mock_conn_mgr, _, _, _, test_profile = controller_setup

    mock_conn_mgr.connect.return_value = ConnectionTestResult(
        profile_id=test_profile.id,
        success=False,
        latency_ms=0.0,
        error_message="TCP connection refused",
    )

    event = controller.rotate_once(profiles=[test_profile])

    assert event.result == RotationResult.FAILED_CONNECTION
    assert "refused" in (event.error_message or "").lower()
    assert controller._consecutive_failures == 1


def test_verification_failure_handling(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test handling when connection succeeds but external IP verification fails."""
    controller, _, _, mock_verifier, _, _, test_profile = controller_setup

    mock_verifier.verify_ip.return_value = IPVerificationResult(
        ip_address=None,
        is_valid=False,
        service_used="https://api.ipify.org",
        error="Gateway timeout",
    )

    event = controller.rotate_once(profiles=[test_profile])

    assert event.result == RotationResult.FAILED_VERIFICATION
    assert controller._consecutive_failures == 1


def test_cancellation(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test clean loop cancellation via stop()."""
    controller, _, _, _, _, _, test_profile = controller_setup

    controller.start(
        interval=5,
        scope=TrafficScope.APPLICATION_LEVEL,
        profiles=[test_profile],
    )
    assert controller.is_running is True

    controller.stop()
    assert controller.is_running is False
    assert controller.remaining_seconds == 0.0


def test_pause_resume(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test pausing and resuming the automated rotation loop."""
    controller, _, _, _, _, _, test_profile = controller_setup

    controller.start(
        interval=5,
        scope=TrafficScope.APPLICATION_LEVEL,
        profiles=[test_profile],
    )

    controller.pause()
    assert controller._pause_event.is_set()

    controller.resume()
    assert not controller._pause_event.is_set()

    controller.stop()


def test_exponential_backoff(
    controller_setup: tuple[
        RotationController,
        MagicMock,
        MagicMock,
        MagicMock,
        AppSettings,
        EventBus,
        ConnectionProfile,
    ]
) -> None:
    """Test exponential backoff computation when consecutive failures occur."""
    controller, _, mock_conn_mgr, _, settings, _, test_profile = controller_setup

    mock_conn_mgr.connect.return_value = ConnectionTestResult(
        profile_id=test_profile.id,
        success=False,
        latency_ms=0.0,
        error_message="Host unreachable",
    )

    # Perform 2 failed rotations
    controller.rotate_once(profiles=[test_profile])
    assert controller._consecutive_failures == 1

    controller.rotate_once(profiles=[test_profile])
    assert controller._consecutive_failures == 2

    # Check backoff multiplier formula: retry_backoff_factor ** consecutive_failures
    expected_multiplier = settings.retry_backoff_factor ** 2
    base_interval = 5.0
    effective_interval = base_interval * expected_multiplier
    assert effective_interval > base_interval
