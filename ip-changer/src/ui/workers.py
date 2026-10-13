"""QThread-based workers for non-blocking asynchronous operations.

Provides thread-safe signal/slot bridges between background engine services
and the PySide6 UI thread, ensuring responsiveness and leak prevention.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from PySide6.QtCore import QObject, QThread, Signal

from src.core.connection_manager import ConnectionManager
from src.core.event_bus import (
    CONNECTION_STATUS_CHANGED,
    EventBus,
    IP_VERIFIED,
    ROTATION_COMPLETED,
    ROTATION_STATE_CHANGED,
)
from src.core.ip_verifier import IPVerificationResult, IPVerifier
from src.core.rotation_controller import RotationController
from src.models.connection_profile import ConnectionProfile, ConnectionTestResult, TrafficScope
from src.models.rotation_event import RotationEvent, RotationState
from src.services.diagnostics_service import DiagnosticCheck, DiagnosticsService

logger = logging.getLogger(__name__)


class RotationMonitorWorker(QThread):
    """Monitors the active rotation controller and dispatches UI updates.

    Tracks countdown ticks, state transitions, and completed rotation events.
    """

    state_changed = Signal(str)            # RotationState value
    countdown_updated = Signal(int)        # Seconds remaining
    rotation_completed = Signal(object)    # RotationEvent
    status_message = Signal(str)
    error_occurred = Signal(str)

    def __init__(
        self,
        rotation_controller: RotationController,
        event_bus: EventBus,
        parent: Optional[QObject] = None,
    ) -> None:
        """Initialize monitor worker.

        Args:
            rotation_controller: The core RotationController instance.
            event_bus: System event bus.
            parent: Parent QObject.
        """
        super().__init__(parent)
        self._controller = rotation_controller
        self._event_bus = event_bus
        self._is_running = True

        # Wire up event bus listeners
        self._event_bus.subscribe(ROTATION_STATE_CHANGED, self._on_state_changed_event)
        self._event_bus.subscribe(ROTATION_COMPLETED, self._on_rotation_completed_event)

    def _on_state_changed_event(self, payload: Any) -> None:
        """Handle state changed event from background thread."""
        if isinstance(payload, dict):
            new_state = payload.get("new_state")
            state_val = new_state.value if isinstance(new_state, RotationState) else str(new_state)
            self.state_changed.emit(state_val)
        elif isinstance(payload, RotationState):
            self.state_changed.emit(payload.value)

    def _on_rotation_completed_event(self, event: Any) -> None:
        """Handle rotation completed event."""
        if isinstance(event, RotationEvent):
            self.rotation_completed.emit(event)
            if event.error_message:
                self.error_occurred.emit(event.error_message)

    def run(self) -> None:
        """Periodic polling loop for countdown timer."""
        last_countdown = -1
        last_state_val = ""

        while self._is_running and not self.isInterruptionRequested():
            try:
                # Sync state if needed
                cur_state = self._controller.state
                cur_state_val = cur_state.value if isinstance(cur_state, RotationState) else str(cur_state)
                if cur_state_val != last_state_val:
                    last_state_val = cur_state_val
                    self.state_changed.emit(cur_state_val)

                # Sync countdown seconds
                if self._controller.is_running:
                    rem = int(self._controller.remaining_seconds)
                    if rem != last_countdown:
                        last_countdown = rem
                        self.countdown_updated.emit(rem)
                else:
                    if last_countdown != 0:
                        last_countdown = 0
                        self.countdown_updated.emit(0)

                time.sleep(0.5)
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("Error in rotation monitor worker: %s", exc)
                time.sleep(1.0)

    def stop(self) -> None:
        """Stop monitor worker thread cleanly."""
        self._is_running = False
        self.requestInterruption()
        try:
            self._event_bus.unsubscribe(ROTATION_STATE_CHANGED, self._on_state_changed_event)
            self._event_bus.unsubscribe(ROTATION_COMPLETED, self._on_rotation_completed_event)
        except Exception:
            pass
        self.wait(1500)


class SingleRotateWorker(QThread):
    """Executes a single immediate rotation cycle in background."""

    finished_event = Signal(object)  # RotationEvent
    error_occurred = Signal(str)

    def __init__(
        self,
        rotation_controller: RotationController,
        scope: Optional[TrafficScope] = None,
        profiles: Optional[List[ConnectionProfile]] = None,
        manual_profile_id: Optional[str] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._controller = rotation_controller
        self._scope = scope
        self._profiles = profiles
        self._manual_profile_id = manual_profile_id

    def run(self) -> None:
        """Perform single rotation cycle."""
        try:
            event = self._controller.rotate_once(
                scope=self._scope,
                profiles=self._profiles,
                manual_profile_id=self._manual_profile_id,
            )
            self.finished_event.emit(event)
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Manual rotation failed: %s", exc)
            self.error_occurred.emit(str(exc))


class IPVerifyWorker(QThread):
    """Fetches public IPv4 and IPv6 addresses asynchronously."""

    # Parameters: ipv4 (str), ipv6 (str), success (bool), error_message (str)
    verification_finished = Signal(str, str, bool, str)
    error_occurred = Signal(str)

    def __init__(
        self,
        ip_verifier: IPVerifier,
        check_ipv6: bool = False,
        proxy_config: Optional[Dict[str, str]] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._ip_verifier = ip_verifier
        self._check_ipv6 = check_ipv6
        self._proxy_config = proxy_config

    def run(self) -> None:
        """Execute IP verification."""
        try:
            ipv4_res: IPVerificationResult = self._ip_verifier.verify_ip(proxy_config=self._proxy_config)
            ipv4_str = ipv4_res.ip_address or ""

            ipv6_str = ""
            if self._check_ipv6 and not self.isInterruptionRequested():
                try:
                    ipv6_res = self._ip_verifier.verify_ipv6(proxy_config=self._proxy_config)
                    if ipv6_res.is_valid and ipv6_res.ip_address:
                        ipv6_str = ipv6_res.ip_address
                except Exception as exc:
                    logger.debug("IPv6 verification skipped or failed: %s", exc)

            success = bool(ipv4_res.is_valid and ipv4_str)
            err = ipv4_res.error or ("Verification failed" if not success else "")
            self.verification_finished.emit(ipv4_str, ipv6_str, success, err)
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("IP verification worker failed: %s", exc)
            self.error_occurred.emit(str(exc))
            self.verification_finished.emit("", "", False, str(exc))


class ConnectionTestWorker(QThread):
    """Probes connectivity and latency of a connection profile."""

    test_finished = Signal(object)  # ConnectionTestResult
    error_occurred = Signal(str)

    def __init__(
        self,
        connection_manager: ConnectionManager,
        profile: ConnectionProfile,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._manager = connection_manager
        self._profile = profile

    def run(self) -> None:
        """Run connection probe."""
        try:
            result: ConnectionTestResult = self._manager.test_connection(self._profile)
            self.test_finished.emit(result)
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Connection test failed: %s", exc)
            self.error_occurred.emit(str(exc))
            err_res = ConnectionTestResult(
                profile_id=self._profile.id,
                success=False,
                latency_ms=0.0,
                error_message=str(exc),
            )
            self.test_finished.emit(err_res)


class DiagnosticsWorker(QThread):
    """Runs network and system diagnostics asynchronously with progress reporting."""

    check_progress = Signal(int, int, str)  # current, total, check_name
    check_result = Signal(object)           # DiagnosticCheck
    diagnostics_finished = Signal(list)     # List[DiagnosticCheck]
    error_occurred = Signal(str)

    def __init__(
        self,
        diagnostics_service: DiagnosticsService,
        check_name: Optional[str] = None,
        parent: Optional[QObject] = None,
    ) -> None:
        super().__init__(parent)
        self._service = diagnostics_service
        self._check_name = check_name

    def run(self) -> None:
        """Execute diagnostic checks."""
        try:
            if self._check_name:
                # Single check execution
                self.check_progress.emit(1, 1, self._check_name)
                result = self._service.run_single_check(self._check_name)
                self.check_result.emit(result)
                self.diagnostics_finished.emit([result])
            else:
                # Full test battery
                checks = self._service.get_available_checks()
                total = len(checks)
                results: List[DiagnosticCheck] = []

                for idx, name in enumerate(checks, start=1):
                    if self.isInterruptionRequested():
                        break
                    self.check_progress.emit(idx, total, name)
                    check_res = self._service.run_single_check(name)
                    results.append(check_res)
                    self.check_result.emit(check_res)

                self.diagnostics_finished.emit(results)
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Diagnostics worker failed: %s", exc)
            self.error_occurred.emit(str(exc))
            self.diagnostics_finished.emit([])
