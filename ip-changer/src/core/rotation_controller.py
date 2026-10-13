"""Rotation controller managing automated and manual IP rotation cycles.

Orchestrates the finite state machine transitions, method selection,
connection switching, address verification, countdown tracking, exponential backoff,
and auditable event logging.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from src.core.connection_manager import ConnectionManager
from src.core.event_bus import (
    EventBus,
    ROTATION_COMPLETED,
    ROTATION_STATE_CHANGED,
)
from src.core.ip_verifier import IPVerifier
from src.core.method_selector import MethodSelector
from src.models.app_settings import AppSettings
from src.models.connection_profile import ConnectionProfile, TrafficScope
from src.models.rotation_event import (
    RotationEvent,
    RotationHistory,
    RotationResult,
    RotationState,
    sanitize_sensitive_text,
)

logger = logging.getLogger(__name__)


class RotationController:
    """Core controller coordinating IP rotation lifecycles and state machines."""

    def __init__(
        self,
        method_selector: MethodSelector,
        connection_manager: ConnectionManager,
        ip_verifier: IPVerifier,
        settings: AppSettings,
        event_bus: EventBus,
    ) -> None:
        """Initialize rotation controller.

        Args:
            method_selector: Engine for profile selection and feasibility checks.
            connection_manager: Adapter coordinator for establishing network tunnels/proxies.
            ip_verifier: Public IP address lookup and verification service.
            settings: Application settings.
            event_bus: System event bus.
        """
        self._selector = method_selector
        self._connection_manager = connection_manager
        self._ip_verifier = ip_verifier
        self._settings = settings
        self._event_bus = event_bus

        self._state: RotationState = RotationState.IDLE
        self._history = RotationHistory(max_history_size=settings.max_history_size)
        self._current_profile: Optional[ConnectionProfile] = None
        self._current_ip: Optional[str] = None
        self._rotation_count: int = 0
        self._consecutive_failures: int = 0

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Loop configuration parameters
        self._loop_interval: int = getattr(
            settings,
            "default_rotation_interval_seconds",
            getattr(settings, "default_rotation_interval", 60),
        )
        self._loop_scope: TrafficScope = TrafficScope.APPLICATION_LEVEL
        self._loop_profiles: List[ConnectionProfile] = []
        self._manual_profile_id: Optional[str] = None
        self._remaining_seconds: float = 0.0

    @property
    def state(self) -> RotationState:
        """Retrieve current rotation finite state machine state."""
        with self._lock:
            return self._state

    @property
    def is_running(self) -> bool:
        """Check whether the automated rotation loop thread is active."""
        with self._lock:
            return (
                self._worker_thread is not None
                and self._worker_thread.is_alive()
                and not self._stop_event.is_set()
            )

    @property
    def current_profile(self) -> Optional[ConnectionProfile]:
        """Get the currently selected or active connection profile."""
        with self._lock:
            return self._current_profile

    @property
    def rotation_count(self) -> int:
        """Get total number of completed rotation cycles in current session."""
        with self._lock:
            return self._rotation_count

    @property
    def history(self) -> RotationHistory:
        """Retrieve the historical rotation event ledger."""
        return self._history

    @property
    def remaining_seconds(self) -> float:
        """Get remaining countdown time before the next scheduled rotation."""
        with self._lock:
            return max(0.0, self._remaining_seconds)

    def _set_state(self, new_state: RotationState) -> None:
        """Transition state machine and notify subscribers via EventBus.

        Args:
            new_state: New finite state machine state.
        """
        with self._lock:
            previous_state = self._state
            self._state = new_state

        if previous_state != new_state:
            logger.info("Rotation state transition: %s -> %s", previous_state.value, new_state.value)
            payload = {
                "previous_state": previous_state,
                "new_state": new_state,
                "profile": self._current_profile,
                "rotation_count": self._rotation_count,
            }
            self._event_bus.emit(ROTATION_STATE_CHANGED, payload)

    def _verify_ip_change(
        self,
        previous_ip: Optional[str],
        proxy_config: Optional[Dict[str, str]],
    ) -> Tuple[bool, Optional[str]]:
        """Verify the public IP address via external verification endpoints.

        Args:
            previous_ip: Baseline IP prior to rotation attempt.
            proxy_config: Active requests proxy configuration.

        Returns:
            Tuple of (changed: bool, observed_ip: Optional[str]).
        """
        result = self._ip_verifier.verify_ip(proxy_config=proxy_config)
        if not result.is_valid or not result.ip_address:
            return False, None

        observed = result.ip_address
        changed = (previous_ip is not None) and (observed != previous_ip)
        return changed, observed

    def _perform_rotation(self) -> RotationEvent:
        """Execute a full rotation cycle with state progression and verification.

        State flow:
        VALIDATING -> CONNECTING -> VERIFYING -> [Check delta] -> IDLE / ROTATING

        Returns:
            RotationEvent recording attempt details and result.
        """
        start_time = time.perf_counter()
        previous_ip = self._current_ip

        # 1. State: VALIDATING
        self._set_state(RotationState.VALIDATING)
        selection = self._selector.select(
            profiles=self._loop_profiles,
            interval=self._loop_interval,
            scope=self._loop_scope,
            manual_override_id=self._manual_profile_id,
        )

        if not selection.selected_profile:
            self._set_state(RotationState.UNSUPPORTED_METHOD)
            duration = time.perf_counter() - start_time
            event = RotationEvent(
                profile_name="None",
                method_type="unknown",
                previous_ip=previous_ip,
                new_ip=None,
                ip_changed=False,
                result=RotationResult.FAILED_SAFETY,
                duration_seconds=duration,
                error_message=selection.reason,
                rotation_number=self._rotation_count + 1,
            )
            self._history.add(event)
            self._event_bus.emit(ROTATION_COMPLETED, event)
            return event

        target_profile = selection.selected_profile
        with self._lock:
            self._current_profile = target_profile

        # 2. State: CONNECTING
        self._set_state(RotationState.CONNECTING)
        conn_result = self._connection_manager.connect(target_profile)
        if not conn_result.success:
            self._set_state(RotationState.CONNECTION_FAILED)
            self._consecutive_failures += 1
            duration = time.perf_counter() - start_time
            event = RotationEvent(
                profile_name=target_profile.name,
                method_type=target_profile.connection_type.value,
                previous_ip=previous_ip,
                new_ip=None,
                ip_changed=False,
                result=RotationResult.FAILED_CONNECTION,
                duration_seconds=duration,
                error_message=conn_result.error_message or "Connection failed",
                rotation_number=self._rotation_count + 1,
            )
            self._history.add(event)
            self._event_bus.emit(ROTATION_COMPLETED, event)
            return event

        # 3. State: VERIFYING
        self._set_state(RotationState.VERIFYING)
        proxy_config = self._connection_manager.get_proxy_config(target_profile)
        changed, observed_ip = self._verify_ip_change(previous_ip, proxy_config)

        duration = time.perf_counter() - start_time

        if not observed_ip:
            self._set_state(RotationState.VERIFICATION_FAILED)
            self._consecutive_failures += 1
            event = RotationEvent(
                profile_name=target_profile.name,
                method_type=target_profile.connection_type.value,
                previous_ip=previous_ip,
                new_ip=None,
                ip_changed=False,
                result=RotationResult.FAILED_VERIFICATION,
                duration_seconds=duration,
                error_message="Public IP verification failed after connecting",
                rotation_number=self._rotation_count + 1,
            )
            self._history.add(event)
            self._event_bus.emit(ROTATION_COMPLETED, event)
            return event

        # Successfully verified
        with self._lock:
            self._current_ip = observed_ip
            self._rotation_count += 1
            self._consecutive_failures = 0

        outcome_result = (
            RotationResult.SUCCESS_IP_CHANGED
            if (changed or previous_ip is None)
            else RotationResult.SUCCESS_IP_UNCHANGED
        )

        event = RotationEvent(
            profile_name=target_profile.name,
            method_type=target_profile.connection_type.value,
            previous_ip=previous_ip,
            new_ip=observed_ip,
            ip_changed=changed,
            result=outcome_result,
            duration_seconds=duration,
            error_message=None,
            rotation_number=self._rotation_count,
        )

        self._history.add(event)
        self._event_bus.emit(ROTATION_COMPLETED, event)

        return event

    def _rotation_loop(self) -> None:
        """Background daemon loop handling timed rotations and countdowns."""
        logger.info("Starting rotation loop with interval=%ds", self._loop_interval)

        while not self._stop_event.is_set():
            # Honor paused state
            if self._pause_event.is_set():
                self._set_state(RotationState.PAUSED)
                while self._pause_event.is_set() and not self._stop_event.is_set():
                    time.sleep(0.2)
                if self._stop_event.is_set():
                    break

            # Execute rotation cycle
            self._perform_rotation()

            # Check if stopped mid-rotation
            if self._stop_event.is_set():
                break

            # Compute wait duration, applying backoff if repeated failures occurred
            base_sleep = float(self._loop_interval)
            if self._consecutive_failures > 0:
                backoff_multiplier = min(
                    self._settings.retry_backoff_factor ** self._consecutive_failures,
                    10.0,
                )
                effective_sleep = base_sleep * backoff_multiplier
                logger.warning(
                    "Failure detected (count=%d). Applying backoff: %.1fs",
                    self._consecutive_failures,
                    effective_sleep,
                )
            else:
                effective_sleep = base_sleep

            with self._lock:
                self._remaining_seconds = effective_sleep
                if self._state not in {
                    RotationState.CONNECTION_FAILED,
                    RotationState.VERIFICATION_FAILED,
                    RotationState.UNSUPPORTED_METHOD,
                    RotationState.SAFETY_BLOCKED,
                }:
                    self._set_state(RotationState.ROTATING)

            # Sleep countdown tick loop
            while self._remaining_seconds > 0 and not self._stop_event.is_set():
                if self._pause_event.is_set():
                    break
                step = min(1.0, self._remaining_seconds)
                time.sleep(step)
                with self._lock:
                    self._remaining_seconds = max(0.0, self._remaining_seconds - step)

        self._set_state(RotationState.IDLE)
        with self._lock:
            self._remaining_seconds = 0.0
        logger.info("Rotation loop terminated cleanly")

    def start(
        self,
        interval: int,
        scope: TrafficScope,
        profiles: List[ConnectionProfile],
        manual_profile_id: Optional[str] = None,
    ) -> None:
        """Start the automated rotation background worker.

        Args:
            interval: Rotation interval in seconds.
            scope: Application or system-wide traffic scope.
            profiles: Available connection profiles.
            manual_profile_id: Optional specific profile constraint.

        Raises:
            RuntimeError: If rotation loop is already active.
        """
        with self._lock:
            if self.is_running:
                logger.warning("Attempted to start rotation controller while already running.")
                return

            self._loop_interval = max(5, interval)
            self._loop_scope = scope
            self._loop_profiles = list(profiles)
            self._manual_profile_id = manual_profile_id
            self._consecutive_failures = 0

            self._stop_event.clear()
            self._pause_event.clear()

            self._worker_thread = threading.Thread(
                target=self._rotation_loop,
                name="RotationControllerWorker",
                daemon=True,
            )
            self._worker_thread.start()

        logger.info("RotationController worker thread launched")

    def stop(self) -> None:
        """Request orderly stop of rotation worker and perform cleanup."""
        with self._lock:
            if not self.is_running:
                return
            self._set_state(RotationState.STOPPING)
            self._stop_event.set()
            self._pause_event.clear()

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=5.0)

        with self._lock:
            self._set_state(RotationState.IDLE)
            self._worker_thread = None

        logger.info("RotationController worker stopped successfully")

    def pause(self) -> None:
        """Pause the automated rotation loop."""
        with self._lock:
            if self.is_running and not self._pause_event.is_set():
                self._pause_event.set()
                self._set_state(RotationState.PAUSED)
                logger.info("RotationController paused")

    def resume(self) -> None:
        """Resume rotation loop from paused state."""
        with self._lock:
            if self._pause_event.is_set():
                self._pause_event.clear()
                self._set_state(RotationState.ROTATING)
                logger.info("RotationController resumed")

    def rotate_once(
        self,
        scope: Optional[TrafficScope] = None,
        profiles: Optional[List[ConnectionProfile]] = None,
        manual_profile_id: Optional[str] = None,
    ) -> RotationEvent:
        """Execute a single immediate rotation cycle synchronously.

        Args:
            scope: Optional traffic scope override.
            profiles: Optional candidate profiles override.
            manual_profile_id: Optional profile ID override.

        Returns:
            RotationEvent representing the cycle outcome.
        """
        with self._lock:
            if profiles is not None:
                self._loop_profiles = list(profiles)
            if scope is not None:
                self._loop_scope = scope
            if manual_profile_id is not None:
                self._manual_profile_id = manual_profile_id

        event = self._perform_rotation()
        if not self.is_running:
            self._set_state(RotationState.IDLE)
        return event
