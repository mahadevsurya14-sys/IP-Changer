"""Main Dashboard Widget for IP Changer.

Designed to be the primary 'hero' screen: clean, immediately comprehensible,
and offering one-click control over automated and manual IP rotation.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)

from src.core.event_bus import (
    CONNECTION_STATUS_CHANGED,
    EventBus,
    IP_VERIFIED,
    PROFILE_ADDED,
    PROFILE_REMOVED,
    PROFILE_UPDATED,
    ROTATION_COMPLETED,
    ROTATION_STATE_CHANGED,
    SETTINGS_CHANGED,
)
from src.core.ip_verifier import IPVerificationResult, IPVerifier
from src.core.rotation_controller import RotationController
from src.models.app_settings import AppSettings
from src.models.connection_profile import ConnectionProfile, ConnectionStatus, TrafficScope
from src.models.rotation_event import RotationEvent, RotationResult, RotationState
from src.services.configuration_service import ConfigurationService
from src.ui.styles import (
    COLOR_DANGER,
    COLOR_MUTED,
    COLOR_SUCCESS,
    COLOR_WARNING,
    get_status_color,
)
from src.ui.workers import IPVerifyWorker, RotationMonitorWorker, SingleRotateWorker

logger = logging.getLogger(__name__)


class DashboardWidget(QWidget):
    """The central hero view of IP Changer."""

    navigate_to_connections = Signal()

    def __init__(
        self,
        rotation_controller: RotationController,
        configuration_service: ConfigurationService,
        ip_verifier: IPVerifier,
        event_bus: EventBus,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._controller = rotation_controller
        self._config_service = configuration_service
        self._ip_verifier = ip_verifier
        self._event_bus = event_bus

        self._active_profile: Optional[ConnectionProfile] = None
        self._current_ipv4: str = "Checking..."
        self._current_ipv6: str = "—"
        self._previous_ip: str = "—"
        self._last_change_time: str = "None yet"
        self._countdown_sec: int = 0
        self._is_paused: bool = False

        self._monitor_worker: Optional[RotationMonitorWorker] = None
        self._verify_worker: Optional[IPVerifyWorker] = None
        self._single_worker: Optional[SingleRotateWorker] = None

        self._init_ui()
        self._setup_monitor_worker()
        self._connect_event_bus()

        # Initial probe of current IP
        QTimer.singleShot(200, self.refresh_ip)

    def _init_ui(self) -> None:
        """Construct dashboard layouts and widgets."""
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)

        container = QWidget()
        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(18)

        # Header Section
        header_layout = QHBoxLayout()
        title_label = QLabel("IP Changer")
        title_font = QFont()
        title_font.setPointSize(20)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #00d4ff; font-weight: bold;")

        author_label = QLabel("by Mahaduuu")
        author_label.setStyleSheet("color: #94a3b8; font-size: 13px; font-style: italic; margin-top: 6px;")

        header_layout.addWidget(title_label)
        header_layout.addWidget(author_label)
        header_layout.addStretch()

        # Quick refresh IP button
        self._btn_refresh_ip = QPushButton("Check IP Now")
        self._btn_refresh_ip.setToolTip("Query external echo service for public IP")
        self._btn_refresh_ip.clicked.connect(self.refresh_ip)
        header_layout.addWidget(self._btn_refresh_ip)

        main_layout.addLayout(header_layout)

        # Empty State Warning Banner (Hidden by default, shown if no profiles)
        self._banner_empty = QFrame()
        self._banner_empty.setStyleSheet(
            "background-color: #2e1065; border: 1px solid #7c3aed; border-radius: 8px; padding: 10px;"
        )
        banner_layout = QHBoxLayout(self._banner_empty)
        banner_layout.setContentsMargins(12, 8, 12, 8)
        self._lbl_empty_msg = QLabel(
            "💡 No proxy or VPN connections configured yet. "
            "You can add your endpoints in the Connections tab to start rotating."
        )
        self._lbl_empty_msg.setStyleSheet("color: #e9d5ff; font-size: 13px;")
        btn_go_connections = QPushButton("Go to Connections")
        btn_go_connections.setProperty("buttonRole", "primary")
        btn_go_connections.clicked.connect(self.navigate_to_connections.emit)
        banner_layout.addWidget(self._lbl_empty_msg)
        banner_layout.addStretch()
        banner_layout.addWidget(btn_go_connections)
        self._banner_empty.setVisible(False)
        main_layout.addWidget(self._banner_empty)

        # Hero IP & Status Card
        card_hero = QGroupBox("Current Network Status")
        hero_layout = QGridLayout(card_hero)
        hero_layout.setContentsMargins(18, 22, 18, 18)
        hero_layout.setSpacing(14)

        # Prominent IP Display
        lbl_ip_title = QLabel("Your Public IP:")
        lbl_ip_title.setStyleSheet("color: #94a3b8; font-size: 14px; font-weight: 600;")
        self._lbl_hero_ip = QLabel("...")
        hero_ip_font = QFont()
        hero_ip_font.setPointSize(26)
        hero_ip_font.setBold(True)
        self._lbl_hero_ip.setFont(hero_ip_font)
        self._lbl_hero_ip.setStyleSheet("color: #22c55e; font-weight: bold; padding: 4px 0;")

        # Status badge
        self._lbl_status_badge = QLabel("IDLE")
        self._lbl_status_badge.setAlignment(Qt.AlignCenter)
        self._lbl_status_badge.setStyleSheet(
            "background-color: #334155; color: #ffffff; font-weight: bold; "
            "padding: 6px 16px; border-radius: 12px; font-size: 12px;"
        )
        self._lbl_status_badge.setFixedWidth(130)

        hero_layout.addWidget(lbl_ip_title, 0, 0)
        hero_layout.addWidget(self._lbl_hero_ip, 1, 0, 1, 2)
        hero_layout.addWidget(self._lbl_status_badge, 1, 2, Qt.AlignRight)

        # Detailed Status Meta Grid
        meta_grid = QGridLayout()
        meta_grid.setContentsMargins(0, 10, 0, 0)
        meta_grid.setSpacing(8)

        lbl_prev_title = QLabel("Previous IP:")
        lbl_prev_title.setStyleSheet("color: #94a3b8; font-weight: 500;")
        self._lbl_prev_ip = QLabel("—")
        self._lbl_prev_ip.setStyleSheet("color: #f1f5f9; font-weight: 600;")

        lbl_method_title = QLabel("Connection Method:")
        lbl_method_title.setStyleSheet("color: #94a3b8; font-weight: 500;")
        self._lbl_method = QLabel("Direct Connection")
        self._lbl_method.setStyleSheet("color: #f1f5f9; font-weight: 600;")

        lbl_provider_title = QLabel("Provider / Endpoint:")
        lbl_provider_title.setStyleSheet("color: #94a3b8; font-weight: 500;")
        self._lbl_provider = QLabel("Local System Gateway")
        self._lbl_provider.setStyleSheet("color: #f1f5f9; font-weight: 600;")

        lbl_ipv6_title = QLabel("IPv6 Address:")
        lbl_ipv6_title.setStyleSheet("color: #94a3b8; font-weight: 500;")
        self._lbl_ipv6 = QLabel("—")
        self._lbl_ipv6.setStyleSheet("color: #f1f5f9; font-weight: 600;")

        meta_grid.addWidget(lbl_prev_title, 0, 0)
        meta_grid.addWidget(self._lbl_prev_ip, 0, 1)
        meta_grid.addWidget(lbl_method_title, 0, 2)
        meta_grid.addWidget(self._lbl_method, 0, 3)

        meta_grid.addWidget(lbl_ipv6_title, 1, 0)
        meta_grid.addWidget(self._lbl_ipv6, 1, 1)
        meta_grid.addWidget(lbl_provider_title, 1, 2)
        meta_grid.addWidget(self._lbl_provider, 1, 3)

        hero_layout.addLayout(meta_grid, 2, 0, 1, 3)
        main_layout.addWidget(card_hero)

        # Hero Action Controls
        card_controls = QGroupBox("Rotation Control")
        controls_layout = QVBoxLayout(card_controls)
        controls_layout.setContentsMargins(18, 20, 18, 18)
        controls_layout.setSpacing(14)

        # Big Action Buttons Row
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        self._btn_start = QPushButton("▶  Start Rotating")
        self._btn_start.setProperty("buttonRole", "success")
        self._btn_start.setMinimumHeight(46)
        self._btn_start.setStyleSheet("font-size: 15px; font-weight: bold; border-radius: 8px;")
        self._btn_start.setToolTip("Start automated IP rotation loop")
        self._btn_start.clicked.connect(self._on_start_clicked)

        self._btn_stop = QPushButton("■  Stop")
        self._btn_stop.setProperty("buttonRole", "danger")
        self._btn_stop.setMinimumHeight(46)
        self._btn_stop.setStyleSheet("font-size: 15px; font-weight: bold; border-radius: 8px;")
        self._btn_stop.setToolTip("Stop automated IP rotation loop")
        self._btn_stop.setEnabled(False)
        self._btn_stop.clicked.connect(self._on_stop_clicked)

        self._btn_pause = QPushButton("⏸  Pause")
        self._btn_pause.setProperty("buttonRole", "warning")
        self._btn_pause.setMinimumHeight(46)
        self._btn_pause.setStyleSheet("font-size: 14px; font-weight: bold; border-radius: 8px;")
        self._btn_pause.setEnabled(False)
        self._btn_pause.clicked.connect(self._on_pause_clicked)

        self._btn_rotate_now = QPushButton("⚡  Change IP Now")
        self._btn_rotate_now.setProperty("buttonRole", "primary")
        self._btn_rotate_now.setMinimumHeight(46)
        self._btn_rotate_now.setStyleSheet("font-size: 14px; font-weight: bold; border-radius: 8px;")
        self._btn_rotate_now.setToolTip("Trigger one immediate IP rotation cycle")
        self._btn_rotate_now.clicked.connect(self._on_rotate_now_clicked)

        btn_row.addWidget(self._btn_start, 2)
        btn_row.addWidget(self._btn_stop, 1)
        btn_row.addWidget(self._btn_pause, 1)
        btn_row.addWidget(self._btn_rotate_now, 2)
        controls_layout.addLayout(btn_row)

        # Countdown & Progress Section
        countdown_row = QHBoxLayout()
        countdown_row.setContentsMargins(4, 4, 4, 4)

        self._lbl_countdown_title = QLabel("Next rotation in:")
        self._lbl_countdown_title.setStyleSheet("color: #94a3b8; font-size: 13px; font-weight: 500;")

        self._lbl_countdown = QLabel("Idle")
        self._lbl_countdown.setStyleSheet("color: #00d4ff; font-size: 15px; font-weight: bold;")

        countdown_row.addWidget(self._lbl_countdown_title)
        countdown_row.addWidget(self._lbl_countdown)
        countdown_row.addStretch()

        self._lbl_interval_info = QLabel("Configured Interval: 30s")
        self._lbl_interval_info.setStyleSheet("color: #94a3b8; font-size: 13px;")
        countdown_row.addWidget(self._lbl_interval_info)

        controls_layout.addLayout(countdown_row)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setFixedHeight(8)
        controls_layout.addWidget(self._progress_bar)

        # Rotation Stats Overview Row
        stats_frame = QFrame()
        stats_frame.setStyleSheet("background-color: #0f172a; border-radius: 8px; padding: 8px;")
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setContentsMargins(12, 6, 12, 6)

        self._lbl_stat_rotations = QLabel("Rotations: 0")
        self._lbl_stat_rotations.setStyleSheet("color: #f1f5f9; font-weight: 600;")

        self._lbl_stat_success = QLabel("Success: 0")
        self._lbl_stat_success.setStyleSheet("color: #22c55e; font-weight: 600;")

        self._lbl_stat_fail = QLabel("Failed: 0")
        self._lbl_stat_fail.setStyleSheet("color: #ef4444; font-weight: 600;")

        self._lbl_stat_last_change = QLabel("Last Changed: Never")
        self._lbl_stat_last_change.setStyleSheet("color: #94a3b8;")

        stats_layout.addWidget(self._lbl_stat_rotations)
        stats_layout.addSpacing(16)
        stats_layout.addWidget(self._lbl_stat_success)
        stats_layout.addSpacing(16)
        stats_layout.addWidget(self._lbl_stat_fail)
        stats_layout.addStretch()
        stats_layout.addWidget(self._lbl_stat_last_change)

        controls_layout.addWidget(stats_frame)
        main_layout.addWidget(card_controls)

        # Status Bar / Message Notification Row
        status_bar_frame = QFrame()
        status_bar_frame.setStyleSheet(
            "background-color: #16213e; border: 1px solid #0f3460; border-radius: 6px; padding: 6px;"
        )
        sb_layout = QHBoxLayout(status_bar_frame)
        sb_layout.setContentsMargins(8, 4, 8, 4)

        lbl_sb_icon = QLabel("ℹ")
        lbl_sb_icon.setStyleSheet("color: #00d4ff; font-weight: bold; font-size: 14px;")

        self._lbl_status_msg = QLabel("Ready. Click 'Start Rotating' or 'Change IP Now'.")
        self._lbl_status_msg.setStyleSheet("color: #e2e8f0; font-size: 13px;")

        sb_layout.addWidget(lbl_sb_icon)
        sb_layout.addWidget(self._lbl_status_msg)
        sb_layout.addStretch()

        main_layout.addWidget(status_bar_frame)
        main_layout.addStretch()

        # Place container in scroll area
        scroll_area.setWidget(container)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll_area)

        self._check_empty_state()

    def _check_empty_state(self) -> None:
        """Toggle empty state notice based on configured profiles count."""
        profiles = self._config_service.list_profiles()
        self._banner_empty.setVisible(len(profiles) == 0)

    def _setup_monitor_worker(self) -> None:
        """Create and start background rotation monitor worker."""
        self._monitor_worker = RotationMonitorWorker(self._controller, self._event_bus, self)
        self._monitor_worker.state_changed.connect(self._on_worker_state_changed)
        self._monitor_worker.countdown_updated.connect(self._on_worker_countdown_updated)
        self._monitor_worker.rotation_completed.connect(self._on_worker_rotation_completed)
        self._monitor_worker.error_occurred.connect(self._on_worker_error)
        self._monitor_worker.start()

    def _connect_event_bus(self) -> None:
        """Subscribe to system event bus updates."""
        self._event_bus.subscribe(SETTINGS_CHANGED, self._on_settings_changed)
        self._event_bus.subscribe(PROFILE_ADDED, lambda _: self._check_empty_state())
        self._event_bus.subscribe(PROFILE_REMOVED, lambda _: self._check_empty_state())
        self._event_bus.subscribe(PROFILE_UPDATED, lambda _: self._check_empty_state())

    def _on_settings_changed(self, settings: AppSettings) -> None:
        """Reflect configuration changes in dashboard."""
        self._lbl_interval_info.setText(f"Configured Interval: {settings.default_rotation_interval}s")

    def refresh_ip(self) -> None:
        """Initiate background verification of public IP address."""
        if self._verify_worker and self._verify_worker.isRunning():
            return

        self._btn_refresh_ip.setEnabled(False)
        self._btn_refresh_ip.setText("Querying...")
        self._set_status_message("Verifying external IP address...")

        settings = self._config_service.get_settings()
        proxy_config = None
        if self._active_profile:
            proxy_config = self._controller._connection_manager.get_proxy_config(self._active_profile)

        self._verify_worker = IPVerifyWorker(
            self._ip_verifier,
            check_ipv6=settings.check_ipv6,
            proxy_config=proxy_config,
            parent=self,
        )
        self._verify_worker.verification_finished.connect(self._on_ip_verified)
        self._verify_worker.start()

    def _on_ip_verified(self, ipv4: str, ipv6: str, success: bool, error: str) -> None:
        """Receive verified IP information from worker."""
        self._btn_refresh_ip.setEnabled(True)
        self._btn_refresh_ip.setText("Check IP Now")

        if success and ipv4:
            if self._current_ipv4 != "Checking..." and self._current_ipv4 != ipv4:
                self._previous_ip = self._current_ipv4
                self._lbl_prev_ip.setText(self._previous_ip)

            self._current_ipv4 = ipv4
            self._lbl_hero_ip.setText(ipv4)
            self._lbl_hero_ip.setStyleSheet("color: #22c55e; font-weight: bold; padding: 4px 0;")
            self._lbl_ipv6.setText(ipv6 if ipv6 else "Not detected")
            self._set_status_message(f"Public IP verified successfully: {ipv4}")
        else:
            self._lbl_hero_ip.setText("Offline / Failed")
            self._lbl_hero_ip.setStyleSheet("color: #ef4444; font-weight: bold; padding: 4px 0;")
            self._set_status_message(f"IP lookup failed: {error or 'No response'}")

    def _on_start_clicked(self) -> None:
        """Start the automated rotation loop."""
        settings = self._config_service.get_settings()
        profiles = self._config_service.list_profiles(enabled_only=True)

        if not profiles:
            self._set_status_message("⚠️ Please add at least one enabled profile in the Connections tab first.")
            self._banner_empty.setVisible(True)
            return

        interval = settings.default_rotation_interval
        scope = TrafficScope.APPLICATION_LEVEL
        preferred_id = settings.preferred_profile_id if not settings.auto_mode else None

        self._controller.start(
            interval=interval,
            scope=scope,
            profiles=profiles,
            manual_profile_id=preferred_id,
        )

        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._btn_pause.setEnabled(True)
        self._btn_pause.setText("⏸  Pause")
        self._is_paused = False

        self._set_status_message("Automated rotation engine started.")

    def _on_stop_clicked(self) -> None:
        """Stop automated rotation."""
        self._controller.stop()
        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._btn_pause.setEnabled(False)
        self._btn_pause.setText("⏸  Pause")
        self._is_paused = False
        self._lbl_countdown.setText("Stopped")
        self._progress_bar.setValue(0)
        self._set_status_message("Rotation stopped.")

    def _on_pause_clicked(self) -> None:
        """Toggle pause/resume on automated loop."""
        if not self._is_paused:
            self._controller.pause()
            self._is_paused = True
            self._btn_pause.setText("▶  Resume")
            self._set_status_message("Rotation paused.")
        else:
            self._controller.resume()
            self._is_paused = False
            self._btn_pause.setText("⏸  Pause")
            self._set_status_message("Rotation resumed.")

    def _on_rotate_now_clicked(self) -> None:
        """Execute single immediate rotation cycle."""
        profiles = self._config_service.list_profiles(enabled_only=True)
        if not profiles:
            self._set_status_message("⚠️ No enabled connection profiles available.")
            return

        self._btn_rotate_now.setEnabled(False)
        self._btn_rotate_now.setText("Rotating...")
        self._set_status_message("Executing manual IP rotation...")

        self._single_worker = SingleRotateWorker(
            self._controller,
            scope=TrafficScope.APPLICATION_LEVEL,
            profiles=profiles,
            parent=self,
        )
        self._single_worker.finished_event.connect(self._on_single_rotate_finished)
        self._single_worker.error_occurred.connect(self._on_worker_error)
        self._single_worker.start()

    def _on_single_rotate_finished(self, event: RotationEvent) -> None:
        """Handle single rotation outcome."""
        self._btn_rotate_now.setEnabled(True)
        self._btn_rotate_now.setText("⚡  Change IP Now")
        self._on_worker_rotation_completed(event)

    def _on_worker_state_changed(self, state_str: str) -> None:
        """Update UI badges and text on state changes."""
        color = get_status_color(state_str)
        text = state_str.replace("_", " ").upper()
        self._lbl_status_badge.setText(text)
        self._lbl_status_badge.setStyleSheet(
            f"background-color: {color}; color: #ffffff; font-weight: bold; "
            f"padding: 6px 16px; border-radius: 12px; font-size: 12px;"
        )

        cur_profile = self._controller.current_profile
        if cur_profile:
            self._active_profile = cur_profile
            self._lbl_method.setText(cur_profile.connection_type.value.replace("_", " ").title())
            self._lbl_provider.setText(cur_profile.provider_name or cur_profile.name)

        if state_str == RotationState.IDLE.value:
            if not self._controller.is_running:
                self._btn_start.setEnabled(True)
                self._btn_stop.setEnabled(False)
                self._btn_pause.setEnabled(False)

    def _on_worker_countdown_updated(self, seconds_left: int) -> None:
        """Update countdown timer readout and progress bar."""
        self._countdown_sec = seconds_left
        settings = self._config_service.get_settings()
        total_interval = max(5, settings.default_rotation_interval)

        if seconds_left > 0:
            self._lbl_countdown.setText(f"{seconds_left}s")
            pct = int(((total_interval - seconds_left) / total_interval) * 100)
            self._progress_bar.setValue(max(0, min(100, pct)))
        else:
            if self._controller.is_running:
                self._lbl_countdown.setText("Rotating now...")
                self._progress_bar.setValue(100)
            else:
                self._lbl_countdown.setText("Idle")
                self._progress_bar.setValue(0)

    def _on_worker_rotation_completed(self, event: RotationEvent) -> None:
        """Update statistics and IP displays when a rotation cycle finishes."""
        if event.new_ip:
            if self._current_ipv4 != event.new_ip:
                self._previous_ip = self._current_ipv4 or (event.previous_ip or "—")
                self._lbl_prev_ip.setText(self._previous_ip)
            self._current_ipv4 = event.new_ip
            self._lbl_hero_ip.setText(event.new_ip)

        # Update stats
        stats = self._controller.history.get_stats()
        self._lbl_stat_rotations.setText(f"Rotations: {stats.get('total', 0)}")
        self._lbl_stat_success.setText(f"Success: {stats.get('success_count', 0)}")
        self._lbl_stat_fail.setText(f"Failed: {stats.get('fail_count', 0)}")

        if event.ip_changed:
            self._last_change_time = datetime.now().strftime("%H:%M:%S")
            self._lbl_stat_last_change.setText(f"Last Changed: {self._last_change_time}")
            self._set_status_message(f"✓ IP successfully changed to {event.new_ip} ({event.method_type})")
        elif event.result == RotationResult.SUCCESS_IP_UNCHANGED:
            self._set_status_message(f"ℹ Connected, but IP remained unchanged: {event.new_ip}")
        else:
            self._set_status_message(f"✗ Rotation failed: {event.error_message or 'Unknown error'}")

    def _on_worker_error(self, err_msg: str) -> None:
        """Display error in status notification bar."""
        self._set_status_message(f"⚠️ {err_msg}")

    def _set_status_message(self, message: str) -> None:
        """Thread-safe update of status notification message."""
        self._lbl_status_msg.setText(message)

    def closeEvent(self, event) -> None:  # pylint: disable=invalid-name
        """Cleanup worker threads upon widget closure."""
        if self._monitor_worker:
            self._monitor_worker.stop()
        super().closeEvent(event)
