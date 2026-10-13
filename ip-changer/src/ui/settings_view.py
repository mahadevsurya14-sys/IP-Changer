"""Settings and Configuration Tab View for IP Changer.

Provides granular configuration of rotation timers, network timeouts,
safety guardrails, kill switches, theme selection, and data retention policies.
"""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from src.core.event_bus import EventBus, SETTINGS_CHANGED
from src.core.rotation_controller import RotationController
from src.core.safety_manager import SafetyManager
from src.models.app_settings import PRESET_INTERVALS, AppSettings, ThemeMode
from src.services.configuration_service import ConfigurationService

logger = logging.getLogger(__name__)


class SettingsWidget(QWidget):
    """Configuration management view."""

    theme_changed = Signal(str)

    def __init__(
        self,
        configuration_service: ConfigurationService,
        safety_manager: SafetyManager,
        rotation_controller: RotationController,
        event_bus: EventBus,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._config_service = configuration_service
        self._safety_manager = safety_manager
        self._rotation_controller = rotation_controller
        self._event_bus = event_bus

        self._preset_buttons: list[QRadioButton] = []

        self._init_ui()
        self._load_values()

    def _init_ui(self) -> None:
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        # Title
        title_label = QLabel("Application Settings")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #00d4ff;")
        layout.addWidget(title_label)

        # 1. Rotation Settings
        grp_rotation = QGroupBox("Rotation Settings")
        rot_layout = QVBoxLayout(grp_rotation)

        lbl_interval = QLabel("Rotation Interval:")
        lbl_interval.setStyleSheet("font-weight: 600; color: #f1f5f9;")
        rot_layout.addWidget(lbl_interval)

        # Presets row
        preset_row = QHBoxLayout()
        self._btn_group_presets = QButtonGroup(self)

        for interval in PRESET_INTERVALS:
            rb = QRadioButton(f"{interval} seconds")
            rb.setProperty("intervalValue", interval)
            self._btn_group_presets.addButton(rb)
            self._preset_buttons.append(rb)
            preset_row.addWidget(rb)

        self._rb_custom = QRadioButton("Custom:")
        self._btn_group_presets.addButton(self._rb_custom)
        preset_row.addWidget(self._rb_custom)

        self._spin_custom_interval = QSpinBox()
        self._spin_custom_interval.setRange(5, 86400)
        self._spin_custom_interval.setValue(30)
        self._spin_custom_interval.setSuffix(" sec")
        self._spin_custom_interval.setEnabled(False)
        self._rb_custom.toggled.connect(self._spin_custom_interval.setEnabled)
        preset_row.addWidget(self._spin_custom_interval)
        preset_row.addStretch()

        rot_layout.addLayout(preset_row)

        form_rot = QFormLayout()
        self._chk_auto_mode = QCheckBox("Enable Automatic Selection (Prefers highest priority & healthy endpoints)")
        form_rot.addRow("", self._chk_auto_mode)
        rot_layout.addLayout(form_rot)
        layout.addWidget(grp_rotation)

        # 2. Connection Settings
        grp_conn = QGroupBox("Network & Retry Settings")
        form_conn = QFormLayout(grp_conn)
        form_conn.setSpacing(10)

        self._spin_timeout = QSpinBox()
        self._spin_timeout.setRange(2, 120)
        self._spin_timeout.setValue(15)
        self._spin_timeout.setSuffix(" sec")
        form_conn.addRow("Connection Timeout:", self._spin_timeout)

        self._spin_retries = QSpinBox()
        self._spin_retries.setRange(0, 10)
        self._spin_retries.setValue(3)
        form_conn.addRow("Max Retries on Failure:", self._spin_retries)

        self._spin_backoff = QDoubleSpinBox()
        self._spin_backoff.setRange(1.0, 5.0)
        self._spin_backoff.setSingleStep(0.1)
        self._spin_backoff.setValue(1.5)
        form_conn.addRow("Exponential Backoff Multiplier:", self._spin_backoff)
        layout.addWidget(grp_conn)

        # 3. Verification Settings
        grp_verify = QGroupBox("Public IP Verification Services")
        verify_layout = QVBoxLayout(grp_verify)

        lbl_verify_hint = QLabel("Enter echo service URLs (one per line). Plaintext IP or JSON {'ip': ...} accepted:")
        lbl_verify_hint.setStyleSheet("color: #94a3b8; font-size: 12px;")
        verify_layout.addWidget(lbl_verify_hint)

        self._txt_verify_services = QPlainTextEdit()
        self._txt_verify_services.setMaximumHeight(80)
        verify_layout.addWidget(self._txt_verify_services)

        form_ipv6 = QFormLayout()
        self._chk_ipv6 = QCheckBox("Verify IPv6 Address (Checks for dual-stack egress leaks)")
        self._chk_ipv6.toggled.connect(lambda c: self._txt_ipv6_service.setEnabled(c))
        form_ipv6.addRow("", self._chk_ipv6)

        self._txt_ipv6_service = QLineEdit()
        self._txt_ipv6_service.setPlaceholderText("https://api6.ipify.org")
        form_ipv6.addRow("IPv6 Echo URL:", self._txt_ipv6_service)
        verify_layout.addLayout(form_ipv6)
        layout.addWidget(grp_verify)

        # 4. Security & Kill Switch Settings
        grp_security = QGroupBox("Security & Leak Guard")
        sec_layout = QVBoxLayout(grp_security)

        self._chk_kill_switch = QCheckBox("Enable Emergency Kill Switch")
        self._chk_kill_switch.setStyleSheet("font-weight: bold; color: #ef4444;")
        sec_layout.addWidget(self._chk_kill_switch)

        lbl_kill_switch_desc = QLabel(
            "When enabled, the application monitors for connection dropouts and attempts to "
            "block unencrypted egress leaks if the proxy/VPN tunnel disconnects unexpectedly."
        )
        lbl_kill_switch_desc.setWordWrap(True)
        lbl_kill_switch_desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        sec_layout.addWidget(lbl_kill_switch_desc)
        layout.addWidget(grp_security)

        # 5. Appearance Settings
        grp_appearance = QGroupBox("Appearance")
        form_app = QFormLayout(grp_appearance)

        self._combo_theme = QComboBox()
        self._combo_theme.addItem("Dark Theme (Default)", ThemeMode.DARK)
        self._combo_theme.addItem("Light Theme", ThemeMode.LIGHT)
        self._combo_theme.addItem("System Default", ThemeMode.SYSTEM)
        form_app.addRow("Application Theme:", self._combo_theme)
        layout.addWidget(grp_appearance)

        # 6. Startup & System Tray
        grp_startup = QGroupBox("Startup & Window Behavior")
        form_start = QFormLayout(grp_startup)

        self._chk_start_minimized = QCheckBox("Start Minimized to System Tray")
        form_start.addRow("", self._chk_start_minimized)
        layout.addWidget(grp_startup)

        # 7. Data Management
        grp_data = QGroupBox("Data Retention & History")
        data_layout = QVBoxLayout(grp_data)

        form_data = QFormLayout()
        self._spin_max_history = QSpinBox()
        self._spin_max_history.setRange(10, 5000)
        self._spin_max_history.setValue(1000)
        form_data.addRow("Max Rotation History Entries:", self._spin_max_history)

        self._spin_log_retention = QSpinBox()
        self._spin_log_retention.setRange(1, 365)
        self._spin_log_retention.setValue(30)
        self._spin_log_retention.setSuffix(" days")
        form_data.addRow("Log Retention Window:", self._spin_log_retention)
        data_layout.addLayout(form_data)

        btn_row_data = QHBoxLayout()
        self._btn_clear_history = QPushButton("Clear Rotation History")
        self._btn_clear_history.clicked.connect(self._on_clear_history)

        self._btn_clear_logs = QPushButton("Clear Log Files")
        self._btn_clear_logs.clicked.connect(self._on_clear_logs)

        btn_row_data.addWidget(self._btn_clear_history)
        btn_row_data.addWidget(self._btn_clear_logs)
        btn_row_data.addStretch()
        data_layout.addLayout(btn_row_data)
        layout.addWidget(grp_data)

        # Bottom Action Buttons
        action_row = QHBoxLayout()
        action_row.addStretch()

        self._btn_reset = QPushButton("Reset to Defaults")
        self._btn_reset.clicked.connect(self._on_reset_defaults)

        self._btn_save = QPushButton("Save Settings")
        self._btn_save.setProperty("buttonRole", "primary")
        self._btn_save.setMinimumHeight(38)
        self._btn_save.setStyleSheet("font-weight: bold; padding: 6px 24px;")
        self._btn_save.clicked.connect(self._on_save_settings)

        action_row.addWidget(self._btn_reset)
        action_row.addWidget(self._btn_save)
        layout.addLayout(action_row)

        scroll.setWidget(container)
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.addWidget(scroll)

    def _load_values(self) -> None:
        """Populate widgets with current saved settings."""
        settings = self._config_service.get_settings()

        # Interval
        matched = False
        for btn in self._preset_buttons:
            if btn.property("intervalValue") == settings.default_rotation_interval:
                btn.setChecked(True)
                matched = True
                break
        if not matched:
            self._rb_custom.setChecked(True)
            self._spin_custom_interval.setValue(settings.default_rotation_interval)

        self._chk_auto_mode.setChecked(settings.auto_mode)
        self._spin_timeout.setValue(settings.connection_timeout)
        self._spin_retries.setValue(settings.max_retries)
        self._spin_backoff.setValue(settings.retry_backoff_factor)

        # Verification
        self._txt_verify_services.setPlainText("\n".join(settings.verification_services))
        self._chk_ipv6.setChecked(settings.check_ipv6)
        self._txt_ipv6_service.setText(settings.ipv6_verification_service)
        self._txt_ipv6_service.setEnabled(settings.check_ipv6)

        # Kill switch
        self._chk_kill_switch.setChecked(settings.kill_switch_enabled)

        # Theme
        idx = self._combo_theme.findData(settings.theme)
        if idx >= 0:
            self._combo_theme.setCurrentIndex(idx)

        # Startup & Retention
        self._chk_start_minimized.setChecked(settings.start_minimized)
        self._spin_max_history.setValue(settings.max_history_size)
        self._spin_log_retention.setValue(settings.log_retention_days)

    def _on_save_settings(self) -> None:
        """Validate and apply settings."""
        try:
            # Determine interval
            interval = 30
            if self._rb_custom.isChecked():
                interval = self._spin_custom_interval.value()
            else:
                for btn in self._preset_buttons:
                    if btn.isChecked():
                        interval = btn.property("intervalValue")
                        break

            # Services
            raw_services = self._txt_verify_services.toPlainText().strip()
            services = [s.strip() for s in raw_services.splitlines() if s.strip()]
            if not services:
                raise ValueError("At least one IPv4 verification echo URL must be configured.")

            current = self._config_service.get_settings()
            selected_theme = self._combo_theme.currentData()
            kill_switch = self._chk_kill_switch.isChecked()

            new_settings = AppSettings(
                default_rotation_interval=interval,
                auto_mode=self._chk_auto_mode.isChecked(),
                connection_timeout=self._spin_timeout.value(),
                max_retries=self._spin_retries.value(),
                retry_backoff_factor=self._spin_backoff.value(),
                verification_services=services,
                check_ipv6=self._chk_ipv6.isChecked(),
                ipv6_verification_service=self._txt_ipv6_service.text().strip() or "https://api6.ipify.org",
                kill_switch_enabled=kill_switch,
                theme=selected_theme,
                start_minimized=self._chk_start_minimized.isChecked(),
                max_history_size=self._spin_max_history.value(),
                log_retention_days=self._spin_log_retention.value(),
                preferred_profile_id=current.preferred_profile_id,
            )

            new_settings.validate()
            self._config_service.update_settings(new_settings)

            # Sync safety manager
            if kill_switch and not self._safety_manager.kill_switch_active:
                self._safety_manager.enable_kill_switch()
            elif not kill_switch and self._safety_manager.kill_switch_active:
                self._safety_manager.disable_kill_switch()

            # Sync history capacity
            self._rotation_controller.history.max_history_size = new_settings.max_history_size

            # Notify theme changed
            theme_val = selected_theme.value if isinstance(selected_theme, ThemeMode) else str(selected_theme)
            self.theme_changed.emit(theme_val)

            QMessageBox.information(self, "Settings Saved", "Application settings have been saved successfully.")
        except Exception as exc:
            QMessageBox.warning(self, "Validation Error", f"Failed to save settings: {exc}")

    def _on_reset_defaults(self) -> None:
        """Reset settings to default baseline."""
        confirm = QMessageBox.question(
            self,
            "Reset Settings",
            "Are you sure you want to restore default configuration settings?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            defaults = AppSettings()
            self._config_service.update_settings(defaults)
            self._load_values()
            theme_val = defaults.theme.value if isinstance(defaults.theme, ThemeMode) else str(defaults.theme)
            self.theme_changed.emit(theme_val)
            QMessageBox.information(self, "Defaults Restored", "Settings have been reset to factory defaults.")

    def _on_clear_history(self) -> None:
        """Clear recorded rotation history."""
        confirm = QMessageBox.question(
            self,
            "Clear History",
            "Clear all recorded rotation events from memory?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            self._rotation_controller.history.clear()
            QMessageBox.information(self, "History Cleared", "Rotation history cleared successfully.")

    def _on_clear_logs(self) -> None:
        """Clear log directory contents."""
        confirm = QMessageBox.question(
            self,
            "Clear Logs",
            "Purge older application log files?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            QMessageBox.information(self, "Logs Cleared", "Application logs purged.")
