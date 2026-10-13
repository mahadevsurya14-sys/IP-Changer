"""Connection Management Tab View for IP Changer.

Provides full CRUD operations for proxy and VPN profiles, credential storage
via SecretStore, one-click connection health probes, priority adjustments,
and selection transparency diagnostics.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.core.capability_registry import CapabilityRegistry
from src.core.connection_manager import ConnectionManager
from src.core.event_bus import (
    CONNECTION_STATUS_CHANGED,
    EventBus,
    PROFILE_ADDED,
    PROFILE_REMOVED,
    PROFILE_UPDATED,
    SETTINGS_CHANGED,
)
from src.core.method_selector import MethodSelector
from src.models.app_settings import AppSettings
from src.models.connection_profile import (
    ConnectionCapabilities,
    ConnectionProfile,
    ConnectionStatus,
    ConnectionTestResult,
    ConnectionType,
    TrafficScope,
)
from src.services.configuration_service import ConfigurationService
from src.services.secret_store import SecretStore
from src.ui.styles import COLOR_DANGER, COLOR_MUTED, COLOR_SUCCESS, COLOR_WARNING
from src.ui.workers import ConnectionTestWorker

logger = logging.getLogger(__name__)


class ProfileDialog(QDialog):
    """Add / Edit Connection Profile Modal Dialog."""

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        profile: Optional[ConnectionProfile] = None,
        secret_store: Optional[SecretStore] = None,
    ) -> None:
        super().__init__(parent)
        self._profile = profile
        self._secret_store = secret_store
        self.setWindowTitle("Edit Connection Profile" if profile else "Add New Connection Profile")
        self.setMinimumWidth(460)
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        form = QFormLayout()
        form.setSpacing(10)

        # Name
        self._txt_name = QLineEdit()
        self._txt_name.setPlaceholderText("e.g. Frankfurt SOCKS5 or Work Proxy")
        form.addRow("Profile Name *:", self._txt_name)

        # Connection Type
        self._combo_type = QComboBox()
        self._combo_type.addItem("HTTP Proxy", ConnectionType.HTTP_PROXY)
        self._combo_type.addItem("HTTPS Proxy", ConnectionType.HTTPS_PROXY)
        self._combo_type.addItem("SOCKS5 Proxy", ConnectionType.SOCKS5_PROXY)
        self._combo_type.addItem("System VPN (Native)", ConnectionType.VPN_SYSTEM)
        self._combo_type.addItem("OpenVPN (Tunnel)", ConnectionType.VPN_OPENVPN)
        self._combo_type.addItem("WireGuard", ConnectionType.VPN_WIREGUARD)
        self._combo_type.addItem("Rotation Gateway", ConnectionType.ROTATION_GATEWAY)
        self._combo_type.currentIndexChanged.connect(self._on_type_changed)
        form.addRow("Connection Type:", self._combo_type)

        # Host
        self._txt_host = QLineEdit()
        self._txt_host.setPlaceholderText("e.g. proxy.example.com or 192.168.1.100")
        form.addRow("Host / Server *:", self._txt_host)

        # Port
        self._spin_port = QSpinBox()
        self._spin_port.setRange(0, 65535)
        self._spin_port.setValue(8080)
        form.addRow("Port (1-65535):", self._spin_port)

        # Username
        self._txt_user = QLineEdit()
        self._txt_user.setPlaceholderText("Optional auth username")
        form.addRow("Username:", self._txt_user)

        # Password
        self._txt_pass = QLineEdit()
        self._txt_pass.setEchoMode(QLineEdit.Password)
        self._txt_pass.setPlaceholderText("Optional password (stored securely in OS Keyring)")
        form.addRow("Password:", self._txt_pass)

        # Provider Name
        self._txt_provider = QLineEdit()
        self._txt_provider.setPlaceholderText("e.g. BrightData, NordVPN, Custom")
        form.addRow("Provider Name:", self._txt_provider)

        # Traffic Scope
        self._combo_scope = QComboBox()
        self._combo_scope.addItem("Application Level (Default)", TrafficScope.APPLICATION_LEVEL)
        self._combo_scope.addItem("System Wide (All apps)", TrafficScope.SYSTEM_WIDE)
        form.addRow("Traffic Scope:", self._combo_scope)

        # Priority
        self._spin_priority = QSpinBox()
        self._spin_priority.setRange(0, 100)
        self._spin_priority.setValue(10)
        self._spin_priority.setToolTip("Higher priority profiles are preferred during automatic rotation")
        form.addRow("Priority (0-100):", self._spin_priority)

        # Enabled Checkbox
        self._chk_enabled = QCheckBox("Enable this profile for rotation")
        self._chk_enabled.setChecked(True)
        form.addRow("", self._chk_enabled)

        layout.addLayout(form)

        # VPN Specific Notice / Group
        self._vpn_box = QGroupBox("VPN Information")
        vpn_box_layout = QVBoxLayout(self._vpn_box)
        self._lbl_vpn_hint = QLabel(
            "For System VPN, specify the exact adapter/connection name in the 'Host' field."
        )
        self._lbl_vpn_hint.setWordWrap(True)
        self._lbl_vpn_hint.setStyleSheet("color: #94a3b8; font-size: 12px;")
        vpn_box_layout.addWidget(self._lbl_vpn_hint)
        self._vpn_box.setVisible(False)
        layout.addWidget(self._vpn_box)

        # Populate fields if editing
        if self._profile:
            self._txt_name.setText(self._profile.name)
            idx = self._combo_type.findData(self._profile.connection_type)
            if idx >= 0:
                self._combo_type.setCurrentIndex(idx)
            self._txt_host.setText(self._profile.host)
            self._spin_port.setValue(self._profile.port)
            self._txt_user.setText(self._profile.username or "")
            self._txt_provider.setText(self._profile.provider_name or "")
            scope_idx = self._combo_scope.findData(self._profile.traffic_scope)
            if scope_idx >= 0:
                self._combo_scope.setCurrentIndex(scope_idx)
            self._spin_priority.setValue(self._profile.priority)
            self._chk_enabled.setChecked(self._profile.enabled)

            # Retrieve existing password if stored
            if self._secret_store and self._profile.auth_token_key:
                stored_pass = self._secret_store.get_secret(self._profile.id, "password")
                if stored_pass:
                    self._txt_pass.setText(stored_pass)

        # Dialog Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self._validate_and_save)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _on_type_changed(self, index: int) -> None:
        """Handle connection type selection change."""
        conn_type = self._combo_type.currentData()
        is_vpn = "vpn" in conn_type.value if hasattr(conn_type, "value") else "vpn" in str(conn_type)
        self._vpn_box.setVisible(is_vpn)
        if conn_type == ConnectionType.VPN_SYSTEM:
            self._spin_port.setValue(0)
            self._spin_port.setEnabled(False)
        else:
            self._spin_port.setEnabled(True)
            if self._spin_port.value() == 0:
                self._spin_port.setValue(8080)

    def _validate_and_save(self) -> None:
        """Validate input parameters before accepting."""
        name = self._txt_name.text().strip()
        host = self._txt_host.text().strip()
        port = self._spin_port.value()

        if not name:
            QMessageBox.warning(self, "Validation Error", "Profile name is required.")
            self._txt_name.setFocus()
            return

        if not host:
            QMessageBox.warning(self, "Validation Error", "Host / Server address is required.")
            self._txt_host.setFocus()
            return

        conn_type = self._combo_type.currentData()
        if conn_type != ConnectionType.VPN_SYSTEM and port <= 0:
            QMessageBox.warning(self, "Validation Error", "Port must be greater than 0.")
            self._spin_port.setFocus()
            return

        self.accept()

    def get_profile_data(self) -> ConnectionProfile:
        """Construct validated ConnectionProfile instance."""
        conn_type = self._combo_type.currentData()
        traffic_scope = self._combo_scope.currentData()
        profile_id = self._profile.id if self._profile else None

        password = self._txt_pass.text()
        auth_key = None
        if password:
            auth_key = f"{profile_id or 'new'}:password"

        kwargs = {
            "name": self._txt_name.text().strip(),
            "connection_type": conn_type,
            "host": self._txt_host.text().strip(),
            "port": self._spin_port.value(),
            "username": self._txt_user.text().strip() or None,
            "auth_token_key": auth_key,
            "enabled": self._chk_enabled.isChecked(),
            "priority": self._spin_priority.value(),
            "traffic_scope": traffic_scope,
            "provider_name": self._txt_provider.text().strip(),
        }

        if profile_id:
            kwargs["id"] = profile_id

        profile = ConnectionProfile(**kwargs)

        # Store password if provided
        if password and self._secret_store:
            profile.auth_token_key = f"{profile.id}:password"
            self._secret_store.store_secret(profile.id, "password", password)
        elif not password and self._secret_store and self._profile and self._profile.auth_token_key:
            self._secret_store.delete_secret(self._profile.id, "password")
            profile.auth_token_key = None

        return profile


class ConnectionManagerWidget(QWidget):
    """Complete connection profiles table, management toolbar, and diagnostics."""

    def __init__(
        self,
        configuration_service: ConfigurationService,
        connection_manager: ConnectionManager,
        method_selector: MethodSelector,
        secret_store: SecretStore,
        event_bus: EventBus,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._config_service = configuration_service
        self._manager = connection_manager
        self._selector = method_selector
        self._secret_store = secret_store
        self._event_bus = event_bus

        self._active_test_workers: List[ConnectionTestWorker] = []

        self._init_ui()
        self._load_profiles()
        self._connect_event_bus()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header Title and Mode Bar
        header_bar = QHBoxLayout()
        title_label = QLabel("Connection Profiles")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #00d4ff;")
        header_bar.addWidget(title_label)
        header_bar.addStretch()

        # Selection Mode Selector (Auto vs Manual)
        mode_box = QFrame()
        mode_box.setStyleSheet("background-color: #16213e; border: 1px solid #0f3460; border-radius: 6px; padding: 4px;")
        mode_layout = QHBoxLayout(mode_box)
        mode_layout.setContentsMargins(8, 2, 8, 2)
        mode_layout.setSpacing(12)

        lbl_mode = QLabel("Selection Mode:")
        lbl_mode.setStyleSheet("color: #94a3b8; font-weight: 600;")
        self._radio_auto = QRadioButton("Automatic (Priority & Health)")
        self._radio_manual = QRadioButton("Manual (Pin Preferred)")
        self._radio_auto.toggled.connect(self._on_mode_toggled)

        settings = self._config_service.get_settings()
        if settings.auto_mode:
            self._radio_auto.setChecked(True)
        else:
            self._radio_manual.setChecked(True)

        mode_layout.addWidget(lbl_mode)
        mode_layout.addWidget(self._radio_auto)
        mode_layout.addWidget(self._radio_manual)
        header_bar.addWidget(mode_box)

        layout.addLayout(header_bar)

        # Top Action Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self._btn_add = QPushButton("➕ Add Profile")
        self._btn_add.setProperty("buttonRole", "primary")
        self._btn_add.clicked.connect(self._on_add_profile)

        self._btn_edit = QPushButton("✏ Edit")
        self._btn_edit.setEnabled(False)
        self._btn_edit.clicked.connect(self._on_edit_profile)

        self._btn_delete = QPushButton("🗑 Remove")
        self._btn_delete.setProperty("buttonRole", "danger")
        self._btn_delete.setEnabled(False)
        self._btn_delete.clicked.connect(self._on_delete_profile)

        self._btn_test = QPushButton("🔍 Test Connection")
        self._btn_test.setEnabled(False)
        self._btn_test.setToolTip("Probe latency and verified exit IP for the selected profile")
        self._btn_test.clicked.connect(self._on_test_connection)

        self._btn_toggle = QPushButton("Toggle Enable")
        self._btn_toggle.setEnabled(False)
        self._btn_toggle.clicked.connect(self._on_toggle_enabled)

        self._btn_priority_up = QPushButton("▲ Priority")
        self._btn_priority_up.setEnabled(False)
        self._btn_priority_up.setToolTip("Increase rotation priority")
        self._btn_priority_up.clicked.connect(lambda: self._adjust_priority(5))

        self._btn_priority_down = QPushButton("▼ Priority")
        self._btn_priority_down.setEnabled(False)
        self._btn_priority_down.setToolTip("Decrease rotation priority")
        self._btn_priority_down.clicked.connect(lambda: self._adjust_priority(-5))

        toolbar.addWidget(self._btn_add)
        toolbar.addWidget(self._btn_edit)
        toolbar.addWidget(self._btn_delete)
        toolbar.addWidget(self._btn_test)
        toolbar.addWidget(self._btn_toggle)
        toolbar.addWidget(self._btn_priority_up)
        toolbar.addWidget(self._btn_priority_down)
        toolbar.addStretch()

        layout.addLayout(toolbar)

        # Profiles Table
        self._table = QTableWidget()
        self._table.setColumnCount(7)
        self._table.setHorizontalHeaderLabels([
            "Name", "Type", "Endpoint (Host:Port)", "Priority", "Status", "Enabled", "Scope"
        ])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)

        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.doubleClicked.connect(self._on_edit_profile)
        layout.addWidget(self._table)

        # Bottom Selection Diagnosis Box
        self._diag_frame = QFrame()
        self._diag_frame.setStyleSheet(
            "background-color: #16213e; border: 1px solid #0f3460; border-radius: 6px; padding: 10px;"
        )
        diag_layout = QVBoxLayout(self._diag_frame)
        diag_layout.setContentsMargins(10, 6, 10, 6)

        self._lbl_diag_title = QLabel("Profile Evaluation & Feasibility:")
        self._lbl_diag_title.setStyleSheet("color: #00d4ff; font-weight: bold;")
        self._lbl_diag_content = QLabel("Select a profile to view evaluation details.")
        self._lbl_diag_content.setStyleSheet("color: #cbd5e1; font-size: 12px;")
        self._lbl_diag_content.setWordWrap(True)

        diag_layout.addWidget(self._lbl_diag_title)
        diag_layout.addWidget(self._lbl_diag_content)
        layout.addWidget(self._diag_frame)

    def _connect_event_bus(self) -> None:
        """Listen for external data changes."""
        self._event_bus.subscribe(PROFILE_ADDED, lambda _: self._load_profiles())
        self._event_bus.subscribe(PROFILE_REMOVED, lambda _: self._load_profiles())
        self._event_bus.subscribe(PROFILE_UPDATED, lambda _: self._load_profiles())
        self._event_bus.subscribe(CONNECTION_STATUS_CHANGED, self._on_connection_status_changed)

    def _on_connection_status_changed(self, payload: Any) -> None:
        """Update status column for matching profile."""
        if not isinstance(payload, dict):
            return
        profile_id = payload.get("profile_id")
        status: ConnectionStatus = payload.get("status")
        if not profile_id or not status:
            return

        for row in range(self._table.rowCount()):
            item_id = self._table.item(row, 0).data(Qt.UserRole)
            if item_id == profile_id:
                status_item = self._table.item(row, 4)
                if status_item:
                    status_item.setText(status.value.upper())
                    status_item.setForeground(QColor(self._get_status_color(status.value)))
                break

    def _get_status_color(self, status_str: str) -> str:
        """Map connection status to UI color."""
        s = status_str.lower()
        if "connected" in s:
            return COLOR_SUCCESS
        if any(w in s for w in ("connecting", "testing", "rotating")):
            return COLOR_WARNING
        if any(w in s for w in ("error", "failed")):
            return COLOR_DANGER
        return COLOR_MUTED

    def _load_profiles(self) -> None:
        """Populate table from configuration service."""
        profiles = self._config_service.list_profiles()
        self._table.setRowCount(len(profiles))

        for row, p in enumerate(profiles):
            # Name
            name_item = QTableWidgetItem(p.name)
            name_item.setData(Qt.UserRole, p.id)
            name_item.setFont(QFont("Segoe UI", weight=QFont.Bold))

            # Type
            type_item = QTableWidgetItem(p.connection_type.value.replace("_", " ").title())

            # Host:Port
            endpoint_str = f"{p.host}:{p.port}" if p.port > 0 else p.host
            endpoint_item = QTableWidgetItem(endpoint_str)

            # Priority
            prio_item = QTableWidgetItem(str(p.priority))
            prio_item.setTextAlignment(Qt.AlignCenter)

            # Status
            status_val = "DISCONNECTED"
            status_item = QTableWidgetItem(status_val)
            status_item.setForeground(QColor(COLOR_MUTED))
            status_item.setTextAlignment(Qt.AlignCenter)

            # Enabled
            enabled_str = "✓ Yes" if p.enabled else "✗ No"
            enabled_item = QTableWidgetItem(enabled_str)
            enabled_item.setForeground(QColor(COLOR_SUCCESS if p.enabled else COLOR_DANGER))
            enabled_item.setTextAlignment(Qt.AlignCenter)

            # Traffic Scope
            scope_str = "App" if p.traffic_scope == TrafficScope.APPLICATION_LEVEL else "System"
            scope_item = QTableWidgetItem(scope_str)
            scope_item.setTextAlignment(Qt.AlignCenter)

            self._table.setItem(row, 0, name_item)
            self._table.setItem(row, 1, type_item)
            self._table.setItem(row, 2, endpoint_item)
            self._table.setItem(row, 3, prio_item)
            self._table.setItem(row, 4, status_item)
            self._table.setItem(row, 5, enabled_item)
            self._table.setItem(row, 6, scope_item)

        self._on_selection_changed()

    def _get_selected_profile(self) -> Optional[ConnectionProfile]:
        """Return the ConnectionProfile of the currently selected row."""
        selected_rows = self._table.selectionModel().selectedRows()
        if not selected_rows:
            return None
        row = selected_rows[0].row()
        profile_id = self._table.item(row, 0).data(Qt.UserRole)
        return self._config_service.get_profile(profile_id)

    def _on_selection_changed(self) -> None:
        """Update toolbar button states and diagnosis message."""
        profile = self._get_selected_profile()
        has_sel = profile is not None

        self._btn_edit.setEnabled(has_sel)
        self._btn_delete.setEnabled(has_sel)
        self._btn_test.setEnabled(has_sel)
        self._btn_toggle.setEnabled(has_sel)
        self._btn_priority_up.setEnabled(has_sel)
        self._btn_priority_down.setEnabled(has_sel)

        if profile:
            # Diagnose selection feasibility
            settings = self._config_service.get_settings()
            feasible, reason = self._selector._evaluate_profile(
                profile,
                interval=settings.default_rotation_interval,
                scope=profile.traffic_scope,
            )
            status_txt = "✓ Eligible for rotation" if feasible else f"✗ Excluded: {reason}"
            color = COLOR_SUCCESS if feasible else COLOR_WARNING
            self._lbl_diag_content.setText(
                f"<b>Profile:</b> {profile.name} ({profile.connection_type.value})<br/>"
                f"<b>Status:</b> <span style='color:{color}'>{status_txt}</span><br/>"
                f"<b>Capabilities:</b> System Wide={profile.capabilities.supports_system_wide}, "
                f"Min Interval={profile.capabilities.min_rotation_interval_seconds}s"
            )
        else:
            self._lbl_diag_content.setText("Select a profile to view evaluation details.")

    def _on_mode_toggled(self, checked: bool) -> None:
        """Save auto / manual selection mode in settings."""
        if not checked:
            return
        settings = self._config_service.get_settings()
        settings.auto_mode = self._radio_auto.isChecked()
        self._config_service.update_settings(settings)

    def _on_add_profile(self) -> None:
        """Open Add Profile dialog."""
        dialog = ProfileDialog(self, secret_store=self._secret_store)
        if dialog.exec() == QDialog.Accepted:
            new_profile = dialog.get_profile_data()
            try:
                self._config_service.add_profile(new_profile)
                self._load_profiles()
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Could not add profile: {exc}")

    def _on_edit_profile(self) -> None:
        """Open Edit Profile dialog for selected row."""
        profile = self._get_selected_profile()
        if not profile:
            return
        dialog = ProfileDialog(self, profile=profile, secret_store=self._secret_store)
        if dialog.exec() == QDialog.Accepted:
            updated = dialog.get_profile_data()
            try:
                self._config_service.update_profile(updated)
                self._load_profiles()
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Could not update profile: {exc}")

    def _on_delete_profile(self) -> None:
        """Prompt confirmation and delete profile."""
        profile = self._get_selected_profile()
        if not profile:
            return
        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to remove profile '{profile.name}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            try:
                self._config_service.remove_profile(profile.id)
                if self._secret_store and profile.auth_token_key:
                    self._secret_store.delete_secret(profile.id, "password")
                self._load_profiles()
            except Exception as exc:
                QMessageBox.critical(self, "Error", f"Failed to delete profile: {exc}")

    def _on_toggle_enabled(self) -> None:
        """Toggle enabled flag on selected profile."""
        profile = self._get_selected_profile()
        if not profile:
            return
        profile.enabled = not profile.enabled
        self._config_service.update_profile(profile)
        self._load_profiles()

    def _adjust_priority(self, delta: int) -> None:
        """Increment or decrement priority score."""
        profile = self._get_selected_profile()
        if not profile:
            return
        profile.priority = max(0, min(100, profile.priority + delta))
        self._config_service.update_profile(profile)
        self._load_profiles()

    def _on_test_connection(self) -> None:
        """Execute one-click connection test."""
        profile = self._get_selected_profile()
        if not profile:
            return

        self._btn_test.setEnabled(False)
        self._btn_test.setText("Testing...")

        # Update status cell
        for row in range(self._table.rowCount()):
            if self._table.item(row, 0).data(Qt.UserRole) == profile.id:
                status_item = self._table.item(row, 4)
                if status_item:
                    status_item.setText("TESTING...")
                    status_item.setForeground(QColor(COLOR_WARNING))
                break

        worker = ConnectionTestWorker(self._manager, profile, parent=self)
        worker.test_finished.connect(lambda res: self._on_test_finished(profile, res, worker))
        self._active_test_workers.append(worker)
        worker.start()

    def _on_test_finished(
        self,
        profile: ConnectionProfile,
        result: ConnectionTestResult,
        worker: ConnectionTestWorker,
    ) -> None:
        """Display test probe results."""
        if worker in self._active_test_workers:
            self._active_test_workers.remove(worker)

        self._btn_test.setEnabled(True)
        self._btn_test.setText("🔍 Test Connection")

        # Update table status cell
        for row in range(self._table.rowCount()):
            if self._table.item(row, 0).data(Qt.UserRole) == profile.id:
                status_item = self._table.item(row, 4)
                if status_item:
                    if result.success:
                        status_item.setText("ONLINE")
                        status_item.setForeground(QColor(COLOR_SUCCESS))
                    else:
                        status_item.setText("OFFLINE")
                        status_item.setForeground(QColor(COLOR_DANGER))
                break

        if result.success:
            msg = (
                f"✓ Connection Successful!\n\n"
                f"Profile: {profile.name}\n"
                f"Observed Public IP: {result.observed_ip or 'Unchanged'}\n"
                f"Latency: {result.latency_ms:.1f} ms"
            )
            QMessageBox.information(self, "Connection Test Passed", msg)
        else:
            msg = (
                f"✗ Connection Test Failed!\n\n"
                f"Profile: {profile.name}\n"
                f"Error: {result.error_message or 'Endpoint unreachable'}"
            )
            QMessageBox.warning(self, "Connection Test Failed", msg)
