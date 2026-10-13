"""Main Application Window for IP Changer.

Integrates the multi-tab layout, menu bar, system tray integration, dynamic theme
switching, and coordinated graceful shutdown lifecycle management.
"""

from __future__ import annotations

import logging
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QCloseEvent, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QMenu,
    QMessageBox,
    QStatusBar,
    QSystemTrayIcon,
    QTabWidget,
)

from src.core.connection_manager import ConnectionManager
from src.core.event_bus import EventBus
from src.core.ip_verifier import IPVerifier
from src.core.method_selector import MethodSelector
from src.core.rotation_controller import RotationController
from src.core.safety_manager import SafetyManager
from src.models.app_settings import ThemeMode
from src.services.configuration_service import ConfigurationService
from src.services.diagnostics_service import DiagnosticsService
from src.services.secret_store import SecretStore
from src.ui.about_view import AboutWidget
from src.ui.connection_manager_view import ConnectionManagerWidget
from src.ui.dashboard import DashboardWidget
from src.ui.diagnostics_view import DiagnosticsWidget
from src.ui.history_view import HistoryWidget
from src.ui.settings_view import SettingsWidget
from src.ui.styles import get_theme_stylesheet

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Primary application window hosting all functional modules."""

    def __init__(
        self,
        rotation_controller: RotationController,
        configuration_service: ConfigurationService,
        connection_manager: ConnectionManager,
        ip_verifier: IPVerifier,
        method_selector: MethodSelector,
        safety_manager: SafetyManager,
        diagnostics_service: DiagnosticsService,
        secret_store: SecretStore,
        event_bus: EventBus,
        parent: Optional[QMainWindow] = None,
    ) -> None:
        super().__init__(parent)
        self._controller = rotation_controller
        self._config_service = configuration_service
        self._manager = connection_manager
        self._ip_verifier = ip_verifier
        self._selector = method_selector
        self._safety_manager = safety_manager
        self._diagnostics_service = diagnostics_service
        self._secret_store = secret_store
        self._event_bus = event_bus

        self.setWindowTitle("IP Changer - by Mahaduuu")
        self.setMinimumSize(920, 680)
        self.resize(1000, 720)

        self._init_ui()
        self._init_menu_bar()
        self._init_system_tray()
        self._apply_current_theme()

    def _init_ui(self) -> None:
        """Construct central tab widget and views."""
        self._tabs = QTabWidget(self)
        self._tabs.setDocumentMode(True)

        # 0. Dashboard View (Hero)
        self._view_dashboard = DashboardWidget(
            rotation_controller=self._controller,
            configuration_service=self._config_service,
            ip_verifier=self._ip_verifier,
            event_bus=self._event_bus,
            parent=self,
        )
        self._view_dashboard.navigate_to_connections.connect(lambda: self._tabs.setCurrentIndex(1))
        self._tabs.addTab(self._view_dashboard, "  🏠 Dashboard  ")

        # 1. Connections View
        self._view_connections = ConnectionManagerWidget(
            configuration_service=self._config_service,
            connection_manager=self._manager,
            method_selector=self._selector,
            secret_store=self._secret_store,
            event_bus=self._event_bus,
            parent=self,
        )
        self._tabs.addTab(self._view_connections, "  🔌 Connections  ")

        # 2. Settings View
        self._view_settings = SettingsWidget(
            configuration_service=self._config_service,
            safety_manager=self._safety_manager,
            rotation_controller=self._controller,
            event_bus=self._event_bus,
            parent=self,
        )
        self._view_settings.theme_changed.connect(self._apply_theme)
        self._tabs.addTab(self._view_settings, "  ⚙ Settings  ")

        # 3. History View
        self._view_history = HistoryWidget(
            rotation_controller=self._controller,
            event_bus=self._event_bus,
            parent=self,
        )
        self._tabs.addTab(self._view_history, "  📜 History  ")

        # 4. Diagnostics View
        self._view_diagnostics = DiagnosticsWidget(
            diagnostics_service=self._diagnostics_service,
            event_bus=self._event_bus,
            parent=self,
        )
        self._tabs.addTab(self._view_diagnostics, "  🩺 Diagnostics  ")

        # 5. About View
        self._view_about = AboutWidget(parent=self)
        self._tabs.addTab(self._view_about, "  ℹ About  ")

        self.setCentralWidget(self._tabs)

        # Status Bar
        self._status_bar = QStatusBar(self)
        self.setStatusBar(self._status_bar)
        self._status_bar.showMessage("IP Changer initialized • Ready")

    def _init_menu_bar(self) -> None:
        """Create standard application menus."""
        menubar = self.menuBar()

        # File Menu
        menu_file = menubar.addMenu("&File")

        act_refresh = QAction("&Check IP Now", self)
        act_refresh.setShortcut("F5")
        act_refresh.triggered.connect(self._view_dashboard.refresh_ip)
        menu_file.addAction(act_refresh)

        menu_file.addSeparator()

        act_exit = QAction("E&xit", self)
        act_exit.setShortcut("Ctrl+Q")
        act_exit.triggered.connect(self.close)
        menu_file.addAction(act_exit)

        # View Menu
        menu_view = menubar.addMenu("&View")

        act_toggle_theme = QAction("Toggle &Dark / Light Theme", self)
        act_toggle_theme.triggered.connect(self._toggle_theme)
        menu_view.addAction(act_toggle_theme)

        # Help Menu
        menu_help = menubar.addMenu("&Help")

        act_about = QAction("&About IP Changer", self)
        act_about.triggered.connect(lambda: self._tabs.setCurrentIndex(5))
        menu_help.addAction(act_about)

    def _init_system_tray(self) -> None:
        """Initialize system tray icon and contextual actions."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            self._tray_icon = None
            return

        self._tray_icon = QSystemTrayIcon(self)
        # Standard system icon fallback
        style = QApplication.style()
        icon = style.standardIcon(style.StandardPixmap.SP_ComputerIcon)
        self._tray_icon.setIcon(icon)

        tray_menu = QMenu()
        act_show = tray_menu.addAction("Show Window")
        act_show.triggered.connect(self._restore_from_tray)

        act_rotate = tray_menu.addAction("Rotate IP Now")
        act_rotate.triggered.connect(self._view_dashboard._on_rotate_now_clicked)

        tray_menu.addSeparator()
        act_quit = tray_menu.addAction("Quit IP Changer")
        act_quit.triggered.connect(self._force_quit)

        self._tray_icon.setContextMenu(tray_menu)
        self._tray_icon.activated.connect(self._on_tray_activated)
        self._tray_icon.show()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        """Handle click on system tray icon."""
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self._restore_from_tray()

    def _restore_from_tray(self) -> None:
        """Restore window to view."""
        self.showNormal()
        self.activateWindow()

    def _force_quit(self) -> None:
        """Unconditionally shutdown the application."""
        self._shutdown()
        QApplication.quit()

    def _apply_current_theme(self) -> None:
        """Load and set stylesheet based on persisted settings."""
        settings = self._config_service.get_settings()
        self._apply_theme(settings.theme)

    def _apply_theme(self, theme_val: str | ThemeMode) -> None:
        """Apply QSS stylesheet globally to QApplication."""
        qss = get_theme_stylesheet(theme_val)
        app = QApplication.instance()
        if app:
            app.setStyleSheet(qss)

    def _toggle_theme(self) -> None:
        """Toggle between Dark and Light mode."""
        settings = self._config_service.get_settings()
        new_theme = ThemeMode.LIGHT if settings.theme == ThemeMode.DARK else ThemeMode.DARK
        settings.theme = new_theme
        self._config_service.update_settings(settings)
        self._apply_theme(new_theme)

    def _shutdown(self) -> None:
        """Stop background engine loops and disconnect gracefully."""
        logger.info("Executing clean application shutdown...")
        if self._controller.is_running:
            self._controller.stop()

        if self._safety_manager.kill_switch_active:
            self._safety_manager.disable_kill_switch()

        if self._tray_icon:
            self._tray_icon.hide()

    def closeEvent(self, event: QCloseEvent) -> None:  # pylint: disable=invalid-name
        """Handle application window close request."""
        settings = self._config_service.get_settings()
        if settings.start_minimized and self._tray_icon and self._tray_icon.isVisible():
            # Minimize to tray instead of exiting
            self.hide()
            self._tray_icon.showMessage(
                "IP Changer",
                "IP Changer is still running in the background.",
                QSystemTrayIcon.Information,
                2000,
            )
            event.ignore()
            return

        self._shutdown()
        event.accept()
