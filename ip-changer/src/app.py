"""Application initialization and dependency wiring for IP Changer.

Assembles services, registers OS network adapters, instantiates the Qt GUI,
and coordinates lifecycle and clean process termination.
"""

from __future__ import annotations

import logging
import sys
from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from src.adapters.proxy_adapter import ProxyAdapter
from src.adapters.system_proxy_adapter import SystemProxyAdapter
from src.core.capability_registry import CapabilityRegistry
from src.core.connection_manager import ConnectionManager
from src.core.event_bus import EventBus
from src.core.ip_verifier import IPVerifier
from src.core.method_selector import MethodSelector
from src.core.rotation_controller import RotationController
from src.core.safety_manager import SafetyManager
from src.models.connection_profile import ConnectionType
from src.services.configuration_service import ConfigurationService
from src.services.diagnostics_service import DiagnosticsService
from src.services.logging_service import LoggingService
from src.services.secret_store import SecretStore
from src.ui.main_window import MainWindow

logger = logging.getLogger(__name__)


class IPChangerApp:
    """Master application controller managing services and UI lifecycle."""

    def __init__(self, argv: Optional[List[str]] = None) -> None:
        """Initialize the application.

        Args:
            argv: Command line arguments.
        """
        self._argv = argv if argv is not None else sys.argv

        # 1. Setup QApplication
        # High DPI attributes are default in Qt 6, but configure application metadata
        QApplication.setApplicationName("IP Changer")
        QApplication.setApplicationDisplayName("IP Changer - by Mahaduuu")
        QApplication.setOrganizationName("Mahaduuu")

        self.qapp = QApplication(self._argv)

        # 2. Initialize Configuration & Logging
        self.config_service = ConfigurationService()
        settings = self.config_service.get_settings()

        try:
            self.logging_service = LoggingService(settings)
            self.logging_service.setup_logging()
        except Exception as exc:  # pylint: disable=broad-except
            logging.basicConfig(level=logging.INFO)
            logger.warning("Could not initialize structured logging service: %s", exc)

        logger.info("Initializing IP Changer Desktop Application...")

        # 3. Create Core Infrastructure & Services
        self.event_bus = EventBus()
        self.capability_registry = CapabilityRegistry()
        self.secret_store = SecretStore()

        self.method_selector = MethodSelector(
            capability_registry=self.capability_registry,
            settings=settings,
            event_bus=self.event_bus,
        )

        self.connection_manager = ConnectionManager(
            event_bus=self.event_bus,
            capability_registry=self.capability_registry,
        )

        self.ip_verifier = IPVerifier(
            settings=settings,
            event_bus=self.event_bus,
        )

        self.safety_manager = SafetyManager(
            event_bus=self.event_bus,
            settings=settings,
        )

        self.rotation_controller = RotationController(
            method_selector=self.method_selector,
            connection_manager=self.connection_manager,
            ip_verifier=self.ip_verifier,
            settings=settings,
            event_bus=self.event_bus,
        )

        self.diagnostics_service = DiagnosticsService(
            ip_verifier=self.ip_verifier,
            connection_manager=self.connection_manager,
            safety_manager=self.safety_manager,
            settings=settings,
            event_bus=self.event_bus,
        )

        # 4. Register Platform Adapters
        self._register_adapters()

        # 5. Create Main UI Window
        self.main_window = MainWindow(
            rotation_controller=self.rotation_controller,
            configuration_service=self.config_service,
            connection_manager=self.connection_manager,
            ip_verifier=self.ip_verifier,
            method_selector=self.method_selector,
            safety_manager=self.safety_manager,
            diagnostics_service=self.diagnostics_service,
            secret_store=self.secret_store,
            event_bus=self.event_bus,
        )

    def _register_adapters(self) -> None:
        """Register proxy and system adapters with ConnectionManager."""
        proxy_adapter = ProxyAdapter(secret_store=self.secret_store)
        self.connection_manager.register_adapter(ConnectionType.HTTP_PROXY, proxy_adapter)
        self.connection_manager.register_adapter(ConnectionType.HTTPS_PROXY, proxy_adapter)
        self.connection_manager.register_adapter(ConnectionType.SOCKS5_PROXY, proxy_adapter)
        self.connection_manager.register_adapter(ConnectionType.ROTATION_GATEWAY, proxy_adapter)

        sys_adapter = SystemProxyAdapter()
        self.connection_manager.register_adapter(ConnectionType.VPN_SYSTEM, sys_adapter)
        logger.info("Platform adapters registered successfully")

    def run(self) -> int:
        """Launch the user interface and enter Qt event loop.

        Returns:
            Process exit status code.
        """
        settings = self.config_service.get_settings()
        if not settings.start_minimized:
            self.main_window.show()
        else:
            logger.info("Application started minimized to system tray.")

        return self.qapp.exec()
