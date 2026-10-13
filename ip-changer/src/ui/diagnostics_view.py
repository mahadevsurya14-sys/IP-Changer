"""Network and System Diagnostics Tab View for IP Changer.

Provides real-time inspection of internet connectivity, DNS leaks, public IPv4/IPv6
egress, kill switch enforcement, proxy latency, and remediation steps.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from src.core.event_bus import EventBus
from src.services.diagnostics_service import (
    DiagnosticCheck,
    DiagnosticSeverity,
    DiagnosticStatus,
    DiagnosticsService,
)
from src.ui.styles import COLOR_DANGER, COLOR_MUTED, COLOR_SUCCESS, COLOR_WARNING

logger = logging.getLogger(__name__)


class DiagnosticRunnerWorker(QThread):
    """Executes diagnostic checks suite in background thread."""

    checks_finished = Signal(list)  # List[DiagnosticCheck]
    error_occurred = Signal(str)

    def __init__(
        self,
        service: DiagnosticsService,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._service = service

    def run(self) -> None:
        try:
            results = self._service.run_all_checks()
            self.checks_finished.emit(results)
        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Diagnostics run failed: %s", exc)
            self.error_occurred.emit(str(exc))


class DiagnosticCard(QFrame):
    """Visual card displaying a single diagnostic check outcome."""

    def __init__(self, check: DiagnosticCheck, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._check = check
        self._remediation_visible = False
        self._init_ui()

    def _init_ui(self) -> None:
        self.setStyleSheet(
            "background-color: #16213e; border: 1px solid #0f3460; "
            "border-radius: 8px; margin-bottom: 8px;"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(8)

        # Header: Name, Status Badge, Severity
        header = QHBoxLayout()
        header.setSpacing(10)

        # Status Icon & Name
        icon_str = "✓"
        status_color = COLOR_SUCCESS
        if self._check.status == DiagnosticStatus.PASS:
            icon_str = "✓ PASS"
            status_color = COLOR_SUCCESS
        elif self._check.status == DiagnosticStatus.WARNING:
            icon_str = "⚠ WARNING"
            status_color = COLOR_WARNING
        elif self._check.status == DiagnosticStatus.FAIL:
            icon_str = "✗ FAIL"
            status_color = COLOR_DANGER
        else:
            icon_str = "? UNKNOWN"
            status_color = COLOR_MUTED

        lbl_name = QLabel(self._check.name)
        lbl_name.setStyleSheet("font-size: 14px; font-weight: bold; color: #f1f5f9;")
        header.addWidget(lbl_name)
        header.addStretch()

        # Severity Badge
        sev_str = self._check.severity.value if hasattr(self._check.severity, "value") else str(self._check.severity)
        lbl_sev = QLabel(sev_str.upper())
        lbl_sev.setStyleSheet(
            "background-color: #0f172a; color: #94a3b8; font-size: 11px; "
            "padding: 3px 8px; border-radius: 4px;"
        )
        header.addWidget(lbl_sev)

        # Status Badge
        lbl_status = QLabel(icon_str)
        lbl_status.setStyleSheet(
            f"background-color: {status_color}; color: #ffffff; font-weight: bold; "
            f"font-size: 11px; padding: 4px 12px; border-radius: 4px;"
        )
        header.addWidget(lbl_status)
        layout.addLayout(header)

        # Message
        lbl_msg = QLabel(self._check.message)
        lbl_msg.setWordWrap(True)
        lbl_msg.setStyleSheet("color: #cbd5e1; font-size: 13px;")
        layout.addWidget(lbl_msg)

        # Remediation Section (if present)
        if self._check.remediation:
            self._btn_toggle_rem = QPushButton("🔧 Show Remediation Steps")
            self._btn_toggle_rem.setStyleSheet(
                "background: transparent; color: #00d4ff; border: none; text-align: left; padding: 0; font-weight: 600;"
            )
            self._btn_toggle_rem.clicked.connect(self._toggle_remediation)
            layout.addWidget(self._btn_toggle_rem)

            self._lbl_remediation = QLabel(f"<b>Suggested Fix:</b> {self._check.remediation}")
            self._lbl_remediation.setWordWrap(True)
            self._lbl_remediation.setStyleSheet(
                "background-color: #0f172a; border-left: 3px solid #00d4ff; padding: 8px; border-radius: 4px; color: #93c5fd;"
            )
            self._lbl_remediation.setVisible(False)
            layout.addWidget(self._lbl_remediation)

    def _toggle_remediation(self) -> None:
        """Expand or collapse remediation details."""
        self._remediation_visible = not self._remediation_visible
        self._lbl_remediation.setVisible(self._remediation_visible)
        self._btn_toggle_rem.setText("🔧 Hide Remediation Steps" if self._remediation_visible else "🔧 Show Remediation Steps")


class DiagnosticsWidget(QWidget):
    """Network Diagnostics tab interface."""

    def __init__(
        self,
        diagnostics_service: DiagnosticsService,
        event_bus: EventBus,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._service = diagnostics_service
        self._event_bus = event_bus

        self._worker: Optional[DiagnosticRunnerWorker] = None
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header Bar
        header = QHBoxLayout()
        title_label = QLabel("Network Diagnostics & Leak Detection")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #00d4ff;")
        header.addWidget(title_label)
        header.addStretch()

        self._lbl_last_run = QLabel("Last Run: Never")
        self._lbl_last_run.setStyleSheet("color: #94a3b8; font-size: 13px;")
        header.addWidget(self._lbl_last_run)

        self._btn_run_all = QPushButton("▶ Run All Checks")
        self._btn_run_all.setProperty("buttonRole", "primary")
        self._btn_run_all.setMinimumHeight(36)
        self._btn_run_all.setStyleSheet("font-weight: bold; padding: 6px 18px;")
        self._btn_run_all.clicked.connect(self._on_run_all_clicked)
        header.addWidget(self._btn_run_all)

        layout.addLayout(header)

        # Progress bar (hidden when idle)
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)  # indeterminate pulsing
        self._progress_bar.setFixedHeight(6)
        self._progress_bar.setTextVisible(False)
        self._progress_bar.setVisible(False)
        layout.addWidget(self._progress_bar)

        # Scrollable Cards Area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        self._cards_container = QWidget()
        self._cards_layout = QVBoxLayout(self._cards_container)
        self._cards_layout.setContentsMargins(0, 0, 0, 0)
        self._cards_layout.setSpacing(10)

        # Initial Welcome / Placeholder Card
        self._lbl_placeholder = QLabel(
            "Click 'Run All Checks' to perform a complete diagnostic audit of "
            "internet connectivity, DNS leaks, egress IP, kill switch posture, and proxy health."
        )
        self._lbl_placeholder.setStyleSheet("color: #94a3b8; font-size: 14px; padding: 40px; text-align: center;")
        self._lbl_placeholder.setAlignment(Qt.AlignCenter)
        self._cards_layout.addWidget(self._lbl_placeholder)
        self._cards_layout.addStretch()

        scroll.setWidget(self._cards_container)
        layout.addWidget(scroll)

    def _on_run_all_clicked(self) -> None:
        """Trigger diagnostic worker execution."""
        if self._worker and self._worker.isRunning():
            return

        self._btn_run_all.setEnabled(False)
        self._btn_run_all.setText("Running Checks...")
        self._progress_bar.setVisible(True)

        self._worker = DiagnosticRunnerWorker(self._service, parent=self)
        self._worker.checks_finished.connect(self._on_checks_completed)
        self._worker.error_occurred.connect(self._on_checks_error)
        self._worker.start()

    def _on_checks_completed(self, results: List[DiagnosticCheck]) -> None:
        """Populate cards with completed diagnostic probe results."""
        self._btn_run_all.setEnabled(True)
        self._btn_run_all.setText("▶ Run All Checks")
        self._progress_bar.setVisible(False)

        self._lbl_last_run.setText(f"Last Run: {datetime.now().strftime('%H:%M:%S')}")

        # Clear existing cards
        while self._cards_layout.count() > 0:
            item = self._cards_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

        for check in results:
            card = DiagnosticCard(check, parent=self._cards_container)
            self._cards_layout.addWidget(card)

        self._cards_layout.addStretch()

    def _on_checks_error(self, err_msg: str) -> None:
        """Handle error from runner."""
        self._btn_run_all.setEnabled(True)
        self._btn_run_all.setText("▶ Run All Checks")
        self._progress_bar.setVisible(False)
        logger.error("Diagnostics error: %s", err_msg)
