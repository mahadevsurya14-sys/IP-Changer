"""Rotation History Tab View for IP Changer.

Maintains an auditable, color-coded tabular ledger of all rotation events,
statistical success rates, filtering, and CSV export capabilities.
"""

from __future__ import annotations

import csv
import logging
from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.core.event_bus import EventBus, ROTATION_COMPLETED
from src.core.rotation_controller import RotationController
from src.models.rotation_event import RotationEvent, RotationResult
from src.ui.styles import COLOR_DANGER, COLOR_MUTED, COLOR_SUCCESS, COLOR_WARNING

logger = logging.getLogger(__name__)


class HistoryWidget(QWidget):
    """Historical rotation event ledger and analysis view."""

    def __init__(
        self,
        rotation_controller: RotationController,
        event_bus: EventBus,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._controller = rotation_controller
        self._event_bus = event_bus

        self._init_ui()
        self._load_events()
        self._connect_event_bus()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # Header Title and Statistics Card
        header_layout = QHBoxLayout()
        title_label = QLabel("Rotation History & Audit Log")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #00d4ff;")
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        # Filter Dropdown
        lbl_filter = QLabel("Filter Result:")
        lbl_filter.setStyleSheet("color: #94a3b8; font-weight: 500;")
        self._combo_filter = QComboBox()
        self._combo_filter.addItem("All Events", "all")
        self._combo_filter.addItem("IP Changed", "changed")
        self._combo_filter.addItem("IP Unchanged", "unchanged")
        self._combo_filter.addItem("Failed Attempts", "failed")
        self._combo_filter.currentIndexChanged.connect(self._load_events)

        header_layout.addWidget(lbl_filter)
        header_layout.addWidget(self._combo_filter)
        layout.addLayout(header_layout)

        # Summary Statistics Bar
        stats_frame = QFrame()
        stats_frame.setStyleSheet(
            "background-color: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 10px;"
        )
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setContentsMargins(14, 8, 14, 8)

        self._lbl_stat_total = QLabel("Total Events: 0")
        self._lbl_stat_total.setStyleSheet("color: #f1f5f9; font-weight: bold;")

        self._lbl_stat_success_rate = QLabel("Success Rate: 0.0%")
        self._lbl_stat_success_rate.setStyleSheet("color: #22c55e; font-weight: bold;")

        self._lbl_stat_change_rate = QLabel("Actual Change Rate: 0.0%")
        self._lbl_stat_change_rate.setStyleSheet("color: #00d4ff; font-weight: bold;")

        self._lbl_stat_avg_dur = QLabel("Avg Duration: 0.00s")
        self._lbl_stat_avg_dur.setStyleSheet("color: #f59e0b; font-weight: bold;")

        stats_layout.addWidget(self._lbl_stat_total)
        stats_layout.addStretch()
        stats_layout.addWidget(self._lbl_stat_success_rate)
        stats_layout.addStretch()
        stats_layout.addWidget(self._lbl_stat_change_rate)
        stats_layout.addStretch()
        stats_layout.addWidget(self._lbl_stat_avg_dur)

        layout.addWidget(stats_frame)

        # History Table
        self._table = QTableWidget()
        self._table.setColumnCount(9)
        self._table.setHorizontalHeaderLabels([
            "#", "Timestamp", "Profile", "Method", "Previous IP", "New IP", "Changed", "Result", "Duration"
        ])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(7, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(8, QHeaderView.ResizeToContents)

        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setAlternatingRowColors(True)
        layout.addWidget(self._table)

        # Bottom Action Buttons
        action_layout = QHBoxLayout()

        self._btn_clear = QPushButton("🗑 Clear History")
        self._btn_clear.setProperty("buttonRole", "danger")
        self._btn_clear.clicked.connect(self._on_clear_history)

        self._btn_export = QPushButton("📥 Export to CSV")
        self._btn_export.setProperty("buttonRole", "primary")
        self._btn_export.clicked.connect(self._on_export_csv)

        action_layout.addWidget(self._btn_clear)
        action_layout.addStretch()
        action_layout.addWidget(self._btn_export)
        layout.addLayout(action_layout)

    def _connect_event_bus(self) -> None:
        """Subscribe to rotation events for auto-refresh."""
        self._event_bus.subscribe(ROTATION_COMPLETED, lambda _: self._load_events())

    def _load_events(self) -> None:
        """Reload events from controller history and update table and stats."""
        events = self._controller.history.get_events()
        filter_mode = self._combo_filter.currentData()

        # Filter events
        filtered: List[RotationEvent] = []
        for e in events:
            if filter_mode == "changed" and not e.ip_changed:
                continue
            if filter_mode == "unchanged" and (
                e.ip_changed or e.result not in {RotationResult.SUCCESS_IP_UNCHANGED, RotationResult.SUCCESS_IP_CHANGED}
            ):
                continue
            if filter_mode == "failed" and e.result in {
                RotationResult.SUCCESS_IP_CHANGED,
                RotationResult.SUCCESS_IP_UNCHANGED,
            }:
                continue
            filtered.append(e)

        # Update stats
        stats = self._controller.history.get_stats()
        total = stats.get("total", 0)
        success_cnt = stats.get("success_count", 0)
        changed_cnt = stats.get("ip_changed_count", 0)
        avg_dur = stats.get("avg_duration_seconds", 0.0)

        success_rate = (success_cnt / total * 100.0) if total > 0 else 0.0
        change_rate = (changed_cnt / total * 100.0) if total > 0 else 0.0

        self._lbl_stat_total.setText(f"Total Events: {total}")
        self._lbl_stat_success_rate.setText(f"Success Rate: {success_rate:.1f}%")
        self._lbl_stat_change_rate.setText(f"Actual Change Rate: {change_rate:.1f}%")
        self._lbl_stat_avg_dur.setText(f"Avg Duration: {avg_dur:.2f}s")

        # Populate table (display newest at the top)
        display_events = list(reversed(filtered))
        self._table.setRowCount(len(display_events))

        for row, ev in enumerate(display_events):
            item_num = QTableWidgetItem(str(ev.rotation_number or (len(filtered) - row)))
            item_num.setTextAlignment(Qt.AlignCenter)

            # Format timestamp nicely
            ts_display = ev.timestamp
            if "T" in ts_display:
                ts_display = ts_display.split("T")[1][:8]

            item_ts = QTableWidgetItem(ts_display)
            item_ts.setTextAlignment(Qt.AlignCenter)

            item_prof = QTableWidgetItem(ev.profile_name or "Direct")
            item_method = QTableWidgetItem(ev.method_type.replace("_", " ").title())

            item_prev = QTableWidgetItem(ev.previous_ip or "—")
            item_prev.setTextAlignment(Qt.AlignCenter)

            item_new = QTableWidgetItem(ev.new_ip or "—")
            item_new.setTextAlignment(Qt.AlignCenter)

            item_changed = QTableWidgetItem("✓ Yes" if ev.ip_changed else "✗ No")
            item_changed.setTextAlignment(Qt.AlignCenter)

            # Result status text & color
            res_str = ev.result.value if isinstance(ev.result, RotationResult) else str(ev.result)
            item_res = QTableWidgetItem(res_str.replace("_", " ").title())
            item_res.setTextAlignment(Qt.AlignCenter)

            item_dur = QTableWidgetItem(f"{ev.duration_seconds:.2f}s")
            item_dur.setTextAlignment(Qt.AlignCenter)

            # Color coding
            if ev.ip_changed:
                row_color = QColor(COLOR_SUCCESS)
            elif ev.result in {RotationResult.SUCCESS_IP_UNCHANGED, RotationResult.SUCCESS_IP_CHANGED}:
                row_color = QColor(COLOR_WARNING)
            else:
                row_color = QColor(COLOR_DANGER)

            item_res.setForeground(row_color)
            item_changed.setForeground(row_color)

            self._table.setItem(row, 0, item_num)
            self._table.setItem(row, 1, item_ts)
            self._table.setItem(row, 2, item_prof)
            self._table.setItem(row, 3, item_method)
            self._table.setItem(row, 4, item_prev)
            self._table.setItem(row, 5, item_new)
            self._table.setItem(row, 6, item_changed)
            self._table.setItem(row, 7, item_res)
            self._table.setItem(row, 8, item_dur)

    def _on_clear_history(self) -> None:
        """Clear recorded events with user confirmation."""
        confirm = QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to purge all recorded rotation events?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            self._controller.history.clear()
            self._load_events()

    def _on_export_csv(self) -> None:
        """Export history entries to CSV."""
        events = self._controller.history.get_events()
        if not events:
            QMessageBox.information(self, "Export CSV", "No rotation events available to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Rotation History to CSV",
            "ip_rotation_history.csv",
            "CSV Files (*.csv);;All Files (*.*)",
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Rotation Number",
                    "Timestamp",
                    "Profile Name",
                    "Method Type",
                    "Previous IP",
                    "New IP",
                    "IP Changed",
                    "Result",
                    "Duration (s)",
                    "Error Message",
                ])
                for ev in events:
                    res_val = ev.result.value if isinstance(ev.result, RotationResult) else str(ev.result)
                    writer.writerow([
                        ev.rotation_number,
                        ev.timestamp,
                        ev.profile_name,
                        ev.method_type,
                        ev.previous_ip or "",
                        ev.new_ip or "",
                        ev.ip_changed,
                        res_val,
                        f"{ev.duration_seconds:.3f}",
                        ev.error_message or "",
                    ])
            QMessageBox.information(self, "Export Successful", f"Saved {len(events)} events to {file_path}")
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", f"Could not write CSV file: {exc}")
