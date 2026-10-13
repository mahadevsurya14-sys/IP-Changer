"""UI styling and theme definitions for IP Changer.

Provides polished modern dark and light Qt stylesheets (QSS) adhering to
application UI design principles.
"""

from __future__ import annotations

import sys
from typing import Union
from src.models.app_settings import ThemeMode

FONT_FAMILY = "Segoe UI" if sys.platform == "win32" else "Sans-Serif"

# Status Colors
COLOR_SUCCESS = "#22c55e"     # Green (Connected / IP Changed)
COLOR_DANGER = "#ef4444"      # Red (Error / Disconnected)
COLOR_WARNING = "#f59e0b"     # Amber / Yellow (Warning / Unchanged / Connecting)
COLOR_INFO = "#3b82f6"        # Blue (Info / Neutral active)
COLOR_MUTED = "#6b7280"       # Gray (Idle / Disabled)
COLOR_ACCENT = "#00d4ff"      # Cyan accent
COLOR_ACCENT_ALT = "#e94560"  # Crimson accent

DARK_THEME = f"""
/* Global Reset and Typography */
QWidget {{
    background-color: #1a1a2e;
    color: #e2e8f0;
    font-family: "{FONT_FAMILY}";
    font-size: 13px;
    selection-background-color: #0f3460;
    selection-color: #00d4ff;
}}

/* Main Window & Central Widget */
QMainWindow, QDialog {{
    background-color: #1a1a2e;
}}

/* Scroll Areas and Container Backgrounds */
QScrollArea, QScrollArea > QWidget > QWidget {{
    background-color: #1a1a2e;
    border: none;
}}

/* Tab Widget Styling */
QTabWidget::pane {{
    border: 1px solid #16213e;
    background-color: #1a1a2e;
    border-radius: 8px;
    margin-top: -1px;
    padding: 6px;
}}

QTabBar::tab {{
    background-color: #16213e;
    color: #94a3b8;
    border: 1px solid #0f3460;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    min-width: 110px;
    padding: 8px 14px;
    font-weight: 600;
    margin-right: 4px;
}}

QTabBar::tab:selected {{
    background-color: #0f3460;
    color: #00d4ff;
    border: 1px solid #00d4ff;
    border-bottom: none;
}}

QTabBar::tab:hover:!selected {{
    background-color: #1e293b;
    color: #f1f5f9;
}}

/* Group Boxes / Cards */
QGroupBox {{
    font-size: 13px;
    font-weight: bold;
    color: #00d4ff;
    border: 1px solid #0f3460;
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 18px;
    padding-bottom: 12px;
    padding-left: 12px;
    padding-right: 12px;
    background-color: #16213e;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    left: 12px;
    background-color: #16213e;
    border-radius: 4px;
}}

/* Buttons */
QPushButton {{
    background-color: #0f3460;
    color: #f8fafc;
    border: 1px solid #1e40af;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 600;
    min-height: 20px;
}}

QPushButton:hover {{
    background-color: #1d4ed8;
    border-color: #3b82f6;
}}

QPushButton:pressed {{
    background-color: #1e3a8a;
}}

QPushButton:disabled {{
    background-color: #27273a;
    border-color: #3f3f5a;
    color: #64748b;
}}

/* Primary / Action Buttons */
QPushButton[buttonRole="primary"] {{
    background-color: #0284c7;
    border: 1px solid #38bdf8;
    color: #ffffff;
}}
QPushButton[buttonRole="primary"]:hover {{
    background-color: #0369a1;
}}
QPushButton[buttonRole="primary"]:pressed {{
    background-color: #075985;
}}

/* Success Buttons */
QPushButton[buttonRole="success"] {{
    background-color: #15803d;
    border: 1px solid #22c55e;
    color: #ffffff;
}}
QPushButton[buttonRole="success"]:hover {{
    background-color: #16a34a;
}}
QPushButton[buttonRole="success"]:pressed {{
    background-color: #14532d;
}}

/* Danger Buttons */
QPushButton[buttonRole="danger"] {{
    background-color: #b91c1c;
    border: 1px solid #ef4444;
    color: #ffffff;
}}
QPushButton[buttonRole="danger"]:hover {{
    background-color: #dc2626;
}}
QPushButton[buttonRole="danger"]:pressed {{
    background-color: #991b1b;
}}

/* Warning / Pause Buttons */
QPushButton[buttonRole="warning"] {{
    background-color: #b45309;
    border: 1px solid #f59e0b;
    color: #ffffff;
}}
QPushButton[buttonRole="warning"]:hover {{
    background-color: #d97706;
}}
QPushButton[buttonRole="warning"]:pressed {{
    background-color: #78350f;
}}

/* Input Fields & Text Editors */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox {{
    background-color: #0f172a;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: #0f3460;
    selection-color: #00d4ff;
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
    border: 1px solid #00d4ff;
}}

QLineEdit:read-only, QTextEdit:read-only {{
    background-color: #1e293b;
    color: #94a3b8;
}}

/* Combo Boxes */
QComboBox {{
    background-color: #0f172a;
    color: #f8fafc;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px 10px;
    min-height: 20px;
}}

QComboBox:focus, QComboBox:hover {{
    border: 1px solid #00d4ff;
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: 1px solid #334155;
    border-top-right-radius: 6px;
    border-bottom-right-radius: 6px;
}}

QComboBox QAbstractItemView {{
    background-color: #0f172a;
    color: #f8fafc;
    border: 1px solid #00d4ff;
    selection-background-color: #0f3460;
    selection-color: #00d4ff;
    padding: 4px;
}}

/* Tables and Lists */
QTableWidget, QTableView, QListWidget, QListView {{
    background-color: #16213e;
    color: #f8fafc;
    border: 1px solid #0f3460;
    border-radius: 6px;
    gridline-color: #1e293b;
    selection-background-color: #0f3460;
    selection-color: #00d4ff;
}}

QHeaderView::section {{
    background-color: #0f172a;
    color: #94a3b8;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #0f3460;
    font-weight: bold;
}}

QTableWidget::item, QListWidget::item {{
    padding: 6px;
}}

QTableWidget::item:selected, QListWidget::item:selected {{
    background-color: #0f3460;
    color: #00d4ff;
}}

/* ScrollBars */
QScrollBar:vertical {{
    background: #16213e;
    width: 10px;
    margin: 0;
    border-radius: 5px;
}}

QScrollBar::handle:vertical {{
    background: #334155;
    min-height: 24px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical:hover {{
    background: #475569;
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background: #16213e;
    height: 10px;
    margin: 0;
    border-radius: 5px;
}}

QScrollBar::handle:horizontal {{
    background: #334155;
    min-width: 24px;
    border-radius: 5px;
}}

QScrollBar::handle:horizontal:hover {{
    background: #475569;
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* CheckBoxes and RadioButtons */
QCheckBox, QRadioButton {{
    spacing: 8px;
    color: #f1f5f9;
}}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 18px;
    height: 18px;
    border: 1px solid #475569;
    border-radius: 4px;
    background-color: #0f172a;
}}

QRadioButton::indicator {{
    border-radius: 9px;
}}

QCheckBox::indicator:hover, QRadioButton::indicator:hover {{
    border-color: #00d4ff;
}}

QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background-color: #00d4ff;
    border-color: #00d4ff;
}}

/* Sliders & Progress Bars */
QProgressBar {{
    border: 1px solid #334155;
    border-radius: 6px;
    text-align: center;
    background-color: #0f172a;
    color: #ffffff;
    height: 18px;
}}

QProgressBar::chunk {{
    background-color: #0284c7;
    border-radius: 5px;
}}

/* Menu and Menu Bar */
QMenuBar {{
    background-color: #16213e;
    color: #e2e8f0;
    border-bottom: 1px solid #0f3460;
    padding: 2px;
}}

QMenuBar::item {{
    background: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}}

QMenuBar::item:selected {{
    background-color: #0f3460;
    color: #00d4ff;
}}

QMenu {{
    background-color: #16213e;
    color: #e2e8f0;
    border: 1px solid #0f3460;
    border-radius: 6px;
    padding: 4px;
}}

QMenu::item {{
    padding: 6px 20px 6px 20px;
    border-radius: 4px;
}}

QMenu::item:selected {{
    background-color: #0f3460;
    color: #00d4ff;
}}

QMenu::separator {{
    height: 1px;
    background: #334155;
    margin: 4px 8px;
}}

/* Status Bar */
QStatusBar {{
    background-color: #16213e;
    color: #94a3b8;
    border-top: 1px solid #0f3460;
}}

/* Tooltips */
QToolTip {{
    background-color: #0f172a;
    color: #f8fafc;
    border: 1px solid #00d4ff;
    border-radius: 4px;
    padding: 5px 8px;
}}
"""

LIGHT_THEME = f"""
/* Global Reset and Typography */
QWidget {{
    background-color: #f8fafc;
    color: #1e293b;
    font-family: "{FONT_FAMILY}";
    font-size: 13px;
    selection-background-color: #e0f2fe;
    selection-color: #0284c7;
}}

/* Main Window & Central Widget */
QMainWindow, QDialog {{
    background-color: #f8fafc;
}}

/* Scroll Areas and Container Backgrounds */
QScrollArea, QScrollArea > QWidget > QWidget {{
    background-color: #f8fafc;
    border: none;
}}

/* Tab Widget Styling */
QTabWidget::pane {{
    border: 1px solid #cbd5e1;
    background-color: #ffffff;
    border-radius: 8px;
    margin-top: -1px;
    padding: 6px;
}}

QTabBar::tab {{
    background-color: #e2e8f0;
    color: #475569;
    border: 1px solid #cbd5e1;
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    min-width: 110px;
    padding: 8px 14px;
    font-weight: 600;
    margin-right: 4px;
}}

QTabBar::tab:selected {{
    background-color: #ffffff;
    color: #0284c7;
    border: 1px solid #0284c7;
    border-bottom: none;
}}

QTabBar::tab:hover:!selected {{
    background-color: #f1f5f9;
    color: #0f172a;
}}

/* Group Boxes / Cards */
QGroupBox {{
    font-size: 13px;
    font-weight: bold;
    color: #0369a1;
    border: 1px solid #cbd5e1;
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 18px;
    padding-bottom: 12px;
    padding-left: 12px;
    padding-right: 12px;
    background-color: #ffffff;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    left: 12px;
    background-color: #ffffff;
    border-radius: 4px;
}}

/* Buttons */
QPushButton {{
    background-color: #f1f5f9;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 600;
    min-height: 20px;
}}

QPushButton:hover {{
    background-color: #e2e8f0;
    border-color: #94a3b8;
}}

QPushButton:pressed {{
    background-color: #cbd5e1;
}}

QPushButton:disabled {{
    background-color: #f8fafc;
    border-color: #e2e8f0;
    color: #94a3b8;
}}

/* Primary Buttons */
QPushButton[buttonRole="primary"] {{
    background-color: #0284c7;
    border: 1px solid #0369a1;
    color: #ffffff;
}}
QPushButton[buttonRole="primary"]:hover {{
    background-color: #0369a1;
}}
QPushButton[buttonRole="primary"]:pressed {{
    background-color: #075985;
}}

/* Success Buttons */
QPushButton[buttonRole="success"] {{
    background-color: #16a34a;
    border: 1px solid #15803d;
    color: #ffffff;
}}
QPushButton[buttonRole="success"]:hover {{
    background-color: #15803d;
}}
QPushButton[buttonRole="success"]:pressed {{
    background-color: #166534;
}}

/* Danger Buttons */
QPushButton[buttonRole="danger"] {{
    background-color: #dc2626;
    border: 1px solid #b91c1c;
    color: #ffffff;
}}
QPushButton[buttonRole="danger"]:hover {{
    background-color: #b91c1c;
}}
QPushButton[buttonRole="danger"]:pressed {{
    background-color: #991b1b;
}}

/* Warning / Pause Buttons */
QPushButton[buttonRole="warning"] {{
    background-color: #d97706;
    border: 1px solid #b45309;
    color: #ffffff;
}}
QPushButton[buttonRole="warning"]:hover {{
    background-color: #b45309;
}}
QPushButton[buttonRole="warning"]:pressed {{
    background-color: #78350f;
}}

/* Input Fields & Text Editors */
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox {{
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: #bae6fd;
    selection-color: #0284c7;
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
    border: 1px solid #0284c7;
}}

QLineEdit:read-only, QTextEdit:read-only {{
    background-color: #f1f5f9;
    color: #64748b;
}}

/* Combo Boxes */
QComboBox {{
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 6px 10px;
    min-height: 20px;
}}

QComboBox:focus, QComboBox:hover {{
    border: 1px solid #0284c7;
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: 1px solid #cbd5e1;
    border-top-right-radius: 6px;
    border-bottom-right-radius: 6px;
}}

QComboBox QAbstractItemView {{
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #0284c7;
    selection-background-color: #e0f2fe;
    selection-color: #0284c7;
    padding: 4px;
}}

/* Tables and Lists */
QTableWidget, QTableView, QListWidget, QListView {{
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    gridline-color: #f1f5f9;
    selection-background-color: #e0f2fe;
    selection-color: #0284c7;
}}

QHeaderView::section {{
    background-color: #f8fafc;
    color: #475569;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #cbd5e1;
    font-weight: bold;
}}

QTableWidget::item, QListWidget::item {{
    padding: 6px;
}}

QTableWidget::item:selected, QListWidget::item:selected {{
    background-color: #e0f2fe;
    color: #0284c7;
}}

/* ScrollBars */
QScrollBar:vertical {{
    background: #f1f5f9;
    width: 10px;
    margin: 0;
    border-radius: 5px;
}}

QScrollBar::handle:vertical {{
    background: #cbd5e1;
    min-height: 24px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical:hover {{
    background: #94a3b8;
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

/* CheckBoxes and RadioButtons */
QCheckBox, QRadioButton {{
    spacing: 8px;
    color: #1e293b;
}}

QCheckBox::indicator, QRadioButton::indicator {{
    width: 18px;
    height: 18px;
    border: 1px solid #cbd5e1;
    border-radius: 4px;
    background-color: #ffffff;
}}

QRadioButton::indicator {{
    border-radius: 9px;
}}

QCheckBox::indicator:hover, QRadioButton::indicator:hover {{
    border-color: #0284c7;
}}

QCheckBox::indicator:checked, QRadioButton::indicator:checked {{
    background-color: #0284c7;
    border-color: #0284c7;
}}

/* Sliders & Progress Bars */
QProgressBar {{
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    text-align: center;
    background-color: #f1f5f9;
    color: #0f172a;
    height: 18px;
}}

QProgressBar::chunk {{
    background-color: #0284c7;
    border-radius: 5px;
}}

/* Menu and Menu Bar */
QMenuBar {{
    background-color: #ffffff;
    color: #1e293b;
    border-bottom: 1px solid #cbd5e1;
    padding: 2px;
}}

QMenuBar::item {{
    background: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}}

QMenuBar::item:selected {{
    background-color: #e0f2fe;
    color: #0284c7;
}}

QMenu {{
    background-color: #ffffff;
    color: #1e293b;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 4px;
}}

QMenu::item {{
    padding: 6px 20px 6px 20px;
    border-radius: 4px;
}}

QMenu::item:selected {{
    background-color: #e0f2fe;
    color: #0284c7;
}}

/* Status Bar */
QStatusBar {{
    background-color: #f1f5f9;
    color: #64748b;
    border-top: 1px solid #cbd5e1;
}}

/* Tooltips */
QToolTip {{
    background-color: #ffffff;
    color: #0f172a;
    border: 1px solid #0284c7;
    border-radius: 4px;
    padding: 5px 8px;
}}
"""


def get_theme_stylesheet(theme: Union[ThemeMode, str]) -> str:
    """Return appropriate QSS stylesheet string for given theme.

    Args:
        theme: ThemeMode enum value or string representation.
    """
    mode = theme.value if isinstance(theme, ThemeMode) else str(theme).lower()
    if mode == ThemeMode.LIGHT.value:
        return LIGHT_THEME
    # Default to dark theme for "dark" and "system"
    return DARK_THEME


def get_status_color(status: str) -> str:
    """Map status string to hex color code."""
    status_lower = str(status).lower()
    if any(s in status_lower for s in ("connected", "success", "pass", "ok")):
        return COLOR_SUCCESS
    if any(s in status_lower for s in ("connecting", "verifying", "rotating", "warn", "unchanged", "validating")):
        return COLOR_WARNING
    if any(s in status_lower for s in ("error", "failed", "blocked")):
        return COLOR_DANGER
    return COLOR_MUTED
