"""IP Changer UI components package.

Contains PySide6 widgets, theme styles, background QThread workers, and main window.
"""

from src.ui.about_view import AboutWidget
from src.ui.connection_manager_view import ConnectionManagerWidget
from src.ui.dashboard import DashboardWidget
from src.ui.diagnostics_view import DiagnosticsWidget
from src.ui.history_view import HistoryWidget
from src.ui.main_window import MainWindow
from src.ui.settings_view import SettingsWidget
from src.ui.styles import DARK_THEME, LIGHT_THEME, get_theme_stylesheet

__all__ = [
    "MainWindow",
    "DashboardWidget",
    "ConnectionManagerWidget",
    "SettingsWidget",
    "HistoryWidget",
    "DiagnosticsWidget",
    "AboutWidget",
    "DARK_THEME",
    "LIGHT_THEME",
    "get_theme_stylesheet",
]
