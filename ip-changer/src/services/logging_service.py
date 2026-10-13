"""Logging service with automatic credential redaction and retention management.

Provides structured, thread-safe file and console logging with automatic sanitization
of sensitive credentials, URLs, bearer tokens, and keys.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

from src.models.app_settings import AppSettings

DEFAULT_LOG_FORMAT = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
DEFAULT_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Regex patterns for credential masking
PATTERNS = [
    # HTTP basic auth / user:pass in URLs
    (re.compile(r"(https?|socks5?|socks5h)://([^:\s]+):([^@\s]+)@", re.IGNORECASE), r"\1://\2:[REDACTED]@"),
    # Bearer tokens
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.\+/]+={0,2}", re.IGNORECASE), r"\1[REDACTED]"),
    # Generic password/token/key query params or key-values
    (re.compile(r"(password|passwd|pwd|token|api_key|secret|auth_token)\s*[:=]\s*([^\s,;]+)", re.IGNORECASE), r"\1=[REDACTED]"),
    # SSH / VPN private key blocks
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"), r"[PRIVATE KEY REDACTED]"),
]


def sanitize_text(text: str) -> str:
    """Mask credentials and sensitive strings within log messages.

    Args:
        text: Raw log message.

    Returns:
        Redacted message string.
    """
    if not isinstance(text, str):
        text = str(text)

    sanitized = text
    for pattern, replacement in PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class SanitizingFilter(logging.Filter):
    """Logging filter that scrubs sensitive credentials from all record messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.msg:
            if isinstance(record.msg, str):
                record.msg = sanitize_text(record.msg)
            elif record.args:
                # If arguments were provided for format string
                try:
                    formatted = record.msg % record.args
                    record.msg = sanitize_text(formatted)
                    record.args = ()
                except Exception:
                    record.msg = sanitize_text(str(record.msg))

        if record.args and isinstance(record.args, tuple):
            record.args = tuple(
                sanitize_text(str(arg)) if isinstance(arg, str) else arg
                for arg in record.args
            )

        return True


class LoggingService:
    """Configures application logging, enforces retention, and sanitizes output."""

    def __init__(self, settings: Optional[AppSettings] = None) -> None:
        """Initialize the LoggingService.

        Args:
            settings: Application settings controlling paths, levels, and rotation.
        """
        self.settings = settings or AppSettings()
        self._log_file_path: Optional[Path] = None
        self._root_logger = logging.getLogger()
        self._sanitizing_filter = SanitizingFilter()

    def get_log_file_path(self) -> Path:
        """Resolve and ensure the active log file directory and path.

        Returns:
            Path object pointing to the primary app.log file.
        """
        if self._log_file_path is None:
            base_dir = Path(self.settings.log_directory)
            if not base_dir.is_absolute():
                base_dir = Path.cwd() / base_dir
            base_dir.mkdir(parents=True, exist_ok=True)
            self._log_file_path = base_dir / "ip_changer.log"
        return self._log_file_path

    def sanitize_message(self, msg: str) -> str:
        """Expose sanitization helper publicly."""
        return sanitize_text(msg)

    def setup_logging(self) -> None:
        """Configure root logger with RotatingFileHandler and StreamHandler."""
        log_level_str = self.settings.log_level.upper()
        log_level = getattr(logging, log_level_str, logging.INFO)

        self._root_logger.setLevel(log_level)

        # Clear any existing handlers to prevent duplicate lines
        for handler in list(self._root_logger.handlers):
            self._root_logger.removeHandler(handler)

        formatter = logging.Formatter(fmt=DEFAULT_LOG_FORMAT, datefmt=DEFAULT_DATE_FORMAT)

        # 1. Console Handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(self._sanitizing_filter)
        self._root_logger.addHandler(console_handler)

        # 2. Rotating File Handler
        log_path = self.get_log_file_path()
        try:
            file_handler = RotatingFileHandler(
                filename=str(log_path),
                maxBytes=self.settings.max_log_size_bytes,
                backupCount=self.settings.log_backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            file_handler.addFilter(self._sanitizing_filter)
            self._root_logger.addHandler(file_handler)
        except Exception as exc:
            print(f"[LoggingService] Failed to initialize file handler at {log_path}: {exc}", file=sys.stderr)

        logging.captureWarnings(True)
        self._root_logger.info("Logging initialized at level %s. Log target: %s", log_level_str, log_path)

        # Apply log retention policy
        self.rotate_logs()

    def rotate_logs(self) -> None:
        """Enforce log retention policy by removing expired archived log files."""
        log_path = self.get_log_file_path()
        log_dir = log_path.parent
        if not log_dir.exists():
            return

        retention_days = max(1, self.settings.log_retention_days)
        cutoff_timestamp = time.time() - (retention_days * 86400)

        try:
            for item in log_dir.iterdir():
                if item.is_file() and item.name.startswith("ip_changer.log"):
                    # Check age of backup log files (e.g., ip_changer.log.1, ip_changer.log.2)
                    if item != log_path:
                        mtime = item.stat().st_mtime
                        if mtime < cutoff_timestamp:
                            item.unlink(missing_ok=True)
                            self._root_logger.info("Purged expired archived log file: %s", item.name)
        except Exception as exc:
            self._root_logger.warning("Error pruning archived logs: %s", exc)

    def clear_logs(self) -> None:
        """Truncate the active log file and delete historical backups."""
        log_path = self.get_log_file_path()
        log_dir = log_path.parent

        # Flush all handlers
        for handler in self._root_logger.handlers:
            handler.flush()

        try:
            # Delete archived files
            if log_dir.exists():
                for item in log_dir.iterdir():
                    if item.is_file() and item.name.startswith("ip_changer.log") and item != log_path:
                        item.unlink(missing_ok=True)

            # Truncate main log file
            if log_path.exists():
                with open(log_path, "w", encoding="utf-8") as f:
                    f.truncate(0)

            self._root_logger.info("Log file reset and history cleared.")
        except Exception as exc:
            self._root_logger.error("Failed to clear log files: %s", exc)
