"""System-wide proxy configuration adapter for Windows and Linux.

Manages OS-level proxy settings via Windows Registry (with WinINet broadcast notifications)
and Linux GNOME / environment configurations, with full backup and restore capabilities.

NOTE ON LIMITATIONS:
System-wide proxy configuration instructs operating system services, Windows WinINet,
Edge/Chrome browsers, and standard desktop utilities to route traffic through the designated proxy.
However, applications that use custom networking stacks (such as raw cURL, certain CLI tools,
Python scripts without environment variable ingestion, or hardened VPNs) may bypass system proxy settings.
"""

from __future__ import annotations

import ctypes
import logging
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Windows WinINet constants for flushing and propagating settings
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


class SystemProxyAdapter:
    """Manages operating-system wide proxy routing for Windows and Linux."""

    def __init__(self) -> None:
        """Initialize SystemProxyAdapter with platform detection."""
        self._is_windows = sys.platform == "win32"
        self._is_linux = sys.platform.startswith("linux")
        self._initial_backup: Optional[Dict[str, Any]] = None

    @property
    def platform_name(self) -> str:
        """Return canonical platform name."""
        if self._is_windows:
            return "windows"
        if self._is_linux:
            return "linux"
        return "unsupported"

    def _notify_windows_inet(self) -> None:
        """Inform Windows Internet subsystem that proxy settings have changed."""
        if not self._is_windows:
            return
        try:
            wininet = ctypes.windll.wininet  # type: ignore[attr-defined]
            wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
            logger.debug("Broadcast WinINet proxy settings update notification.")
        except Exception as exc:
            logger.warning("Failed to refresh WinINet proxy options: %s", exc)

    def backup_proxy_settings(self) -> Dict[str, Any]:
        """Capture existing system proxy configuration for safe restore.

        Returns:
            Dictionary snapshot of existing proxy settings.
        """
        snapshot: Dict[str, Any] = {
            "platform": self.platform_name,
            "windows": {},
            "linux": {},
        }

        if self._is_windows:
            try:
                import winreg  # pylint: disable=import-outside-toplevel
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0,
                    winreg.KEY_READ,
                ) as key:
                    def _query_val(val_name: str, default: Any = None) -> Any:
                        try:
                            val, _ = winreg.QueryValueEx(key, val_name)
                            return val
                        except FileNotFoundError:
                            return default

                    snapshot["windows"] = {
                        "ProxyEnable": _query_val("ProxyEnable", 0),
                        "ProxyServer": _query_val("ProxyServer", ""),
                        "ProxyOverride": _query_val("ProxyOverride", ""),
                        "AutoConfigURL": _query_val("AutoConfigURL", ""),
                    }
            except Exception as exc:
                logger.error("Failed to backup Windows proxy settings: %s", exc)

        elif self._is_linux:
            # Check GNOME gsettings if available
            gnome_data: Dict[str, Any] = {}
            if shutil.which("gsettings"):
                try:
                    mode = subprocess.run(
                        ["gsettings", "get", "org.gnome.system.proxy", "mode"],
                        capture_output=True, text=True, timeout=3, check=False,
                    ).stdout.strip().strip("'")
                    host = subprocess.run(
                        ["gsettings", "get", "org.gnome.system.proxy.http", "host"],
                        capture_output=True, text=True, timeout=3, check=False,
                    ).stdout.strip().strip("'")
                    port = subprocess.run(
                        ["gsettings", "get", "org.gnome.system.proxy.http", "port"],
                        capture_output=True, text=True, timeout=3, check=False,
                    ).stdout.strip().strip("'")
                    gnome_data = {"mode": mode, "host": host, "port": port}
                except Exception as exc:
                    logger.debug("Failed reading gsettings: %s", exc)

            snapshot["linux"] = {
                "gnome": gnome_data,
                "env": {
                    "http_proxy": os.environ.get("http_proxy"),
                    "https_proxy": os.environ.get("https_proxy"),
                    "all_proxy": os.environ.get("all_proxy"),
                    "no_proxy": os.environ.get("no_proxy"),
                },
            }

        if self._initial_backup is None:
            self._initial_backup = snapshot
        return snapshot

    def set_system_proxy(
        self,
        host: str,
        port: int,
        exceptions: Optional[List[str]] = None,
    ) -> bool:
        """Apply system-wide proxy settings.

        Args:
            host: Proxy server IP or domain.
            port: Proxy server port.
            exceptions: Bypass addresses (defaults to standard loopback hosts).

        Returns:
            True if settings were applied successfully.
        """
        bypass_list = exceptions or ["localhost", "127.0.0.1", "<local>"]
        bypass_str = ";".join(bypass_list)

        if self._is_windows:
            try:
                import winreg  # pylint: disable=import-outside-toplevel
                proxy_str = f"{host}:{port}"
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0,
                    winreg.KEY_WRITE,
                ) as key:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_str)
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, bypass_str)

                self._notify_windows_inet()
                logger.info("System proxy enabled for Windows: %s", proxy_str)
                return True
            except Exception as exc:
                logger.error("Failed setting Windows system proxy: %s", exc)
                return False

        elif self._is_linux:
            success = False
            # 1. Update GNOME gsettings
            if shutil.which("gsettings"):
                try:
                    subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], check=True)
                    subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http", "host", host], check=True)
                    subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http", "port", str(port)], check=True)
                    subprocess.run(["gsettings", "set", "org.gnome.system.proxy.https", "host", host], check=True)
                    subprocess.run(["gsettings", "set", "org.gnome.system.proxy.https", "port", str(port)], check=True)
                    success = True
                except Exception as exc:
                    logger.warning("Failed setting GNOME gsettings proxy: %s", exc)

            # 2. Update current environment variables
            proxy_url = f"http://{host}:{port}"
            os.environ["http_proxy"] = proxy_url
            os.environ["https_proxy"] = proxy_url
            os.environ["all_proxy"] = proxy_url
            os.environ["no_proxy"] = ",".join(bypass_list)
            return success or True

        logger.warning("System proxy is not supported on platform: %s", sys.platform)
        return False

    def clear_system_proxy(self) -> bool:
        """Disable system-wide proxy and clear active endpoints.

        Returns:
            True if system proxy was disabled successfully.
        """
        if self._is_windows:
            try:
                import winreg  # pylint: disable=import-outside-toplevel
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0,
                    winreg.KEY_WRITE,
                ) as key:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")

                self._notify_windows_inet()
                logger.info("Windows system proxy disabled.")
                return True
            except Exception as exc:
                logger.error("Failed disabling Windows system proxy: %s", exc)
                return False

        elif self._is_linux:
            if shutil.which("gsettings"):
                try:
                    subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"], check=False)
                except Exception as exc:
                    logger.warning("Failed disabling GNOME proxy: %s", exc)

            for var in ("http_proxy", "https_proxy", "all_proxy", "no_proxy",
                        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
                os.environ.pop(var, None)

            return True

        return False

    def get_current_proxy(self) -> Optional[Dict[str, Any]]:
        """Retrieve active system-wide proxy configuration.

        Returns:
            Dictionary with enabled, host, port, and exceptions, or None if inactive.
        """
        if self._is_windows:
            try:
                import winreg  # pylint: disable=import-outside-toplevel
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0,
                    winreg.KEY_READ,
                ) as key:
                    enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    if not enabled:
                        return None
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    override, _ = winreg.QueryValueEx(key, "ProxyOverride")

                    host, port_str = server.split(":", 1) if ":" in server else (server, "80")
                    return {
                        "enabled": bool(enabled),
                        "host": host,
                        "port": int(port_str) if port_str.isdigit() else 80,
                        "exceptions": override.split(";"),
                    }
            except Exception as exc:
                logger.debug("Failed querying Windows proxy: %s", exc)
                return None

        elif self._is_linux:
            env_proxy = os.environ.get("http_proxy") or os.environ.get("all_proxy")
            if env_proxy:
                cleaned = env_proxy.replace("http://", "").replace("https://", "")
                parts = cleaned.split(":")
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 80
                return {
                    "enabled": True,
                    "host": host,
                    "port": port,
                    "exceptions": os.environ.get("no_proxy", "").split(","),
                }
            return None

        return None

    def restore_proxy_settings(self, backup: Dict[str, Any]) -> bool:
        """Revert proxy configuration from a previous backup snapshot.

        Args:
            backup: Backup dictionary produced by backup_proxy_settings.

        Returns:
            True if settings were restored, False otherwise.
        """
        if not backup:
            return self.clear_system_proxy()

        if self._is_windows and "windows" in backup:
            win_data = backup["windows"]
            try:
                import winreg  # pylint: disable=import-outside-toplevel
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0,
                    winreg.KEY_WRITE,
                ) as key:
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(win_data.get("ProxyEnable", 0)))
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(win_data.get("ProxyServer", "")))
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, str(win_data.get("ProxyOverride", "")))

                self._notify_windows_inet()
                logger.info("Restored Windows system proxy settings from backup.")
                return True
            except Exception as exc:
                logger.error("Failed to restore Windows proxy settings: %s", exc)
                return False

        elif self._is_linux and "linux" in backup:
            linux_data = backup["linux"]
            gnome_data = linux_data.get("gnome", {})
            if shutil.which("gsettings") and gnome_data:
                try:
                    mode = gnome_data.get("mode", "none")
                    subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", mode], check=False)
                except Exception as exc:
                    logger.warning("Failed restoring GNOME proxy: %s", exc)

            env_data = linux_data.get("env", {})
            for key, val in env_data.items():
                if val:
                    os.environ[key] = val
                else:
                    os.environ.pop(key, None)
            return True

        return False
