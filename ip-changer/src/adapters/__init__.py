"""Network and platform adapters for IP Changer."""

from src.adapters.base_adapter import BaseAdapter
from src.adapters.firewall_adapter import FirewallAdapter
from src.adapters.linux_vpn_adapter import LinuxVPNAdapter
from src.adapters.proxy_adapter import ProxyAdapter
from src.adapters.system_proxy_adapter import SystemProxyAdapter
from src.adapters.windows_vpn_adapter import WindowsVPNAdapter

__all__ = [
    "BaseAdapter",
    "ProxyAdapter",
    "WindowsVPNAdapter",
    "LinuxVPNAdapter",
    "SystemProxyAdapter",
    "FirewallAdapter",
]
