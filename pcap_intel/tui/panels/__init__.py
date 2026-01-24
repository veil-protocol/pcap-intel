"""Panel system for PCAP-Intel TUI."""

from .base import Panel, PanelState, PanelConfig
from .credentials import CredentialsPanel
from .flows import FlowsPanel
from .dns import DNSPanel
from .hosts import HostsPanel
from .alerts import AlertsPanel

__all__ = [
    "Panel",
    "PanelState",
    "PanelConfig",
    "CredentialsPanel",
    "FlowsPanel",
    "DNSPanel",
    "HostsPanel",
    "AlertsPanel",
]
