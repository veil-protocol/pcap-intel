"""
PCAP-Intel: Real-time Network Traffic Intelligence Platform

A streaming PCAP analysis TUI for red team operators and network analysts.
Provides real-time credential extraction, host discovery, and attack surface mapping.

Version: 2.0.0 (SHADOW_SERPENT)
"""

__version__ = "2.0.0"
__codename__ = "SHADOW_SERPENT"

from .streaming.tui import PcapIntelApp

__all__ = ["PcapIntelApp", "__version__", "__codename__"]
