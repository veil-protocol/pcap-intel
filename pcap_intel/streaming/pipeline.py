#!/usr/bin/env python3
"""
PIPELINE - Core Event Types and Live Pipeline

Provides the main streaming abstraction for real-time packet processing.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import AsyncIterator, Dict, Any, Optional, List


class EventType(Enum):
    """Types of events emitted by the pipeline."""
    PACKET = auto()         # Raw packet data
    CREDENTIAL = auto()     # Extracted credential
    ALERT = auto()          # Security alert
    ENTITY = auto()         # Discovered entity (host, service, etc.)
    AUTH_ATTEMPT = auto()   # Authentication attempt (may not have creds)
    DNS = auto()            # DNS resolution
    FLOW = auto()           # Network flow data


@dataclass
class PipelineEvent:
    """
    Event emitted by the processing pipeline.

    Attributes:
        type: Type of event (PACKET, CREDENTIAL, etc.)
        timestamp: When the event was created
        data: Event-specific payload
        source: Protocol or component that generated this event
    """
    type: EventType
    timestamp: datetime = field(default_factory=datetime.now)
    data: Any = None
    source: str = ""

    @classmethod
    def credential(cls, cred: Any, source: str = "") -> "PipelineEvent":
        """Factory for credential events."""
        return cls(
            type=EventType.CREDENTIAL,
            data=cred,
            source=source
        )

    @classmethod
    def alert(cls, alert_data: Dict[str, Any], source: str = "") -> "PipelineEvent":
        """Factory for alert events."""
        return cls(
            type=EventType.ALERT,
            data=alert_data,
            source=source
        )

    @classmethod
    def entity(cls, entity_data: Any, source: str = "") -> "PipelineEvent":
        """Factory for entity events."""
        return cls(
            type=EventType.ENTITY,
            data=entity_data,
            source=source
        )


class LivePipeline:
    """
    Real-time packet capture and processing pipeline.

    Integrates:
        - Live capture (tshark or file)
        - Protocol processors
        - Auth engine for credential extraction
        - Entity extraction
        - Alert generation

    Usage:
        async for event in LivePipeline("eth0").stream():
            if event.type == EventType.CREDENTIAL:
                print(f"Found: {event.data}")
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        enable_intel: bool = True,
        protocols: Optional[List[str]] = None,
    ):
        """
        Initialize live pipeline.

        Args:
            interface: Network interface for live capture (e.g., "eth0")
            pcap_file: Path to pcap file (alternative to live)
            bpf_filter: BPF filter expression
            enable_intel: Enable intelligence extraction (creds, entities)
            protocols: Protocols to process (default: all common)
        """
        if not interface and not pcap_file:
            raise ValueError("Must specify either interface or pcap_file")

        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.enable_intel = enable_intel
        self.protocols = protocols or ["ntlm", "kerberos", "http", "ldap", "smb", "ftp", "ssh"]

        self._capture = None
        self._auth_engine = None
        self._entity_extractor = None
        self._running = False

    async def stream(self) -> AsyncIterator[PipelineEvent]:
        """
        Stream events from the pipeline.

        Yields events as they're detected: packets, credentials, alerts, etc.
        """
        from .capture import LiveCapture, CapturedPacket

        self._running = True

        # Initialize capture
        self._capture = LiveCapture(
            interface=self.interface,
            pcap_file=self.pcap_file,
            bpf_filter=self.bpf_filter,
        )

        # Initialize processors if intel enabled
        if self.enable_intel:
            from .auth_stream import StreamingAuthEngine
            from .entity_stream import StreamingEntityExtractor

            self._auth_engine = StreamingAuthEngine(protocols=self.protocols)
            self._entity_extractor = StreamingEntityExtractor()

        # Process packets
        try:
            async for packet in self._capture.packets():
                if not self._running:
                    break

                # Emit raw packet event
                yield PipelineEvent(
                    type=EventType.PACKET,
                    data=packet,
                    source=packet.protocol
                )

                # Process for intel if enabled
                if self.enable_intel:
                    # Auth extraction
                    if self._auth_engine:
                        async for event in self._auth_engine.process_packet(packet):
                            yield event

                    # Entity extraction
                    if self._entity_extractor:
                        async for event in self._entity_extractor.process_packet(packet):
                            yield event

        except asyncio.CancelledError:
            pass
        finally:
            self._running = False
            if self._capture:
                await self._capture.stop()

    async def stop(self):
        """Stop the pipeline."""
        self._running = False
        if self._capture:
            await self._capture.stop()
