#!/usr/bin/env python3
"""
PROCESSOR - Streaming Packet Processor

Coordinates packet processing across multiple analyzers.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncIterator, Dict, Any, Optional, List, Set

from .capture import CapturedPacket
from .pipeline import PipelineEvent, EventType


@dataclass
class StreamState:
    """State for a network stream (TCP connection or UDP flow)."""
    stream_key: str
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    packet_count: int = 0
    bytes_total: int = 0
    protocols_seen: Set[str] = field(default_factory=set)


class StreamingProcessor:
    """
    Streaming packet processor with state tracking.

    Maintains state for active streams and provides processing
    coordination for multiple analysis engines.
    """

    # Stream timeout in seconds
    STREAM_TIMEOUT = 120.0

    def __init__(
        self,
        protocols: Optional[List[str]] = None,
        track_flows: bool = True,
    ):
        """
        Initialize processor.

        Args:
            protocols: Protocols to process (default: all)
            track_flows: Whether to track flow state
        """
        self.protocols = set(protocols) if protocols else None
        self.track_flows = track_flows

        # Active streams
        self._streams: Dict[str, StreamState] = {}

        # Stats
        self.packets_processed = 0
        self.streams_tracked = 0

    async def process_packet(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """
        Process a packet and yield events.

        Updates stream state and yields flow events as needed.
        """
        self.packets_processed += 1

        # Skip if protocol filter doesn't match
        if self.protocols and packet.protocol not in self.protocols:
            return

        # Update stream state
        if self.track_flows:
            stream_key = packet.stream_key
            if stream_key not in self._streams:
                self._streams[stream_key] = StreamState(stream_key=stream_key)
                self.streams_tracked += 1

                # New flow event
                yield PipelineEvent(
                    type=EventType.FLOW,
                    data={
                        "type": "new",
                        "stream_key": stream_key,
                        "src": f"{packet.src_ip}:{packet.src_port}",
                        "dst": f"{packet.dst_ip}:{packet.dst_port}",
                        "protocol": packet.protocol,
                    },
                    source="processor"
                )

            stream = self._streams[stream_key]
            stream.last_seen = datetime.now()
            stream.packet_count += 1
            stream.protocols_seen.add(packet.protocol)

        # Periodic cleanup
        if self.packets_processed % 100 == 0:
            await self._cleanup_old_streams()

    async def _cleanup_old_streams(self):
        """Remove streams that have timed out."""
        now = datetime.now()
        expired = []

        for key, stream in self._streams.items():
            age = (now - stream.last_seen).total_seconds()
            if age > self.STREAM_TIMEOUT:
                expired.append(key)

        for key in expired:
            del self._streams[key]

    def get_stream_state(self, stream_key: str) -> Optional[StreamState]:
        """Get state for a stream."""
        return self._streams.get(stream_key)

    def get_active_streams(self) -> List[StreamState]:
        """Get all active streams."""
        return list(self._streams.values())
