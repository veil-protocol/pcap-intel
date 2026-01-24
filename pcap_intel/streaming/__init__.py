"""
STREAMING PCAP INTELLIGENCE

Real-time packet capture and credential extraction.

Components:
    - LiveCapture: tshark live capture with async streaming
    - StreamingAuthEngine: Real-time credential extraction
    - EventEmitter: Callbacks for credentials, entities, alerts

Usage:
    async for event in LivePipeline("eth0"):
        if event.type == EventType.CREDENTIAL:
            print(f"[CRED] {event.data.username}@{event.data.domain}")
        elif event.type == EventType.ENTITY:
            print(f"[ENTITY] {event.data.type}: {event.data.value}")
"""

from .pipeline import LivePipeline, PipelineEvent, EventType
from .capture import LiveCapture
from .processor import StreamingProcessor
from .auth_stream import StreamingAuthEngine
from .entity_stream import StreamingEntityExtractor

__all__ = [
    "LivePipeline",
    "PipelineEvent",
    "EventType",
    "LiveCapture",
    "StreamingProcessor",
    "StreamingAuthEngine",
    "StreamingEntityExtractor",
]
