#!/usr/bin/env python3
"""
AUTH ENGINE - Message Correlation

Groups authentication messages by correlation key (TCP stream, session ID, etc.)
and orders them by timestamp for credential building.

The correlation engine handles the universal pattern:
    1. Messages arrive out of order (async extraction)
    2. Group by correlation key (usually TCP stream)
    3. Sort by timestamp within each group
    4. Hand off to protocol handler for credential building
"""

from collections import defaultdict
from typing import Dict, List, Optional, Iterator, Tuple
from dataclasses import dataclass, field

from .base import AuthMessage, AuthPhase


@dataclass
class CorrelatedSession:
    """
    A group of auth messages belonging to the same session.

    Messages are ordered by timestamp. The session tracks which
    phases have been seen to determine completeness.
    """
    correlation_key: str
    protocol: str
    messages: List[AuthMessage] = field(default_factory=list)
    phases_seen: set = field(default_factory=set)

    def add_message(self, msg: AuthMessage):
        """Add a message and track its phase."""
        self.messages.append(msg)
        self.phases_seen.add(msg.phase)
        # Keep sorted by timestamp
        self.messages.sort(key=lambda m: (m.timestamp, m.frame_number))

    def has_challenge_response(self) -> bool:
        """Check if session has both challenge and response."""
        return (AuthPhase.CHALLENGE in self.phases_seen and
                AuthPhase.RESPONSE in self.phases_seen)

    def has_complete_exchange(self) -> bool:
        """Check if session has a complete auth exchange."""
        # Minimum: challenge + response
        # Some protocols may only have response (e.g., HTTP Basic)
        return (self.has_challenge_response() or
                AuthPhase.RESPONSE in self.phases_seen)

    def get_messages_by_phase(self, phase: AuthPhase) -> List[AuthMessage]:
        """Get all messages of a specific phase."""
        return [m for m in self.messages if m.phase == phase]

    @property
    def first_timestamp(self) -> float:
        """Get timestamp of first message."""
        return self.messages[0].timestamp if self.messages else 0.0

    @property
    def last_timestamp(self) -> float:
        """Get timestamp of last message."""
        return self.messages[-1].timestamp if self.messages else 0.0

    @property
    def source_ip(self) -> Optional[str]:
        """Get client IP (from response message)."""
        responses = self.get_messages_by_phase(AuthPhase.RESPONSE)
        if responses:
            return responses[0].source_ip
        # Fall back to initiation
        inits = self.get_messages_by_phase(AuthPhase.INITIATION)
        if inits:
            return inits[0].source_ip
        return self.messages[0].source_ip if self.messages else None

    @property
    def target_ip(self) -> Optional[str]:
        """Get server IP (from challenge message)."""
        challenges = self.get_messages_by_phase(AuthPhase.CHALLENGE)
        if challenges:
            return challenges[0].source_ip
        # Fall back to response destination
        responses = self.get_messages_by_phase(AuthPhase.RESPONSE)
        if responses:
            return responses[0].dest_ip
        return self.messages[0].dest_ip if self.messages else None


class CorrelationEngine:
    """
    Groups auth messages by correlation key.

    Usage:
        engine = CorrelationEngine()

        for fields in tshark_output:
            msg = handler.classify_message(fields)
            if msg:
                engine.add_message(msg)

        for session in engine.get_complete_sessions():
            credential = handler.build_credential(session.messages)
    """

    def __init__(self):
        # Key: (protocol, correlation_key) -> CorrelatedSession
        self.sessions: Dict[Tuple[str, str], CorrelatedSession] = {}

        # Stats
        self.messages_processed = 0
        self.sessions_created = 0

    def add_message(self, msg: AuthMessage):
        """
        Add a message to the appropriate session.

        Creates a new session if one doesn't exist for this correlation key.
        """
        self.messages_processed += 1

        key = (msg.protocol, msg.correlation_key)

        if key not in self.sessions:
            self.sessions[key] = CorrelatedSession(
                correlation_key=msg.correlation_key,
                protocol=msg.protocol
            )
            self.sessions_created += 1

        self.sessions[key].add_message(msg)

    def add_messages(self, messages: List[AuthMessage]):
        """Add multiple messages."""
        for msg in messages:
            self.add_message(msg)

    def get_session(self, protocol: str, correlation_key: str) -> Optional[CorrelatedSession]:
        """Get a specific session by key."""
        return self.sessions.get((protocol, correlation_key))

    def get_all_sessions(self, protocol: Optional[str] = None) -> Iterator[CorrelatedSession]:
        """
        Iterate over all sessions.

        Args:
            protocol: Filter by protocol name (optional)
        """
        for (proto, key), session in self.sessions.items():
            if protocol is None or proto == protocol:
                yield session

    def get_complete_sessions(self, protocol: Optional[str] = None) -> Iterator[CorrelatedSession]:
        """
        Iterate over sessions with complete auth exchanges.

        A complete exchange has at least a response (for single-message auth like HTTP Basic)
        or both challenge and response (for challenge-response auth like NTLM).
        """
        for session in self.get_all_sessions(protocol):
            if session.has_complete_exchange():
                yield session

    def get_sessions_by_ip(self, ip: str, as_source: bool = True) -> Iterator[CorrelatedSession]:
        """Get sessions involving a specific IP."""
        for session in self.get_all_sessions():
            if as_source and session.source_ip == ip:
                yield session
            elif not as_source and session.target_ip == ip:
                yield session

    def get_stats(self) -> Dict:
        """Get correlation statistics."""
        protocol_counts = defaultdict(int)
        complete_counts = defaultdict(int)

        for session in self.get_all_sessions():
            protocol_counts[session.protocol] += 1
            if session.has_complete_exchange():
                complete_counts[session.protocol] += 1

        return {
            "messages_processed": self.messages_processed,
            "sessions_created": self.sessions_created,
            "sessions_by_protocol": dict(protocol_counts),
            "complete_sessions_by_protocol": dict(complete_counts),
        }

    def clear(self):
        """Clear all sessions."""
        self.sessions.clear()
        self.messages_processed = 0
        self.sessions_created = 0


class MultiProtocolCorrelator:
    """
    Correlates messages across multiple protocols for the same session.

    Example: NTLM-over-HTTP where we need both HTTP and NTLMSSP fields.
    """

    def __init__(self):
        self.primary_correlation = CorrelationEngine()
        self.secondary_correlations: Dict[str, CorrelationEngine] = {}

    def add_secondary_protocol(self, name: str):
        """Add a secondary protocol for cross-correlation."""
        self.secondary_correlations[name] = CorrelationEngine()

    def correlate_cross_protocol(
        self,
        primary_session: CorrelatedSession,
        secondary_protocol: str
    ) -> Optional[CorrelatedSession]:
        """
        Find matching session in secondary protocol.

        Matches by correlation key (usually TCP stream).
        """
        if secondary_protocol not in self.secondary_correlations:
            return None

        secondary_engine = self.secondary_correlations[secondary_protocol]
        return secondary_engine.get_session(
            secondary_protocol,
            primary_session.correlation_key
        )
