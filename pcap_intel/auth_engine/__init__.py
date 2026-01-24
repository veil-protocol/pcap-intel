"""
AUTH ENGINE - Protocol-Agnostic Authentication Extraction

A generic engine for extracting credentials from any authentication protocol.
Instead of protocol-specific extractors (ntlmssp_full.py, kerberos_extractor.py),
this engine uses a plugin pattern where each protocol is a handler.

Architecture:
    1. AuthProtocolHandler ABC defines the interface
    2. Protocol handlers implement classify_message() and build_credential()
    3. AuthEngine orchestrates extraction across all registered handlers
    4. Correlation engine groups messages by session/stream

Adding a new protocol:
    1. Create handlers/myprotocol.py implementing AuthProtocolHandler
    2. Register with engine.register_handler(MyProtocolHandler())
    3. Done - credentials extracted automatically

Supported protocols:
    - NTLM (NTLMv1, NTLMv2, NTLM-over-HTTP)
    - Kerberos (AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP)
    - HTTP (Basic, Digest, Bearer, NTLM)
    - LDAP (Simple bind, SASL)
    - More via plugin handlers
"""

from .base import (
    AuthPhase,
    AuthMessage,
    ExtractedCredential,
    AuthProtocolHandler,
    ProtocolMetadata,
)
from .engine import AuthEngine
from .correlation import CorrelationEngine

__all__ = [
    "AuthPhase",
    "AuthMessage",
    "ExtractedCredential",
    "AuthProtocolHandler",
    "ProtocolMetadata",
    "AuthEngine",
    "CorrelationEngine",
]
