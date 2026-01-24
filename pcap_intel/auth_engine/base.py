#!/usr/bin/env python3
"""
AUTH ENGINE - Base Classes and Interfaces

Defines the universal pattern for authentication protocol extraction:
    1. INITIATION - Client starts auth (hello, bind request)
    2. CHALLENGE - Server sends challenge (nonce, ticket, realm)
    3. RESPONSE - Client proves identity (hash, encrypted blob)
    4. RESULT - Server confirms (success/failure)

Every auth protocol follows this pattern. Protocol handlers only need
to implement the protocol-specific parsing.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum
from datetime import datetime


class AuthPhase(Enum):
    """Universal authentication phases across all protocols."""
    INITIATION = "initiation"   # Client hello / bind request / negotiate
    CHALLENGE = "challenge"      # Server challenge / ticket / nonce
    RESPONSE = "response"        # Client response / auth / proof
    RESULT = "result"           # Success/failure confirmation


@dataclass
class AuthMessage:
    """
    Universal auth message structure.

    Represents a single authentication-related packet regardless of protocol.
    Protocol-specific data goes in raw_data dict.
    """
    phase: AuthPhase
    correlation_key: str          # TCP stream, session ID, message ID
    timestamp: float              # Epoch timestamp
    frame_number: int             # Packet frame number
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    protocol: str                 # ntlm, kerberos, http, ldap, etc.
    raw_data: Dict[str, Any] = field(default_factory=dict)  # Protocol-specific

    def __hash__(self):
        return hash((self.frame_number, self.protocol, self.phase))


@dataclass
class ProtocolMetadata:
    """
    Additional intelligence extracted from auth exchange.

    Things like OS fingerprinting, signing status, encryption level, etc.
    """
    os_info: Optional[str] = None
    client_version: Optional[str] = None
    server_version: Optional[str] = None
    encryption_level: Optional[str] = None
    signing_enabled: Optional[bool] = None
    signing_required: Optional[bool] = None
    target_spn: Optional[str] = None
    target_realm: Optional[str] = None
    session_key: Optional[str] = None
    flags: Dict[str, bool] = field(default_factory=dict)
    raw_fields: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractedCredential:
    """
    Universal credential output format.

    Regardless of protocol, all credentials are normalized to this format.
    Protocol-specific data (hash components, tickets, etc.) goes in credential_data.
    """
    # Core identity
    protocol: str                           # ntlm, kerberos, http_basic, ldap, etc.
    username: str
    domain: Optional[str] = None

    # Credential material
    credential_data: Dict[str, Any] = field(default_factory=dict)
    hashcat_format: Optional[str] = None    # Ready for cracking
    hashcat_mode: Optional[int] = None      # Hashcat mode number

    # Network context
    source_ip: str = ""
    source_port: int = 0
    target_ip: str = ""
    target_port: int = 0
    target_service: str = ""                # smb, http, ldap, mssql, etc.

    # Timing
    timestamp: float = 0.0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    # Additional intelligence
    metadata: ProtocolMetadata = field(default_factory=ProtocolMetadata)
    auth_success: Optional[bool] = None     # If we can determine success/failure

    # Packet references
    frame_numbers: Set[int] = field(default_factory=set)

    def __hash__(self):
        return hash((self.protocol, self.username, self.domain, self.target_ip))

    def __eq__(self, other):
        if not isinstance(other, ExtractedCredential):
            return False
        return (self.protocol == other.protocol and
                self.username == other.username and
                self.domain == other.domain and
                self.target_ip == other.target_ip)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "protocol": self.protocol,
            "username": self.username,
            "domain": self.domain,
            "credential_data": self.credential_data,
            "hashcat_format": self.hashcat_format,
            "hashcat_mode": self.hashcat_mode,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "target_service": self.target_service,
            "timestamp": self.timestamp,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "auth_success": self.auth_success,
            "frame_numbers": list(self.frame_numbers),
            "metadata": {
                "os_info": self.metadata.os_info,
                "client_version": self.metadata.client_version,
                "server_version": self.metadata.server_version,
                "encryption_level": self.metadata.encryption_level,
                "signing_enabled": self.metadata.signing_enabled,
                "signing_required": self.metadata.signing_required,
                "target_spn": self.metadata.target_spn,
                "target_realm": self.metadata.target_realm,
                "flags": self.metadata.flags,
            }
        }


class AuthProtocolHandler(ABC):
    """
    Abstract base class for protocol-specific handlers.

    Each authentication protocol (NTLM, Kerberos, HTTP, LDAP, etc.) implements
    this interface. The handler is responsible for:

    1. Defining the tshark filter to capture relevant packets
    2. Classifying packets into auth phases (challenge, response, etc.)
    3. Building credentials from correlated messages

    Example implementation for a new protocol:

        class MyProtocolHandler(AuthProtocolHandler):
            @property
            def protocol_name(self) -> str:
                return "myprotocol"

            @property
            def tshark_filter(self) -> str:
                return "myprotocol.auth"

            @property
            def tshark_fields(self) -> List[str]:
                return ["myprotocol.user", "myprotocol.hash"]

            @property
            def correlation_field(self) -> str:
                return "tcp.stream"

            def classify_message(self, fields: Dict) -> Optional[AuthMessage]:
                # Parse fields and return AuthMessage or None
                pass

            def build_credential(self, messages: List[AuthMessage]) -> Optional[ExtractedCredential]:
                # Build credential from correlated messages
                pass
    """

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """
        Unique identifier for this protocol.
        Examples: 'ntlm', 'kerberos', 'http_basic', 'ldap_simple'
        """
        pass

    @property
    @abstractmethod
    def tshark_filter(self) -> str:
        """
        Wireshark display filter for this protocol's auth packets.
        Examples: 'ntlmssp', 'kerberos', 'http.authorization'
        """
        pass

    @property
    @abstractmethod
    def tshark_fields(self) -> List[str]:
        """
        List of tshark fields to extract.
        Should include all fields needed for classify_message() and build_credential().
        """
        pass

    @property
    @abstractmethod
    def correlation_field(self) -> str:
        """
        Field used to correlate related messages.
        Usually 'tcp.stream' but can be protocol-specific (e.g., 'kerberos.pvno').
        """
        pass

    @property
    def common_fields(self) -> List[str]:
        """
        Common fields extracted for all protocols.
        Handlers can override to add more.
        """
        return [
            "frame.number",
            "frame.time_epoch",
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
        ]

    def get_all_fields(self) -> List[str]:
        """Get all fields to extract (common + protocol-specific)."""
        all_fields = list(self.common_fields)
        all_fields.append(self.correlation_field)
        all_fields.extend(self.tshark_fields)
        return list(set(all_fields))  # Deduplicate

    @abstractmethod
    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """
        Classify a packet as an auth message.

        Args:
            fields: Dictionary of tshark field values
            frame_num: Frame number for reference

        Returns:
            AuthMessage if this packet is part of auth exchange, None otherwise
        """
        pass

    @abstractmethod
    def build_credential(self, messages: List[AuthMessage]) -> Optional[ExtractedCredential]:
        """
        Build a credential from correlated auth messages.

        Args:
            messages: List of AuthMessages with same correlation_key

        Returns:
            ExtractedCredential if complete auth exchange found, None otherwise
        """
        pass

    def validate_credential(self, cred: ExtractedCredential) -> bool:
        """
        Validate that a credential is complete and usable.
        Override for protocol-specific validation.

        Returns:
            True if credential is valid, False otherwise
        """
        if not cred.username:
            return False
        if cred.username.upper() in ["", "NULL", "ANONYMOUS", "-"]:
            return False
        return True

    def get_hashcat_mode(self) -> Optional[int]:
        """
        Return hashcat mode for this protocol's hash format.
        Override in handlers that produce crackable hashes.
        """
        return None
