#!/usr/bin/env python3
"""
STREAMING AUTH ENGINE - Real-Time Credential Extraction (ALL 38 PROTOCOLS)

Processes packets in real-time and emits credentials as soon as
a complete challenge/response exchange is detected.

Architecture:
    - 5 optimized inline handlers: NTLM, Kerberos, HTTP, LDAP, FTP
    - 33 generic handlers via AuthProtocolHandler bridge
    - CorrelationEngine for challenge/response pairing
    - Session timeout cleanup
"""

import asyncio
import base64
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import AsyncIterator, Dict, List, Optional, Set, Tuple, Any
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
        return self.challenge_packet is not None and self.response_packet is not None

    def age_seconds(self) -> float:
        return (datetime.now() - self.created_at).total_seconds()


class StreamingAuthEngine:
    """
    Real-time streaming authentication extractor — ALL 38 PROTOCOLS.

    5 protocols have optimized inline handlers (NTLM, Kerberos, HTTP, LDAP, FTP).
    The remaining 33 protocols use the generic AuthProtocolHandler bridge which
    feeds packets through classify_message() → CorrelationEngine → build_credential().
    """

    SESSION_TIMEOUT = 30.0

    # Protocols with optimized inline streaming handlers
    INLINE_PROTOCOLS = {"ntlm", "kerberos", "http", "ldap", "ftp"}

    def __init__(
        self,
        protocols: Optional[List[str]] = None,
        session_timeout: float = 30.0,
    ):
        self.session_timeout = session_timeout

        # Pending NTLM authentications by (stream_key, protocol, sequence_num)
        self._pending: Dict[Tuple[str, str, int], PendingAuth] = {}
        self._stream_sequences: Dict[Tuple[str, str], int] = defaultdict(int)
        self._emitted_hashes: Set[str] = set()

        # FTP session state
        self._ftp_sessions: Dict[str, Dict[str, Any]] = {}

        # Stats
        self.packets_processed = 0
        self.credentials_emitted = 0
        self.sessions_timed_out = 0

        # === GENERIC HANDLER BRIDGE ===
        # Register all 38 auth_engine handlers and a correlation engine
        from ..auth_engine.correlation import CorrelationEngine
        self._correlator = CorrelationEngine()
        self._handlers: Dict[str, Any] = {}
        self._handler_protocol_map: Dict[int, str] = {}  # port -> protocol hint
        self._emitted_sessions: Set[str] = set()
        self._register_all_handlers()

        # Build set of all supported protocols
        self._all_protocols = set(self.INLINE_PROTOCOLS) | set(self._handlers.keys())
        if protocols:
            self._all_protocols = self._all_protocols & set(protocols)

    def _register_all_handlers(self):
        """Register all 38 auth_engine protocol handlers."""
        try:
            from ..auth_engine.engine import AuthEngine
            engine = AuthEngine.__new__(AuthEngine)
            engine.handlers = {}

            # Import and register all handlers
            from ..auth_engine.handlers import (
                # Enterprise
                RADIUSAuthHandler, TACACSAuthHandler, DiameterAuthHandler, DCERPCAuthHandler,
                # Email
                POP3AuthHandler, SMTPAuthHandler, IMAPAuthHandler, NNTPAuthHandler,
                # Remote Access
                RDPAuthHandler, VNCAuthHandler, TelnetAuthHandler, RCommandsAuthHandler,
                # Database
                MySQLAuthHandler, PostgreSQLAuthHandler, MSSQLAuthHandler,
                MongoDBAuthHandler, RedisAuthHandler,
                # Network Services
                SNMPAuthHandler, SOCKSAuthHandler, NFSAuthHandler, AFPAuthHandler,
                # Wireless/802.1X
                WPAAuthHandler, EAPAuthHandler, MSCHAPv2AuthHandler, LLMNRAuthHandler,
                # VoIP/Streaming
                SIPAuthHandler, RTSPAuthHandler, XMPPAuthHandler,
                # IoT/Industrial
                MQTTAuthHandler, IPMIAuthHandler, ModbusAuthHandler, DNP3AuthHandler,
                # Chat
                IRCAuthHandler,
            )

            handler_classes = [
                RADIUSAuthHandler, TACACSAuthHandler, DiameterAuthHandler, DCERPCAuthHandler,
                POP3AuthHandler, SMTPAuthHandler, IMAPAuthHandler, NNTPAuthHandler,
                RDPAuthHandler, VNCAuthHandler, TelnetAuthHandler, RCommandsAuthHandler,
                MySQLAuthHandler, PostgreSQLAuthHandler, MSSQLAuthHandler,
                MongoDBAuthHandler, RedisAuthHandler,
                SNMPAuthHandler, SOCKSAuthHandler, NFSAuthHandler, AFPAuthHandler,
                WPAAuthHandler, EAPAuthHandler, MSCHAPv2AuthHandler, LLMNRAuthHandler,
                SIPAuthHandler, RTSPAuthHandler, XMPPAuthHandler,
                MQTTAuthHandler, IPMIAuthHandler, ModbusAuthHandler, DNP3AuthHandler,
                IRCAuthHandler,
            ]

            for cls in handler_classes:
                try:
                    handler = cls()
                    self._handlers[handler.protocol_name] = handler
                except Exception:
                    pass

        except Exception:
            pass  # If handlers fail to import, inline handlers still work

    def _packet_to_fields(self, packet: CapturedPacket) -> Dict[str, Any]:
        """Convert CapturedPacket fields to the format handlers expect."""
        fields = dict(packet.fields)
        # Ensure common fields are present
        fields.setdefault("frame.number", str(packet.raw_frame))
        fields.setdefault("frame.time_epoch", str(packet.timestamp.timestamp() if hasattr(packet.timestamp, 'timestamp') else 0))
        fields.setdefault("ip.src", packet.src_ip)
        fields.setdefault("ip.dst", packet.dst_ip)
        fields.setdefault("tcp.srcport", str(packet.src_port))
        fields.setdefault("tcp.dstport", str(packet.dst_port))
        fields.setdefault("udp.srcport", str(packet.src_port))
        fields.setdefault("udp.dstport", str(packet.dst_port))
        fields.setdefault("tcp.stream", packet.stream_key)
        return fields

    async def process_packet(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """Process a single packet and yield any resulting events."""
        self.packets_processed += 1

        # === INLINE OPTIMIZED HANDLERS ===
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
        elif packet.protocol == "ftp":
            async for event in self._process_ftp(packet):
                yield event
        else:
            # === GENERIC HANDLER BRIDGE ===
            async for event in self._process_generic(packet):
                yield event

        # Also try generic handlers on ALL packets (catches auth nested in other protos)
        if packet.protocol in self.INLINE_PROTOCOLS:
            async for event in self._process_generic(packet):
                yield event

        # Periodic cleanup
        if self.packets_processed % 50 == 0:
            await self._cleanup_expired()

    async def _process_generic(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """
        Process packet through ALL registered AuthProtocolHandlers.

        Each handler's classify_message() decides if the packet is relevant.
        Messages go into the CorrelationEngine, and when a session is complete,
        build_credential() extracts the credential.
        """
        fields = self._packet_to_fields(packet)
        frame_num = packet.raw_frame

        for proto_name, handler in self._handlers.items():
            try:
                msg = handler.classify_message(fields, frame_num)
                if msg:
                    self._correlator.add_message(msg)

                    # Check if this session is now complete
                    session = self._correlator.get_session(proto_name, msg.correlation_key)
                    if session and session.has_complete_exchange():
                        session_key = f"{proto_name}:{msg.correlation_key}"
                        if session_key not in self._emitted_sessions:
                            # Try to build credential
                            if hasattr(handler, 'build_all_credentials'):
                                creds = handler.build_all_credentials(session.messages)
                            else:
                                cred = handler.build_credential(session.messages)
                                creds = [cred] if cred else []

                            for cred in creds:
                                if cred and handler.validate_credential(cred):
                                    dedup = cred.hashcat_format or f"{cred.protocol}:{cred.username}:{cred.target_ip}"
                                    if dedup not in self._emitted_hashes:
                                        self._emitted_hashes.add(dedup)
                                        self._emitted_sessions.add(session_key)
                                        self.credentials_emitted += 1
                                        yield PipelineEvent.credential(cred, source=proto_name)

                                        # Alert for plaintext protocols
                                        pw = cred.credential_data.get("password", "") if cred.credential_data else ""
                                        if pw:
                                            yield PipelineEvent.alert(
                                                {
                                                    "severity": "CRITICAL",
                                                    "type": f"{proto_name.upper()} Plaintext Auth",
                                                    "message": f"Plaintext password: {cred.username}",
                                                    "source": cred.source_ip,
                                                    "target": f"{cred.target_ip}:{cred.target_port}",
                                                },
                                                source=proto_name,
                                            )
            except Exception:
                pass  # Don't let one handler crash others

    # ================================================================
    # INLINE OPTIMIZED HANDLERS (NTLM, Kerberos, HTTP, LDAP, FTP)
    # ================================================================

    async def _process_ntlm(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        """Process NTLM packet."""
        from ..auth_engine.base import ExtractedCredential, ProtocolMetadata

        fields = packet.fields
        msg_type = fields.get("ntlmssp.messagetype")
        if not msg_type:
            return

        stream_key = packet.stream_key

        if msg_type == "0x00000001":
            self._stream_sequences[(stream_key, "ntlm")] += 1
        elif msg_type == "0x00000002":
            seq = self._stream_sequences[(stream_key, "ntlm")]
            key = (stream_key, "ntlm", seq)
            if key not in self._pending:
                self._pending[key] = PendingAuth(stream_key=stream_key, protocol="ntlm")
            self._pending[key].challenge_packet = packet
        elif msg_type == "0x00000003":
            seq = self._stream_sequences[(stream_key, "ntlm")]
            key = (stream_key, "ntlm", seq)
            if key not in self._pending:
                self._pending[key] = PendingAuth(stream_key=stream_key, protocol="ntlm")
            self._pending[key].response_packet = packet

            if self._pending[key].is_complete() and not self._pending[key].emitted:
                cred = self._build_ntlm_credential(self._pending[key])
                if cred:
                    self._pending[key].emitted = True
                    self.credentials_emitted += 1
                    yield PipelineEvent.credential(cred, source="ntlm")

    def _build_ntlm_credential(self, pending: PendingAuth):
        from ..auth_engine.base import ExtractedCredential, ProtocolMetadata

        challenge = pending.challenge_packet
        response = pending.response_packet
        if not challenge or not response:
            return None

        cf = challenge.fields
        rf = response.fields

        server_challenge = self._get_first(cf.get("ntlmssp.ntlmserverchallenge", ""))
        if not server_challenge:
            return None

        username = self._get_first(rf.get("ntlmssp.auth.username", ""))
        domain = self._get_first(rf.get("ntlmssp.auth.domain", ""))
        workstation = self._get_first(rf.get("ntlmssp.auth.hostname", ""))

        if not username or username.upper() in ["", "NULL", "ANONYMOUS", "-"]:
            return None

        ntlmv2_response = self._get_first(rf.get("ntlmssp.ntlmv2_response", ""))
        ntresponse = self._get_first(rf.get("ntlmssp.auth.ntresponse", ""))
        ntproofstr = self._get_first(rf.get("ntlmssp.ntlmv2_response.ntproofstr", ""))

        hashcat_format = None
        hashcat_mode = None
        version = None

        if ntlmv2_response and ntproofstr:
            version = "NTLMv2"
            hashcat_mode = 5600
            sc = server_challenge.replace(":", "").lower()
            np = ntproofstr.replace(":", "").lower()
            blob = ntlmv2_response.replace(":", "").lower()
            if blob.startswith(np):
                blob = blob[len(np):]
            hashcat_format = f"{username}::{domain}:{sc}:{np}:{blob}"
        elif ntresponse and not ntlmv2_response:
            version = "NTLMv1"
            hashcat_mode = 5500
            lm = self._get_first(rf.get("ntlmssp.auth.lmresponse", "")).replace(":", "").lower()
            nt = ntresponse.replace(":", "").lower()
            sc = server_challenge.replace(":", "").lower()
            hashcat_format = f"{username}::{domain}:{lm}:{nt}:{sc}"

        if hashcat_format:
            if hashcat_format in self._emitted_hashes:
                return None
            self._emitted_hashes.add(hashcat_format)

        metadata = ProtocolMetadata()
        major = self._get_first(cf.get("ntlmssp.version.major", ""))
        minor = self._get_first(cf.get("ntlmssp.version.minor", ""))
        build = self._get_first(cf.get("ntlmssp.version.build_number", ""))
        if major and minor:
            metadata.server_version = f"NT {major}.{minor}"
            if build:
                metadata.server_version += f" Build {build}"

        port = response.dst_port
        svc = {445: "smb", 139: "netbios", 80: "http", 443: "https", 1433: "mssql"}.get(port, f"tcp/{port}")

        return ExtractedCredential(
            protocol="ntlm", username=username, domain=domain,
            credential_data={"version": version, "server_challenge": server_challenge, "ntproofstr": ntproofstr, "workstation": workstation},
            hashcat_format=hashcat_format, hashcat_mode=hashcat_mode,
            source_ip=response.src_ip, source_port=response.src_port,
            target_ip=response.dst_ip, target_port=port, target_service=svc,
            timestamp=response.timestamp, metadata=metadata,
        )

    async def _process_kerberos(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        from ..auth_engine.base import ExtractedCredential, ProtocolMetadata
        fields = packet.fields
        msg_type = fields.get("kerberos.msg_type")
        if msg_type not in ["11", "13"]:
            return

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

        dedup_key = f"krb:{msg_type}:{cname}:{sname}:{cipher[:32]}"
        if dedup_key in self._emitted_hashes:
            return
        self._emitted_hashes.add(dedup_key)

        cc = cipher.replace(":", "").replace(" ", "").lower()
        if msg_type == "11":
            hf = f"$krb5asrep${etype or '23'}${cname}@{realm}:{cc}"
            hm, proto, user = 18200, "kerberos_asrep", cname
        else:
            hf = f"$krb5tgs${etype or '23'}$*{cname}${realm}${sname}*${cc[:32]}${cc[32:]}"
            hm, proto, user = 13100, "kerberos_tgsrep", sname

        cred = ExtractedCredential(
            protocol=proto, username=user, domain=realm,
            credential_data={"cipher": cc, "etype": etype, "attack": "AS-REP Roasting" if msg_type == "11" else "Kerberoasting"},
            hashcat_format=hf, hashcat_mode=hm,
            source_ip=packet.dst_ip, target_ip=packet.src_ip, target_port=packet.src_port,
            target_service="kerberos", timestamp=packet.timestamp,
            metadata=ProtocolMetadata(target_realm=realm, target_spn=sname),
        )
        self.credentials_emitted += 1
        yield PipelineEvent.credential(cred, source="kerberos")

    async def _process_http(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        from ..auth_engine.base import ExtractedCredential, ProtocolMetadata
        fields = packet.fields
        auth_header = self._get_first(fields.get("http.authorization", ""))
        if not auth_header:
            return

        auth_lower = auth_header.lower()

        if auth_lower.startswith("basic "):
            try:
                encoded = auth_header.split(" ", 1)[1].strip()
                decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
                if ":" not in decoded:
                    return
                username, password = decoded.split(":", 1)

                dedup_key = f"http_basic:{username}:{packet.dst_ip}"
                if dedup_key in self._emitted_hashes:
                    return
                self._emitted_hashes.add(dedup_key)

                host = self._get_first(fields.get("http.host", ""))
                uri = self._get_first(fields.get("http.request.uri", ""))

                cred = ExtractedCredential(
                    protocol="http_basic", username=username, domain=host,
                    credential_data={"password": password, "auth_type": "Basic", "uri": uri},
                    source_ip=packet.src_ip, source_port=packet.src_port,
                    target_ip=packet.dst_ip, target_port=packet.dst_port,
                    target_service="http", timestamp=packet.timestamp,
                    metadata=ProtocolMetadata(raw_fields={"host": host, "uri": uri}),
                )
                self.credentials_emitted += 1
                yield PipelineEvent.credential(cred, source="http")
                yield PipelineEvent.alert(
                    {"severity": "CRITICAL", "type": "HTTP Basic Auth",
                     "message": f"Plaintext password captured: {username}",
                     "source": packet.src_ip, "target": f"{packet.dst_ip}:{packet.dst_port}"},
                    source="http",
                )
            except Exception:
                pass

        elif auth_lower.startswith("bearer "):
            try:
                token = auth_header.split(" ", 1)[1].strip()
                dedup_key = f"http_bearer:{token[:32]}"
                if dedup_key in self._emitted_hashes:
                    return
                self._emitted_hashes.add(dedup_key)
                host = self._get_first(fields.get("http.host", ""))
                cred = ExtractedCredential(
                    protocol="http_bearer", username="bearer_token", domain=host,
                    credential_data={"token": token, "auth_type": "Bearer"},
                    source_ip=packet.src_ip, target_ip=packet.dst_ip,
                    target_port=packet.dst_port, target_service="http",
                    timestamp=packet.timestamp,
                )
                self.credentials_emitted += 1
                yield PipelineEvent.credential(cred, source="http")
            except Exception:
                pass

    async def _process_ldap(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        from ..auth_engine.base import ExtractedCredential, ProtocolMetadata
        fields = packet.fields
        bind_dn = self._get_first(fields.get("ldap.name", ""))
        simple_password = self._get_first(fields.get("ldap.simple", ""))
        if not bind_dn or not simple_password:
            return

        dedup_key = f"ldap:{bind_dn}:{packet.dst_ip}"
        if dedup_key in self._emitted_hashes:
            return
        self._emitted_hashes.add(dedup_key)

        username = self._extract_username_from_dn(bind_dn)
        domain = self._extract_domain_from_dn(bind_dn)
        is_encrypted = packet.dst_port == 636

        metadata = ProtocolMetadata(raw_fields={"bind_dn": bind_dn, "encrypted": is_encrypted, "auth_type": "simple"})
        if not is_encrypted:
            metadata.flags["plaintext_password"] = True

        cred = ExtractedCredential(
            protocol="ldap_simple", username=username, domain=domain,
            credential_data={"password": simple_password, "bind_dn": bind_dn, "auth_type": "simple", "encrypted": is_encrypted},
            source_ip=packet.src_ip, source_port=packet.src_port,
            target_ip=packet.dst_ip, target_port=packet.dst_port,
            target_service="ldaps" if is_encrypted else "ldap",
            timestamp=packet.timestamp, metadata=metadata,
        )
        self.credentials_emitted += 1
        yield PipelineEvent.credential(cred, source="ldap")

        if not is_encrypted:
            yield PipelineEvent.alert(
                {"severity": "CRITICAL", "type": "LDAP Plaintext Bind",
                 "message": f"Plaintext password: {username}@{domain}",
                 "source": packet.src_ip, "target": f"{packet.dst_ip}:{packet.dst_port}"},
                source="ldap",
            )

    async def _process_ftp(self, packet: CapturedPacket) -> AsyncIterator[PipelineEvent]:
        from ..auth_engine.base import ExtractedCredential, ProtocolMetadata
        fields = packet.fields
        stream_key = packet.stream_key

        command = self._get_first(fields.get("ftp.ftp.request.command", "")) or self._get_first(fields.get("ftp.request.command", ""))
        arg = self._get_first(fields.get("ftp.ftp.request.arg", "")) or self._get_first(fields.get("ftp.request.arg", ""))
        response_code = self._get_first(fields.get("ftp.ftp.response.code", "")) or self._get_first(fields.get("ftp.response.code", ""))
        command = command.upper().strip()

        if command == "USER" and arg:
            self._ftp_sessions[stream_key] = {
                "username": arg, "password": None,
                "client_ip": packet.src_ip, "server_ip": packet.dst_ip,
                "server_port": packet.dst_port, "timestamp": packet.timestamp,
            }
            return

        if command == "PASS" and stream_key in self._ftp_sessions:
            self._ftp_sessions[stream_key]["password"] = arg
            return

        if response_code and stream_key in self._ftp_sessions:
            code = int(response_code) if response_code.isdigit() else 0
            session = self._ftp_sessions[stream_key]

            if code in (230, 530) and session.get("username"):
                auth_success = code == 230
                dedup_key = f"ftp:{session['username']}:{session['server_ip']}:{session.get('password', '')}"
                if dedup_key in self._emitted_hashes:
                    del self._ftp_sessions[stream_key]
                    return
                self._emitted_hashes.add(dedup_key)

                cred = ExtractedCredential(
                    protocol="ftp", username=session["username"], domain=session["server_ip"],
                    credential_data={"password": session.get("password", "")},
                    source_ip=session["client_ip"], source_port=0,
                    target_ip=session["server_ip"], target_port=session.get("server_port", 21),
                    target_service="ftp", timestamp=session["timestamp"],
                    metadata=ProtocolMetadata(raw_fields={"auth_success": auth_success}),
                    auth_success=auth_success,
                )
                self.credentials_emitted += 1
                yield PipelineEvent.credential(cred, source="ftp")
                yield PipelineEvent.alert(
                    {"severity": "HIGH" if auth_success else "MEDIUM",
                     "type": "FTP Plaintext Auth",
                     "message": f"FTP {'login OK' if auth_success else 'login failed'}: {session['username']}",
                     "source": session["client_ip"],
                     "target": f"{session['server_ip']}:{session.get('server_port', 21)}"},
                    source="ftp",
                )
                del self._ftp_sessions[stream_key]

    # ================================================================
    # UTILITIES
    # ================================================================

    async def _cleanup_expired(self):
        now = datetime.now()
        expired = [k for k, p in self._pending.items() if p.age_seconds() > self.session_timeout]
        for k in expired:
            del self._pending[k]
            self.sessions_timed_out += 1

        # Also clean old FTP sessions
        expired_ftp = [k for k, s in self._ftp_sessions.items()
                       if hasattr(s.get("timestamp"), "timestamp") and
                       (datetime.now() - s["timestamp"]).total_seconds() > self.session_timeout]
        for k in expired_ftp:
            del self._ftp_sessions[k]

    def _get_first(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def _extract_username_from_dn(self, dn: str) -> str:
        if not dn:
            return ""
        if "\\" in dn:
            return dn.split("\\", 1)[1]
        dn_lower = dn.lower()
        for prefix in ["cn=", "uid=", "samaccountname="]:
            if prefix in dn_lower:
                start = dn_lower.find(prefix) + len(prefix)
                end = dn.find(",", start)
                return dn[start:] if end == -1 else dn[start:end]
        return dn

    def _extract_domain_from_dn(self, dn: str) -> str:
        if not dn:
            return ""
        if "\\" in dn:
            return dn.split("\\", 1)[0]
        dc_parts = re.findall(r'dc=([^,]+)', dn, re.IGNORECASE)
        return ".".join(dc_parts) if dc_parts else ""

    def get_stats(self) -> dict:
        return {
            "packets_processed": self.packets_processed,
            "credentials_emitted": self.credentials_emitted,
            "pending_sessions": len(self._pending),
            "sessions_timed_out": self.sessions_timed_out,
            "generic_handlers": len(self._handlers),
            "correlator_sessions": self._correlator.sessions_created,
        }
