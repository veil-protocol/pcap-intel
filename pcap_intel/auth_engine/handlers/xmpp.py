#!/usr/bin/env python3
"""
AUTH ENGINE - XMPP/Jabber Credential Handler

Extracts XMPP (Jabber) authentication credentials.

XMPP Auth Methods:
    - PLAIN: Base64 encoded username/password
    - DIGEST-MD5: Challenge/response
    - SCRAM-SHA-1: Salted challenge/response
    - EXTERNAL: Certificate-based

Hashcat Mode:
    - N/A for PLAIN (plaintext)
    - 11400 for DIGEST-MD5 (similar to HTTP Digest)
"""

from typing import Dict, List, Optional, Any
import base64
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class XMPPAuthHandler(AuthProtocolHandler):
    """
    Handler for XMPP/Jabber authentication.

    Extracts SASL credentials from XMPP streams.
    """

    @property
    def protocol_name(self) -> str:
        return "xmpp"

    @property
    def tshark_filter(self) -> str:
        return "xmpp"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "xmpp.auth",
            "xmpp.auth.mechanism",
            "xmpp.challenge",
            "xmpp.response",
            "xmpp.success",
            "xmpp.failure",
            "xmpp.failure.condition",
            "xmpp.iq.type",
            "xmpp.iq.id",
            "xmpp.jid",
            "xmpp.from",
            "xmpp.to",
            "xmpp.query.username",
            "xmpp.query.password",
            "xmpp.query.resource",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify XMPP message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        auth = self._get_first(fields.get("xmpp.auth", ""))
        challenge = self._get_first(fields.get("xmpp.challenge", ""))
        response = self._get_first(fields.get("xmpp.response", ""))
        success = self._get_first(fields.get("xmpp.success", ""))
        failure = self._get_first(fields.get("xmpp.failure", ""))
        username = self._get_first(fields.get("xmpp.query.username", ""))
        password = self._get_first(fields.get("xmpp.query.password", ""))

        if auth:
            phase = AuthPhase.INITIATION  # Client starting auth
        elif challenge:
            phase = AuthPhase.CHALLENGE  # Server challenge
        elif response or password:
            phase = AuthPhase.RESPONSE  # Client response
        elif success:
            phase = AuthPhase.RESULT  # Auth success
        elif failure:
            phase = AuthPhase.RESULT  # Auth failure
        else:
            return None

        return AuthMessage(
            phase=phase,
            correlation_key=correlation_key,
            timestamp=timestamp,
            frame_number=frame_num,
            source_ip=src_ip,
            source_port=src_port,
            dest_ip=dst_ip,
            dest_port=dst_port,
            protocol=self.protocol_name,
            raw_data=fields
        )

    def build_credential(self, messages: List[AuthMessage]) -> Optional[ExtractedCredential]:
        """Build XMPP credential from SASL exchange."""
        username = None
        password = None
        mechanism = None
        jid = None
        resource = None
        challenge = None
        response = None
        server_domain = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            mech = self._get_first(msg.raw_data.get("xmpp.auth.mechanism", ""))
            if mech:
                mechanism = mech

            # Legacy IQ auth
            user = self._get_first(msg.raw_data.get("xmpp.query.username", ""))
            if user:
                username = user
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

            pwd = self._get_first(msg.raw_data.get("xmpp.query.password", ""))
            if pwd:
                password = pwd

            res = self._get_first(msg.raw_data.get("xmpp.query.resource", ""))
            if res:
                resource = res

            # SASL auth
            auth_data = self._get_first(msg.raw_data.get("xmpp.auth", ""))
            if auth_data and mechanism == "PLAIN":
                # PLAIN format: base64(authzid\0authcid\0password)
                try:
                    decoded = base64.b64decode(auth_data).decode('utf-8', errors='ignore')
                    parts = decoded.split('\x00')
                    if len(parts) >= 3:
                        username = parts[1] if parts[1] else parts[0]
                        password = parts[2]
                    elif len(parts) == 2:
                        username = parts[0]
                        password = parts[1]
                    client_ip = msg.source_ip
                    server_ip = msg.dest_ip
                    timestamp = msg.timestamp
                except Exception:
                    pass

            chal = self._get_first(msg.raw_data.get("xmpp.challenge", ""))
            if chal:
                challenge = chal
                server_ip = msg.source_ip

            resp = self._get_first(msg.raw_data.get("xmpp.response", ""))
            if resp:
                response = resp
                client_ip = msg.source_ip
                timestamp = msg.timestamp

            j = self._get_first(msg.raw_data.get("xmpp.jid", ""))
            if j:
                jid = j
                if '@' in j:
                    username = j.split('@')[0]
                    server_domain = j.split('@')[1].split('/')[0]

            to = self._get_first(msg.raw_data.get("xmpp.to", ""))
            if to:
                server_domain = to

            success = self._get_first(msg.raw_data.get("xmpp.success", ""))
            if success:
                auth_success = True

            failure = self._get_first(msg.raw_data.get("xmpp.failure", ""))
            if failure:
                auth_success = False

        if not username:
            return None

        # For DIGEST-MD5, could build hashcat format
        hashcat_format = None
        hashcat_mode = None

        if mechanism == "DIGEST-MD5" and challenge and response:
            # Would need to parse DIGEST-MD5 challenge/response
            # Similar to HTTP Digest, mode 11400
            hashcat_mode = 11400

        metadata = ProtocolMetadata(
            target_realm=server_domain,
            raw_fields={
                "mechanism": mechanism,
                "jid": jid,
                "resource": resource,
                "note": "XMPP SASL authentication",
            }
        )

        return ExtractedCredential(
            protocol="xmpp",
            username=username,
            domain=server_domain,
            credential_data={
                "password": password,  # PLAINTEXT for PLAIN/legacy
                "mechanism": mechanism,
                "challenge": challenge,
                "response": response,
                "jid": jid,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=5222,
            target_service="xmpp",
            timestamp=timestamp,
            metadata=metadata,
            auth_success=auth_success,
        )

    def _get_first(self, value) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def get_hashcat_mode(self) -> Optional[int]:
        return None  # Depends on mechanism
