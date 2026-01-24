#!/usr/bin/env python3
"""
AUTH ENGINE - SIP Credential Handler

Extracts SIP Digest authentication credentials.

SIP Auth (RFC 3261):
    - Uses HTTP Digest auth (MD5 challenge/response)
    - Common in VoIP environments
    - Credentials in REGISTER, INVITE requests

Hashcat Mode: 11400 (SIP digest authentication MD5)
"""

import re
from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class SIPAuthHandler(AuthProtocolHandler):
    """
    Handler for SIP Digest authentication.

    Common in VoIP deployments. Uses MD5 digest auth.
    """

    @property
    def protocol_name(self) -> str:
        return "sip"

    @property
    def tshark_filter(self) -> str:
        return "sip.auth or sip.www_authenticate or sip.proxy_authenticate"

    @property
    def correlation_field(self) -> str:
        return "sip.Call-ID"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "sip.Method",
            "sip.Status-Code",
            "sip.auth",
            "sip.auth.username",
            "sip.auth.realm",
            "sip.auth.nonce",
            "sip.auth.uri",
            "sip.auth.response",
            "sip.auth.cnonce",
            "sip.auth.nc",
            "sip.auth.qop",
            "sip.auth.algorithm",
            "sip.www_authenticate",
            "sip.proxy_authenticate",
            "sip.Call-ID",
            "sip.From",
            "sip.To",
            "sip.Contact",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify SIP auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("udp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("udp.dstport", 0)) or 0)

        # Try TCP if UDP not available
        if not src_port:
            src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
            dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)

        correlation_key = self._get_first(fields.get("sip.Call-ID", ""))
        if not correlation_key:
            return None

        status_code = self._get_first(fields.get("sip.Status-Code", ""))
        auth_header = self._get_first(fields.get("sip.auth", ""))
        www_auth = self._get_first(fields.get("sip.www_authenticate", ""))
        proxy_auth = self._get_first(fields.get("sip.proxy_authenticate", ""))

        if www_auth or proxy_auth:
            phase = AuthPhase.CHALLENGE
        elif auth_header:
            phase = AuthPhase.RESPONSE
        elif status_code == "401" or status_code == "407":
            phase = AuthPhase.CHALLENGE
        elif status_code == "200":
            phase = AuthPhase.RESULT
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
        """Build SIP credential from digest auth exchange."""
        username = None
        realm = None
        nonce = None
        uri = None
        response = None
        cnonce = None
        nc = None
        qop = None
        algorithm = None
        method = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            # Extract from tshark-parsed fields
            user = self._get_first(msg.raw_data.get("sip.auth.username", ""))
            r = self._get_first(msg.raw_data.get("sip.auth.realm", ""))
            n = self._get_first(msg.raw_data.get("sip.auth.nonce", ""))
            u = self._get_first(msg.raw_data.get("sip.auth.uri", ""))
            resp = self._get_first(msg.raw_data.get("sip.auth.response", ""))
            cn = self._get_first(msg.raw_data.get("sip.auth.cnonce", ""))
            nc_val = self._get_first(msg.raw_data.get("sip.auth.nc", ""))
            qop_val = self._get_first(msg.raw_data.get("sip.auth.qop", ""))
            algo = self._get_first(msg.raw_data.get("sip.auth.algorithm", ""))
            meth = self._get_first(msg.raw_data.get("sip.Method", ""))
            status = self._get_first(msg.raw_data.get("sip.Status-Code", ""))

            if user:
                username = user.strip('"')
            if r:
                realm = r.strip('"')
            if n:
                nonce = n.strip('"')
            if u:
                uri = u.strip('"')
            if resp:
                response = resp.strip('"')
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp
            if cn:
                cnonce = cn.strip('"')
            if nc_val:
                nc = nc_val
            if qop_val:
                qop = qop_val.strip('"')
            if algo:
                algorithm = algo.strip('"')
            if meth:
                method = meth

            if status == "200":
                auth_success = True
            elif status in ["401", "403", "407"]:
                auth_success = False

        if not username or not response or not nonce:
            return None

        # Hashcat format for SIP digest (mode 11400):
        # $sip$*realm*method*uri*nonce*cnonce*nc*qop*response
        hashcat_format = f"$sip$*{realm or ''}*{method or 'REGISTER'}*{uri or ''}*{nonce}*{cnonce or ''}*{nc or ''}*{qop or 'auth'}*{response}"

        metadata = ProtocolMetadata(
            target_realm=realm,
            raw_fields={
                "method": method,
                "algorithm": algorithm or "MD5",
                "qop": qop,
            }
        )

        return ExtractedCredential(
            protocol="sip",
            username=username,
            domain=realm,
            credential_data={
                "nonce": nonce,
                "response": response,
                "uri": uri,
                "cnonce": cnonce,
                "nc": nc,
                "qop": qop,
                "method": method,
                "algorithm": algorithm or "MD5",
            },
            hashcat_format=hashcat_format,
            hashcat_mode=11400,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 5060,
            target_service="sip",
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
        return 11400
