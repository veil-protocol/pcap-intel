#!/usr/bin/env python3
"""
AUTH ENGINE - RTSP Credential Handler

Extracts RTSP (Real Time Streaming Protocol) authentication.

RTSP Auth Methods (same as HTTP):
    - Basic: Base64 encoded username:password
    - Digest: MD5 challenge/response

Common in IP cameras, streaming servers.

Hashcat Mode:
    - N/A for Basic (plaintext)
    - 11400 for Digest (SIP digest format compatible)
"""

from typing import Dict, List, Optional, Any
import base64
import re
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class RTSPAuthHandler(AuthProtocolHandler):
    """
    Handler for RTSP authentication.

    Common in IP cameras and streaming infrastructure.
    """

    @property
    def protocol_name(self) -> str:
        return "rtsp"

    @property
    def tshark_filter(self) -> str:
        return "rtsp.authorization or rtsp.www_authenticate"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "rtsp.method",
            "rtsp.status",
            "rtsp.url",
            "rtsp.session",
            "rtsp.authorization",
            "rtsp.www_authenticate",
            "rtsp.content_type",
            "rtsp.user_agent",
            "rtsp.server",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify RTSP message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        auth = self._get_first(fields.get("rtsp.authorization", ""))
        www_auth = self._get_first(fields.get("rtsp.www_authenticate", ""))
        status = self._get_first(fields.get("rtsp.status", ""))

        if www_auth:
            phase = AuthPhase.CHALLENGE  # Server requesting auth
        elif auth:
            phase = AuthPhase.RESPONSE  # Client sending credentials
        elif status == "401":
            phase = AuthPhase.CHALLENGE  # Unauthorized
        elif status == "200":
            phase = AuthPhase.RESULT  # Success
        elif status and status.startswith("4"):
            phase = AuthPhase.RESULT  # Error
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
        """Build RTSP credential from auth exchange."""
        username = None
        password = None
        auth_type = None
        realm = None
        nonce = None
        uri = None
        response_hash = None
        qop = None
        nc = None
        cnonce = None
        method = None
        url = None
        session = None
        user_agent = None
        server = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            status = self._get_first(msg.raw_data.get("rtsp.status", ""))
            auth_header = self._get_first(msg.raw_data.get("rtsp.authorization", ""))
            www_auth = self._get_first(msg.raw_data.get("rtsp.www_authenticate", ""))

            m = self._get_first(msg.raw_data.get("rtsp.method", ""))
            if m:
                method = m

            u = self._get_first(msg.raw_data.get("rtsp.url", ""))
            if u:
                url = u

            s = self._get_first(msg.raw_data.get("rtsp.session", ""))
            if s:
                session = s

            ua = self._get_first(msg.raw_data.get("rtsp.user_agent", ""))
            if ua:
                user_agent = ua

            srv = self._get_first(msg.raw_data.get("rtsp.server", ""))
            if srv:
                server = srv

            # Parse WWW-Authenticate for realm/nonce
            if www_auth:
                if "Digest" in www_auth:
                    auth_type = "Digest"
                    realm_match = re.search(r'realm="([^"]+)"', www_auth)
                    if realm_match:
                        realm = realm_match.group(1)
                    nonce_match = re.search(r'nonce="([^"]+)"', www_auth)
                    if nonce_match:
                        nonce = nonce_match.group(1)
                elif "Basic" in www_auth:
                    auth_type = "Basic"
                    realm_match = re.search(r'realm="([^"]+)"', www_auth)
                    if realm_match:
                        realm = realm_match.group(1)
                server_ip = msg.source_ip

            # Parse Authorization header
            if auth_header:
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

                if auth_header.startswith("Basic "):
                    auth_type = "Basic"
                    try:
                        decoded = base64.b64decode(auth_header[6:]).decode('utf-8', errors='ignore')
                        if ':' in decoded:
                            username, password = decoded.split(':', 1)
                    except Exception:
                        pass

                elif auth_header.startswith("Digest "):
                    auth_type = "Digest"
                    # Parse digest components
                    user_match = re.search(r'username="([^"]+)"', auth_header)
                    if user_match:
                        username = user_match.group(1)

                    realm_match = re.search(r'realm="([^"]+)"', auth_header)
                    if realm_match:
                        realm = realm_match.group(1)

                    nonce_match = re.search(r'nonce="([^"]+)"', auth_header)
                    if nonce_match:
                        nonce = nonce_match.group(1)

                    uri_match = re.search(r'uri="([^"]+)"', auth_header)
                    if uri_match:
                        uri = uri_match.group(1)

                    response_match = re.search(r'response="([^"]+)"', auth_header)
                    if response_match:
                        response_hash = response_match.group(1)

                    qop_match = re.search(r'qop=([^,\s]+)', auth_header)
                    if qop_match:
                        qop = qop_match.group(1).strip('"')

                    nc_match = re.search(r'nc=([^,\s]+)', auth_header)
                    if nc_match:
                        nc = nc_match.group(1)

                    cnonce_match = re.search(r'cnonce="([^"]+)"', auth_header)
                    if cnonce_match:
                        cnonce = cnonce_match.group(1)

            if status == "200":
                auth_success = True
            elif status == "401" or status == "403":
                auth_success = False

        if not username:
            return None

        # Build hashcat format for Digest
        hashcat_format = None
        hashcat_mode = None

        if auth_type == "Digest" and response_hash and nonce:
            # Format similar to SIP/HTTP Digest: mode 11400
            hashcat_mode = 11400
            hashcat_format = f"$sip$*{realm or ''}*{method or 'DESCRIBE'}*{uri or url or ''}*{nonce}*{cnonce or ''}*{nc or ''}*{qop or 'auth'}*{response_hash}"

        metadata = ProtocolMetadata(
            target_realm=realm,
            server_version=server,
            client_version=user_agent,
            raw_fields={
                "auth_type": auth_type,
                "url": url,
                "session": session,
                "method": method,
            }
        )

        return ExtractedCredential(
            protocol="rtsp",
            username=username,
            domain=realm,
            credential_data={
                "password": password,  # For Basic auth
                "auth_type": auth_type,
                "nonce": nonce,
                "response": response_hash,
                "uri": uri,
                "qop": qop,
                "nc": nc,
                "cnonce": cnonce,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=554,
            target_service="rtsp",
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
        return 11400  # Digest auth
