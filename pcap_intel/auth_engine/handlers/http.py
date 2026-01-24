#!/usr/bin/env python3
"""
AUTH ENGINE - HTTP Authentication Handler

Extracts HTTP authentication credentials from Basic, Digest, Bearer, and NTLM auth.

HTTP Auth Types:
    - Basic: Base64 encoded username:password (trivially decoded)
    - Digest: Challenge-response with MD5 (crackable)
    - Bearer: OAuth tokens (not crackable, but valuable)
    - NTLM: NTLM-over-HTTP (handled by NTLM handler for hash extraction)

Hashcat Modes:
    11400: SIP digest authentication (MD5)
    HTTP Basic is not hashed - direct plaintext

The challenge is in WWW-Authenticate header (401 response).
The response is in Authorization header (subsequent request).
"""

import base64
import re
from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class HTTPAuthHandler(AuthProtocolHandler):
    """
    Handler for HTTP authentication (Basic, Digest, Bearer).

    Note: NTLM-over-HTTP produces NTLM hashes and should be handled
    by the NTLM handler for proper hash extraction. This handler
    captures the HTTP layer metadata.

    Extracts:
        - Basic auth credentials (plaintext!)
        - Digest auth challenges/responses
        - Bearer tokens
        - Target URLs and hosts
    """

    @property
    def protocol_name(self) -> str:
        return "http"

    @property
    def tshark_filter(self) -> str:
        # Capture auth challenges (401) and auth headers
        return "http.authorization or http.www_authenticate"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # Auth headers
            "http.authorization",
            "http.www_authenticate",

            # Request info
            "http.request.method",
            "http.request.uri",
            "http.host",
            "http.request.full_uri",

            # Response info
            "http.response.code",

            # User agent (fingerprinting)
            "http.user_agent",

            # For correlation
            "http.request_in",
            "http.response_in",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify HTTP auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        # Determine phase based on which headers are present
        www_auth = fields.get("http.www_authenticate")
        auth_header = fields.get("http.authorization")
        response_code = fields.get("http.response.code")

        if www_auth:
            # Server challenge (401 response)
            phase = AuthPhase.CHALLENGE
        elif auth_header:
            # Client auth attempt
            phase = AuthPhase.RESPONSE
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
        """Build HTTP credential from auth exchange."""
        # Find response (Authorization header)
        response_msg = None
        challenge_msg = None

        for msg in messages:
            if msg.phase == AuthPhase.RESPONSE:
                response_msg = msg
            elif msg.phase == AuthPhase.CHALLENGE:
                challenge_msg = msg

        # Need at least the auth response
        if not response_msg:
            return None

        auth_header = self._get_first(response_msg.raw_data.get("http.authorization", ""))
        if not auth_header:
            return None

        # Determine auth type and extract
        auth_lower = auth_header.lower()

        if auth_lower.startswith("basic "):
            return self._build_basic_credential(response_msg, auth_header)
        elif auth_lower.startswith("digest "):
            return self._build_digest_credential(response_msg, challenge_msg, auth_header)
        elif auth_lower.startswith("bearer "):
            return self._build_bearer_credential(response_msg, auth_header)
        elif auth_lower.startswith("ntlm ") or auth_lower.startswith("negotiate "):
            # NTLM-over-HTTP - let NTLM handler deal with the actual hash
            # We just capture the HTTP context
            return self._build_ntlm_http_credential(response_msg, auth_header)

        return None

    def _build_basic_credential(
        self,
        response_msg: AuthMessage,
        auth_header: str
    ) -> Optional[ExtractedCredential]:
        """Extract Basic auth credential (plaintext!)."""
        # Format: Basic base64(username:password)
        try:
            encoded = auth_header.split(" ", 1)[1].strip()
            decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")

            if ":" not in decoded:
                return None

            username, password = decoded.split(":", 1)
        except Exception:
            return None

        fields = response_msg.raw_data
        host = self._get_first(fields.get("http.host", ""))
        uri = self._get_first(fields.get("http.request.uri", ""))
        user_agent = self._get_first(fields.get("http.user_agent", ""))

        metadata = ProtocolMetadata(
            raw_fields={
                "host": host,
                "uri": uri,
                "user_agent": user_agent,
                "auth_type": "Basic",
            }
        )

        return ExtractedCredential(
            protocol="http_basic",
            username=username,
            domain=host,
            credential_data={
                "password": password,  # PLAINTEXT!
                "auth_type": "Basic",
                "uri": uri,
            },
            hashcat_format=None,  # Not a hash
            hashcat_mode=None,
            source_ip=response_msg.source_ip,
            source_port=response_msg.source_port,
            target_ip=response_msg.dest_ip,
            target_port=response_msg.dest_port,
            target_service="http",
            timestamp=response_msg.timestamp,
            metadata=metadata,
        )

    def _build_digest_credential(
        self,
        response_msg: AuthMessage,
        challenge_msg: Optional[AuthMessage],
        auth_header: str
    ) -> Optional[ExtractedCredential]:
        """Extract Digest auth credential."""
        # Parse Digest response
        # Format: Digest username="user", realm="realm", nonce="...", uri="...", response="..."
        digest_fields = self._parse_digest_header(auth_header)

        username = digest_fields.get("username", "").strip('"')
        realm = digest_fields.get("realm", "").strip('"')
        nonce = digest_fields.get("nonce", "").strip('"')
        uri = digest_fields.get("uri", "").strip('"')
        response_hash = digest_fields.get("response", "").strip('"')
        cnonce = digest_fields.get("cnonce", "").strip('"')
        nc = digest_fields.get("nc", "").strip('"')
        qop = digest_fields.get("qop", "").strip('"')
        algorithm = digest_fields.get("algorithm", "MD5").strip('"')

        if not username or not response_hash:
            return None

        fields = response_msg.raw_data
        host = self._get_first(fields.get("http.host", ""))
        method = self._get_first(fields.get("http.request.method", "GET"))

        # Build hashcat format for HTTP Digest
        # Mode 11400 format: $sip$*challenge*response
        # For HTTP Digest, we construct a similar format
        hashcat_format = None
        if nonce and response_hash:
            # Format varies by tool - provide raw components
            hashcat_format = f"$digest${username}*{realm}*{method}*{uri}*{nonce}*{nc}*{cnonce}*{qop}*{response_hash}"

        metadata = ProtocolMetadata(
            target_realm=realm,
            raw_fields={
                "host": host,
                "uri": uri,
                "nonce": nonce,
                "cnonce": cnonce,
                "nc": nc,
                "qop": qop,
                "algorithm": algorithm,
                "auth_type": "Digest",
            }
        )

        return ExtractedCredential(
            protocol="http_digest",
            username=username,
            domain=realm,
            credential_data={
                "response_hash": response_hash,
                "nonce": nonce,
                "cnonce": cnonce,
                "nc": nc,
                "qop": qop,
                "uri": uri,
                "method": method,
                "algorithm": algorithm,
                "auth_type": "Digest",
            },
            hashcat_format=hashcat_format,
            hashcat_mode=11400,  # SIP digest (similar)
            source_ip=response_msg.source_ip,
            source_port=response_msg.source_port,
            target_ip=response_msg.dest_ip,
            target_port=response_msg.dest_port,
            target_service="http",
            timestamp=response_msg.timestamp,
            metadata=metadata,
        )

    def _build_bearer_credential(
        self,
        response_msg: AuthMessage,
        auth_header: str
    ) -> Optional[ExtractedCredential]:
        """Extract Bearer token (OAuth, JWT, etc.)."""
        # Format: Bearer <token>
        try:
            token = auth_header.split(" ", 1)[1].strip()
        except Exception:
            return None

        if not token:
            return None

        fields = response_msg.raw_data
        host = self._get_first(fields.get("http.host", ""))
        uri = self._get_first(fields.get("http.request.uri", ""))

        # Try to decode JWT (if it is one)
        jwt_payload = None
        username = "bearer_token"

        if token.count(".") == 2:
            # Looks like JWT (header.payload.signature)
            try:
                parts = token.split(".")
                # Decode payload (second part)
                payload_b64 = parts[1]
                # Add padding if needed
                padding = 4 - len(payload_b64) % 4
                if padding != 4:
                    payload_b64 += "=" * padding
                payload = base64.urlsafe_b64decode(payload_b64)
                jwt_payload = payload.decode("utf-8", errors="replace")

                # Try to extract username from common JWT claims
                import json
                claims = json.loads(jwt_payload)
                username = claims.get("sub") or claims.get("username") or claims.get("email") or "jwt_user"
            except Exception:
                pass

        metadata = ProtocolMetadata(
            raw_fields={
                "host": host,
                "uri": uri,
                "token_type": "JWT" if jwt_payload else "Bearer",
                "auth_type": "Bearer",
            }
        )

        return ExtractedCredential(
            protocol="http_bearer",
            username=username,
            domain=host,
            credential_data={
                "token": token,
                "jwt_payload": jwt_payload,
                "uri": uri,
                "auth_type": "Bearer",
            },
            hashcat_format=None,  # Tokens aren't crackable
            hashcat_mode=None,
            source_ip=response_msg.source_ip,
            source_port=response_msg.source_port,
            target_ip=response_msg.dest_ip,
            target_port=response_msg.dest_port,
            target_service="http",
            timestamp=response_msg.timestamp,
            metadata=metadata,
        )

    def _build_ntlm_http_credential(
        self,
        response_msg: AuthMessage,
        auth_header: str
    ) -> Optional[ExtractedCredential]:
        """
        Capture NTLM-over-HTTP context.

        The actual NTLM hash is extracted by the NTLM handler.
        This captures the HTTP-layer context.
        """
        fields = response_msg.raw_data
        host = self._get_first(fields.get("http.host", ""))
        uri = self._get_first(fields.get("http.request.uri", ""))

        # We don't extract the hash here - NTLM handler does that
        # Just note that NTLM auth occurred over HTTP

        metadata = ProtocolMetadata(
            raw_fields={
                "host": host,
                "uri": uri,
                "auth_type": "NTLM-over-HTTP",
            }
        )

        # Return minimal credential noting NTLM-over-HTTP
        # Real hash comes from NTLM handler
        return ExtractedCredential(
            protocol="http_ntlm",
            username="(see NTLM handler)",
            domain=host,
            credential_data={
                "note": "NTLM hash extracted by NTLM handler",
                "uri": uri,
                "auth_type": "NTLM",
            },
            source_ip=response_msg.source_ip,
            source_port=response_msg.source_port,
            target_ip=response_msg.dest_ip,
            target_port=response_msg.dest_port,
            target_service="http",
            timestamp=response_msg.timestamp,
            metadata=metadata,
        )

    def _parse_digest_header(self, header: str) -> Dict[str, str]:
        """Parse Digest auth header into components."""
        # Remove "Digest " prefix
        if header.lower().startswith("digest "):
            header = header[7:]

        # Parse key=value pairs
        result = {}
        # Handle quoted values with commas inside
        pattern = r'(\w+)=(?:"([^"]+)"|([^\s,]+))'
        for match in re.finditer(pattern, header):
            key = match.group(1)
            value = match.group(2) if match.group(2) else match.group(3)
            result[key] = value

        return result

    def _get_first(self, value) -> str:
        """Get first value if list, otherwise return as string."""
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def validate_credential(self, cred: ExtractedCredential) -> bool:
        """Validate HTTP credential."""
        # Skip NTLM-over-HTTP placeholders
        if cred.protocol == "http_ntlm":
            return False  # Let NTLM handler provide the real credential

        return super().validate_credential(cred)

    def get_hashcat_mode(self) -> Optional[int]:
        """Return hashcat mode for Digest auth."""
        return 11400
