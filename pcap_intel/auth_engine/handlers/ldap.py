#!/usr/bin/env python3
"""
AUTH ENGINE - LDAP Bind Handler

Extracts LDAP authentication from bind operations.

LDAP Auth Types:
    - Simple bind: DN + password (plaintext!)
    - SASL bind: Various mechanisms (GSSAPI, DIGEST-MD5, etc.)
    - Anonymous bind: No credentials (still logged)

LDAP Message Types:
    bindRequest (0): Client sends credentials
    bindResponse (1): Server confirms

The bind password in simple auth is PLAINTEXT over the wire
(unless using LDAPS/StartTLS). Major security finding!
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class LDAPBindHandler(AuthProtocolHandler):
    """
    Handler for LDAP bind authentication.

    Extracts:
        - Simple bind credentials (plaintext passwords!)
        - SASL bind mechanism info
        - Bind DN (distinguished name)
        - Server response (success/failure)

    Security Note:
        LDAP simple bind sends passwords in PLAINTEXT.
        Finding simple binds on non-encrypted connections is a critical finding.
    """

    @property
    def protocol_name(self) -> str:
        return "ldap"

    @property
    def tshark_filter(self) -> str:
        # Use general ldap filter - fields extraction handles specifics
        return "ldap"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # Bind request fields
            "ldap.bindRequest_element",
            "ldap.name",                    # Bind DN
            "ldap.simple",                  # Simple auth password (PLAINTEXT!)

            # SASL fields
            "ldap.mechanism",               # SASL mechanism name

            # Bind response
            "ldap.bindResponse_element",
            "ldap.resultCode",              # 0=success, others=failure
            "ldap.bindResponse_resultCode",
            "ldap.bindResponse_matchedDN",

            # Message ID for correlation within stream
            "ldap.messageID",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify LDAP bind message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        # Determine if this is bind request or response
        is_request = fields.get("ldap.bindRequest_element") or fields.get("ldap.name") or fields.get("ldap.simple")
        is_response = fields.get("ldap.bindResponse_element") or fields.get("ldap.resultCode") or fields.get("ldap.bindResponse_resultCode")

        if is_request:
            phase = AuthPhase.RESPONSE  # Client sending creds
        elif is_response:
            phase = AuthPhase.RESULT    # Server confirming
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
        """Build LDAP credential from bind exchange."""
        # Find bind request and response
        bind_request = None
        bind_response = None

        for msg in messages:
            if msg.phase == AuthPhase.RESPONSE:
                bind_request = msg
            elif msg.phase == AuthPhase.RESULT:
                bind_response = msg

        # Need at least the bind request
        if not bind_request:
            return None

        fields = bind_request.raw_data

        # Get bind DN
        bind_dn = self._get_first(fields.get("ldap.name", ""))

        # Determine auth type
        simple_password = self._get_first(fields.get("ldap.simple", ""))
        sasl_mechanism = self._get_first(fields.get("ldap.mechanism", ""))
        sasl_creds = self._get_first(fields.get("ldap.credentials", ""))

        if simple_password:
            return self._build_simple_bind_credential(
                bind_request, bind_response, bind_dn, simple_password
            )
        elif sasl_mechanism:
            return self._build_sasl_bind_credential(
                bind_request, bind_response, bind_dn, sasl_mechanism, sasl_creds
            )
        elif bind_dn:
            # Anonymous or password-less bind attempt
            return self._build_anonymous_bind_credential(
                bind_request, bind_response, bind_dn
            )

        return None

    def _build_simple_bind_credential(
        self,
        bind_request: AuthMessage,
        bind_response: Optional[AuthMessage],
        bind_dn: str,
        password: str
    ) -> ExtractedCredential:
        """Build credential for LDAP simple bind (PLAINTEXT password!)."""
        # Determine success/failure
        auth_success = None
        if bind_response:
            result_code = self._get_first(bind_response.raw_data.get("ldap.resultCode", ""))
            auth_success = result_code == "0"

        # Extract username from DN
        # DN format: cn=username,ou=users,dc=domain,dc=com
        username = self._extract_username_from_dn(bind_dn)

        # Determine if encrypted
        target_port = bind_request.dest_port
        is_encrypted = target_port == 636  # LDAPS

        metadata = ProtocolMetadata(
            raw_fields={
                "bind_dn": bind_dn,
                "ldap_version": self._get_first(bind_request.raw_data.get("ldap.version", "")),
                "encrypted": is_encrypted,
                "auth_type": "simple",
            }
        )

        if not is_encrypted:
            metadata.flags["plaintext_password"] = True
            metadata.flags["critical_finding"] = True

        return ExtractedCredential(
            protocol="ldap_simple",
            username=username,
            domain=self._extract_domain_from_dn(bind_dn),
            credential_data={
                "password": password,  # PLAINTEXT!
                "bind_dn": bind_dn,
                "auth_type": "simple",
                "encrypted": is_encrypted,
            },
            hashcat_format=None,  # Not hashed
            hashcat_mode=None,
            source_ip=bind_request.source_ip,
            source_port=bind_request.source_port,
            target_ip=bind_request.dest_ip,
            target_port=target_port,
            target_service="ldaps" if is_encrypted else "ldap",
            timestamp=bind_request.timestamp,
            metadata=metadata,
            auth_success=auth_success,
        )

    def _build_sasl_bind_credential(
        self,
        bind_request: AuthMessage,
        bind_response: Optional[AuthMessage],
        bind_dn: str,
        mechanism: str,
        credentials: str
    ) -> ExtractedCredential:
        """Build credential for LDAP SASL bind."""
        # Determine success/failure
        auth_success = None
        if bind_response:
            result_code = self._get_first(bind_response.raw_data.get("ldap.resultCode", ""))
            auth_success = result_code == "0"

        username = self._extract_username_from_dn(bind_dn) if bind_dn else f"sasl_{mechanism}"

        metadata = ProtocolMetadata(
            raw_fields={
                "bind_dn": bind_dn,
                "sasl_mechanism": mechanism,
                "auth_type": "SASL",
            }
        )

        # Note: GSSAPI means Kerberos is involved
        if mechanism.upper() == "GSSAPI":
            metadata.flags["kerberos_involved"] = True

        return ExtractedCredential(
            protocol="ldap_sasl",
            username=username,
            domain=self._extract_domain_from_dn(bind_dn),
            credential_data={
                "sasl_mechanism": mechanism,
                "sasl_credentials": credentials,
                "bind_dn": bind_dn,
                "auth_type": "SASL",
            },
            hashcat_format=None,
            hashcat_mode=None,
            source_ip=bind_request.source_ip,
            source_port=bind_request.source_port,
            target_ip=bind_request.dest_ip,
            target_port=bind_request.dest_port,
            target_service="ldap",
            timestamp=bind_request.timestamp,
            metadata=metadata,
            auth_success=auth_success,
        )

    def _build_anonymous_bind_credential(
        self,
        bind_request: AuthMessage,
        bind_response: Optional[AuthMessage],
        bind_dn: str
    ) -> Optional[ExtractedCredential]:
        """Build credential for anonymous/empty password bind."""
        # Skip truly anonymous binds (empty DN)
        if not bind_dn:
            return None

        auth_success = None
        if bind_response:
            result_code = self._get_first(bind_response.raw_data.get("ldap.resultCode", ""))
            auth_success = result_code == "0"

        username = self._extract_username_from_dn(bind_dn)

        metadata = ProtocolMetadata(
            raw_fields={
                "bind_dn": bind_dn,
                "auth_type": "anonymous_or_empty",
            }
        )

        # Empty password bind that succeeded is a finding
        if auth_success:
            metadata.flags["empty_password_success"] = True

        return ExtractedCredential(
            protocol="ldap_anonymous",
            username=username,
            domain=self._extract_domain_from_dn(bind_dn),
            credential_data={
                "bind_dn": bind_dn,
                "password": "",
                "auth_type": "anonymous",
            },
            source_ip=bind_request.source_ip,
            source_port=bind_request.source_port,
            target_ip=bind_request.dest_ip,
            target_port=bind_request.dest_port,
            target_service="ldap",
            timestamp=bind_request.timestamp,
            metadata=metadata,
            auth_success=auth_success,
        )

    def _extract_username_from_dn(self, dn: str) -> str:
        """
        Extract username from LDAP DN.

        Examples:
            cn=admin,dc=example,dc=com -> admin
            uid=jsmith,ou=users,dc=corp,dc=local -> jsmith
            DOMAIN\\username -> username
        """
        if not dn:
            return ""

        # Handle DOMAIN\\username format
        if "\\" in dn:
            return dn.split("\\", 1)[1]

        # Handle DN format
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
        """
        Extract domain from LDAP DN.

        Example: cn=admin,dc=example,dc=com -> example.com
        """
        if not dn:
            return ""

        # Handle DOMAIN\\username format
        if "\\" in dn:
            return dn.split("\\", 1)[0]

        # Extract DC components
        import re
        dc_parts = re.findall(r'dc=([^,]+)', dn, re.IGNORECASE)
        if dc_parts:
            return ".".join(dc_parts)

        return ""

    def _get_first(self, value) -> str:
        """Get first value if list, otherwise return as string."""
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def validate_credential(self, cred: ExtractedCredential) -> bool:
        """Validate LDAP credential."""
        # Skip anonymous binds with empty DN
        if cred.protocol == "ldap_anonymous" and not cred.username:
            return False

        return super().validate_credential(cred)

    def get_hashcat_mode(self) -> Optional[int]:
        """LDAP simple bind is plaintext, no hashcat mode."""
        return None
