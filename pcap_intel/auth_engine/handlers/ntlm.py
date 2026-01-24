#!/usr/bin/env python3
"""
AUTH ENGINE - NTLM Handler

Extracts NTLMv1/NTLMv2 credentials from NTLMSSP exchanges.
Supports NTLM over SMB, HTTP, LDAP, MSSQL, etc.

NTLM Message Types:
    Type 1 (0x00000001): NEGOTIATE - Client initiates
    Type 2 (0x00000002): CHALLENGE - Server sends challenge
    Type 3 (0x00000003): AUTHENTICATE - Client sends response

Hashcat Modes:
    5500: NTLMv1 (NetNTLMv1)
    5600: NTLMv2 (NetNTLMv2)

Format (NTLMv2):
    USER::DOMAIN:SERVER_CHALLENGE:NTPROOFSTR:BLOB
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class NTLMHandler(AuthProtocolHandler):
    """
    Handler for NTLM (NT LAN Manager) authentication.

    Supports:
        - NTLMv1 (NetNTLMv1) - hashcat mode 5500
        - NTLMv2 (NetNTLMv2) - hashcat mode 5600
        - NTLM over SMB, HTTP, LDAP, MSSQL

    Nation-state level extraction includes:
        - OS fingerprinting from NTLMSSP version info
        - SMB signing status (relay vulnerability detection)
        - Target SPN (service principal name)
        - Session keys
        - Workstation names
    """

    @property
    def protocol_name(self) -> str:
        return "ntlm"

    @property
    def tshark_filter(self) -> str:
        return "ntlmssp"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # Message type
            "ntlmssp.messagetype",

            # Type 2 (Challenge) fields
            "ntlmssp.ntlmserverchallenge",
            "ntlmssp.version.major",
            "ntlmssp.version.minor",
            "ntlmssp.version.build_number",
            "ntlmssp.version.ntlm_current_revision",
            "ntlmssp.challenge.target_name",
            "ntlmssp.challenge.target_info.nb_domain_name",
            "ntlmssp.challenge.target_info.nb_computer_name",
            "ntlmssp.challenge.target_info.dns_domain_name",
            "ntlmssp.challenge.target_info.dns_computer_name",
            "ntlmssp.ntlmclientchallenge",

            # Type 3 (Authenticate) fields
            "ntlmssp.auth.username",
            "ntlmssp.auth.domain",
            "ntlmssp.auth.hostname",
            "ntlmssp.ntlmv2_response",
            "ntlmssp.ntlmv2_response.ntproofstr",
            "ntlmssp.auth.lmresponse",
            "ntlmssp.auth.ntresponse",

            # Session key
            "ntlmssp.auth.sesskey",

            # SMB signing (if over SMB)
            "smb2.flags.signature",
            "smb2.sec_mode.sign_required",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify NTLM message by type."""
        msg_type = fields.get("ntlmssp.messagetype")

        if not msg_type:
            return None

        # Get common fields
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        # Classify by message type
        if msg_type == "0x00000001":
            phase = AuthPhase.INITIATION
        elif msg_type == "0x00000002":
            phase = AuthPhase.CHALLENGE
        elif msg_type == "0x00000003":
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
        """Build NTLM credential from challenge/response pair."""
        # Use build_all_credentials and return first (for backward compat)
        creds = self.build_all_credentials(messages)
        return creds[0] if creds else None

    def build_all_credentials(self, messages: List[AuthMessage]) -> List[ExtractedCredential]:
        """
        Build all NTLM credentials from a session.

        Handles multiple auth sequences on same TCP stream by pairing
        each Type 2 (challenge) with its corresponding Type 3 (response).
        """
        credentials = []

        # Sort by frame number to maintain sequence order
        sorted_msgs = sorted(messages, key=lambda m: m.frame_number)

        # Find all challenge/response pairs
        # Each Type 1 starts a new sequence, Type 2 provides challenge, Type 3 provides response
        challenges = [m for m in sorted_msgs if m.phase == AuthPhase.CHALLENGE]
        responses = [m for m in sorted_msgs if m.phase == AuthPhase.RESPONSE]

        # Pair challenges with responses by frame order
        # A challenge pairs with the next response that comes after it
        for challenge_msg in challenges:
            # Find the first response after this challenge
            response_msg = None
            for resp in responses:
                if resp.frame_number > challenge_msg.frame_number:
                    response_msg = resp
                    break

            if not response_msg:
                continue

            # Remove used response from list to avoid re-pairing
            responses.remove(response_msg)

            # Build credential from this pair
            cred = self._build_single_credential(challenge_msg, response_msg)
            if cred:
                credentials.append(cred)

        return credentials

    def _build_single_credential(
        self,
        challenge_msg: AuthMessage,
        response_msg: AuthMessage
    ) -> Optional[ExtractedCredential]:
        """Build a single NTLM credential from a challenge/response pair."""

        # Extract fields
        challenge_fields = challenge_msg.raw_data
        response_fields = response_msg.raw_data

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
            # NTLMv2
            version = "NTLMv2"
            hashcat_mode = 5600

            # Clean up the values (remove colons if present)
            server_challenge_clean = server_challenge.replace(":", "").lower()
            ntproofstr_clean = ntproofstr.replace(":", "").lower()
            blob = ntlmv2_response.replace(":", "").lower()

            # The blob includes the NTProofStr at the start - remove it
            if blob.startswith(ntproofstr_clean):
                blob = blob[len(ntproofstr_clean):]

            # Format: USER::DOMAIN:SERVER_CHALLENGE:NTPROOFSTR:BLOB
            hashcat_format = f"{username}::{domain}:{server_challenge_clean}:{ntproofstr_clean}:{blob}"

        elif ntresponse and not ntlmv2_response:
            # NTLMv1 (has ntresponse but no ntlmv2_response)
            version = "NTLMv1"
            hashcat_mode = 5500

            lm_response = self._get_first(response_fields.get("ntlmssp.auth.lmresponse", ""))
            nt_response = ntresponse

            lm_clean = lm_response.replace(":", "").lower() if lm_response else ""
            nt_clean = nt_response.replace(":", "").lower()
            server_challenge_clean = server_challenge.replace(":", "").lower()

            # Format: USER::DOMAIN:LM_RESPONSE:NT_RESPONSE:SERVER_CHALLENGE
            hashcat_format = f"{username}::{domain}:{lm_clean}:{nt_clean}:{server_challenge_clean}"

        else:
            # Unknown NTLM version
            version = "NTLM"

        # Build metadata
        metadata = self._extract_metadata(challenge_fields, response_fields)

        # Determine target service from port
        target_port = response_msg.dest_port
        target_service = self._port_to_service(target_port)

        return ExtractedCredential(
            protocol=self.protocol_name,
            username=username,
            domain=domain,
            credential_data={
                "version": version,
                "server_challenge": server_challenge,
                "ntproofstr": ntproofstr,
                "ntlmv2_response": ntlmv2_response,
                "ntresponse": ntresponse,
                "workstation": workstation,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=response_msg.source_ip,
            source_port=response_msg.source_port,
            target_ip=response_msg.dest_ip,
            target_port=target_port,
            target_service=target_service,
            timestamp=response_msg.timestamp,
            metadata=metadata,
        )

    def _extract_metadata(
        self,
        challenge_fields: Dict,
        response_fields: Dict
    ) -> ProtocolMetadata:
        """Extract additional intelligence from NTLM exchange."""
        metadata = ProtocolMetadata()

        # OS fingerprinting from version info
        major = self._get_first(challenge_fields.get("ntlmssp.version.major", ""))
        minor = self._get_first(challenge_fields.get("ntlmssp.version.minor", ""))
        build = self._get_first(challenge_fields.get("ntlmssp.version.build_number", ""))

        if major and minor:
            metadata.server_version = f"NT {major}.{minor}"
            if build:
                metadata.server_version += f" Build {build}"
            metadata.os_info = self._version_to_os(major, minor, build)

        # Target info
        nb_domain = self._get_first(challenge_fields.get("ntlmssp.challenge.target_info.nb_domain_name", ""))
        nb_computer = self._get_first(challenge_fields.get("ntlmssp.challenge.target_info.nb_computer_name", ""))
        dns_domain = self._get_first(challenge_fields.get("ntlmssp.challenge.target_info.dns_domain_name", ""))
        dns_computer = self._get_first(challenge_fields.get("ntlmssp.challenge.target_info.dns_computer_name", ""))

        metadata.target_realm = dns_domain or nb_domain
        metadata.raw_fields["nb_domain"] = nb_domain
        metadata.raw_fields["nb_computer"] = nb_computer
        metadata.raw_fields["dns_domain"] = dns_domain
        metadata.raw_fields["dns_computer"] = dns_computer

        # SMB signing (relay vulnerability indicator)
        signing_flag = self._get_first(challenge_fields.get("smb2.flags.signature", ""))
        signing_required = self._get_first(challenge_fields.get("smb2.sec_mode.sign_required", ""))

        if signing_flag:
            metadata.signing_enabled = signing_flag.lower() in ["true", "1"]
        if signing_required:
            metadata.signing_required = signing_required.lower() in ["true", "1"]

        # Session key
        session_key = self._get_first(response_fields.get("ntlmssp.auth.sesskey", ""))
        if session_key:
            metadata.session_key = session_key

        return metadata

    def _version_to_os(self, major: str, minor: str, build: str = None) -> str:
        """Convert NTLM version to OS name."""
        version_map = {
            ("6", "1"): "Windows 7 / Server 2008 R2",
            ("6", "2"): "Windows 8 / Server 2012",
            ("6", "3"): "Windows 8.1 / Server 2012 R2",
            ("10", "0"): "Windows 10 / Server 2016+",
            ("5", "1"): "Windows XP",
            ("5", "2"): "Windows XP x64 / Server 2003",
            ("5", "0"): "Windows 2000",
        }

        os_name = version_map.get((major, minor), f"Windows NT {major}.{minor}")

        # Refine Windows 10+ by build number
        if major == "10" and minor == "0" and build:
            try:
                build_num = int(build)
                if build_num >= 22000:
                    os_name = "Windows 11 / Server 2022"
                elif build_num >= 20348:
                    os_name = "Windows Server 2022"
                elif build_num >= 19041:
                    os_name = "Windows 10 20H1+ / Server 2019"
                elif build_num >= 17763:
                    os_name = "Windows 10 1809 / Server 2019"
                elif build_num >= 14393:
                    os_name = "Windows 10 1607 / Server 2016"
            except ValueError:
                pass

        return os_name

    def _port_to_service(self, port: int) -> str:
        """Convert port to service name."""
        services = {
            445: "smb",
            139: "netbios-ssn",
            80: "http",
            443: "https",
            8080: "http-proxy",
            1433: "mssql",
            3389: "rdp",
            5985: "winrm",
            5986: "winrm-ssl",
            389: "ldap",
            636: "ldaps",
            25: "smtp",
            587: "smtp-submission",
        }
        return services.get(port, f"tcp/{port}")

    def _get_first(self, value) -> str:
        """Get first value if list, otherwise return as string."""
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def get_hashcat_mode(self) -> Optional[int]:
        """Return default hashcat mode (NTLMv2)."""
        return 5600
