#!/usr/bin/env python3
"""
AUTH ENGINE - Kerberos Handler

Extracts Kerberos authentication data for AS-REP roasting and TGS roasting.

Kerberos Message Types:
    AS-REQ (10): Client requests TGT
    AS-REP (11): KDC returns TGT (roastable if no preauth)
    TGS-REQ (12): Client requests service ticket
    TGS-REP (13): KDC returns service ticket (Kerberoastable)
    AP-REQ (14): Client sends ticket to service
    AP-REP (15): Service confirms

Hashcat Modes:
    18200: Kerberos 5 AS-REP etype 23 (rc4-hmac)
    19600: Kerberos 5 TGS-REP etype 23 (rc4-hmac)
    19700: Kerberos 5 TGS-REP etype 17 (aes128)
    19800: Kerberos 5 TGS-REP etype 18 (aes256)

Attack Techniques:
    - AS-REP Roasting: Users without preauth required
    - Kerberoasting: Service tickets for SPNs
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class KerberosHandler(AuthProtocolHandler):
    """
    Handler for Kerberos v5 authentication.

    Extracts:
        - AS-REP hashes (AS-REP roasting)
        - TGS-REP hashes (Kerberoasting)
        - Principal names and realms
        - Encryption types
        - Service Principal Names (SPNs)
    """

    @property
    def protocol_name(self) -> str:
        return "kerberos"

    @property
    def tshark_filter(self) -> str:
        return "kerberos"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # Message type
            "kerberos.msg_type",

            # Realm and principal
            "kerberos.realm",
            "kerberos.CNameString",
            "kerberos.SNameString",
            "kerberos.name_string",

            # Encryption type
            "kerberos.etype",

            # Cipher fields (different contexts)
            "kerberos.encryptedTicketData_cipher",
            "kerberos.encryptedKDCREPData_cipher",

            # Preauth
            "kerberos.padata_type",

            # Error info (useful for detection)
            "kerberos.error_code",

            # For UDP (Kerberos often uses UDP 88)
            "udp.srcport",
            "udp.dstport",
        ]

    @property
    def common_fields(self) -> List[str]:
        """Override to add UDP support."""
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

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify Kerberos message by type."""
        msg_type = fields.get("kerberos.msg_type")

        if not msg_type:
            return None

        # Get common fields
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))

        # Kerberos uses TCP or UDP port 88
        src_port = int(self._get_first(fields.get("tcp.srcport") or fields.get("udp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport") or fields.get("udp.dstport", 0)) or 0)

        # Correlation key - use stream if TCP, else construct from IPs
        tcp_stream = fields.get("tcp.stream")
        if tcp_stream:
            correlation_key = self._get_first(tcp_stream)
        else:
            # UDP - correlate by client IP + server IP
            correlation_key = f"{src_ip}-{dst_ip}"

        if not correlation_key:
            return None

        # Classify by message type
        # 10=AS-REQ, 11=AS-REP, 12=TGS-REQ, 13=TGS-REP, 14=AP-REQ, 15=AP-REP
        phase_map = {
            "10": AuthPhase.INITIATION,   # AS-REQ
            "11": AuthPhase.CHALLENGE,    # AS-REP (contains roastable hash)
            "12": AuthPhase.RESPONSE,     # TGS-REQ
            "13": AuthPhase.RESULT,       # TGS-REP (contains service ticket)
            "14": AuthPhase.RESPONSE,     # AP-REQ
            "15": AuthPhase.RESULT,       # AP-REP
        }

        phase = phase_map.get(msg_type)
        if not phase:
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
        """Build Kerberos credential from message exchange."""
        # Look for AS-REP (roastable) or TGS-REP (Kerberoastable)
        as_rep = None
        tgs_rep = None
        as_req = None
        tgs_req = None

        for msg in messages:
            msg_type = msg.raw_data.get("kerberos.msg_type")
            if msg_type == "11":
                as_rep = msg
            elif msg_type == "13":
                tgs_rep = msg
            elif msg_type == "10":
                as_req = msg
            elif msg_type == "12":
                tgs_req = msg

        # Prefer AS-REP (more valuable - no preauth user)
        if as_rep:
            return self._build_asrep_credential(as_rep, as_req)

        # Fall back to TGS-REP (Kerberoasting)
        if tgs_rep:
            return self._build_tgsrep_credential(tgs_rep, tgs_req)

        return None

    def _build_asrep_credential(
        self,
        as_rep: AuthMessage,
        as_req: Optional[AuthMessage]
    ) -> Optional[ExtractedCredential]:
        """Build AS-REP roasting credential."""
        fields = as_rep.raw_data

        # Get cipher (the roastable part)
        cipher = self._get_first(fields.get("kerberos.encryptedKDCREPData_cipher", ""))
        if not cipher:
            cipher = self._get_first(fields.get("kerberos.encryptedTicketData_cipher", ""))

        if not cipher:
            return None

        # Get principal info
        realm = self._get_first(fields.get("kerberos.realm", ""))
        cname = self._get_first(fields.get("kerberos.CNameString", ""))

        if not cname:
            return None

        # Get encryption type
        etype = self._get_first(fields.get("kerberos.etype", ""))
        etype = self._get_first(fields.get("kerberos.encryption_type", "")) or etype

        # Determine hashcat mode based on etype
        # 23=rc4-hmac, 17=aes128, 18=aes256
        hashcat_mode = self._etype_to_hashcat(etype, "asrep")

        # Clean cipher (remove colons/spaces)
        cipher_clean = cipher.replace(":", "").replace(" ", "").lower()

        # Format: $krb5asrep$etype$user@realm:cipher
        if etype:
            hashcat_format = f"$krb5asrep${etype}${cname}@{realm}:{cipher_clean}"
        else:
            hashcat_format = f"$krb5asrep$23${cname}@{realm}:{cipher_clean}"

        metadata = ProtocolMetadata(
            target_realm=realm,
            encryption_level=self._etype_to_name(etype),
            raw_fields={
                "etype": etype,
                "msg_type": "AS-REP",
            }
        )

        return ExtractedCredential(
            protocol="kerberos_asrep",
            username=cname,
            domain=realm,
            credential_data={
                "cipher": cipher_clean,
                "etype": etype,
                "attack": "AS-REP Roasting",
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=as_rep.dest_ip,  # Client received the AS-REP
            source_port=as_rep.dest_port,
            target_ip=as_rep.source_ip,  # KDC sent the AS-REP
            target_port=as_rep.source_port,
            target_service="kerberos",
            timestamp=as_rep.timestamp,
            metadata=metadata,
        )

    def _build_tgsrep_credential(
        self,
        tgs_rep: AuthMessage,
        tgs_req: Optional[AuthMessage]
    ) -> Optional[ExtractedCredential]:
        """Build TGS-REP Kerberoasting credential."""
        fields = tgs_rep.raw_data

        # Get ticket cipher
        cipher = self._get_first(fields.get("kerberos.encryptedTicketData_cipher", ""))
        if not cipher:
            cipher = self._get_first(fields.get("kerberos.encryptedKDCREPData_cipher", ""))

        if not cipher:
            return None

        # Get SPN (service principal name)
        sname = self._get_first(fields.get("kerberos.SNameString", ""))
        realm = self._get_first(fields.get("kerberos.realm", ""))

        # Get requesting user from TGS-REQ if available
        cname = ""
        if tgs_req:
            cname = self._get_first(tgs_req.raw_data.get("kerberos.CNameString", ""))

        if not sname:
            return None

        # Get encryption type
        etype = self._get_first(fields.get("kerberos.etype", ""))

        # Determine hashcat mode
        hashcat_mode = self._etype_to_hashcat(etype, "tgsrep")

        # Clean cipher
        cipher_clean = cipher.replace(":", "").replace(" ", "").lower()

        # Format: $krb5tgs$etype$*user$realm$spn*$checksum$cipher
        # Simplified format for hashcat:
        if etype:
            hashcat_format = f"$krb5tgs${etype}$*{cname}${realm}${sname}*${cipher_clean[:32]}${cipher_clean[32:]}"
        else:
            hashcat_format = f"$krb5tgs$23$*{cname}${realm}${sname}*${cipher_clean[:32]}${cipher_clean[32:]}"

        metadata = ProtocolMetadata(
            target_realm=realm,
            target_spn=sname,
            encryption_level=self._etype_to_name(etype),
            raw_fields={
                "etype": etype,
                "msg_type": "TGS-REP",
                "requesting_user": cname,
            }
        )

        return ExtractedCredential(
            protocol="kerberos_tgsrep",
            username=sname,  # SPN as username for Kerberoasting
            domain=realm,
            credential_data={
                "cipher": cipher_clean,
                "etype": etype,
                "spn": sname,
                "requesting_user": cname,
                "attack": "Kerberoasting",
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=tgs_rep.dest_ip,
            source_port=tgs_rep.dest_port,
            target_ip=tgs_rep.source_ip,
            target_port=tgs_rep.source_port,
            target_service="kerberos",
            timestamp=tgs_rep.timestamp,
            metadata=metadata,
        )

    def _etype_to_hashcat(self, etype: str, mode: str) -> int:
        """Convert Kerberos encryption type to hashcat mode."""
        if mode == "asrep":
            # AS-REP modes
            etype_map = {
                "23": 18200,  # rc4-hmac
                "17": 19600,  # aes128 (using TGS mode as fallback)
                "18": 19700,  # aes256 (using TGS mode as fallback)
            }
        else:
            # TGS-REP modes
            etype_map = {
                "23": 13100,  # rc4-hmac
                "17": 19600,  # aes128
                "18": 19700,  # aes256
            }

        return etype_map.get(etype, 18200)  # Default to AS-REP rc4

    def _etype_to_name(self, etype: str) -> str:
        """Convert encryption type number to name."""
        etype_names = {
            "1": "des-cbc-crc",
            "3": "des-cbc-md5",
            "17": "aes128-cts-hmac-sha1-96",
            "18": "aes256-cts-hmac-sha1-96",
            "23": "rc4-hmac",
            "24": "rc4-hmac-exp",
        }
        return etype_names.get(etype, f"etype-{etype}")

    def _get_first(self, value) -> str:
        """Get first value if list, otherwise return as string."""
        if value is None:
            return ""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value)

    def get_hashcat_mode(self) -> Optional[int]:
        """Return default hashcat mode (AS-REP rc4)."""
        return 18200
