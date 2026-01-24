#!/usr/bin/env python3
"""
AUTH ENGINE - IRC Credential Handler

Extracts IRC authentication credentials.

IRC Authentication:
    - PASS <password> (server password, before NICK/USER)
    - NICK <nickname>
    - USER <username> <mode> <unused> :<realname>
    - NickServ IDENTIFY <password>
    - OPER <name> <password> (IRC operator)

Also captures:
    - SASL PLAIN authentication
    - Channel keys (JOIN #channel key)

Hashcat: N/A (plaintext passwords)
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


class IRCAuthHandler(AuthProtocolHandler):
    """
    Handler for IRC authentication.

    Extracts PASS, OPER, NickServ IDENTIFY, and SASL credentials.
    """

    @property
    def protocol_name(self) -> str:
        return "irc"

    @property
    def tshark_filter(self) -> str:
        return "irc.request or irc.response"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "irc.request",
            "irc.request.command",
            "irc.request.prefix",
            "irc.request.trailer",
            "irc.response",
            "irc.response.command",
            "irc.response.prefix",
            "irc.response.trailer",
            "irc.response.num_command",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify IRC auth message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        request = self._get_first(fields.get("irc.request", ""))
        req_cmd = self._get_first(fields.get("irc.request.command", "")).upper()
        response = self._get_first(fields.get("irc.response", ""))
        resp_num = self._get_first(fields.get("irc.response.num_command", ""))

        # Auth-related commands
        auth_commands = ["PASS", "NICK", "USER", "OPER", "PRIVMSG", "AUTHENTICATE", "CAP"]

        if req_cmd in auth_commands:
            if req_cmd == "PASS":
                phase = AuthPhase.RESPONSE
            elif req_cmd == "NICK":
                phase = AuthPhase.INITIATION
            elif req_cmd == "OPER":
                phase = AuthPhase.RESPONSE
            elif req_cmd == "PRIVMSG":
                # Check for NickServ IDENTIFY
                trailer = self._get_first(fields.get("irc.request.trailer", "")).upper()
                if "IDENTIFY" in trailer or "LOGIN" in trailer:
                    phase = AuthPhase.RESPONSE
                else:
                    return None
            elif req_cmd == "AUTHENTICATE":
                phase = AuthPhase.RESPONSE
            else:
                phase = AuthPhase.INITIATION
        elif resp_num:
            # Server responses
            num = int(resp_num) if resp_num.isdigit() else 0
            if num == 900:  # SASL success
                phase = AuthPhase.RESULT
            elif num == 903:  # SASL success
                phase = AuthPhase.RESULT
            elif num == 904:  # SASL fail
                phase = AuthPhase.RESULT
            elif num == 381:  # Now OPER
                phase = AuthPhase.RESULT
            elif num == 464:  # Password incorrect
                phase = AuthPhase.RESULT
            elif num == 1:  # Welcome (connected)
                phase = AuthPhase.RESULT
            else:
                return None
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
        """Build IRC credential from auth exchange."""
        nickname = None
        username = None
        password = None
        oper_password = None
        nickserv_password = None
        sasl_data = None
        client_ip = None
        server_ip = None
        server_port = None
        auth_success = None
        timestamp = 0.0
        auth_type = None

        for msg in sorted(messages, key=lambda m: m.timestamp):
            req_cmd = self._get_first(msg.raw_data.get("irc.request.command", "")).upper()
            request = self._get_first(msg.raw_data.get("irc.request", ""))
            trailer = self._get_first(msg.raw_data.get("irc.request.trailer", ""))
            resp_num = self._get_first(msg.raw_data.get("irc.response.num_command", ""))

            if req_cmd == "PASS":
                # PASS <password>
                parts = request.split(None, 1)
                if len(parts) >= 2:
                    password = parts[1].lstrip(':')
                auth_type = "server_password"
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp

            elif req_cmd == "NICK":
                # NICK <nickname>
                parts = request.split(None, 1)
                if len(parts) >= 2:
                    nickname = parts[1].lstrip(':')
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port

            elif req_cmd == "USER":
                # USER <username> <mode> <unused> :<realname>
                parts = request.split()
                if len(parts) >= 2:
                    username = parts[1]

            elif req_cmd == "OPER":
                # OPER <name> <password>
                parts = request.split(None, 2)
                if len(parts) >= 3:
                    username = parts[1]
                    oper_password = parts[2]
                auth_type = "oper"
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp

            elif req_cmd == "PRIVMSG":
                # PRIVMSG NickServ :IDENTIFY <password>
                trailer_upper = trailer.upper()
                if "NICKSERV" in request.upper() or "NS" in request.upper():
                    if "IDENTIFY" in trailer_upper:
                        parts = trailer.split()
                        for i, p in enumerate(parts):
                            if p.upper() == "IDENTIFY" and i + 1 < len(parts):
                                nickserv_password = parts[i + 1]
                                auth_type = "nickserv"
                                break
                    elif "LOGIN" in trailer_upper:
                        parts = trailer.split()
                        for i, p in enumerate(parts):
                            if p.upper() == "LOGIN" and i + 2 < len(parts):
                                username = parts[i + 1]
                                nickserv_password = parts[i + 2]
                                auth_type = "nickserv"
                                break
                    client_ip = msg.source_ip
                    server_ip = msg.dest_ip
                    server_port = msg.dest_port
                    timestamp = msg.timestamp

            elif req_cmd == "AUTHENTICATE":
                # SASL AUTHENTICATE <base64>
                parts = request.split(None, 1)
                if len(parts) >= 2 and parts[1] != "+":
                    sasl_data = parts[1]
                    auth_type = "sasl"
                    # Try to decode SASL PLAIN
                    try:
                        decoded = base64.b64decode(sasl_data).decode("utf-8", errors="replace")
                        sasl_parts = decoded.split("\x00")
                        if len(sasl_parts) >= 3:
                            username = sasl_parts[1] or sasl_parts[0]
                            password = sasl_parts[2]
                    except Exception:
                        pass
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                server_port = msg.dest_port
                timestamp = msg.timestamp

            # Results
            if resp_num:
                num = int(resp_num) if resp_num.isdigit() else 0
                if num in [900, 903, 381, 1]:  # Success codes
                    auth_success = True
                elif num in [904, 464]:  # Failure codes
                    auth_success = False

        # Determine best credential to return
        final_username = username or nickname
        final_password = password or oper_password or nickserv_password

        if not final_username and not final_password:
            return None

        cred_data = {
            "auth_type": auth_type or "unknown",
        }

        if password:
            cred_data["server_password"] = password
        if oper_password:
            cred_data["oper_password"] = oper_password
        if nickserv_password:
            cred_data["nickserv_password"] = nickserv_password
        if nickname:
            cred_data["nickname"] = nickname
        if sasl_data:
            cred_data["sasl_data"] = sasl_data

        metadata = ProtocolMetadata(
            raw_fields={
                "auth_type": auth_type,
                "nickname": nickname,
            }
        )

        return ExtractedCredential(
            protocol="irc",
            username=final_username or "unknown",
            domain=server_ip,
            credential_data=cred_data,
            hashcat_format=None,  # Plaintext
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=server_port or 6667,
            target_service="irc",
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
        return None  # Plaintext
