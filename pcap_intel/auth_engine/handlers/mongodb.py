#!/usr/bin/env python3
"""
AUTH ENGINE - MongoDB Credential Handler

Extracts MongoDB authentication credentials.

MongoDB Auth Methods:
    - SCRAM-SHA-1: Default (MongoDB 3.0+)
    - SCRAM-SHA-256: Stronger (MongoDB 4.0+)
    - MONGODB-CR: Legacy (deprecated)
    - X.509: Certificate-based
    - LDAP/Kerberos: Enterprise

Hashcat Mode: 24100 (MongoDB SCRAM-SHA-1)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class MongoDBAuthHandler(AuthProtocolHandler):
    """
    Handler for MongoDB authentication.

    Extracts SCRAM-SHA-1/256 credentials for offline cracking.
    """

    @property
    def protocol_name(self) -> str:
        return "mongodb"

    @property
    def tshark_filter(self) -> str:
        return "mongo"

    @property
    def correlation_field(self) -> str:
        return "tcp.stream"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            "mongo.opcode",
            "mongo.request_id",
            "mongo.response_to",
            "mongo.full_collection_name",
            "mongo.query",
            "mongo.document",
            "mongo.elements",
            # OP_MSG fields (MongoDB 3.6+)
            "mongo.msg.sections",
            "mongo.msg.body",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify MongoDB message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("tcp.dstport", 0)) or 0)
        correlation_key = self._get_first(fields.get("tcp.stream", ""))

        if not correlation_key:
            return None

        collection = self._get_first(fields.get("mongo.full_collection_name", ""))
        document = self._get_first(fields.get("mongo.document", ""))
        elements = self._get_first(fields.get("mongo.elements", ""))
        msg_body = self._get_first(fields.get("mongo.msg.body", ""))

        # Look for auth-related commands
        content = f"{collection} {document} {elements} {msg_body}".lower()

        if "$external" in collection or "admin.$cmd" in collection:
            if "saslstart" in content or "authenticate" in content:
                phase = AuthPhase.INITIATION
            elif "saslcontinue" in content:
                phase = AuthPhase.RESPONSE
            elif "ok" in content:
                phase = AuthPhase.RESULT
            else:
                return None
        elif "sasl" in content or "authenticate" in content or "scram" in content:
            if "start" in content:
                phase = AuthPhase.INITIATION
            elif "continue" in content:
                phase = AuthPhase.RESPONSE
            else:
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
        """Build MongoDB credential from SCRAM exchange."""
        username = None
        mechanism = None
        client_nonce = None
        server_nonce = None
        salt = None
        iterations = None
        client_proof = None
        server_signature = None
        database = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        for msg in sorted(messages, key=lambda m: m.timestamp):
            content = ""
            for field in ["mongo.document", "mongo.elements", "mongo.msg.body", "mongo.query"]:
                val = self._get_first(msg.raw_data.get(field, ""))
                if val:
                    content += " " + val

            content_lower = content.lower()

            # Extract mechanism
            if "scram-sha-256" in content_lower:
                mechanism = "SCRAM-SHA-256"
            elif "scram-sha-1" in content_lower:
                mechanism = "SCRAM-SHA-1"
            elif "mongodb-cr" in content_lower:
                mechanism = "MONGODB-CR"

            # Extract username from saslStart
            if "saslstart" in content_lower or "authenticate" in content_lower:
                # Look for username in payload
                import re
                user_match = re.search(r'n=([^,]+)', content)
                if user_match:
                    username = user_match.group(1)
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

                # Client nonce
                nonce_match = re.search(r'r=([^,\s]+)', content)
                if nonce_match:
                    client_nonce = nonce_match.group(1)

            # Extract server challenge
            if "saslcontinue" in content_lower or (msg.source_port == 27017):
                import re
                # Server nonce (full)
                nonce_match = re.search(r'r=([^,\s]+)', content)
                if nonce_match:
                    server_nonce = nonce_match.group(1)

                # Salt
                salt_match = re.search(r's=([^,\s]+)', content)
                if salt_match:
                    salt = salt_match.group(1)

                # Iterations
                iter_match = re.search(r'i=(\d+)', content)
                if iter_match:
                    iterations = iter_match.group(1)

                # Client proof
                proof_match = re.search(r'p=([^,\s]+)', content)
                if proof_match:
                    client_proof = proof_match.group(1)

                # Server signature
                sig_match = re.search(r'v=([^,\s]+)', content)
                if sig_match:
                    server_signature = sig_match.group(1)

            # Check for success/failure
            if '"ok":1' in content or '"ok": 1' in content:
                auth_success = True
            elif '"ok":0' in content or '"ok": 0' in content or "authentication failed" in content_lower:
                auth_success = False

            # Extract database
            collection = self._get_first(msg.raw_data.get("mongo.full_collection_name", ""))
            if collection and ".$cmd" in collection:
                database = collection.split(".$cmd")[0]

        if not username:
            return None

        # Build hashcat format for MongoDB SCRAM
        # Mode 24100: $mongodb-scram$*iteration*salt*storedKey
        # This requires server-side data, but we can capture client proof
        hashcat_format = None
        hashcat_mode = None

        if mechanism == "SCRAM-SHA-1" and salt and iterations and client_proof:
            hashcat_mode = 24100
            # Note: Full hashcat format requires stored key from server
            # We capture client-side data for correlation

        metadata = ProtocolMetadata(
            raw_fields={
                "mechanism": mechanism,
                "database": database,
                "iterations": iterations,
                "client_nonce": client_nonce,
                "server_nonce": server_nonce,
            }
        )

        return ExtractedCredential(
            protocol="mongodb",
            username=username,
            domain=database,
            credential_data={
                "mechanism": mechanism,
                "salt": salt,
                "iterations": iterations,
                "client_nonce": client_nonce,
                "server_nonce": server_nonce,
                "client_proof": client_proof,
                "server_signature": server_signature,
            },
            hashcat_format=hashcat_format,
            hashcat_mode=hashcat_mode,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=27017,
            target_service="mongodb",
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
        return 24100  # MongoDB SCRAM-SHA-1
