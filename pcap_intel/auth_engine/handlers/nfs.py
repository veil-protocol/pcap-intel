#!/usr/bin/env python3
"""
AUTH ENGINE - NFS Credential Handler

Extracts NFS (Network File System) authentication data.

NFS Auth Methods (AUTH flavors):
    - AUTH_NONE (0): No authentication
    - AUTH_SYS/AUTH_UNIX (1): UID/GID trust
    - AUTH_SHORT (2): Short hand for AUTH_SYS
    - AUTH_DH (3): Diffie-Hellman (AUTH_DES)
    - RPCSEC_GSS (6): Kerberos/GSSAPI

AUTH_SYS is commonly used and reveals UID/GID info.

Hashcat Mode: N/A (trust-based, no password)
"""

from typing import Dict, List, Optional, Any
from ..base import (
    AuthProtocolHandler,
    AuthMessage,
    AuthPhase,
    ExtractedCredential,
    ProtocolMetadata,
)


class NFSAuthHandler(AuthProtocolHandler):
    """
    Handler for NFS authentication.

    Extracts AUTH_SYS credentials (UID/GID/hostname).
    """

    @property
    def protocol_name(self) -> str:
        return "nfs"

    @property
    def tshark_filter(self) -> str:
        return "nfs or rpc.auth.flavor"

    @property
    def correlation_field(self) -> str:
        return "rpc.xid"

    @property
    def tshark_fields(self) -> List[str]:
        return [
            # RPC fields
            "rpc.xid",
            "rpc.msgtyp",
            "rpc.auth.flavor",
            "rpc.auth.machinename",
            "rpc.auth.uid",
            "rpc.auth.gid",
            "rpc.auth.stamp",
            "rpc.auth.gids",
            "rpc.replystat",
            "rpc.state_accept",
            # NFS fields
            "nfs.procedure_v3",
            "nfs.procedure_v4",
            "nfs.status",
            "nfs.fh.hash",
            # RPCSEC_GSS
            "rpc.auth.gss.svc",
            "rpc.auth.gss.proc",
            "rpc.auth.gss.seq",
        ]

    def classify_message(self, fields: Dict[str, Any], frame_num: int) -> Optional[AuthMessage]:
        """Classify NFS/RPC message."""
        timestamp = float(fields.get("frame.time_epoch", 0) or 0)
        src_ip = self._get_first(fields.get("ip.src", ""))
        dst_ip = self._get_first(fields.get("ip.dst", ""))
        src_port = int(self._get_first(fields.get("udp.srcport", 0)) or 0) or \
                   int(self._get_first(fields.get("tcp.srcport", 0)) or 0)
        dst_port = int(self._get_first(fields.get("udp.dstport", 0)) or 0) or \
                   int(self._get_first(fields.get("tcp.dstport", 0)) or 0)

        xid = self._get_first(fields.get("rpc.xid", ""))
        if not xid:
            return None

        auth_flavor = self._get_first(fields.get("rpc.auth.flavor", ""))
        msg_type = self._get_first(fields.get("rpc.msgtyp", ""))
        machine = self._get_first(fields.get("rpc.auth.machinename", ""))
        uid = self._get_first(fields.get("rpc.auth.uid", ""))
        reply_stat = self._get_first(fields.get("rpc.replystat", ""))

        # Message type: 0=CALL, 1=REPLY
        if msg_type == "0" and (auth_flavor or machine or uid):
            phase = AuthPhase.RESPONSE  # Client sending credentials
        elif msg_type == "1":
            phase = AuthPhase.RESULT  # Server reply
        else:
            return None

        return AuthMessage(
            phase=phase,
            correlation_key=xid,
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
        """Build NFS credential from RPC auth."""
        machine_name = None
        uid = None
        gid = None
        gids = None
        auth_flavor = None
        stamp = None
        gss_svc = None
        nfs_procedure = None
        client_ip = None
        server_ip = None
        auth_success = None
        timestamp = 0.0

        auth_flavors = {
            "0": "AUTH_NONE",
            "1": "AUTH_SYS",
            "2": "AUTH_SHORT",
            "3": "AUTH_DH",
            "6": "RPCSEC_GSS",
        }

        for msg in sorted(messages, key=lambda m: m.timestamp):
            flavor = self._get_first(msg.raw_data.get("rpc.auth.flavor", ""))
            if flavor:
                auth_flavor = auth_flavors.get(flavor, f"FLAVOR_{flavor}")

            machine = self._get_first(msg.raw_data.get("rpc.auth.machinename", ""))
            if machine:
                machine_name = machine
                client_ip = msg.source_ip
                server_ip = msg.dest_ip
                timestamp = msg.timestamp

            u = self._get_first(msg.raw_data.get("rpc.auth.uid", ""))
            if u:
                uid = u

            g = self._get_first(msg.raw_data.get("rpc.auth.gid", ""))
            if g:
                gid = g

            gs = self._get_first(msg.raw_data.get("rpc.auth.gids", ""))
            if gs:
                gids = gs

            s = self._get_first(msg.raw_data.get("rpc.auth.stamp", ""))
            if s:
                stamp = s

            gsvc = self._get_first(msg.raw_data.get("rpc.auth.gss.svc", ""))
            if gsvc:
                gss_svc = gsvc

            proc_v3 = self._get_first(msg.raw_data.get("nfs.procedure_v3", ""))
            proc_v4 = self._get_first(msg.raw_data.get("nfs.procedure_v4", ""))
            if proc_v3:
                nfs_procedure = f"NFSv3:{proc_v3}"
            elif proc_v4:
                nfs_procedure = f"NFSv4:{proc_v4}"

            reply = self._get_first(msg.raw_data.get("rpc.replystat", ""))
            accept = self._get_first(msg.raw_data.get("rpc.state_accept", ""))
            nfs_status = self._get_first(msg.raw_data.get("nfs.status", ""))

            if reply == "0" and accept == "0":  # MSG_ACCEPTED, SUCCESS
                auth_success = True
            elif reply == "1" or nfs_status not in ["", "0"]:  # MSG_DENIED or NFS error
                auth_success = False

        if not uid and not machine_name:
            return None

        # For AUTH_SYS, username is typically derived from UID
        # We use machine_name as identifier
        username = f"uid:{uid}" if uid else machine_name or "unknown"

        metadata = ProtocolMetadata(
            target_hostname=machine_name,
            raw_fields={
                "auth_flavor": auth_flavor,
                "uid": uid,
                "gid": gid,
                "gids": gids,
                "stamp": stamp,
                "gss_svc": gss_svc,
                "nfs_procedure": nfs_procedure,
                "note": "NFS AUTH_SYS is trust-based (no password)",
            }
        )

        return ExtractedCredential(
            protocol="nfs",
            username=username,
            domain=server_ip,
            credential_data={
                "machine_name": machine_name,
                "uid": uid,
                "gid": gid,
                "gids": gids,
                "auth_flavor": auth_flavor,
            },
            hashcat_format=None,  # Trust-based, no password
            hashcat_mode=None,
            source_ip=client_ip or "",
            source_port=0,
            target_ip=server_ip or "",
            target_port=2049,
            target_service="nfs",
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
        return None  # Trust-based
