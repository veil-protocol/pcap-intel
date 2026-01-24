#!/usr/bin/env python3
"""
AUTH ENGINE - Unified Orchestrator

Protocol-agnostic authentication extraction engine.
Registers handlers, runs tshark extractions, correlates messages,
and builds credentials.

Usage:
    from auth_engine import AuthEngine

    engine = AuthEngine()
    credentials = engine.extract_all("/path/to/capture.pcap")

    for cred in credentials:
        print(f"{cred.protocol}: {cred.username}@{cred.domain}")
        if cred.hashcat_format:
            print(f"  Hashcat: {cred.hashcat_format}")
"""

import subprocess
import shutil
import json
from pathlib import Path
from typing import Dict, List, Optional, Iterator, Type
from collections import defaultdict
from dataclasses import dataclass, field

from .base import AuthProtocolHandler, ExtractedCredential, AuthMessage
from .correlation import CorrelationEngine, CorrelatedSession


@dataclass
class ExtractionStats:
    """Statistics from credential extraction."""
    pcap_path: str
    extraction_time_seconds: float = 0.0
    protocols_processed: List[str] = field(default_factory=list)
    messages_by_protocol: Dict[str, int] = field(default_factory=dict)
    sessions_by_protocol: Dict[str, int] = field(default_factory=dict)
    credentials_by_protocol: Dict[str, int] = field(default_factory=dict)
    total_credentials: int = 0
    errors: List[str] = field(default_factory=list)


class AuthEngine:
    """
    Protocol-agnostic authentication extraction engine.

    Manages protocol handlers and orchestrates the extraction pipeline:
    1. Run tshark for each registered handler
    2. Classify packets into auth messages
    3. Correlate messages by session
    4. Build credentials from complete sessions
    """

    def __init__(self, tshark_path: str = "tshark"):
        self.tshark_path = tshark_path
        self.handlers: Dict[str, AuthProtocolHandler] = {}
        self.correlator = CorrelationEngine()
        self.stats: Optional[ExtractionStats] = None

        # Verify tshark is available
        if not shutil.which(tshark_path):
            raise RuntimeError(f"tshark not found at: {tshark_path}")

    def register_handler(self, handler: AuthProtocolHandler):
        """
        Register a protocol handler.

        Args:
            handler: Instance of AuthProtocolHandler subclass
        """
        self.handlers[handler.protocol_name] = handler

    def register_handlers(self, *handlers: AuthProtocolHandler):
        """Register multiple handlers at once."""
        for handler in handlers:
            self.register_handler(handler)

    def register_default_handlers(self):
        """Register all built-in handlers."""
        from .handlers.ntlm import NTLMHandler
        from .handlers.kerberos import KerberosHandler
        from .handlers.http import HTTPAuthHandler
        from .handlers.ldap import LDAPBindHandler

        self.register_handlers(
            NTLMHandler(),
            KerberosHandler(),
            HTTPAuthHandler(),
            LDAPBindHandler(),
        )

    def get_handler(self, protocol: str) -> Optional[AuthProtocolHandler]:
        """Get a handler by protocol name."""
        return self.handlers.get(protocol)

    def list_protocols(self) -> List[str]:
        """List registered protocol names."""
        return list(self.handlers.keys())

    def extract_all(
        self,
        pcap_path: str,
        protocols: Optional[List[str]] = None
    ) -> List[ExtractedCredential]:
        """
        Extract credentials from all registered protocols.

        Args:
            pcap_path: Path to PCAP file
            protocols: List of protocol names to process (None = all)

        Returns:
            List of extracted credentials
        """
        import time
        start_time = time.time()

        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        # Initialize stats
        self.stats = ExtractionStats(pcap_path=str(pcap_path))
        self.correlator.clear()

        # Determine which handlers to run
        handlers_to_run = []
        if protocols:
            for proto in protocols:
                if proto in self.handlers:
                    handlers_to_run.append(self.handlers[proto])
                else:
                    self.stats.errors.append(f"Unknown protocol: {proto}")
        else:
            handlers_to_run = list(self.handlers.values())

        # Extract from each protocol
        all_credentials = []

        for handler in handlers_to_run:
            proto_name = handler.protocol_name
            self.stats.protocols_processed.append(proto_name)

            try:
                # Run extraction for this protocol
                messages = self._extract_protocol_messages(pcap_path, handler)
                self.stats.messages_by_protocol[proto_name] = len(messages)

                # Add to correlator
                self.correlator.add_messages(messages)

                # Build credentials from complete sessions
                credentials = self._build_credentials(handler)
                self.stats.credentials_by_protocol[proto_name] = len(credentials)
                all_credentials.extend(credentials)

            except Exception as e:
                self.stats.errors.append(f"{proto_name}: {str(e)}")

        # Update stats
        self.stats.total_credentials = len(all_credentials)
        self.stats.extraction_time_seconds = time.time() - start_time

        # Session counts from correlator
        corr_stats = self.correlator.get_stats()
        self.stats.sessions_by_protocol = corr_stats.get("complete_sessions_by_protocol", {})

        return all_credentials

    def extract_protocol(
        self,
        pcap_path: str,
        protocol: str
    ) -> List[ExtractedCredential]:
        """
        Extract credentials from a single protocol.

        Args:
            pcap_path: Path to PCAP file
            protocol: Protocol name to process

        Returns:
            List of extracted credentials
        """
        return self.extract_all(pcap_path, protocols=[protocol])

    def _extract_protocol_messages(
        self,
        pcap_path: Path,
        handler: AuthProtocolHandler
    ) -> List[AuthMessage]:
        """
        Run tshark extraction for a single protocol.

        Returns list of AuthMessage objects.
        """
        # Build tshark command
        fields = handler.get_all_fields()
        cmd = [
            self.tshark_path,
            "-r", str(pcap_path),
            "-Y", handler.tshark_filter,
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "occurrence=a",  # Get all occurrences for multi-value fields
        ]

        for field in fields:
            cmd.extend(["-e", field])

        # Run tshark
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            raise RuntimeError(f"tshark failed: {result.stderr}")

        # Parse output
        messages = []
        lines = result.stdout.strip().split("\n")

        for line_num, line in enumerate(lines):
            if not line.strip():
                continue

            # Parse tab-separated fields
            values = line.split("\t")
            field_dict = {}

            for i, field_name in enumerate(fields):
                if i < len(values):
                    value = values[i].strip()
                    # Handle multi-value fields (comma-separated by tshark)
                    if "," in value and field_name not in ["frame.time_epoch"]:
                        field_dict[field_name] = value.split(",")
                    else:
                        field_dict[field_name] = value if value else None
                else:
                    field_dict[field_name] = None

            # Get frame number for reference
            frame_num = int(field_dict.get("frame.number", 0) or 0)

            # Let handler classify the message
            msg = handler.classify_message(field_dict, frame_num)
            if msg:
                messages.append(msg)

        return messages

    def _build_credentials(
        self,
        handler: AuthProtocolHandler
    ) -> List[ExtractedCredential]:
        """
        Build credentials from correlated sessions for a protocol.

        Uses build_all_credentials if available (handles multiple auth
        sequences on same TCP stream), otherwise falls back to build_credential.
        """
        credentials = []

        for session in self.correlator.get_complete_sessions(handler.protocol_name):
            # Check if handler supports multiple credentials per session
            if hasattr(handler, 'build_all_credentials'):
                session_creds = handler.build_all_credentials(session.messages)
            else:
                cred = handler.build_credential(session.messages)
                session_creds = [cred] if cred else []

            for cred in session_creds:
                if cred and handler.validate_credential(cred):
                    # Add session context
                    cred.first_seen = session.first_timestamp
                    cred.last_seen = session.last_timestamp
                    cred.frame_numbers = {m.frame_number for m in session.messages}
                    credentials.append(cred)

        return credentials

    def get_stats(self) -> Optional[ExtractionStats]:
        """Get extraction statistics from last run."""
        return self.stats

    def print_stats(self):
        """Print extraction statistics."""
        if not self.stats:
            print("No extraction stats available. Run extract_all() first.")
            return

        print("=" * 60)
        print("AUTH ENGINE EXTRACTION STATS")
        print("=" * 60)
        print(f"PCAP: {self.stats.pcap_path}")
        print(f"Time: {self.stats.extraction_time_seconds:.2f}s")
        print(f"Total Credentials: {self.stats.total_credentials}")
        print()

        print("By Protocol:")
        for proto in self.stats.protocols_processed:
            msgs = self.stats.messages_by_protocol.get(proto, 0)
            sessions = self.stats.sessions_by_protocol.get(proto, 0)
            creds = self.stats.credentials_by_protocol.get(proto, 0)
            print(f"  {proto:15} {msgs:5} msgs → {sessions:4} sessions → {creds:4} creds")

        if self.stats.errors:
            print()
            print("Errors:")
            for err in self.stats.errors:
                print(f"  - {err}")


def extract_credentials(
    pcap_path: str,
    protocols: Optional[List[str]] = None,
    tshark_path: str = "tshark"
) -> List[ExtractedCredential]:
    """
    Convenience function for quick credential extraction.

    Args:
        pcap_path: Path to PCAP file
        protocols: List of protocols to extract (None = all)
        tshark_path: Path to tshark binary

    Returns:
        List of extracted credentials
    """
    engine = AuthEngine(tshark_path=tshark_path)
    engine.register_default_handlers()
    return engine.extract_all(pcap_path, protocols)


def main():
    """CLI entry point."""
    import sys
    import argparse

    parser = argparse.ArgumentParser(
        description="AUTH ENGINE - Protocol-agnostic credential extraction"
    )
    parser.add_argument("pcap", help="PCAP file to analyze")
    parser.add_argument(
        "-p", "--protocols",
        nargs="+",
        help="Protocols to extract (default: all)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file"
    )
    parser.add_argument(
        "--hashcat",
        action="store_true",
        help="Output hashcat format only"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print extraction statistics"
    )

    args = parser.parse_args()

    # Run extraction
    engine = AuthEngine()
    engine.register_default_handlers()

    print(f"[*] Extracting credentials from {args.pcap}")
    print(f"[*] Registered protocols: {', '.join(engine.list_protocols())}")
    print()

    credentials = engine.extract_all(args.pcap, args.protocols)

    if args.stats:
        engine.print_stats()
        print()

    if args.hashcat:
        # Output hashcat format
        for cred in credentials:
            if cred.hashcat_format:
                print(cred.hashcat_format)
    elif args.output:
        # Output JSON
        output_data = [cred.to_dict() for cred in credentials]
        with open(args.output, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        print(f"[+] Wrote {len(credentials)} credentials to {args.output}")
    else:
        # Pretty print
        for cred in credentials:
            print(f"[{cred.protocol.upper()}] {cred.username}", end="")
            if cred.domain:
                print(f"@{cred.domain}", end="")
            print(f" → {cred.target_ip}:{cred.target_port} ({cred.target_service})")

            if cred.hashcat_format:
                print(f"  Hashcat [{cred.hashcat_mode}]: {cred.hashcat_format[:80]}...")

            if cred.metadata.os_info:
                print(f"  OS: {cred.metadata.os_info}")

            print()

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
