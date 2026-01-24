#!/usr/bin/env python3
"""
PCAP-INTEL Timeline Panel

Real-time behavioral timeline for TUI integration.
Converts live flow/credential/alert events into a temporal activity stream.

Features:
- Activity timeline with timestamps
- Session detection and grouping
- Behavioral pattern recognition
- User profile scoring
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
from enum import Enum

from rich.text import Text
from rich.markup import render as render_markup


class ActivityType(Enum):
    """Types of timeline activities."""
    FLOW = "flow"
    CREDENTIAL = "credential"
    ALERT = "alert"
    DNS = "dns"
    SERVICE = "service"
    LATERAL = "lateral"
    EXFIL = "exfil"
    C2_BEACON = "c2_beacon"


@dataclass
class TimelineEvent:
    """Single event in timeline."""
    timestamp: datetime
    activity_type: ActivityType
    src_ip: str
    dst_ip: str
    port: int
    protocol: str
    description: str
    severity: str = "info"  # info, medium, high, critical
    codenames: Tuple[str, str] = ("", "")  # (src_codename, dst_codename)
    metadata: Dict = field(default_factory=dict)


@dataclass
class ActivitySession:
    """Grouped session of related activities."""
    session_id: str
    host_ip: str
    start_time: datetime
    end_time: datetime
    activity_count: int
    primary_service: str
    services_used: Set[str] = field(default_factory=set)
    is_suspicious: bool = False
    automation_score: float = 0.0
    events: List[TimelineEvent] = field(default_factory=list)


@dataclass
class HostProfile:
    """Behavioral profile for a host."""
    ip: str
    codename: str
    total_activities: int = 0
    active_duration: float = 0.0
    services_used: Dict[str, int] = field(default_factory=dict)
    sessions: List[ActivitySession] = field(default_factory=list)
    automation_score: float = 0.0
    likely_role: str = ""  # workstation, server, attacker, c2
    risk_score: int = 0


class TimelinePanel:
    """
    Real-time behavioral timeline for TUI.

    Integrates flow/credential/alert data into a temporal view.
    """

    # Session gap threshold (seconds)
    SESSION_GAP = 30.0

    # Beacon detection thresholds
    BEACON_MIN_EVENTS = 5
    BEACON_REGULARITY_THRESHOLD = 0.8  # 80% regular intervals

    # Service port mappings
    SERVICE_MAP = {
        22: "SSH", 23: "TELNET", 80: "HTTP", 443: "HTTPS",
        445: "SMB", 139: "NETBIOS", 3389: "RDP", 5985: "WINRM",
        88: "KERBEROS", 389: "LDAP", 636: "LDAPS",
        53: "DNS", 25: "SMTP", 110: "POP3", 143: "IMAP",
        21: "FTP", 3306: "MYSQL", 5432: "POSTGRES",
        1433: "MSSQL", 6379: "REDIS", 27017: "MONGO",
    }

    # Lateral movement ports
    LATERAL_PORTS = {22, 23, 135, 139, 445, 3389, 5985, 5986, 5900, 5901}

    # C2 suspicious ports (non-standard HTTPS)
    C2_SUSPECT_PORTS = {8443, 4443, 9443, 8080, 8000, 8888}

    def __init__(self, codename_resolver=None, local_subnet: str = "10.0.0"):
        """
        Initialize timeline panel.

        Args:
            codename_resolver: Function (ip) -> (name, cat, color)
            local_subnet: Local subnet prefix for classification
        """
        self.codename_resolver = codename_resolver
        self.local_subnet = local_subnet

        # Event storage
        self.events: List[TimelineEvent] = []
        self.max_events = 1000  # Rolling window

        # Computed data
        self.profiles: Dict[str, HostProfile] = {}
        self.sessions: List[ActivitySession] = []

        # Detection state
        self._beacon_candidates: Dict[str, List[datetime]] = defaultdict(list)
        self._session_counter = 0

    def add_flow(
        self,
        src: str,
        dst: str,
        port: int,
        proto: str = "TCP",
        count: int = 1,
        timestamp: datetime = None
    ):
        """Add flow event to timeline."""
        timestamp = timestamp or datetime.now()

        # Classify flow type
        activity_type = self._classify_flow(src, dst, port)
        severity = self._flow_severity(activity_type, port)

        # Get codenames
        src_cn = self._get_codename(src)
        dst_cn = self._get_codename(dst)

        event = TimelineEvent(
            timestamp=timestamp,
            activity_type=activity_type,
            src_ip=src,
            dst_ip=dst,
            port=port,
            protocol=proto,
            description=self._flow_description(src_cn, dst_cn, port, activity_type),
            severity=severity,
            codenames=(src_cn, dst_cn),
            metadata={"count": count}
        )

        self._add_event(event)
        self._update_profiles(event)
        self._check_beaconing(src, dst, port, timestamp)

    def add_credential(
        self,
        protocol: str,
        username: str,
        domain: str,
        target_ip: str,
        target_port: int,
        timestamp: datetime = None
    ):
        """Add credential capture event."""
        timestamp = timestamp or datetime.now()
        target_cn = self._get_codename(target_ip)

        event = TimelineEvent(
            timestamp=timestamp,
            activity_type=ActivityType.CREDENTIAL,
            src_ip="",
            dst_ip=target_ip,
            port=target_port,
            protocol=protocol.upper(),
            description=f"CRED {protocol.upper()}: {username}@{domain} → {target_cn}",
            severity="critical",
            codenames=("", target_cn),
            metadata={"username": username, "domain": domain}
        )

        self._add_event(event)

    def add_alert(
        self,
        severity: str,
        alert_type: str,
        message: str,
        src_ip: str = "",
        dst_ip: str = "",
        timestamp: datetime = None
    ):
        """Add alert event."""
        timestamp = timestamp or datetime.now()
        src_cn = self._get_codename(src_ip) if src_ip else ""
        dst_cn = self._get_codename(dst_ip) if dst_ip else ""

        event = TimelineEvent(
            timestamp=timestamp,
            activity_type=ActivityType.ALERT,
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=0,
            protocol=alert_type,
            description=f"ALERT [{severity.upper()[:4]}] {message[:50]}",
            severity=severity.lower(),
            codenames=(src_cn, dst_cn),
            metadata={"type": alert_type, "message": message}
        )

        self._add_event(event)

    def add_dns(
        self,
        domain: str,
        answers: List[str],
        timestamp: datetime = None
    ):
        """Add DNS resolution event."""
        timestamp = timestamp or datetime.now()
        first_ip = answers[0] if answers else ""
        ip_cn = self._get_codename(first_ip) if first_ip else ""

        event = TimelineEvent(
            timestamp=timestamp,
            activity_type=ActivityType.DNS,
            src_ip="",
            dst_ip=first_ip,
            port=53,
            protocol="DNS",
            description=f"DNS {domain[:30]} → {ip_cn or first_ip}",
            severity="info",
            codenames=("", ip_cn),
            metadata={"domain": domain, "answers": answers}
        )

        self._add_event(event)

    def _add_event(self, event: TimelineEvent):
        """Add event to timeline."""
        self.events.append(event)

        # Trim old events
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]

    def _get_codename(self, ip: str) -> str:
        """Get codename for IP."""
        if not ip:
            return ""
        if self.codename_resolver:
            try:
                name, _, _ = self.codename_resolver(ip)
                return name
            except:
                pass
        return ip[:15]

    def _classify_flow(self, src: str, dst: str, port: int) -> ActivityType:
        """Classify flow type."""
        src_internal = src.startswith(('10.', '192.168.', '172.'))
        dst_internal = dst.startswith(('10.', '192.168.', '172.'))

        # Lateral movement detection
        if src_internal and dst_internal and port in self.LATERAL_PORTS:
            return ActivityType.LATERAL

        # Potential exfiltration
        if src_internal and not dst_internal:
            if port in (443, 53, 80) or port in self.C2_SUSPECT_PORTS:
                return ActivityType.EXFIL

        return ActivityType.FLOW

    def _flow_severity(self, activity_type: ActivityType, port: int) -> str:
        """Determine flow severity."""
        if activity_type == ActivityType.LATERAL:
            return "high"
        if activity_type == ActivityType.EXFIL:
            return "medium"
        if activity_type == ActivityType.C2_BEACON:
            return "critical"
        return "info"

    def _flow_description(self, src_cn: str, dst_cn: str, port: int, activity_type: ActivityType) -> str:
        """Generate flow description."""
        svc = self.SERVICE_MAP.get(port, str(port))

        if activity_type == ActivityType.LATERAL:
            return f"LAT {src_cn} → {dst_cn}:{svc}"
        if activity_type == ActivityType.EXFIL:
            return f"EGR {src_cn} → {dst_cn}:{svc}"

        return f"{src_cn} → {dst_cn}:{svc}"

    def _update_profiles(self, event: TimelineEvent):
        """Update host profiles with event."""
        for ip in [event.src_ip, event.dst_ip]:
            if not ip:
                continue

            if ip not in self.profiles:
                self.profiles[ip] = HostProfile(
                    ip=ip,
                    codename=self._get_codename(ip)
                )

            profile = self.profiles[ip]
            profile.total_activities += 1

            # Track services
            if event.port and event.port > 0:
                svc = self.SERVICE_MAP.get(event.port, str(event.port))
                if svc not in profile.services_used:
                    profile.services_used[svc] = 0
                profile.services_used[svc] += 1

    def _check_beaconing(self, src: str, dst: str, port: int, timestamp: datetime):
        """Check for C2 beaconing patterns."""
        if port not in self.C2_SUSPECT_PORTS and port not in (443, 80):
            return

        key = f"{src}:{dst}:{port}"
        self._beacon_candidates[key].append(timestamp)

        # Keep only recent timestamps
        cutoff = timestamp - timedelta(minutes=30)
        self._beacon_candidates[key] = [
            t for t in self._beacon_candidates[key]
            if t > cutoff
        ]

        # Check for regularity
        times = self._beacon_candidates[key]
        if len(times) >= self.BEACON_MIN_EVENTS:
            intervals = []
            for i in range(1, len(times)):
                intervals.append((times[i] - times[i-1]).total_seconds())

            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)
                regularity = 1 - min(variance / (avg_interval**2 + 0.01), 1)

                if regularity >= self.BEACON_REGULARITY_THRESHOLD:
                    # Detected beacon!
                    beacon_event = TimelineEvent(
                        timestamp=timestamp,
                        activity_type=ActivityType.C2_BEACON,
                        src_ip=src,
                        dst_ip=dst,
                        port=port,
                        protocol="BEACON",
                        description=f"C2 BEACON {self._get_codename(src)} → {self._get_codename(dst)} ({avg_interval:.0f}s interval)",
                        severity="critical",
                        codenames=(self._get_codename(src), self._get_codename(dst)),
                        metadata={"interval": avg_interval, "regularity": regularity}
                    )
                    self._add_event(beacon_event)

    def detect_sessions(self) -> List[ActivitySession]:
        """Detect activity sessions from events."""
        # Group events by host
        host_events: Dict[str, List[TimelineEvent]] = defaultdict(list)
        for event in self.events:
            for ip in [event.src_ip, event.dst_ip]:
                if ip:
                    host_events[ip].append(event)

        sessions = []
        for ip, events in host_events.items():
            if len(events) < 2:
                continue

            # Sort by timestamp
            events = sorted(events, key=lambda e: e.timestamp)

            # Split into sessions by gap
            current_session: List[TimelineEvent] = []
            for event in events:
                if current_session:
                    gap = (event.timestamp - current_session[-1].timestamp).total_seconds()
                    if gap > self.SESSION_GAP:
                        # New session
                        if len(current_session) >= 2:
                            sessions.append(self._create_session(ip, current_session))
                        current_session = []

                current_session.append(event)

            # Final session
            if len(current_session) >= 2:
                sessions.append(self._create_session(ip, current_session))

        self.sessions = sessions
        return sessions

    def _create_session(self, ip: str, events: List[TimelineEvent]) -> ActivitySession:
        """Create session from events."""
        self._session_counter += 1

        services = set()
        for e in events:
            if e.port:
                services.add(self.SERVICE_MAP.get(e.port, str(e.port)))

        # Check for suspicious activity
        suspicious = any(e.activity_type in (ActivityType.LATERAL, ActivityType.C2_BEACON, ActivityType.CREDENTIAL) for e in events)

        # Calculate automation score (high event rate = automated)
        duration = (events[-1].timestamp - events[0].timestamp).total_seconds()
        rate = len(events) / max(duration, 1)
        automation_score = min(rate / 10, 1.0)  # 10 events/sec = 100%

        return ActivitySession(
            session_id=f"S{self._session_counter:04d}",
            host_ip=ip,
            start_time=events[0].timestamp,
            end_time=events[-1].timestamp,
            activity_count=len(events),
            primary_service=max(services, key=lambda s: sum(1 for e in events if self.SERVICE_MAP.get(e.port) == s), default="?"),
            services_used=services,
            is_suspicious=suspicious,
            automation_score=automation_score,
            events=events
        )

    # ===================
    # Rendering
    # ===================

    def render(self, width: int = 80, max_lines: int = 25) -> Text:
        """
        Render timeline panel.

        Args:
            width: Panel width
            max_lines: Maximum lines to render

        Returns:
            Rich Text object for display
        """
        output = Text()

        # Header
        output.append("═" * width + "\n", style="bold #58a6ff")
        output.append("  ", style="")
        output.append("📊 BEHAVIORAL TIMELINE", style="bold white")
        output.append(f"  │  {len(self.events)} events  {len(self.profiles)} hosts", style="dim")
        output.append("\n")
        output.append("═" * width + "\n", style="bold #58a6ff")

        # Recent events
        recent = self.events[-max_lines:] if len(self.events) > max_lines else self.events
        recent = list(reversed(recent))  # Most recent first

        for event in recent:
            line = self._render_event(event, width)
            output.append(line)
            output.append("\n")

        if not recent:
            output.append("  [dim]No activity yet...[/]\n", style="dim")

        return output

    def _render_event(self, event: TimelineEvent, width: int = 80) -> Text:
        """Render single event line."""
        line = Text()

        # Timestamp
        ts = event.timestamp.strftime("%H:%M:%S")
        line.append(ts, style="dim")
        line.append(" ", style="")

        # Severity indicator
        sev_style = {
            "critical": "bold white on red",
            "high": "bold #f85149",
            "medium": "#d29922",
            "info": "dim",
        }.get(event.severity, "dim")

        sev_char = {
            "critical": "!",
            "high": "▲",
            "medium": "●",
            "info": "·",
        }.get(event.severity, "·")

        line.append(sev_char, style=sev_style)
        line.append(" ", style="")

        # Activity type badge
        type_styles = {
            ActivityType.CREDENTIAL: ("CRED", "bold white on red"),
            ActivityType.LATERAL: ("LAT", "bold #f0883e on #21262d"),
            ActivityType.C2_BEACON: ("C2", "bold white on #f85149"),
            ActivityType.EXFIL: ("EGR", "bold #d29922"),
            ActivityType.ALERT: ("ALT", "bold #f85149"),
            ActivityType.DNS: ("DNS", "#58a6ff"),
            ActivityType.FLOW: ("FLW", "dim"),
        }

        badge, badge_style = type_styles.get(event.activity_type, ("???", "dim"))
        line.append(f"[{badge}]", style=badge_style)
        line.append(" ", style="")

        # Description (truncated)
        desc_width = width - 20  # Account for timestamp, badge, etc.
        desc = event.description[:desc_width]
        line.append(desc, style="")

        return line

    def render_compact(self, width: int = 40, max_lines: int = 10) -> Text:
        """Render compact timeline for side panel."""
        output = Text()

        output.append("── TIMELINE ──\n", style="bold #a371f7")

        recent = self.events[-max_lines:] if len(self.events) > max_lines else self.events
        recent = list(reversed(recent))

        for event in recent:
            ts = event.timestamp.strftime("%H:%M")
            sev_char = "!" if event.severity == "critical" else "▲" if event.severity == "high" else "·"

            # Very compact format
            desc = event.description[:width-10]
            style = "bold red" if event.severity == "critical" else ""

            output.append(f"{ts} {sev_char} {desc}\n", style=style)

        if not recent:
            output.append("[dim]Waiting...[/]\n", style="dim")

        return output

    def get_summary(self) -> Dict:
        """Get timeline summary statistics."""
        if not self.events:
            return {"total_events": 0}

        # Compute stats
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)

        for event in self.events:
            severity_counts[event.severity] += 1
            type_counts[event.activity_type.value] += 1

        # Time range
        first = self.events[0].timestamp
        last = self.events[-1].timestamp
        duration = (last - first).total_seconds()

        return {
            "total_events": len(self.events),
            "duration_seconds": duration,
            "events_per_minute": len(self.events) / max(duration / 60, 1),
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
            "lateral_count": type_counts.get("lateral", 0),
            "credential_count": type_counts.get("credential", 0),
            "beacon_count": type_counts.get("c2_beacon", 0),
            "first_event": first.isoformat(),
            "last_event": last.isoformat(),
        }
