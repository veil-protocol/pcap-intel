#!/usr/bin/env python3
"""
PCAP-INTEL Advanced Filter Engine

Provides BPF-style filter syntax for TUI:
- ip 10.0.0.1           - Filter by IP
- codename SHADOW_VIPER - Filter by codename
- port 445              - Filter by port
- proto smb             - Filter by protocol
- creds > 0             - Filter hosts with credentials
- compromised           - Filter compromised hosts only
- hvt                   - Filter high-value targets

Compound filters:
- ip 10.0.0.1 and port 445
- codename SHADOW* or port 22
- not port 80

Examples:
- "ip 192.168.1.0/24 and proto rdp"
- "codename INT-* and creds > 0"
- "hvt or compromised"
- "port 22,445,3389"
"""

import re
from typing import Dict, List, Set, Optional, Any, Callable, Tuple
from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_network, ip_address, IPv4Network, IPv4Address


class FilterOp(Enum):
    """Filter operations."""
    AND = "and"
    OR = "or"
    NOT = "not"


class FilterType(Enum):
    """Filter field types."""
    IP = "ip"
    CODENAME = "codename"
    PORT = "port"
    PROTO = "proto"
    CREDS = "creds"
    COMPROMISED = "compromised"
    HVT = "hvt"
    FLOWS = "flows"
    ALERTS = "alerts"
    OS = "os"
    DNS = "dns"


@dataclass
class FilterCondition:
    """Single filter condition."""
    field: FilterType
    operator: str  # =, !=, >, <, >=, <=, ~, !~
    value: Any
    negate: bool = False


@dataclass
class FilterExpression:
    """Compound filter expression."""
    conditions: List[FilterCondition]
    operators: List[FilterOp]  # Between conditions


class AdvancedFilter:
    """
    Advanced filter engine for PCAP-INTEL TUI.

    Supports BPF-style syntax with extensions for network intel.
    """

    # Protocol aliases (common names -> port numbers)
    PROTO_MAP = {
        "http": {80, 8080, 8000, 8888},
        "https": {443, 8443},
        "ssh": {22},
        "ftp": {20, 21},
        "smb": {445, 139},
        "rdp": {3389},
        "dns": {53},
        "ldap": {389, 636},
        "kerberos": {88, 464},
        "kerb": {88, 464},
        "winrm": {5985, 5986},
        "mysql": {3306},
        "mssql": {1433, 1434},
        "postgres": {5432},
        "pgsql": {5432},
        "redis": {6379},
        "mongo": {27017, 27018},
        "vnc": {5900, 5901},
        "smtp": {25, 587},
        "imap": {143, 993},
        "pop3": {110, 995},
        "ntp": {123},
        "snmp": {161, 162},
        "docker": {2375, 2376},
        "k8s": {6443, 10250},
    }

    # Regex for parsing
    IP_CIDR_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
    CODENAME_PATTERN = re.compile(r'^[A-Z][A-Z0-9_*-]+$', re.IGNORECASE)

    def __init__(self, codename_resolver: Callable[[str], Tuple[str, str, str]] = None):
        """
        Initialize filter engine.

        Args:
            codename_resolver: Function to get codename for IP (ip -> (name, cat, color))
        """
        self.codename_resolver = codename_resolver
        self._expression: Optional[FilterExpression] = None
        self._filter_text = ""
        self._error = None

    @property
    def is_active(self) -> bool:
        """Check if filter is active."""
        return self._expression is not None and len(self._expression.conditions) > 0

    @property
    def filter_text(self) -> str:
        """Get current filter text."""
        return self._filter_text

    @property
    def error(self) -> Optional[str]:
        """Get last parse error."""
        return self._error

    def parse(self, filter_text: str) -> bool:
        """
        Parse filter expression.

        Args:
            filter_text: BPF-style filter string

        Returns:
            True if parse succeeded
        """
        self._filter_text = filter_text.strip()
        self._error = None

        if not self._filter_text:
            self._expression = None
            return True

        try:
            self._expression = self._parse_expression(self._filter_text)
            return True
        except Exception as e:
            self._error = str(e)
            self._expression = None
            return False

    def clear(self):
        """Clear active filter."""
        self._expression = None
        self._filter_text = ""
        self._error = None

    def _parse_expression(self, text: str) -> FilterExpression:
        """Parse compound expression."""
        # Tokenize
        tokens = self._tokenize(text)
        if not tokens:
            raise ValueError("Empty filter expression")

        conditions = []
        operators = []
        negate_next = False

        i = 0
        while i < len(tokens):
            token = tokens[i].lower()

            # Handle operators
            if token == "and":
                operators.append(FilterOp.AND)
                i += 1
                continue
            elif token == "or":
                operators.append(FilterOp.OR)
                i += 1
                continue
            elif token == "not":
                negate_next = True
                i += 1
                continue

            # Parse condition
            condition, consumed = self._parse_condition(tokens[i:], negate_next)
            conditions.append(condition)
            negate_next = False
            i += consumed

            # Default to AND if no operator between conditions
            if i < len(tokens) and tokens[i].lower() not in ("and", "or", "not"):
                operators.append(FilterOp.AND)

        return FilterExpression(conditions=conditions, operators=operators)

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize filter text."""
        # Handle quoted strings
        tokens = []
        current = ""
        in_quotes = False

        for char in text:
            if char == '"':
                in_quotes = not in_quotes
            elif char.isspace() and not in_quotes:
                if current:
                    tokens.append(current)
                    current = ""
            else:
                current += char

        if current:
            tokens.append(current)

        return tokens

    def _parse_condition(self, tokens: List[str], negate: bool = False) -> Tuple[FilterCondition, int]:
        """
        Parse a single condition.

        Returns: (condition, tokens_consumed)
        """
        if not tokens:
            raise ValueError("Expected condition")

        field_token = tokens[0].lower()
        consumed = 1

        # Special single-token conditions
        if field_token == "compromised":
            return FilterCondition(
                field=FilterType.COMPROMISED,
                operator="=",
                value=True,
                negate=negate
            ), 1

        if field_token == "hvt":
            return FilterCondition(
                field=FilterType.HVT,
                operator="=",
                value=True,
                negate=negate
            ), 1

        # Field conditions (field op value)
        if len(tokens) < 2:
            # Single token might be IP or codename
            if self.IP_CIDR_PATTERN.match(tokens[0]):
                return FilterCondition(
                    field=FilterType.IP,
                    operator="=",
                    value=tokens[0],
                    negate=negate
                ), 1
            elif self.CODENAME_PATTERN.match(tokens[0]):
                return FilterCondition(
                    field=FilterType.CODENAME,
                    operator="~",  # Regex match
                    value=tokens[0],
                    negate=negate
                ), 1
            raise ValueError(f"Unknown filter: {tokens[0]}")

        # Map field name to type
        field_map = {
            "ip": FilterType.IP,
            "host": FilterType.IP,
            "src": FilterType.IP,
            "dst": FilterType.IP,
            "codename": FilterType.CODENAME,
            "name": FilterType.CODENAME,
            "port": FilterType.PORT,
            "proto": FilterType.PROTO,
            "protocol": FilterType.PROTO,
            "creds": FilterType.CREDS,
            "credentials": FilterType.CREDS,
            "flows": FilterType.FLOWS,
            "alerts": FilterType.ALERTS,
            "os": FilterType.OS,
            "dns": FilterType.DNS,
            "domain": FilterType.DNS,
        }

        if field_token not in field_map:
            # Maybe it's a bare IP or codename
            if self.IP_CIDR_PATTERN.match(tokens[0]):
                return FilterCondition(
                    field=FilterType.IP,
                    operator="=",
                    value=tokens[0],
                    negate=negate
                ), 1
            raise ValueError(f"Unknown field: {field_token}")

        field_type = field_map[field_token]

        # Check for operator
        if len(tokens) >= 3 and tokens[1] in ("=", "==", "!=", ">", "<", ">=", "<=", "~", "!~"):
            operator = tokens[1]
            value = tokens[2]
            consumed = 3
        else:
            # Implicit equals
            operator = "="
            value = tokens[1]
            consumed = 2

        # Parse value based on field type
        parsed_value = self._parse_value(field_type, value)

        return FilterCondition(
            field=field_type,
            operator=operator,
            value=parsed_value,
            negate=negate
        ), consumed

    def _parse_value(self, field_type: FilterType, value: str) -> Any:
        """Parse value for field type."""
        if field_type == FilterType.IP:
            # Support CIDR notation
            if "/" in value:
                return ip_network(value, strict=False)
            return value

        if field_type == FilterType.PORT:
            # Support comma-separated ports
            if "," in value:
                return {int(p.strip()) for p in value.split(",")}
            return int(value)

        if field_type == FilterType.PROTO:
            # Map protocol name to ports
            proto_lower = value.lower()
            if proto_lower in self.PROTO_MAP:
                return self.PROTO_MAP[proto_lower]
            return {int(value)} if value.isdigit() else value

        if field_type in (FilterType.CREDS, FilterType.FLOWS, FilterType.ALERTS):
            return int(value)

        return value

    # ===================
    # Filter Execution
    # ===================

    def matches_host(
        self,
        ip: str,
        host_data: Dict,
        compromised_hosts: Set[str],
        codenames: Dict[str, tuple],
        hvt_check: Callable[[set], tuple] = None
    ) -> bool:
        """
        Check if host matches filter.

        Args:
            ip: Host IP address
            host_data: Host data dict
            compromised_hosts: Set of compromised IPs
            codenames: IP -> (name, cat, color) mapping
            hvt_check: Function to check HVT status (ports -> (role, icon, cat, desc))

        Returns:
            True if host matches filter
        """
        if not self.is_active:
            return True

        return self._eval_expression(
            self._expression,
            ip, host_data, compromised_hosts, codenames, hvt_check
        )

    def matches_flow(
        self,
        flow: Dict,
        codenames: Dict[str, tuple]
    ) -> bool:
        """
        Check if flow matches filter.

        Args:
            flow: Flow data dict (src, dst, port, proto, count)
            codenames: IP -> (name, cat, color) mapping

        Returns:
            True if flow matches filter
        """
        if not self.is_active:
            return True

        # Create pseudo host data for flow matching
        src = flow.get("src", "")
        dst = flow.get("dst", "")
        port = flow.get("port", 0)

        # Check if either endpoint matches IP filter
        for condition in self._expression.conditions:
            if condition.field == FilterType.IP:
                if self._match_ip(src, condition.value) or self._match_ip(dst, condition.value):
                    if condition.negate:
                        return False
                    continue
                if not condition.negate:
                    return False

            elif condition.field == FilterType.PORT:
                if self._match_port(port, condition.value):
                    if condition.negate:
                        return False
                    continue
                if not condition.negate:
                    return False

            elif condition.field == FilterType.CODENAME:
                src_name = codenames.get(src, ("", "", ""))[0] if src in codenames else ""
                dst_name = codenames.get(dst, ("", "", ""))[0] if dst in codenames else ""
                if self._match_codename(src_name, condition.value) or self._match_codename(dst_name, condition.value):
                    if condition.negate:
                        return False
                    continue
                if not condition.negate:
                    return False

        return True

    def matches_alert(
        self,
        alert: Dict,
        codenames: Dict[str, tuple]
    ) -> bool:
        """Check if alert matches filter."""
        if not self.is_active:
            return True

        src = alert.get("src_ip", "")
        dst = alert.get("dst_ip", "") or alert.get("target", "")

        for condition in self._expression.conditions:
            if condition.field == FilterType.IP:
                if self._match_ip(src, condition.value) or self._match_ip(dst, condition.value):
                    if condition.negate:
                        return False
                    continue
                if not condition.negate:
                    return False

            elif condition.field == FilterType.CODENAME:
                src_name = codenames.get(src, ("", "", ""))[0] if src in codenames else ""
                dst_name = codenames.get(dst, ("", "", ""))[0] if dst in codenames else ""
                if self._match_codename(src_name, condition.value) or self._match_codename(dst_name, condition.value):
                    if condition.negate:
                        return False
                    continue
                if not condition.negate:
                    return False

        return True

    def _eval_expression(
        self,
        expr: FilterExpression,
        ip: str,
        host_data: Dict,
        compromised: Set[str],
        codenames: Dict[str, tuple],
        hvt_check: Callable
    ) -> bool:
        """Evaluate filter expression against host."""
        if not expr.conditions:
            return True

        # Evaluate first condition
        result = self._eval_condition(
            expr.conditions[0], ip, host_data, compromised, codenames, hvt_check
        )

        # Apply operators
        for i, op in enumerate(expr.operators):
            if i + 1 >= len(expr.conditions):
                break

            next_result = self._eval_condition(
                expr.conditions[i + 1], ip, host_data, compromised, codenames, hvt_check
            )

            if op == FilterOp.AND:
                result = result and next_result
            elif op == FilterOp.OR:
                result = result or next_result

        return result

    def _eval_condition(
        self,
        cond: FilterCondition,
        ip: str,
        host_data: Dict,
        compromised: Set[str],
        codenames: Dict[str, tuple],
        hvt_check: Callable
    ) -> bool:
        """Evaluate single condition."""
        result = False

        if cond.field == FilterType.IP:
            result = self._match_ip(ip, cond.value)

        elif cond.field == FilterType.CODENAME:
            codename = codenames.get(ip, ("", "", ""))[0] if ip in codenames else ""
            if not codename and self.codename_resolver:
                codename = self.codename_resolver(ip)[0]
            result = self._match_codename(codename, cond.value)

        elif cond.field == FilterType.PORT:
            ports = host_data.get("services", set())
            result = self._match_port_set(ports, cond.value, cond.operator)

        elif cond.field == FilterType.PROTO:
            ports = host_data.get("services", set())
            if isinstance(cond.value, set):
                result = bool(ports & cond.value)
            else:
                result = cond.value in ports

        elif cond.field == FilterType.CREDS:
            cred_count = len(host_data.get("creds", []))
            result = self._compare_numeric(cred_count, cond.value, cond.operator)

        elif cond.field == FilterType.COMPROMISED:
            result = ip in compromised

        elif cond.field == FilterType.HVT:
            if hvt_check:
                ports = host_data.get("services", set())
                _, _, cat, _ = hvt_check(ports)
                result = cat == "HVT"

        elif cond.field == FilterType.FLOWS:
            flow_count = len(host_data.get("flows", []))
            result = self._compare_numeric(flow_count, cond.value, cond.operator)

        elif cond.field == FilterType.ALERTS:
            alert_count = host_data.get("alert_count", 0)
            result = self._compare_numeric(alert_count, cond.value, cond.operator)

        elif cond.field == FilterType.OS:
            os_str = host_data.get("os", "")
            result = cond.value.lower() in os_str.lower()

        elif cond.field == FilterType.DNS:
            dns = host_data.get("dns", "")
            if dns:
                result = cond.value.lower() in dns.lower()

        return not result if cond.negate else result

    def _match_ip(self, ip: str, pattern: Any) -> bool:
        """Match IP against pattern (exact or CIDR)."""
        try:
            if isinstance(pattern, (IPv4Network,)):
                return ip_address(ip) in pattern
            return ip == pattern
        except:
            return False

    def _match_codename(self, codename: str, pattern: str) -> bool:
        """Match codename against pattern (supports * wildcard)."""
        if not codename or not pattern:
            return False

        # Convert wildcard to regex
        if "*" in pattern:
            regex = pattern.replace("*", ".*")
            return bool(re.match(regex, codename, re.IGNORECASE))

        return codename.lower() == pattern.lower()

    def _match_port(self, port: int, value: Any) -> bool:
        """Match single port against value."""
        if isinstance(value, set):
            return port in value
        return port == value

    def _match_port_set(self, ports: set, value: Any, operator: str) -> bool:
        """Match port set against value."""
        if isinstance(value, set):
            if operator in ("=", "=="):
                return bool(ports & value)
            elif operator == "!=":
                return not bool(ports & value)
        else:
            if operator in ("=", "=="):
                return value in ports
            elif operator == "!=":
                return value not in ports

        return False

    def _compare_numeric(self, actual: int, expected: int, operator: str) -> bool:
        """Compare numeric values."""
        if operator in ("=", "=="):
            return actual == expected
        elif operator == "!=":
            return actual != expected
        elif operator == ">":
            return actual > expected
        elif operator == "<":
            return actual < expected
        elif operator == ">=":
            return actual >= expected
        elif operator == "<=":
            return actual <= expected
        return False

    # ===================
    # Help Text
    # ===================

    @staticmethod
    def get_help() -> str:
        """Get filter syntax help."""
        return """
PCAP-INTEL FILTER SYNTAX
========================

FIELD FILTERS:
  ip 10.0.0.1          Match specific IP
  ip 10.0.0.0/24       Match IP range (CIDR)
  codename SHADOW*     Match codename (wildcards OK)
  port 445             Match port
  port 22,445,3389     Match multiple ports
  proto smb            Match protocol (smb, rdp, ssh, etc.)
  creds > 0            Hosts with credentials
  os windows           Match OS string

SPECIAL FILTERS:
  compromised          Compromised hosts only
  hvt                  High-value targets only

OPERATORS:
  and                  Both conditions must match
  or                   Either condition matches
  not                  Negate next condition

COMPARISON:
  =, ==                Equals
  !=                   Not equals
  >, <, >=, <=        Numeric comparison

EXAMPLES:
  ip 10.0.0.0/24 and port 445
  codename EXT-* or compromised
  proto rdp and creds > 0
  not port 80 and not port 443
  hvt or creds >= 1

Press ESC to close, Enter to apply filter.
"""


# Quick filter presets for common operations
FILTER_PRESETS = {
    "compromised": "compromised",
    "hvt": "hvt",
    "lateral": "port 22,445,3389,5985",
    "web": "port 80,443,8080,8443",
    "db": "port 1433,3306,5432,27017",
    "auth": "proto kerberos or proto ldap",
    "external": "codename EXT-*",
    "internal": "codename INT-* or codename LAN-*",
    "creds": "creds > 0",
}
