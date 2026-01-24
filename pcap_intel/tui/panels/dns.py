"""
DNS Panel - Displays DNS resolutions and queries.

Filters out common noise domains and shows interesting resolutions.
"""

from typing import Any, Dict, List, Optional, Set

from rich.text import Text

from .base import Panel, PanelConfig


# Common noise domains to filter
DNS_NOISE = {
    'google', 'gstatic', 'googleapis', 'doubleclick', 'facebook', 'fbcdn',
    'amazon', 'amazonaws', 'cloudfront', 'akamai', 'microsoft', 'apple',
    'analytics', 'tracking', 'telemetry', 'cdn', 'static', 'ads', 'beacon',
    'metric', 'pixel', 'tag', 'fonts', 'jquery', 'bootstrap', 'mozilla',
    'firefox', 'chrome', 'safari', 'edge', 'windows', 'update', 'ocsp',
}


def is_interesting_dns(domain: str) -> bool:
    """Check if a domain is interesting (not noise)."""
    if not domain or len(domain) < 5:
        return False
    d = domain.lower()
    return not any(p in d for p in DNS_NOISE)


class DNSPanel(Panel):
    """
    Panel for displaying DNS resolutions.

    Tracks domain -> IP mappings and filters out noise.
    """

    def __init__(self, config: PanelConfig, app=None):
        super().__init__(config, app)
        self._resolutions: Dict[str, List[str]] = {}  # domain -> [ips]
        self._seen_domains: Set[str] = set()

    @classmethod
    def create_default(cls, app=None) -> "DNSPanel":
        """Create a DNS panel with default configuration."""
        config = PanelConfig(
            id="dns",
            title="DNS",
            shortcut="3",
            color="#58a6ff",
            priority=60,
            columns=["DOMAIN", "IP"],
        )
        return cls(config, app)

    def on_data_update(self, entity: Any) -> None:
        """
        Process a DNS resolution event.

        Args:
            entity: DNS entity with domain and answers
        """
        domain = getattr(entity, "value", "")
        answers = self._get_attr(entity, "answers", [])

        if not domain or not answers:
            return

        # Filter noise
        if not is_interesting_dns(domain):
            return

        # Check for duplicates
        if domain in self._seen_domains:
            return
        self._seen_domains.add(domain)

        # Store resolution
        self._resolutions[domain] = [str(a) for a in answers]
        self._data.append((domain, answers))

        # Update table
        if len(self._resolutions) <= 100:
            self._add_table_row(domain, answers)

    def _get_attr(self, entity: Any, attr: str, default: Any = None) -> Any:
        """Safely get attribute from entity."""
        if hasattr(entity, "details") and isinstance(entity.details, dict):
            if attr in entity.details:
                return entity.details[attr]
        if hasattr(entity, "attributes") and isinstance(entity.attributes, dict):
            if attr in entity.attributes:
                return entity.attributes[attr]
        if hasattr(entity, attr):
            return getattr(entity, attr)
        return default

    def get_selected_item(self) -> Optional[tuple]:
        """Get the currently selected DNS resolution."""
        idx = self.get_cursor_row()
        dns_list = list(self._resolutions.items())
        if idx is not None and idx < len(dns_list):
            return dns_list[idx]
        return None

    def _add_table_row(self, domain: str, answers: List) -> None:
        """Add a single DNS row to the table."""
        if not self._table:
            return

        ip_str = ", ".join(str(a) for a in answers[:2])
        if len(answers) > 2:
            ip_str += "..."

        self._table.add_row(
            domain[:30],
            ip_str,
        )

    def _render_rows(self, limit: int) -> None:
        """Render DNS rows to the table."""
        if not self._table:
            return

        self._table.clear()
        for domain, answers in list(self._resolutions.items())[:limit]:
            self._add_table_row(domain, answers)

    @property
    def data_count(self) -> int:
        """Number of DNS resolutions."""
        return len(self._resolutions)

    def clear_data(self) -> None:
        """Clear all DNS data."""
        super().clear_data()
        self._resolutions.clear()
        self._seen_domains.clear()

    def resolve(self, domain: str) -> Optional[List[str]]:
        """
        Get IP addresses for a domain.

        Args:
            domain: Domain to look up

        Returns:
            List of IP addresses or None if not found
        """
        return self._resolutions.get(domain)

    def reverse_lookup(self, ip: str) -> List[str]:
        """
        Get domains that resolve to an IP.

        Args:
            ip: IP address to look up

        Returns:
            List of domains that resolve to this IP
        """
        domains = []
        for domain, answers in self._resolutions.items():
            if ip in answers:
                domains.append(domain)
        return domains

    def get_subdomains(self, base_domain: str) -> List[str]:
        """
        Get all subdomains of a base domain.

        Args:
            base_domain: Base domain (e.g., "example.com")

        Returns:
            List of subdomains (e.g., ["www.example.com", "mail.example.com"])
        """
        return [d for d in self._resolutions.keys() if d.endswith(base_domain)]

    @classmethod
    def get_panel_css(cls) -> str:
        """Get CSS specific to the DNS panel."""
        return """
        #dns-pane {
            border-right: solid $surface-darken-2;
        }

        #dns-pane .pane-title {
            background: $primary-darken-3;
        }

        #dns-pane DataTable > .datatable--cursor {
            background: $primary;
            color: white;
        }
        """
