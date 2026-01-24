"""
Theme Manager - CSS variable-based theme system for PCAP-Intel TUI.

Supports multiple themes with semantic color naming and live switching.
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class ThemeColors:
    """Color palette for a theme."""

    # Base colors
    background: str = "#0d1117"
    surface: str = "#161b22"
    surface_light: str = "#21262d"
    border: str = "#30363d"

    # Text colors
    text_primary: str = "#e6edf3"
    text_secondary: str = "#8b949e"
    text_muted: str = "#484f58"

    # Semantic colors
    primary: str = "#58a6ff"        # Links, highlights
    secondary: str = "#a371f7"      # Hosts, secondary info
    accent: str = "#388bfd"         # Focus, emphasis

    # Status colors
    success: str = "#7ee787"        # Flows, positive
    warning: str = "#d29922"        # Alerts, caution
    error: str = "#f85149"          # Credentials, danger
    info: str = "#58a6ff"           # DNS, informational

    # Panel-specific colors (can override)
    creds_color: str = "#f85149"
    flows_color: str = "#7ee787"
    dns_color: str = "#58a6ff"
    hosts_color: str = "#a371f7"
    alerts_color: str = "#d29922"

    # Table colors
    table_header: str = "#161b22"
    table_cursor: str = "#388bfd"
    table_even_row: str = "#0d1117"
    table_odd_row: str = "#161b22"


@dataclass
class Theme:
    """Complete theme definition."""
    name: str
    description: str
    colors: ThemeColors
    is_dark: bool = True


# ===== BUILT-IN THEMES =====

THEMES: Dict[str, Theme] = {

    "github-dark": Theme(
        name="GitHub Dark",
        description="Default dark theme inspired by GitHub",
        is_dark=True,
        colors=ThemeColors(
            background="#0d1117",
            surface="#161b22",
            surface_light="#21262d",
            border="#30363d",
            text_primary="#e6edf3",
            text_secondary="#8b949e",
            text_muted="#484f58",
            primary="#58a6ff",
            secondary="#a371f7",
            accent="#388bfd",
            success="#7ee787",
            warning="#d29922",
            error="#f85149",
            info="#58a6ff",
        ),
    ),

    "dracula": Theme(
        name="Dracula",
        description="Dracula color scheme",
        is_dark=True,
        colors=ThemeColors(
            background="#282a36",
            surface="#44475a",
            surface_light="#6272a4",
            border="#44475a",
            text_primary="#f8f8f2",
            text_secondary="#6272a4",
            text_muted="#44475a",
            primary="#8be9fd",
            secondary="#bd93f9",
            accent="#ff79c6",
            success="#50fa7b",
            warning="#ffb86c",
            error="#ff5555",
            info="#8be9fd",
            creds_color="#ff5555",
            flows_color="#50fa7b",
            dns_color="#8be9fd",
            hosts_color="#bd93f9",
            alerts_color="#ffb86c",
        ),
    ),

    "nord": Theme(
        name="Nord",
        description="Arctic, north-bluish color palette",
        is_dark=True,
        colors=ThemeColors(
            background="#2e3440",
            surface="#3b4252",
            surface_light="#434c5e",
            border="#4c566a",
            text_primary="#eceff4",
            text_secondary="#d8dee9",
            text_muted="#4c566a",
            primary="#88c0d0",
            secondary="#b48ead",
            accent="#81a1c1",
            success="#a3be8c",
            warning="#ebcb8b",
            error="#bf616a",
            info="#88c0d0",
            creds_color="#bf616a",
            flows_color="#a3be8c",
            dns_color="#88c0d0",
            hosts_color="#b48ead",
            alerts_color="#ebcb8b",
        ),
    ),

    "monokai": Theme(
        name="Monokai",
        description="Classic Monokai color scheme",
        is_dark=True,
        colors=ThemeColors(
            background="#272822",
            surface="#3e3d32",
            surface_light="#49483e",
            border="#75715e",
            text_primary="#f8f8f2",
            text_secondary="#a6a6a6",
            text_muted="#75715e",
            primary="#66d9ef",
            secondary="#ae81ff",
            accent="#a6e22e",
            success="#a6e22e",
            warning="#e6db74",
            error="#f92672",
            info="#66d9ef",
            creds_color="#f92672",
            flows_color="#a6e22e",
            dns_color="#66d9ef",
            hosts_color="#ae81ff",
            alerts_color="#e6db74",
        ),
    ),

    "solarized-dark": Theme(
        name="Solarized Dark",
        description="Solarized dark color scheme",
        is_dark=True,
        colors=ThemeColors(
            background="#002b36",
            surface="#073642",
            surface_light="#586e75",
            border="#657b83",
            text_primary="#fdf6e3",
            text_secondary="#93a1a1",
            text_muted="#657b83",
            primary="#268bd2",
            secondary="#6c71c4",
            accent="#2aa198",
            success="#859900",
            warning="#b58900",
            error="#dc322f",
            info="#268bd2",
            creds_color="#dc322f",
            flows_color="#859900",
            dns_color="#268bd2",
            hosts_color="#6c71c4",
            alerts_color="#b58900",
        ),
    ),

    "high-contrast": Theme(
        name="High Contrast",
        description="Maximum visibility theme",
        is_dark=True,
        colors=ThemeColors(
            background="#000000",
            surface="#1a1a1a",
            surface_light="#333333",
            border="#ffffff",
            text_primary="#ffffff",
            text_secondary="#cccccc",
            text_muted="#808080",
            primary="#00ff00",
            secondary="#ff00ff",
            accent="#00ffff",
            success="#00ff00",
            warning="#ffff00",
            error="#ff0000",
            info="#00ffff",
            creds_color="#ff0000",
            flows_color="#00ff00",
            dns_color="#00ffff",
            hosts_color="#ff00ff",
            alerts_color="#ffff00",
        ),
    ),

    "light": Theme(
        name="Light",
        description="Light theme for bright environments",
        is_dark=False,
        colors=ThemeColors(
            background="#ffffff",
            surface="#f6f8fa",
            surface_light="#eaeef2",
            border="#d0d7de",
            text_primary="#1f2328",
            text_secondary="#656d76",
            text_muted="#8c959f",
            primary="#0969da",
            secondary="#8250df",
            accent="#0550ae",
            success="#1a7f37",
            warning="#9a6700",
            error="#cf222e",
            info="#0969da",
            creds_color="#cf222e",
            flows_color="#1a7f37",
            dns_color="#0969da",
            hosts_color="#8250df",
            alerts_color="#9a6700",
            table_header="#f6f8fa",
            table_cursor="#0550ae",
            table_even_row="#ffffff",
            table_odd_row="#f6f8fa",
        ),
    ),

    # ===== OPERATIONAL THEMES (USF Design) =====

    "red-team": Theme(
        name="Red Team",
        description="Offensive operations - credential emphasis",
        is_dark=True,
        colors=ThemeColors(
            background="#0d0d0d",
            surface="#1a0a0a",
            surface_light="#2a1515",
            border="#4a2020",
            text_primary="#f0f0f0",
            text_secondary="#cc9999",
            text_muted="#665555",
            primary="#f85149",
            secondary="#ff7b72",
            accent="#da3633",
            success="#7ee787",
            warning="#d29922",
            error="#f85149",
            info="#ff7b72",
            creds_color="#f85149",
            flows_color="#666666",
            dns_color="#666666",
            hosts_color="#ff7b72",
            alerts_color="#d29922",
            table_header="#1a0a0a",
            table_cursor="#da3633",
            table_even_row="#0d0d0d",
            table_odd_row="#1a0a0a",
        ),
    ),

    "blue-team": Theme(
        name="Blue Team",
        description="Defensive operations - alert emphasis",
        is_dark=True,
        colors=ThemeColors(
            background="#0a0a14",
            surface="#0d1020",
            surface_light="#15192d",
            border="#253050",
            text_primary="#e0e8f0",
            text_secondary="#8899bb",
            text_muted="#556688",
            primary="#388bfd",
            secondary="#58a6ff",
            accent="#1f6feb",
            success="#7ee787",
            warning="#d29922",
            error="#f85149",
            info="#388bfd",
            creds_color="#666666",
            flows_color="#7ee787",
            dns_color="#58a6ff",
            hosts_color="#a371f7",
            alerts_color="#f85149",
            table_header="#0d1020",
            table_cursor="#1f6feb",
            table_even_row="#0a0a14",
            table_odd_row="#0d1020",
        ),
    ),

    "network-recon": Theme(
        name="Network Recon",
        description="Discovery operations - host/service emphasis",
        is_dark=True,
        colors=ThemeColors(
            background="#0a1410",
            surface="#0d1a15",
            surface_light="#152520",
            border="#254035",
            text_primary="#e0f0e8",
            text_secondary="#88bb99",
            text_muted="#557766",
            primary="#56d4dd",
            secondary="#7ee787",
            accent="#39c5cf",
            success="#7ee787",
            warning="#d29922",
            error="#f85149",
            info="#56d4dd",
            creds_color="#666666",
            flows_color="#7ee787",
            dns_color="#56d4dd",
            hosts_color="#7ee787",
            alerts_color="#666666",
            table_header="#0d1a15",
            table_cursor="#39c5cf",
            table_even_row="#0a1410",
            table_odd_row="#0d1a15",
        ),
    ),

    "compromised-host": Theme(
        name="Compromised Host",
        description="Incident analysis - timeline/activity emphasis",
        is_dark=True,
        colors=ThemeColors(
            background="#12100a",
            surface="#1a1510",
            surface_light="#252015",
            border="#403520",
            text_primary="#f0e8e0",
            text_secondary="#bbaa88",
            text_muted="#776655",
            primary="#d29922",
            secondary="#f0883e",
            accent="#bf8700",
            success="#7ee787",
            warning="#d29922",
            error="#f85149",
            info="#f0883e",
            creds_color="#f85149",
            flows_color="#7ee787",
            dns_color="#666666",
            hosts_color="#666666",
            alerts_color="#d29922",
            table_header="#1a1510",
            table_cursor="#bf8700",
            table_even_row="#12100a",
            table_odd_row="#1a1510",
        ),
    ),
}


class ThemeManager:
    """
    Manages themes and CSS variable generation.

    The ThemeManager handles:
    - Theme registration and switching
    - CSS variable generation
    - Live theme updates
    - Custom theme creation
    """

    def __init__(self, default_theme: str = "github-dark"):
        """
        Initialize the theme manager.

        Args:
            default_theme: Name of the default theme to use
        """
        self._themes: Dict[str, Theme] = dict(THEMES)
        self._current_theme_name = default_theme
        self._current_theme = self._themes.get(default_theme, THEMES["github-dark"])
        self._callbacks: Dict[str, List[Callable]] = {}

    @property
    def current_theme(self) -> Theme:
        """Get the current theme."""
        return self._current_theme

    @property
    def current_theme_name(self) -> str:
        """Get the current theme name."""
        return self._current_theme_name

    @property
    def is_dark(self) -> bool:
        """Check if current theme is dark."""
        return self._current_theme.is_dark

    # ===== THEME SWITCHING =====

    def set_theme(self, theme_name: str) -> bool:
        """
        Switch to a different theme.

        Args:
            theme_name: Name of the theme to switch to

        Returns:
            True if successful, False if theme not found
        """
        if theme_name not in self._themes:
            return False

        old_theme = self._current_theme_name
        self._current_theme_name = theme_name
        self._current_theme = self._themes[theme_name]

        self._trigger_callback("theme_changed", old_theme, theme_name)
        return True

    def cycle_themes(self, themes: Optional[List[str]] = None) -> str:
        """
        Cycle to the next theme.

        Args:
            themes: Optional list of theme names to cycle through

        Returns:
            Name of the new theme
        """
        if themes is None:
            themes = list(self._themes.keys())

        try:
            current_idx = themes.index(self._current_theme_name)
            next_idx = (current_idx + 1) % len(themes)
        except ValueError:
            next_idx = 0

        self.set_theme(themes[next_idx])
        return themes[next_idx]

    def toggle_dark_mode(self) -> None:
        """Toggle between dark and light themes."""
        if self.is_dark:
            self.set_theme("light")
        else:
            self.set_theme("github-dark")

    # ===== THEME REGISTRATION =====

    def register_theme(self, name: str, theme: Theme) -> None:
        """
        Register a custom theme.

        Args:
            name: Unique name for the theme
            theme: Theme instance
        """
        self._themes[name] = theme

    def create_theme(
        self,
        name: str,
        description: str,
        colors: Dict[str, str],
        base_theme: str = "github-dark"
    ) -> Theme:
        """
        Create a new theme based on an existing one.

        Args:
            name: Name for the new theme
            description: Theme description
            colors: Dictionary of color overrides
            base_theme: Name of theme to base on

        Returns:
            New Theme instance
        """
        base = self._themes.get(base_theme, THEMES["github-dark"])

        # Copy base colors
        new_colors = ThemeColors(
            background=base.colors.background,
            surface=base.colors.surface,
            surface_light=base.colors.surface_light,
            border=base.colors.border,
            text_primary=base.colors.text_primary,
            text_secondary=base.colors.text_secondary,
            text_muted=base.colors.text_muted,
            primary=base.colors.primary,
            secondary=base.colors.secondary,
            accent=base.colors.accent,
            success=base.colors.success,
            warning=base.colors.warning,
            error=base.colors.error,
            info=base.colors.info,
            creds_color=base.colors.creds_color,
            flows_color=base.colors.flows_color,
            dns_color=base.colors.dns_color,
            hosts_color=base.colors.hosts_color,
            alerts_color=base.colors.alerts_color,
        )

        # Apply overrides
        for key, value in colors.items():
            if hasattr(new_colors, key):
                setattr(new_colors, key, value)

        theme = Theme(
            name=name,
            description=description,
            colors=new_colors,
            is_dark=base.is_dark,
        )

        self.register_theme(name.lower().replace(" ", "-"), theme)
        return theme

    # ===== CSS GENERATION =====

    def get_css_variables(self) -> str:
        """
        Generate CSS variables for the current theme.

        Returns:
            CSS string with variable definitions
        """
        colors = self._current_theme.colors

        return f"""
        :root {{
            /* Base colors */
            --background: {colors.background};
            --surface: {colors.surface};
            --surface-light: {colors.surface_light};
            --border: {colors.border};

            /* Text colors */
            --text-primary: {colors.text_primary};
            --text-secondary: {colors.text_secondary};
            --text-muted: {colors.text_muted};

            /* Semantic colors */
            --primary: {colors.primary};
            --secondary: {colors.secondary};
            --accent: {colors.accent};

            /* Status colors */
            --success: {colors.success};
            --warning: {colors.warning};
            --error: {colors.error};
            --info: {colors.info};

            /* Panel colors */
            --creds-color: {colors.creds_color};
            --flows-color: {colors.flows_color};
            --dns-color: {colors.dns_color};
            --hosts-color: {colors.hosts_color};
            --alerts-color: {colors.alerts_color};

            /* Table colors */
            --table-header: {colors.table_header};
            --table-cursor: {colors.table_cursor};
            --table-even-row: {colors.table_even_row};
            --table-odd-row: {colors.table_odd_row};
        }}
        """

    def get_full_css(self) -> str:
        """
        Generate complete CSS for the current theme.

        Returns:
            Full CSS string including variables and styles
        """
        colors = self._current_theme.colors

        return f"""
        /* Theme: {self._current_theme.name} */
        {self.get_css_variables()}

        Screen {{
            background: {colors.background};
        }}

        Header {{
            dock: top;
            height: 1;
            background: {colors.surface};
        }}

        Footer {{
            dock: bottom;
            height: 1;
            background: {colors.surface};
        }}

        #stats {{
            dock: top;
            height: 1;
            width: 100%;
            background: {colors.surface_light};
            padding: 0 1;
        }}

        #main {{
            width: 100%;
            height: 1fr;
        }}

        .pane-title {{
            height: 1;
            width: 100%;
            background: {colors.surface_light};
            padding: 0 1;
        }}

        DataTable {{
            height: 1fr;
            width: 100%;
        }}

        DataTable:focus {{
            border: tall {colors.accent};
        }}

        DataTable > .datatable--header {{
            background: {colors.table_header};
            color: {colors.primary};
        }}

        DataTable > .datatable--cursor {{
            background: {colors.table_cursor};
            color: white;
        }}

        DataTable > .datatable--even-row {{
            background: {colors.table_even_row};
        }}

        DataTable > .datatable--odd-row {{
            background: {colors.table_odd_row};
        }}

        /* Panel borders */
        #creds-pane {{ border-right: solid {colors.border}; }}
        #dns-pane {{ border-right: solid {colors.border}; }}

        /* Row borders */
        #row1 {{ border-bottom: solid {colors.border}; }}
        #row2 {{ border-bottom: solid {colors.border}; }}

        /* Panel-specific title colors */
        #creds-pane .pane-title {{ color: {colors.creds_color}; }}
        #flows-pane .pane-title {{ color: {colors.flows_color}; }}
        #dns-pane .pane-title {{ color: {colors.dns_color}; }}
        #hosts-pane .pane-title {{ color: {colors.hosts_color}; }}
        #alerts-pane .pane-title {{ color: {colors.alerts_color}; }}

        /* Fullscreen overlay */
        #detail-overlay {{
            display: none;
            width: 100%;
            height: 100%;
            background: {colors.background};
            layer: fullscreen;
            dock: top;
        }}

        #detail-overlay.visible {{
            display: block;
        }}

        #detail-header {{
            dock: top;
            height: 1;
            width: 100%;
            background: {colors.error};
            color: white;
            text-style: bold;
            padding: 0 1;
        }}

        RichLog {{
            height: 100%;
            width: 100%;
            background: {colors.background};
            padding: 0 1;
        }}
        """

    # ===== CALLBACKS =====

    def on(self, event: str, callback: Callable) -> None:
        """
        Register a callback for theme events.

        Events:
            - theme_changed: (old_theme, new_theme)
        """
        if event not in self._callbacks:
            self._callbacks[event] = []
        self._callbacks[event].append(callback)

    def _trigger_callback(self, event: str, *args) -> None:
        """Trigger registered callbacks for an event."""
        for callback in self._callbacks.get(event, []):
            try:
                callback(*args)
            except Exception:
                pass

    # ===== UTILITIES =====

    def list_themes(self) -> List[Dict]:
        """List all available themes."""
        return [
            {
                "name": name,
                "display_name": theme.name,
                "description": theme.description,
                "is_dark": theme.is_dark,
            }
            for name, theme in self._themes.items()
        ]

    def get_theme(self, name: str) -> Optional[Theme]:
        """Get a theme by name."""
        return self._themes.get(name)

    def get_color(self, color_name: str) -> str:
        """
        Get a specific color from the current theme.

        Args:
            color_name: Name of the color (e.g., "primary", "error")

        Returns:
            Color value string
        """
        colors = self._current_theme.colors
        return getattr(colors, color_name, colors.text_primary)
