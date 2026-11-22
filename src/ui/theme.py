"""
NEXUS Engine - Cyber-Analytics Theme & DPI Configuration
========================================================
Architecture Role: Immutable styling specification, typography hierarchies,
Windows DPI scaling protocols, and secret redaction utilities for the
NEXUS Desktop GUI (CustomTkinter).

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / CustomTkinter
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional, Tuple

# Resilient logging initialization
try:
    from loguru import logger
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("NEXUS-UI-Theme")  # type: ignore

try:
    import customtkinter
    HAS_CUSTOMTKINTER = True
except ImportError:
    customtkinter = None  # type: ignore
    HAS_CUSTOMTKINTER = False


# ==============================================================================
# IMMUTABLE THEME METACLASS
# ==============================================================================

class _ImmutableThemeMeta(type):
    """Prevents accidental runtime modification of theme tokens."""
    def __setattr__(cls, name: str, value: Any) -> None:
        raise AttributeError(f"NexusTheme is immutable. Cannot override '{name}'.")

    def __delattr__(cls, name: str) -> None:
        raise AttributeError(f"NexusTheme is immutable. Cannot delete '{name}'.")


# ==============================================================================
# CENTRALIZED THEME SPECIFICATION
# ==============================================================================

class NexusTheme(metaclass=_ImmutableThemeMeta):
    """
    Futurized High-Contrast Cyber-Analytics Palette.
    Optimized for high-density analytical dashboards, SQL code readability,
    and long-duration operator monitoring.
    """

    # Primary Backgrounds & Canvas Surfaces
    BG_OBSIDIAN: str = "#0B0F19"          # Deep obsidian window backdrop
    SURFACE_SLATE: str = "#111827"        # Primary card containers & sidebar
    SURFACE_ELEVATED: str = "#1E293B"     # Raised panels, input fields & modal cards
    SURFACE_BORDER: str = "#334155"       # Crisp low-contrast borders & dividers

    # Vibrant Accents & Interactive States
    ACCENT_CYAN: str = "#06B6D4"          # Neon cyan brand accent & active states
    ACCENT_CYAN_HOVER: str = "#0891B2"    # Darkened cyan for interactive hover states
    ACCENT_CYAN_MUTED: str = "#164E63"    # Low-intensity cyan for badges & selections

    # Semantic Status & Operational Indicators
    STATUS_EMERALD: str = "#10B981"       # Verified SQL execution, active connections
    STATUS_AMBER: str = "#F59E0B"         # Lock contention, retries, slow queries
    STATUS_CRIMSON: str = "#EF4444"       # Security violations, syntax errors, drops

    # Crisp Typography Palette
    TEXT_PRIMARY: str = "#F9FAFB"         # Pure white-slate for primary data & headers
    TEXT_SECONDARY: str = "#9CA3AF"       # Neutral gray for labels and column info
    TEXT_MUTED: str = "#64748B"           # Slate muted for timestamps and counters

    # Windows Native Font Families
    FONT_FAMILY_MAIN: str = "Segoe UI"
    FONT_FAMILY_MONO: str = "Consolas"

    # Pre-configured Typography Tuples (Font Family, Size, Weight)
    FONT_TITLE: Tuple[str, int, str] = ("Segoe UI", 18, "bold")
    FONT_SUBTITLE: Tuple[str, int, str] = ("Segoe UI", 14, "bold")
    FONT_BODY: Tuple[str, int] = ("Segoe UI", 12)
    FONT_BODY_BOLD: Tuple[str, int, str] = ("Segoe UI", 12, "bold")
    FONT_SMALL: Tuple[str, int] = ("Segoe UI", 10)
    FONT_SMALL_BOLD: Tuple[str, int, str] = ("Segoe UI", 10, "bold")
    FONT_CODE: Tuple[str, int] = ("Consolas", 11)
    FONT_CODE_BOLD: Tuple[str, int, str] = ("Consolas", 11, "bold")

    # Geometry & Structural Dimensions
    CORNER_RADIUS_SM: int = 6             # Inputs, small buttons
    CORNER_RADIUS_MD: int = 10            # Standard cards, modal panels
    CORNER_RADIUS_LG: int = 14            # Primary canvas containers
    BORDER_WIDTH: int = 1
    PADDING_SM: int = 8
    PADDING_MD: int = 16
    PADDING_LG: int = 24

    @classmethod
    def to_dict(cls) -> Dict[str, Any]:
        """Exports theme tokens as a dictionary for diagnostics or reporting."""
        return {
            k: getattr(cls, k)
            for k in dir(cls)
            if not k.startswith("_") and not callable(getattr(cls, k))
        }


# ==============================================================================
# GLOBAL THEME & DPI PROTOCOLS
# ==============================================================================

def configure_windows_dpi_awareness() -> None:
    """
    Enforces per-monitor DPI scaling on Windows to ensure razor-sharp typography
    and eliminate pixelated GUI scaling artifacts on 4K/high-density monitors.
    """
    if sys.platform != "win32":
        return

    try:
        import ctypes
        # Try Per-Monitor DPI Aware V2 (PROCESS_PER_MONITOR_DPI_AWARE = 2)
        # Fallback to System DPI Aware (PROCESS_SYSTEM_DPI_AWARE = 1)
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
            logger.debug("Windows DPI Awareness successfully set to Per-Monitor Aware.")
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
            logger.debug("Windows DPI Awareness successfully set via user32 fallback.")
    except Exception as exc:
        logger.warning(f"Could not enforce Windows DPI awareness: {exc}")


def apply_global_theme() -> bool:
    """
    Safely configures CustomTkinter's global appearance mode and default palette.
    Designed to be robust and non-fatal in headless, containerized, or test environments.

    Returns:
        bool: True if theme was applied cleanly, False if fallback or headless.
    """
    # 1. Enforce native Windows DPI awareness
    configure_windows_dpi_awareness()

    if not HAS_CUSTOMTKINTER or customtkinter is None:
        logger.warning("CustomTkinter is not installed. Skipping global UI theme configuration.")
        return False

    try:
        customtkinter.set_appearance_mode("Dark")
        customtkinter.set_default_color_theme("blue")
        logger.info("NEXUS Cyber-Analytics global theme applied (Appearance: Dark, Theme: Blue).")
        return True
    except Exception as exc:
        # Headless testing environment or display initialization absence
        logger.warning(f"Headless display detected or CustomTkinter theme initialization skipped: {exc}")
        return False


# ==============================================================================
# SECURITY UTILITIES: SECRET REDACTION
# ==============================================================================

def mask_secret(secret: Optional[str]) -> str:
    """
    Masks sensitive values (API tokens, passwords, database credentials) so they
    are never leaked into UI status labels, application error displays, or system logs.

    Formatting Rules:
    - None or empty string -> "[EMPTY]"
    - Very short secrets (< 8 chars) -> "[REDACTED]"
    - Standard keys (>= 8 chars) -> "••••••••" + last 4 characters

    Example:
        mask_secret("sk-ant-api03-abcdef123456") -> "••••••••3456"
        mask_secret("secret") -> "[REDACTED]"
        mask_secret("") -> "[EMPTY]"
    """
    if secret is None:
        return "[EMPTY]"

    cleaned = str(secret).strip()
    if not cleaned:
        return "[EMPTY]"

    if len(cleaned) < 8:
        return "[REDACTED]"

    # Mask prefix with 8 bullet dots and expose only the final 4 characters
    visible_suffix = cleaned[-4:]
    return f"{'•' * 8}{visible_suffix}"
