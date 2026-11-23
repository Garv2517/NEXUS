"""
NEXUS Engine - Desktop UI Package (Phase 2)
===========================================
Exposes styling, themes, secret redaction, and non-blocking asynchronous
background worker execution components.
"""

from src.ui.theme import (
    NexusTheme,
    apply_global_theme,
    configure_windows_dpi_awareness,
    mask_secret,
)
from src.ui.async_worker import (
    AsyncWorkerManager,
    WorkerEvent,
    WorkerEventType,
)
from src.ui.formatters import (
    format_cell_value,
    format_ascii_table,
)


def __getattr__(name: str):
    if name == "NexusApp":
        from src.ui.app import NexusApp
        return NexusApp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    # Theming & Typography
    "NexusTheme",
    "apply_global_theme",
    "configure_windows_dpi_awareness",
    "mask_secret",
    # Asynchronous Worker Pipeline
    "AsyncWorkerManager",
    "WorkerEvent",
    "WorkerEventType",
    # Data Formatters
    "format_cell_value",
    "format_ascii_table",
    # Root Desktop Application
    "NexusApp",
]
