"""
NEXUS Engine - Desktop UI Components Package (Phase 2)
======================================================
Modular CustomTkinter interface components for the NEXUS Desktop Application:
1. SidebarPanel: Brand header, file selector, live schema tree, and secure LLM toggle.
2. DataExplorerTab: Table quick-preview, safe SQL scratchpad, and query results view.
3. TelemetryHudTab: 4 KPI metric cards, interactive SQLi simulator, and live audit ledger.
4. ChatAnalystTab: Conversational AI analyst feed, schema context extraction, and prompt input.
"""

from src.ui.components.sidebar import SidebarPanel
from src.ui.components.data_explorer_tab import DataExplorerTab
from src.ui.components.telemetry_hud_tab import TelemetryHudTab
from src.ui.components.chat_tab import ChatAnalystTab
from src.ui.components.cleaning_modal import CleaningPlanModal
from src.ui.components.sheet_picker_modal import SheetPickerModal

__all__ = [
    "SidebarPanel",
    "DataExplorerTab",
    "TelemetryHudTab",
    "ChatAnalystTab",
    "CleaningPlanModal",
    "SheetPickerModal",
]
