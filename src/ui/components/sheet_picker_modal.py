"""
NEXUS Engine - Multi-Sheet Excel Workbook Selector Modal
========================================================
Modeless-safe, dark cyber-analytics dialog enabling users to select a specific
worksheet from multi-sheet Excel (.xlsx / .xls) workbooks prior to AI profiling
and database ingestion.

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / CustomTkinter
"""

from __future__ import annotations

from typing import Any, Callable, List, Optional

import customtkinter as ctk

from src.ui.theme import NexusTheme


class SheetPickerModal(ctk.CTkToplevel):
    """
    Cyber-Analytics Modal Dialog for selecting an individual worksheet
    from a multi-sheet Excel workbook.
    """

    def __init__(
        self,
        master: Any,
        file_name: str,
        sheet_names: List[str],
        on_select: Callable[[str], None],
        on_cancel: Optional[Callable[[], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=NexusTheme.BG_OBSIDIAN, **kwargs)

        self.file_name = file_name
        self.sheet_names = sheet_names or ["Sheet1"]
        self.on_select = on_select
        self.on_cancel = on_cancel

        # Window configuration (modeless-safe)
        self.title("NEXUS — Select Excel Sheet")
        self.geometry("520x360")
        self.minsize(460, 300)

        try:
            if master and hasattr(master, "winfo_exists") and master.winfo_exists():
                self.transient(master)
        except Exception:
            pass

        try:
            self.grab_set()
        except Exception:
            pass

        self.protocol("WM_DELETE_WINDOW", self.cancel)

        # Build UI layout
        self._build_ui()

    def _build_ui(self) -> None:
        """Constructs modal card layout: header, sheet selector, and footer action buttons."""
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        card = ctk.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER,
        )
        card.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)

        # 1. Header Bar
        title_label = ctk.CTkLabel(
            card,
            text="⚡ Multi-Sheet Excel Workbook",
            font=NexusTheme.FONT_SUBTITLE,
            text_color=NexusTheme.ACCENT_CYAN,
            anchor="w",
        )
        title_label.pack(fill="x", padx=20, pady=(20, 6))

        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(fill="x", padx=20, pady=(0, 16))

        file_label = ctk.CTkLabel(
            info_frame,
            text=f"Workbook: {self.file_name}",
            font=NexusTheme.FONT_BODY,
            text_color=NexusTheme.TEXT_PRIMARY,
            anchor="w",
        )
        file_label.pack(side="left")

        badge_pill = ctk.CTkLabel(
            info_frame,
            text=f"{len(self.sheet_names)} Sheets Found",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.STATUS_EMERALD,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            padx=8,
            pady=2,
        )
        badge_pill.pack(side="right")

        # Divider
        divider = ctk.CTkFrame(card, height=1, fg_color=NexusTheme.SURFACE_BORDER)
        divider.pack(fill="x", padx=20, pady=(0, 16))

        # 2. Sheet Selection Section
        select_label = ctk.CTkLabel(
            card,
            text="Choose sheet to profile and ingest into database:",
            font=NexusTheme.FONT_BODY,
            text_color=NexusTheme.TEXT_SECONDARY,
            anchor="w",
        )
        select_label.pack(fill="x", padx=20, pady=(0, 8))

        default_val = self.sheet_names[0] if self.sheet_names else "Sheet1"
        self.sheet_selector = ctk.CTkOptionMenu(
            card,
            values=self.sheet_names,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            button_color=NexusTheme.SURFACE_BORDER,
            button_hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            dropdown_fg_color=NexusTheme.SURFACE_ELEVATED,
            dropdown_hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            dropdown_text_color=NexusTheme.TEXT_PRIMARY,
            font=NexusTheme.FONT_BODY,
            dynamic_resizing=False,
            height=36,
        )
        self.sheet_selector.set(default_val)
        self.sheet_selector.pack(fill="x", padx=20, pady=(0, 24))

        # 3. Footer Action Buttons
        button_row = ctk.CTkFrame(card, fg_color="transparent")
        button_row.pack(fill="x", padx=20, pady=(0, 20), side="bottom")

        self.cancel_btn = ctk.CTkButton(
            button_row,
            text="Cancel",
            font=NexusTheme.FONT_BODY_BOLD,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.SURFACE_BORDER,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            width=110,
            height=36,
            command=self.cancel,
        )
        self.cancel_btn.pack(side="right", padx=(8, 0))

        self.load_btn = ctk.CTkButton(
            button_row,
            text="⚡ Load Selected Sheet",
            font=NexusTheme.FONT_BODY_BOLD,
            fg_color=NexusTheme.ACCENT_CYAN,
            hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            height=36,
            command=lambda: self.confirm_select(),
        )
        self.load_btn.pack(side="right")

    def confirm_select(self, sheet_name: Optional[str] = None) -> None:
        """Confirms worksheet selection, releases modal grab, and fires on_select callback."""
        chosen = sheet_name if sheet_name is not None else self.sheet_selector.get()
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

        if callable(self.on_select):
            self.on_select(chosen)

    def cancel(self) -> None:
        """Dismisses the modal dialog without selecting a sheet."""
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()

        if callable(self.on_cancel):
            self.on_cancel()
