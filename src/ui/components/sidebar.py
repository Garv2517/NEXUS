"""
NEXUS Engine - Desktop Sidebar Navigation & Control Panel
=========================================================
Architecture Role: Modular CustomTkinter sidebar providing connection state,
dataset file ingestion, live dynamic schema inspection, and volatile
credential management for Local (Ollama) vs Cloud AI models.

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / CustomTkinter
"""

from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog
from typing import Any, Callable, Dict, List, Optional

import customtkinter

# Resilient logging initialization
try:
    from loguru import logger
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("NEXUS-Sidebar")  # type: ignore

from src.core.db_manager import DatabaseManager
from src.core.key_vault import WindowsDPAPIVault
from src.core.schema_parser import SchemaParser, default_parser
from src.ui.async_worker import AsyncWorkerManager
from src.ui.theme import NexusTheme, mask_secret


class SidebarPanel(customtkinter.CTkFrame):
    """
    Left-hand persistent navigation and status panel for the NEXUS GUI.

    Components:
    1. Brand Header with real-time SQLite WAL Mode badge.
    2. File Ingestion Dropzone / Selector (.csv, .tsv, .xlsx, .db, .sqlite).
    3. Live Database Schema Explorer with asynchronous background reflection.
    4. LLM Provider Toggle & Secret Redaction Management.
    """

    LOCAL_MODELS: List[str] = ["llama3:8b", "codellama:7b", "mistral:7b"]
    CLOUD_MODELS: List[str] = ["gemini-1.5-pro", "gemini-1.5-flash", "claude-3-5-sonnet"]

    def __init__(
        self,
        master: Any,
        db_manager: Optional[DatabaseManager] = None,
        schema_parser: Optional[SchemaParser] = None,
        async_worker: Optional[AsyncWorkerManager] = None,
        on_file_selected: Optional[Callable[[str], None]] = None,
        on_table_selected: Optional[Callable[[str], None]] = None,
        on_llm_config_changed: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_rename_table: Optional[Callable[[str, str], None]] = None,
        on_drop_table: Optional[Callable[[str], None]] = None,
        width: int = 300,
        key_vault: Optional[WindowsDPAPIVault] = None,
        **kwargs: Any
    ) -> None:
        worker = async_worker or kwargs.pop("worker_manager", None)
        super().__init__(
            master,
            width=width,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=0,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER,
            **kwargs
        )

        self.db = db_manager or DatabaseManager()
        self.schema_parser = schema_parser or default_parser
        self.worker = worker
        self.on_file_selected = on_file_selected
        self.on_table_selected = on_table_selected
        self.on_llm_config_changed = on_llm_config_changed
        self.on_rename_table = on_rename_table
        self.on_drop_table = on_drop_table
        self._key_vault = key_vault

        # Volatile security state: API keys stored in memory only, never written to disk or logged
        self._volatile_api_key: Optional[str] = None
        self._selected_file_path: Optional[str] = None
        self._active_provider: str = "local"  # "local" or "cloud"
        self._selected_table: Optional[str] = None
        self._table_buttons: Dict[str, customtkinter.CTkButton] = {}

        self._build_ui()

        # Property aliases for full cross-module compatibility
        self.stats_lbl = self.schema_summary_label
        self.filename_lbl = self.file_label
        self.key_status_lbl = self.key_status_label
        self.model_dropdown = self.model_selector
        self.table_scroll = self.table_scroll_frame

        self.refresh_schema()

    # --------------------------------------------------------------------------
    # UI CONSTRUCTION
    # --------------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Constructs all sub-widgets inside the sidebar."""
        self.grid_rowconfigure(2, weight=1)  # Schema list expands vertically
        self.grid_columnconfigure(0, weight=1)

        # 1. Brand Header
        self._build_brand_header()

        # 2. File Upload Dropzone / Selector
        self._build_file_selector()

        # 3. Live Database Schema Explorer
        self._build_schema_inspector()

        # 4. LLM Provider & Security Panel
        self._build_llm_security_toggle()

    def _build_brand_header(self) -> None:
        header_frame = customtkinter.CTkFrame(
            self,
            fg_color="transparent",
            corner_radius=0
        )
        header_frame.grid(row=0, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(NexusTheme.PADDING_MD, 8))

        # Title & Subtitle
        title_label = customtkinter.CTkLabel(
            header_frame,
            text="⚡ NEXUS CORE",
            font=NexusTheme.FONT_TITLE,
            text_color=NexusTheme.ACCENT_CYAN,
            anchor="w"
        )
        title_label.pack(fill="x", anchor="w")

        subtitle_label = customtkinter.CTkLabel(
            header_frame,
            text="Autonomous Data & SQL Engine",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_MUTED,
            anchor="w"
        )
        subtitle_label.pack(fill="x", anchor="w", pady=(0, 6))

        # SQLite Connection Status Badge
        badge_frame = customtkinter.CTkFrame(
            header_frame,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        badge_frame.pack(fill="x", pady=(2, 4))

        self.status_badge = customtkinter.CTkLabel(
            badge_frame,
            text="● WAL MODE ACTIVE",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.STATUS_EMERALD,
            padx=8,
            pady=3
        )
        self.status_badge.pack(anchor="w")

    def _build_file_selector(self) -> None:
        card = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        card.grid(row=1, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=8)

        card_title = customtkinter.CTkLabel(
            card,
            text="DATASET INGESTION",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.TEXT_SECONDARY
        )
        card_title.pack(anchor="w", padx=NexusTheme.PADDING_SM, pady=(NexusTheme.PADDING_SM, 4))

        self.select_file_btn = customtkinter.CTkButton(
            card,
            text="📂 Select CSV / Dataset",
            font=NexusTheme.FONT_BODY,
            fg_color=NexusTheme.ACCENT_CYAN,
            hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self._handle_file_browse
        )
        self.select_file_btn.pack(fill="x", padx=NexusTheme.PADDING_SM, pady=4)

        # AI Smart Clean Toggle (Default False for 100% backward compatibility)
        self.ai_clean_var = customtkinter.BooleanVar(value=False)
        self.ai_clean_switch = customtkinter.CTkSwitch(
            card,
            text="🤖 AI Smart Clean",
            variable=self.ai_clean_var,
            font=NexusTheme.FONT_SMALL_BOLD,
            progress_color=NexusTheme.ACCENT_CYAN,
            button_color=NexusTheme.TEXT_PRIMARY,
            button_hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            text_color=NexusTheme.TEXT_PRIMARY,
        )
        self.ai_clean_switch.pack(anchor="w", padx=NexusTheme.PADDING_SM, pady=(2, 4))

        self.file_label = customtkinter.CTkLabel(
            card,
            text="No file selected",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_MUTED,
            wraplength=260,
            anchor="w"
        )
        self.file_label.pack(fill="x", padx=NexusTheme.PADDING_SM, pady=(0, NexusTheme.PADDING_SM))

    def _build_schema_inspector(self) -> None:
        inspector_frame = customtkinter.CTkFrame(
            self,
            fg_color="transparent"
        )
        inspector_frame.grid(row=2, column=0, sticky="nsew", padx=NexusTheme.PADDING_MD, pady=8)
        inspector_frame.grid_rowconfigure(2, weight=1)
        inspector_frame.grid_columnconfigure(0, weight=1)

        # Header Row with Refresh Button
        header_row = customtkinter.CTkFrame(inspector_frame, fg_color="transparent")
        header_row.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        header_row.grid_columnconfigure(0, weight=1)

        lbl = customtkinter.CTkLabel(
            header_row,
            text="DATABASE SCHEMA",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.TEXT_SECONDARY,
            anchor="w"
        )
        lbl.grid(row=0, column=0, sticky="w")

        self.refresh_btn = customtkinter.CTkButton(
            header_row,
            text="↻ Refresh",
            width=70,
            height=24,
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self.refresh_schema
        )
        self.refresh_btn.grid(row=0, column=1, sticky="e")

        # Summary Metric Counter
        self.schema_summary_label = customtkinter.CTkLabel(
            inspector_frame,
            text="Tables: -- | Columns: -- | FKs: --",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_MUTED,
            anchor="w"
        )
        self.schema_summary_label.grid(row=1, column=0, sticky="ew", pady=(0, 6))

        # Scrollable Discovered Tables List
        self.table_scroll_frame = customtkinter.CTkScrollableFrame(
            inspector_frame,
            fg_color=NexusTheme.BG_OBSIDIAN,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        self.table_scroll_frame.grid(row=2, column=0, sticky="nsew")

        # Table Management Action Row
        self.table_action_frame = customtkinter.CTkFrame(inspector_frame, fg_color="transparent")
        self.table_action_frame.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        self.table_action_frame.grid_columnconfigure(0, weight=1)
        self.table_action_frame.grid_columnconfigure(1, weight=1)

        self.rename_table_btn = customtkinter.CTkButton(
            self.table_action_frame,
            text="✏️ Rename",
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            state="disabled",
            height=26,
            command=self._handle_rename_click
        )
        self.rename_table_btn.grid(row=0, column=0, sticky="ew", padx=(0, 3))

        self.drop_table_btn = customtkinter.CTkButton(
            self.table_action_frame,
            text="🗑️ Drop",
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.STATUS_CRIMSON,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            state="disabled",
            height=26,
            command=self._handle_drop_click
        )
        self.drop_table_btn.grid(row=0, column=1, sticky="ew", padx=(3, 0))

    def _canonical_cloud_provider(self) -> str:
        """Maps active Cloud provider/model selection cleanly to a canonical lowercase slug ('gemini' or 'claude')."""
        active_model = (self.model_selector.get() or "").lower() if hasattr(self, "model_selector") else ""
        if "claude" in active_model or "anthropic" in active_model:
            return "claude"
        return "gemini"

    def _build_llm_security_toggle(self) -> None:
        llm_frame = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        llm_frame.grid(row=3, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(8, NexusTheme.PADDING_MD))

        llm_title = customtkinter.CTkLabel(
            llm_frame,
            text="AI AGENT & SECURITY",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.TEXT_SECONDARY
        )
        llm_title.pack(anchor="w", padx=NexusTheme.PADDING_SM, pady=(NexusTheme.PADDING_SM, 4))

        # Provider Switch
        self.provider_seg = customtkinter.CTkSegmentedButton(
            llm_frame,
            values=["Local (Ollama)", "Cloud API"],
            font=NexusTheme.FONT_SMALL,
            selected_color=NexusTheme.ACCENT_CYAN,
            selected_hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            command=self._handle_provider_change
        )
        self.provider_seg.set("Local (Ollama)")
        self.provider_seg.pack(fill="x", padx=NexusTheme.PADDING_SM, pady=4)

        # Model Selector Dropdown
        self.model_selector = customtkinter.CTkOptionMenu(
            llm_frame,
            values=self.LOCAL_MODELS,
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_SLATE,
            button_color=NexusTheme.ACCENT_CYAN_MUTED,
            button_hover_color=NexusTheme.ACCENT_CYAN,
            text_color=NexusTheme.TEXT_PRIMARY,
            command=self._handle_model_change
        )
        self.model_selector.set(self.LOCAL_MODELS[0])
        self.model_selector.pack(fill="x", padx=NexusTheme.PADDING_SM, pady=4)

        # Cloud API Key Sub-Panel (Revealed when Cloud API is selected)
        self.key_container = customtkinter.CTkFrame(llm_frame, fg_color="transparent")

        self.api_key_entry = customtkinter.CTkEntry(
            self.key_container,
            placeholder_text="Paste Cloud API Key...",
            show="•",
            font=NexusTheme.FONT_CODE,
            fg_color=NexusTheme.BG_OBSIDIAN,
            border_color=NexusTheme.SURFACE_BORDER
        )
        self.api_key_entry.pack(fill="x", pady=2)

        self.apply_key_btn = customtkinter.CTkButton(
            self.key_container,
            text="🔒 Apply Key (Volatile Memory)",
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.ACCENT_CYAN_MUTED,
            hover_color=NexusTheme.ACCENT_CYAN,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self._handle_apply_api_key
        )
        self.apply_key_btn.pack(fill="x", pady=2)

        # Opt-in DPAPI Remember Key Checkbox
        self.remember_key_var = customtkinter.BooleanVar(value=False)
        vault_supported = (self._key_vault is not None and self._key_vault.is_supported())
        self.remember_key_checkbox = customtkinter.CTkCheckBox(
            self.key_container,
            text="🔒 Remember Key (DPAPI)",
            variable=self.remember_key_var,
            command=self._on_remember_key_toggled,
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_PRIMARY,
            checkmark_color="#000000",
            fg_color=NexusTheme.ACCENT_CYAN,
            hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            state="normal" if vault_supported else "disabled"
        )
        self.remember_key_checkbox.pack(anchor="w", pady=(4, 2))

        # Vault Status Row: Pill and Forget Key Button
        vault_ctrl_row = customtkinter.CTkFrame(self.key_container, fg_color="transparent")
        vault_ctrl_row.pack(fill="x", pady=(2, 4))
        vault_ctrl_row.grid_columnconfigure(0, weight=1)

        self.vault_status_label = customtkinter.CTkLabel(
            vault_ctrl_row,
            text="Volatile (RAM-only)",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_MUTED,
            anchor="w"
        )
        self.vault_status_label.grid(row=0, column=0, sticky="w")

        self.forget_key_btn = customtkinter.CTkButton(
            vault_ctrl_row,
            text="🗑️ Forget Key",
            font=NexusTheme.FONT_SMALL,
            width=85,
            height=24,
            fg_color=NexusTheme.SURFACE_SLATE,
            hover_color=NexusTheme.STATUS_CRIMSON,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self.forget_current_provider_key
        )
        self.forget_key_btn.grid(row=0, column=1, sticky="e")

        # Key Masked Status Indicator
        self.key_status_label = customtkinter.CTkLabel(
            llm_frame,
            text="Mode: Local Ollama (Zero Cloud I/O)",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.STATUS_EMERALD,
            wraplength=260,
            anchor="w"
        )
        self.key_status_label.pack(fill="x", padx=NexusTheme.PADDING_SM, pady=(2, NexusTheme.PADDING_SM))

    # --------------------------------------------------------------------------
    # EVENT HANDLERS & SCHEMA REFLECTION
    # --------------------------------------------------------------------------

    def _handle_file_browse(self) -> None:
        """Opens native file picker filtered for tabular datasets and SQLite files."""
        file_path = filedialog.askopenfilename(
            title="Select Dataset / Database",
            filetypes=[
                ("Supported Datasets", "*.csv;*.tsv;*.xlsx;*.db;*.sqlite"),
                ("CSV Files", "*.csv"),
                ("Excel Workbooks", "*.xlsx"),
                ("SQLite Databases", "*.db;*.sqlite"),
                ("All Files", "*.*")
            ]
        )
        if not file_path:
            return

        self._selected_file_path = file_path
        filename = os.path.basename(file_path)
        self.file_label.configure(
            text=f"Selected: {filename}",
            text_color=NexusTheme.ACCENT_CYAN
        )
        logger.info(f"Dataset selected for ingestion: {filename}")

        if callable(self.on_file_selected):
            try:
                self.on_file_selected(file_path)
            except Exception as exc:
                logger.error(f"Error in on_file_selected callback: {exc}")

    def refresh_schema(self) -> None:
        """
        Refreshes database metadata. Executes asynchronously via AsyncWorkerManager
        if available to guarantee zero UI thread lockups.
        """
        def _fetch_stats() -> Dict[str, Any]:
            self.schema_parser.invalidate_cache()
            return self.schema_parser.get_summary_stats()

        if self.worker is not None and not self.worker.is_shutdown:
            self.schema_summary_label.configure(text="Reflecting schema metadata...")
            self.worker.submit_task(
                _fetch_stats,
                on_success=self._on_schema_refreshed,
                on_error=self._on_schema_refresh_failed,
                task_name="SchemaRefresh"
            )
        else:
            # Synchronous fallback for headless test execution
            try:
                stats = _fetch_stats()
                self._on_schema_refreshed(stats)
            except Exception as exc:
                self._on_schema_refresh_failed(exc)

    def _on_schema_refreshed(self, stats: Dict[str, Any]) -> None:
        """Updates UI counter and populates table scroll frame on main thread."""
        if not self.winfo_exists():
            return
        table_count = stats.get("table_count", 0)
        col_count = stats.get("total_columns", 0)
        fk_count = stats.get("total_foreign_keys", 0)
        table_names = stats.get("table_names", [])

        self.schema_summary_label.configure(
            text=f"Tables: {table_count} | Columns: {col_count} | FKs: {fk_count}",
            text_color=NexusTheme.TEXT_SECONDARY
        )

        # Clear existing table buttons
        for widget in self.table_scroll_frame.winfo_children():
            widget.destroy()
        self._table_buttons.clear()

        if not table_names:
            self._selected_table = None
            self._update_table_action_buttons()
            empty_lbl = customtkinter.CTkLabel(
                self.table_scroll_frame,
                text="No user tables found in database.",
                font=NexusTheme.FONT_SMALL,
                text_color=NexusTheme.TEXT_MUTED,
                anchor="center"
            )
            empty_lbl.pack(fill="x", pady=12)
            return

        # If previous selection is no longer valid, clear it
        if self._selected_table not in table_names:
            self._selected_table = None

        # Populate table buttons
        for name in table_names:
            is_selected = (name == self._selected_table)
            btn = customtkinter.CTkButton(
                self.table_scroll_frame,
                text=f"📊  {name}",
                font=NexusTheme.FONT_CODE,
                anchor="w",
                fg_color=NexusTheme.SURFACE_ELEVATED if is_selected else "transparent",
                hover_color=NexusTheme.SURFACE_ELEVATED,
                text_color=NexusTheme.ACCENT_CYAN if is_selected else NexusTheme.TEXT_PRIMARY,
                height=26,
                command=lambda t=name: self._handle_table_click(t)
            )
            btn.pack(fill="x", padx=2, pady=1)
            self._table_buttons[name] = btn

        self._update_table_action_buttons()

    def _on_schema_refresh_failed(self, error: Exception) -> None:
        if not self.winfo_exists():
            return
        logger.error(f"Schema refresh failed: {error}")
        self.schema_summary_label.configure(
            text="Schema reflection failed.",
            text_color=NexusTheme.STATUS_CRIMSON
        )
        self._update_table_action_buttons()

    def _handle_table_click(self, table_name: str) -> None:
        logger.debug(f"Table clicked in schema inspector: {table_name}")
        self._selected_table = table_name
        self._update_table_action_buttons()

        for name, btn in self._table_buttons.items():
            try:
                if btn.winfo_exists():
                    if name == table_name:
                        btn.configure(fg_color=NexusTheme.SURFACE_ELEVATED, text_color=NexusTheme.ACCENT_CYAN)
                    else:
                        btn.configure(fg_color="transparent", text_color=NexusTheme.TEXT_PRIMARY)
            except Exception:
                pass

        if callable(self.on_table_selected):
            try:
                self.on_table_selected(table_name)
            except Exception as exc:
                logger.error(f"Error in on_table_selected callback: {exc}")

    @staticmethod
    def _is_table_protected(table_name: Optional[str]) -> bool:
        if not table_name:
            return True
        lower = table_name.lower().strip()
        return lower.startswith("_nexus_") or lower.startswith("sqlite_")

    def _update_table_action_buttons(self) -> None:
        """Enables or disables Rename and Drop buttons based on current table selection."""
        is_prot = self._is_table_protected(self._selected_table)
        btn_state = "normal" if (self._selected_table and not is_prot) else "disabled"
        if hasattr(self, "rename_table_btn") and self.rename_table_btn.winfo_exists():
            self.rename_table_btn.configure(state=btn_state)
        if hasattr(self, "drop_table_btn") and self.drop_table_btn.winfo_exists():
            self.drop_table_btn.configure(state=btn_state)

    def _handle_rename_click(self) -> None:
        """Prompts user for a new table name and invokes on_rename_table callback."""
        if not self._selected_table or self._is_table_protected(self._selected_table):
            return
        old_name = self._selected_table
        dialog = customtkinter.CTkInputDialog(
            text=f"Enter new name for table '{old_name}':",
            title="Rename Table"
        )
        new_name = dialog.get_input()
        if new_name and new_name.strip():
            cleaned_new_name = new_name.strip()
            if callable(self.on_rename_table):
                try:
                    self.on_rename_table(old_name, cleaned_new_name)
                except Exception as exc:
                    logger.error(f"Error in on_rename_table callback: {exc}")

    def _handle_drop_click(self) -> None:
        """Prompts user for confirmation and invokes on_drop_table callback."""
        if not self._selected_table or self._is_table_protected(self._selected_table):
            return
        table_name = self._selected_table
        from tkinter import messagebox
        confirmed = messagebox.askyesno(
            title="Confirm Drop Table",
            message=f"Are you sure you want to permanently drop table '{table_name}'?\nThis action cannot be undone."
        )
        if confirmed:
            if callable(self.on_drop_table):
                try:
                    self.on_drop_table(table_name)
                except Exception as exc:
                    logger.error(f"Error in on_drop_table callback: {exc}")

    def get_selected_table(self) -> Optional[str]:
        """Returns the currently selected database table name, or None."""
        return self._selected_table

    def _handle_provider_change(self, value: str) -> None:
        """Toggles between Local Ollama and Cloud API view and models."""
        if value == "Cloud API":
            self._active_provider = "cloud"
            self.model_selector.configure(values=self.CLOUD_MODELS)
            self.model_selector.set(self.CLOUD_MODELS[0])
            self.key_container.pack(fill="x", padx=NexusTheme.PADDING_SM, pady=4)
            self.load_key_from_vault_for_provider()
            self._update_key_status_label()
        else:
            self._active_provider = "local"
            self.model_selector.configure(values=self.LOCAL_MODELS)
            self.model_selector.set(self.LOCAL_MODELS[0])
            self.key_container.pack_forget()
            self.key_status_label.configure(
                text="Mode: Local Ollama (Zero Cloud I/O)",
                text_color=NexusTheme.STATUS_EMERALD
            )

        self._notify_llm_config_changed()

    def _handle_model_change(self, selected_model: str) -> None:
        if self._active_provider == "cloud":
            self.load_key_from_vault_for_provider()
        self._notify_llm_config_changed()

    def _handle_apply_api_key(self) -> None:
        """Stores the API key strictly in volatile instance memory and masks display."""
        raw_key = self.api_key_entry.get().strip()
        if not raw_key:
            self._volatile_api_key = None
            self._update_key_status_label()
            return

        # Store in volatile instance memory (never written to file or logged unless opted into DPAPI)
        self._volatile_api_key = raw_key
        if hasattr(self, "remember_key_var") and self.remember_key_var.get():
            self.save_current_key_to_vault()
        else:
            self.api_key_entry.delete(0, "end")
            self._update_key_status_label()
            self._notify_llm_config_changed()
            logger.info(f"Cloud API key applied to volatile memory: {mask_secret(raw_key)}")

    def _on_remember_key_toggled(self) -> None:
        """Handles toggling the Remember Key checkbox."""
        if self.remember_key_var.get():
            self.save_current_key_to_vault()
        else:
            slug = self._canonical_cloud_provider()
            if self._key_vault is not None:
                self._key_vault.delete_key(slug)
            if hasattr(self, "vault_status_label") and self.vault_status_label.winfo_exists():
                self.vault_status_label.configure(
                    text="Volatile (RAM-only)",
                    text_color=NexusTheme.TEXT_MUTED
                )

    def load_key_from_vault_for_provider(self, provider: Optional[str] = None) -> bool:
        """
        Loads and decrypts saved API key from the DPAPI key vault if present.
        Updates volatile memory, checkbox, status pill, and notifies LLM config listeners.
        """
        slug = (provider.strip().lower() if provider else self._canonical_cloud_provider())
        if "claude" in slug or "anthropic" in slug:
            slug = "claude"
        elif "gemini" in slug:
            slug = "gemini"

        if self._key_vault is not None and self._key_vault.is_supported():
            saved_key = self._key_vault.load_key(slug, raise_on_corrupt=False)
            if saved_key:
                self._volatile_api_key = saved_key
                if hasattr(self, "api_key_entry") and self.api_key_entry.winfo_exists():
                    self.api_key_entry.delete(0, "end")
                    self.api_key_entry.insert(0, saved_key)
                if hasattr(self, "remember_key_var"):
                    self.remember_key_var.set(True)
                if hasattr(self, "vault_status_label") and self.vault_status_label.winfo_exists():
                    self.vault_status_label.configure(
                        text="🔒 Key Saved (DPAPI)",
                        text_color=NexusTheme.STATUS_EMERALD
                    )
                self._update_key_status_label()
                self._notify_llm_config_changed()
                return True

        if hasattr(self, "remember_key_var"):
            self.remember_key_var.set(False)
        if hasattr(self, "vault_status_label") and self.vault_status_label.winfo_exists():
            self.vault_status_label.configure(
                text="Volatile (RAM-only)",
                text_color=NexusTheme.TEXT_MUTED
            )
        return False

    def save_current_key_to_vault(self) -> bool:
        """Saves current raw API key into DPAPI vault for active cloud provider."""
        slug = self._canonical_cloud_provider()
        raw_key = self._volatile_api_key
        if not raw_key and hasattr(self, "api_key_entry") and self.api_key_entry.winfo_exists():
            raw_key = self.api_key_entry.get().strip()

        if not raw_key:
            return False

        if self._key_vault is not None and self._key_vault.is_supported():
            self._key_vault.save_key(slug, raw_key)
            self._volatile_api_key = raw_key
            if hasattr(self, "remember_key_var"):
                self.remember_key_var.set(True)
            if hasattr(self, "vault_status_label") and self.vault_status_label.winfo_exists():
                self.vault_status_label.configure(
                    text="🔒 Key Saved (DPAPI)",
                    text_color=NexusTheme.STATUS_EMERALD
                )
            self._update_key_status_label()
            self._notify_llm_config_changed()
            return True
        return False

    def forget_current_provider_key(self) -> bool:
        """Deletes key from DPAPI vault, wipes volatile memory, and clears UI entry."""
        slug = self._canonical_cloud_provider()
        if self._key_vault is not None:
            self._key_vault.delete_key(slug)

        self._volatile_api_key = None
        if hasattr(self, "api_key_entry") and self.api_key_entry.winfo_exists():
            self.api_key_entry.delete(0, "end")
        if hasattr(self, "remember_key_var"):
            self.remember_key_var.set(False)
        if hasattr(self, "vault_status_label") and self.vault_status_label.winfo_exists():
            self.vault_status_label.configure(
                text="Volatile (RAM-only)",
                text_color=NexusTheme.TEXT_MUTED
            )
        self._update_key_status_label()
        self._notify_llm_config_changed()
        return True

    def _update_key_status_label(self) -> None:
        if self._volatile_api_key:
            self.key_status_label.configure(
                text=f"Key: {mask_secret(self._volatile_api_key)} (Active)",
                text_color=NexusTheme.STATUS_EMERALD
            )
        else:
            self.key_status_label.configure(
                text="No Cloud API key configured.",
                text_color=NexusTheme.STATUS_AMBER
            )

    def _notify_llm_config_changed(self) -> None:
        if callable(self.on_llm_config_changed):
            try:
                self.on_llm_config_changed(self.get_llm_config())
            except Exception as exc:
                logger.error(f"Error in on_llm_config_changed callback: {exc}")

    # --------------------------------------------------------------------------
    # PUBLIC API
    # --------------------------------------------------------------------------

    def update_local_models(self, models: List[str]) -> None:
        """
        Dynamically updates the local Ollama models list from auto-discovery.
        Filters out embedding-only models, falls back to self.LOCAL_MODELS if empty,
        and updates the UI dropdown if in Local mode.
        """
        if not self.winfo_exists():
            return

        # Filter out embedding models (case-insensitive)
        embedding_patterns = ("embed", "nomic-embed", "mxbai-embed", "bge-")
        filtered = [
            m for m in models
            if m and not any(pat in m.lower() for pat in embedding_patterns)
        ]

        # Preserve fallback if filtered list is empty
        if filtered:
            self.LOCAL_MODELS = filtered

        target_models = list(self.LOCAL_MODELS)

        if self._active_provider == "local":
            current_model = self.model_selector.get()
            chosen_model = current_model

            # If current model is not among installed models, choose preferred or first
            if current_model not in target_models:
                preferred = ("phi4-mini:latest", "granite4.1:3b", "gemma3:4b")
                found_pref = None
                for pref in preferred:
                    matches = [m for m in target_models if m == pref or m.split(":")[0] == pref.split(":")[0]]
                    if matches:
                        found_pref = matches[0]
                        break
                chosen_model = found_pref if found_pref else target_models[0]

            self.model_selector.configure(values=target_models)
            self.model_selector.set(chosen_model)
            self._notify_llm_config_changed()

    def get_llm_config(self) -> Dict[str, Any]:
        """
        Returns the active AI provider configuration with masked secrets.
        100% safe to serialize, display in UI labels, or emit in audit logs.
        """
        model = self.model_selector.get()
        masked = mask_secret(self._volatile_api_key)
        return {
            "provider": self._active_provider,
            "mode": self._active_provider,
            "provider_name": "Local (Ollama)" if self._active_provider == "local" else "Cloud API",
            "model": model,
            "selected_model": model,
            "masked_api_key": masked,
            "masked_key": masked,
            "has_api_key": bool(self._volatile_api_key),
        }

    def get_volatile_api_key(self) -> Optional[str]:
        """
        Returns the raw API key for Phase 4 LangChain LLM Router consumption.
        Restricted to internal in-memory pipeline invocations.
        """
        return self._volatile_api_key

    def get_selected_file_path(self) -> Optional[str]:
        """Returns the absolute path to the selected tabular dataset."""
        return self._selected_file_path

    def get_selected_file(self) -> Optional[str]:
        """Alias for get_selected_file_path for full interface compatibility."""
        return self._selected_file_path

    def is_ai_clean_enabled(self) -> bool:
        """Returns whether AI Smart Clean is enabled for tabular file ingestion."""
        return bool(self.ai_clean_var.get())

    def set_ai_clean_enabled(self, enabled: bool) -> None:
        """Sets the AI Smart Clean toggle state."""
        self.ai_clean_var.set(enabled)

