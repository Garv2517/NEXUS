"""
NEXUS Engine - Data Explorer & Safe SQL Query Tab
=================================================
Architecture Role: Interactive tabular data inspector and guarded SQL scratchpad.
Provides asynchronous query execution, strict query validation via QueryGuard,
and structured results rendering with zero UI thread blocking.

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / CustomTkinter
"""

from __future__ import annotations

import io
import time
from pathlib import Path
from tkinter import filedialog, ttk
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

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
    logger = logging.getLogger("NEXUS-DataExplorer")  # type: ignore

from src.core.db_manager import (
    DatabaseManager,
    QueryResult,
    ReadOnlyViolationError,
    DatabaseLockedError,
    QueryExecutionError,
)
from src.core.export_engine import DataExportEngine
from src.core.query_guard import QueryGuard, SecurityException, guard_query
from src.core.schema_parser import SchemaParser, default_parser
from src.ui.async_worker import AsyncWorkerManager
from src.ui.formatters import format_ascii_table, format_cell_value
from src.ui.theme import NexusTheme


class DataExplorerTab(customtkinter.CTkFrame):
    """
    Main data exploration and interactive query execution workspace.

    Key Features:
    1. Table quick-select dropdown and automated 100-row preview generator.
    2. Monospace safe read-only SQL query editor.
    3. Defense-in-depth query interceptor using QueryGuard (rejects non-SELECT).
    4. Non-blocking asynchronous query execution via AsyncWorkerManager.
    5. Clean tabular text grid rendering and persistent audit logging.
    """

    DEFAULT_QUERY_PLACEHOLDER = "SELECT name, type FROM sqlite_schema WHERE type = 'table' ORDER BY name LIMIT 25;"
    DEFAULT_PREVIEW_LIMIT = 100

    def __init__(
        self,
        master: Any,
        db_manager: Optional[DatabaseManager] = None,
        schema_parser: Optional[SchemaParser] = None,
        async_worker: Optional[AsyncWorkerManager] = None,
        **kwargs: Any
    ) -> None:
        worker = async_worker or kwargs.pop("worker_manager", None)
        super().__init__(
            master,
            fg_color=NexusTheme.BG_OBSIDIAN,
            corner_radius=0,
            **kwargs
        )

        self.db = db_manager or DatabaseManager()
        self.schema_parser = schema_parser or default_parser
        self.worker = worker

        self._last_result: Optional[QueryResult] = None
        self._all_display_rows: List[Tuple[Any, ...]] = []
        self._active_columns: List[str] = []
        self._sort_state: Dict[str, bool] = {}
        self._user_selected_text_mode: bool = False

        self._build_ui()

        # Cross-compatibility aliases
        self.data_view = self.results_textbox
        self.result_status_lbl = self.query_status_label
        self.timing_badge = self.latency_badge
        self.table_dropdown = self.table_selector
        self.exec_btn = self.execute_btn
        self.execute_user_query = self.execute_current_query

        self.refresh_table_list()

    # --------------------------------------------------------------------------
    # UI CONSTRUCTION
    # --------------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Constructs layout: top controls, SQL scratchpad, and results viewer."""
        self.grid_rowconfigure(3, weight=1)  # Results frame expands
        self.grid_columnconfigure(0, weight=1)

        # 1. Top Controls Bar: Table Selector & Quick Preview
        self._build_top_controls()

        # 2. Security Alert Banner (Hidden by default, shown on violation)
        self._build_security_banner()

        # 3. Safe SQL Scratchpad Editor
        self._build_sql_scratchpad()

        # 4. Tabular Results Display
        self._build_results_viewer()

    def _build_top_controls(self) -> None:
        control_frame = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        control_frame.grid(row=0, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(NexusTheme.PADDING_MD, 8))
        control_frame.grid_columnconfigure(1, weight=1)

        # Active Table Dropdown
        lbl = customtkinter.CTkLabel(
            control_frame,
            text="Active Table:",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.TEXT_SECONDARY
        )
        lbl.grid(row=0, column=0, padx=(NexusTheme.PADDING_MD, 8), pady=NexusTheme.PADDING_SM, sticky="w")

        self.table_selector = customtkinter.CTkOptionMenu(
            control_frame,
            values=["(Loading tables...)"],
            font=NexusTheme.FONT_CODE,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            button_color=NexusTheme.ACCENT_CYAN_MUTED,
            button_hover_color=NexusTheme.ACCENT_CYAN,
            text_color=NexusTheme.TEXT_PRIMARY,
            command=self._on_table_selected_from_menu
        )
        self.table_selector.grid(row=0, column=1, padx=8, pady=NexusTheme.PADDING_SM, sticky="ew")

        # Preview Button
        self.preview_btn = customtkinter.CTkButton(
            control_frame,
            text="⚡ Preview Table (LIMIT 100)",
            font=NexusTheme.FONT_BODY,
            fg_color=NexusTheme.ACCENT_CYAN,
            hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self._handle_quick_preview_click
        )
        self.preview_btn.grid(row=0, column=2, padx=(8, NexusTheme.PADDING_MD), pady=NexusTheme.PADDING_SM)

    def _build_security_banner(self) -> None:
        """Prominent crimson alert banner for intercepted SQL injection attempts."""
        self.alert_frame = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.STATUS_CRIMSON,
            corner_radius=NexusTheme.CORNER_RADIUS_SM
        )
        # Not gridded initially; gridded dynamically when security violation occurs

        self.alert_label = customtkinter.CTkLabel(
            self.alert_frame,
            text="[SECURITY ALERT] Destructive query blocked by QueryGuard.",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color="#FFFFFF",
            anchor="w",
            padx=12,
            pady=8
        )
        self.alert_label.pack(side="left", fill="x", expand=True)

        dismiss_btn = customtkinter.CTkButton(
            self.alert_frame,
            text="✕ Dismiss",
            width=80,
            height=26,
            font=NexusTheme.FONT_SMALL,
            fg_color="#B91C1C",
            hover_color="#991B1B",
            text_color="#FFFFFF",
            command=self._dismiss_security_banner
        )
        dismiss_btn.pack(side="right", padx=12, pady=6)

    def _build_sql_scratchpad(self) -> None:
        scratchpad_frame = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        scratchpad_frame.grid(row=2, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=8)
        scratchpad_frame.grid_columnconfigure(0, weight=1)

        # Header bar
        header_bar = customtkinter.CTkFrame(scratchpad_frame, fg_color="transparent")
        header_bar.grid(row=0, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(NexusTheme.PADDING_SM, 4))
        header_bar.grid_columnconfigure(0, weight=1)

        title_lbl = customtkinter.CTkLabel(
            header_bar,
            text="SAFE READ-ONLY SQL QUERY SCRATCHPAD",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.TEXT_SECONDARY,
            anchor="w"
        )
        title_lbl.grid(row=0, column=0, sticky="w")

        guard_badge = customtkinter.CTkLabel(
            header_bar,
            text="🛡️ GUARDED EXECUTION",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.STATUS_EMERALD,
            anchor="e"
        )
        guard_badge.grid(row=0, column=1, sticky="e")

        # Monospace SQL Textbox
        self.sql_textbox = customtkinter.CTkTextbox(
            scratchpad_frame,
            height=110,
            font=NexusTheme.FONT_CODE,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            text_color=NexusTheme.TEXT_PRIMARY,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER,
            corner_radius=NexusTheme.CORNER_RADIUS_SM
        )
        self.sql_textbox.grid(row=1, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=4)
        self.sql_textbox.insert("1.0", self.DEFAULT_QUERY_PLACEHOLDER)

        # Action Bar (Execute, Clear, Status)
        action_bar = customtkinter.CTkFrame(scratchpad_frame, fg_color="transparent")
        action_bar.grid(row=2, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(4, NexusTheme.PADDING_SM))
        action_bar.grid_columnconfigure(2, weight=1)

        self.execute_btn = customtkinter.CTkButton(
            action_bar,
            text="▶ Execute Safe Query",
            font=NexusTheme.FONT_BODY_BOLD,
            fg_color=NexusTheme.ACCENT_CYAN,
            hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self.execute_current_query
        )
        self.execute_btn.grid(row=0, column=0, padx=(0, 8), pady=2)

        self.clear_btn = customtkinter.CTkButton(
            action_bar,
            text="Clear",
            width=70,
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.SURFACE_BORDER,
            text_color=NexusTheme.TEXT_SECONDARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self._clear_scratchpad
        )
        self.clear_btn.grid(row=0, column=1, padx=(0, 8), pady=2)

        self.query_status_label = customtkinter.CTkLabel(
            action_bar,
            text="Ready. Only read-only SELECT queries are permitted.",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_MUTED,
            anchor="w"
        )
        self.query_status_label.grid(row=0, column=2, sticky="w", padx=8)

    def _build_results_viewer(self) -> None:
        results_container = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        results_container.grid(row=3, column=0, sticky="nsew", padx=NexusTheme.PADDING_MD, pady=(8, NexusTheme.PADDING_MD))
        results_container.grid_rowconfigure(2, weight=1)
        results_container.grid_columnconfigure(0, weight=1)

        # 1. Results Header Bar
        results_header = customtkinter.CTkFrame(results_container, fg_color="transparent")
        results_header.grid(row=0, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(NexusTheme.PADDING_SM, 4))
        results_header.grid_columnconfigure(0, weight=1)

        self.results_title = customtkinter.CTkLabel(
            results_header,
            text="QUERY EXECUTION RESULTS",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.TEXT_SECONDARY,
            anchor="w"
        )
        self.results_title.grid(row=0, column=0, sticky="w")

        self.latency_badge = customtkinter.CTkLabel(
            results_header,
            text="Latency: -- ms | Rows: --",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_MUTED,
            anchor="e"
        )
        self.latency_badge.grid(row=0, column=1, sticky="e")

        # 2. Results Toolbar (Live Filter, Export Buttons, View Mode Switch)
        toolbar = customtkinter.CTkFrame(results_container, fg_color="transparent")
        toolbar.grid(row=1, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(0, 6))
        toolbar.grid_columnconfigure(0, weight=1)

        # Live Search Filter Entry
        self.grid_search_entry = customtkinter.CTkEntry(
            toolbar,
            placeholder_text="🔍 Filter displayed rows...",
            width=210,
            height=26,
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.BG_OBSIDIAN,
            text_color=NexusTheme.TEXT_PRIMARY,
            border_color=NexusTheme.SURFACE_BORDER,
            border_width=1,
            corner_radius=NexusTheme.CORNER_RADIUS_SM
        )
        self.grid_search_entry.grid(row=0, column=0, sticky="w")
        self.grid_search_entry.bind("<KeyRelease>", lambda event: self.filter_grid(self.grid_search_entry.get()))

        # Right Action Controls
        actions_frame = customtkinter.CTkFrame(toolbar, fg_color="transparent")
        actions_frame.grid(row=0, column=1, sticky="e")

        self.export_csv_btn = customtkinter.CTkButton(
            actions_frame,
            text="📊 Export CSV",
            width=95,
            height=26,
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self._handle_export_csv,
            state="disabled"
        )
        self.export_csv_btn.pack(side="left", padx=(0, 6))

        self.export_xlsx_btn = customtkinter.CTkButton(
            actions_frame,
            text="📗 Export Excel",
            width=95,
            height=26,
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self._handle_export_xlsx,
            state="disabled"
        )
        self.export_xlsx_btn.pack(side="left", padx=(0, 10))

        self.view_mode_switch = customtkinter.CTkSegmentedButton(
            actions_frame,
            values=["Grid", "Text"],
            width=110,
            height=26,
            font=NexusTheme.FONT_SMALL,
            selected_color=NexusTheme.ACCENT_CYAN,
            selected_hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            unselected_color=NexusTheme.SURFACE_ELEVATED,
            unselected_hover_color=NexusTheme.SURFACE_BORDER,
            text_color=NexusTheme.TEXT_PRIMARY,
            command=self._on_view_mode_changed
        )
        self.view_mode_switch.set("Grid")
        self.view_mode_switch.pack(side="left")

        # 3. Main Display Frame Hosting Treeview Grid and Text View
        self.display_frame = customtkinter.CTkFrame(results_container, fg_color="transparent")
        self.display_frame.grid(row=2, column=0, sticky="nsew", padx=NexusTheme.PADDING_MD, pady=(0, NexusTheme.PADDING_MD))
        self.display_frame.grid_rowconfigure(0, weight=1)
        self.display_frame.grid_columnconfigure(0, weight=1)

        # A. Treeview Grid Frame
        self.tree_frame = customtkinter.CTkFrame(self.display_frame, fg_color="transparent")
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)

        # Configure Scoped ttk.Style for Dark Cyber Treeview
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Nexus.Treeview",
            background=NexusTheme.BG_OBSIDIAN,
            foreground=NexusTheme.TEXT_PRIMARY,
            fieldbackground=NexusTheme.BG_OBSIDIAN,
            bordercolor=NexusTheme.SURFACE_BORDER,
            borderwidth=0,
            rowheight=26,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Nexus.Treeview.Heading",
            background=NexusTheme.SURFACE_SLATE,
            foreground=NexusTheme.ACCENT_CYAN,
            bordercolor=NexusTheme.SURFACE_BORDER,
            borderwidth=1,
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Nexus.Treeview.Heading",
            background=[("active", NexusTheme.SURFACE_ELEVATED)],
            foreground=[("active", NexusTheme.ACCENT_CYAN_HOVER)],
        )
        style.map(
            "Nexus.Treeview",
            background=[("selected", NexusTheme.SURFACE_ELEVATED)],
            foreground=[("selected", NexusTheme.ACCENT_CYAN)],
        )

        self.results_tree = ttk.Treeview(
            self.tree_frame,
            style="Nexus.Treeview",
            selectmode="browse"
        )
        self.results_tree.tag_configure("evenrow", background=NexusTheme.SURFACE_SLATE)
        self.results_tree.tag_configure("oddrow", background=NexusTheme.BG_OBSIDIAN)

        tree_vsb = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.results_tree.yview)
        tree_hsb = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=tree_vsb.set, xscrollcommand=tree_hsb.set)

        self.results_tree.grid(row=0, column=0, sticky="nsew")
        tree_vsb.grid(row=0, column=1, sticky="ns")
        tree_hsb.grid(row=1, column=0, sticky="ew")

        # B. Monospace Formatted Table View (Backward Compatibility Invariant)
        self.results_textbox = customtkinter.CTkTextbox(
            self.display_frame,
            font=NexusTheme.FONT_CODE,
            fg_color=NexusTheme.BG_OBSIDIAN,
            text_color=NexusTheme.TEXT_PRIMARY,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            wrap="none"  # Horizontal scrolling for large tabular datasets
        )
        self.results_textbox.insert("1.0", "(No query executed yet. Run a query above to view tabular results.)")
        self.results_textbox.configure(state="disabled")

        # Default view: Grid mode
        self._show_grid_view()

    def _show_grid_view(self) -> None:
        self.results_textbox.grid_forget()
        self.tree_frame.grid(row=0, column=0, sticky="nsew")

    def _show_text_view(self) -> None:
        self.tree_frame.grid_forget()
        self.results_textbox.grid(row=0, column=0, sticky="nsew")

    def _on_view_mode_changed(self, mode: str) -> None:
        if mode == "Grid":
            self._user_selected_text_mode = False
            self._show_grid_view()
        else:
            self._user_selected_text_mode = True
            self._show_text_view()

    # --------------------------------------------------------------------------
    # TABLE MANAGEMENT & SELECTION
    # --------------------------------------------------------------------------

    def refresh_table_list(self) -> None:
        """Refreshes the active table option menu asynchronously."""
        def _fetch_tables() -> List[str]:
            return self.schema_parser.get_table_names(include_views=True)

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _fetch_tables,
                on_success=self._on_tables_loaded,
                on_error=self._on_tables_failed,
                task_name="LoadTablesList"
            )
        else:
            try:
                tables = _fetch_tables()
                self._on_tables_loaded(tables)
            except Exception as exc:
                self._on_tables_failed(exc)

    def _on_tables_loaded(self, tables: List[str]) -> None:
        if not self.winfo_exists():
            return
        if tables:
            self.table_selector.configure(values=tables)
            current = self.table_selector.get()
            if current not in tables:
                self.table_selector.set(tables[0])
        else:
            self.table_selector.configure(values=["(No user tables found)"])
            self.table_selector.set("(No user tables found)")

    def _on_tables_failed(self, error: Exception) -> None:
        if not self.winfo_exists():
            return
        logger.error(f"Failed to load table names: {error}")

    def _on_table_selected_from_menu(self, selected_table: str) -> None:
        if selected_table and not selected_table.startswith("("):
            escaped = selected_table.replace('"', '""')
            sql = f'SELECT * FROM "{escaped}" LIMIT {self.DEFAULT_PREVIEW_LIMIT};'
            self._set_scratchpad_sql(sql)

    def select_table_and_preview(self, table_name: str) -> None:
        """
        Public programmatic trigger. Selects a table, updates the scratchpad,
        and automatically initiates query execution with safe identifier quoting.
        """
        self.table_selector.set(table_name)
        escaped = table_name.replace('"', '""')
        sql = f'SELECT * FROM "{escaped}" LIMIT {self.DEFAULT_PREVIEW_LIMIT};'
        self._set_scratchpad_sql(sql)
        self.execute_current_query()

    def _handle_quick_preview_click(self) -> None:
        table_name = self.table_selector.get()
        if table_name and not table_name.startswith("("):
            self.select_table_and_preview(table_name)

    # --------------------------------------------------------------------------
    # QUERY EXECUTION & SECURITY INTERCEPTION
    # --------------------------------------------------------------------------

    def execute_current_query(self) -> None:
        """
        Validates the SQL query through QueryGuard and executes it asynchronously
        with read_only=True in a single worker job. Catches all security violations
        and displays the crimson alert banner.
        """
        raw_sql = self.sql_textbox.get("1.0", "end-1c").strip()
        if not raw_sql:
            self.query_status_label.configure(
                text="Please enter a SQL query to execute.",
                text_color=NexusTheme.STATUS_AMBER
            )
            return

        # Hide any previous alert banner
        self._dismiss_security_banner()
        self.query_status_label.configure(
            text="Executing query in background worker thread...",
            text_color=NexusTheme.ACCENT_CYAN
        )
        self.execute_btn.configure(state="disabled")

        def _bg_execute_and_audit() -> Dict[str, Any]:
            start_time = time.perf_counter()
            # 1. Background Layer 7 QueryGuard Validation
            try:
                validated_sql = guard_query(raw_sql)
            except SecurityException as sec_exc:
                logger.warning(f"QueryGuard rejected query in background worker: {sec_exc}")
                self.db.log_audit_event(
                    natural_query="Direct SQL Execution",
                    generated_sql=raw_sql,
                    status="REJECTED",
                    error_message=str(sec_exc)
                )
                return {
                    "status": "REJECTED",
                    "error": str(sec_exc),
                    "violation_type": getattr(sec_exc, "violation_type", "SECURITY_VIOLATION"),
                    "sql": raw_sql,
                    "latency_ms": (time.perf_counter() - start_time) * 1000.0,
                    "result": None,
                }

            # 2. Database Read-Only Execution & Auditing
            try:
                result = self.db.execute_query(validated_sql, read_only=True)
                self.db.log_audit_event(
                    natural_query="Direct SQL Execution",
                    generated_sql=validated_sql,
                    status="SUCCESS"
                )
                return {
                    "status": "SUCCESS",
                    "error": None,
                    "sql": validated_sql,
                    "latency_ms": result.execution_time_ms,
                    "result": result,
                }
            except ReadOnlyViolationError as ro_exc:
                logger.warning(f"ReadOnlyViolation in background worker: {ro_exc}")
                self.db.log_audit_event(
                    natural_query="Direct SQL Execution",
                    generated_sql=raw_sql,
                    status="REJECTED",
                    error_message=str(ro_exc)
                )
                return {
                    "status": "REJECTED",
                    "error": str(ro_exc),
                    "violation_type": "READ_ONLY_VIOLATION",
                    "sql": raw_sql,
                    "latency_ms": (time.perf_counter() - start_time) * 1000.0,
                    "result": None,
                }
            except Exception as exc:
                logger.error(f"SQL execution error in background worker: {exc}")
                self.db.log_audit_event(
                    natural_query="Direct SQL Execution",
                    generated_sql=raw_sql,
                    status="FAILED",
                    error_message=str(exc)
                )
                return {
                    "status": "FAILED",
                    "error": str(exc),
                    "violation_type": "EXECUTION_ERROR",
                    "sql": raw_sql,
                    "latency_ms": (time.perf_counter() - start_time) * 1000.0,
                    "result": None,
                }

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _bg_execute_and_audit,
                on_success=self._on_query_completed,
                on_error=self._on_query_worker_error,
                task_name="ExecuteSQLAndAudit"
            )
        else:
            try:
                data = _bg_execute_and_audit()
                self._on_query_completed(data)
            except Exception as exc:
                self._on_query_worker_error(exc)

    def _on_query_completed(self, data: Dict[str, Any]) -> None:
        if not self.winfo_exists():
            return
        self.execute_btn.configure(state="normal")
        status = data.get("status")

        if status == "SUCCESS":
            result: QueryResult = data["result"]
            sql: str = data["sql"]
            latency_str = f"{result.execution_time_ms:.2f}ms"
            if getattr(result, "truncated", False):
                self.query_status_label.configure(
                    text=f"⚠️ Capped at {result.row_count:,} rows for RAM safety ({latency_str})",
                    text_color=NexusTheme.STATUS_AMBER
                )
                self.latency_badge.configure(
                    text=f"Latency: {latency_str} | Rows: {result.row_count:,} (capped)",
                    text_color=NexusTheme.STATUS_AMBER
                )
            else:
                self.query_status_label.configure(
                    text=f"✓ Executed successfully ({result.row_count} rows in {latency_str}).",
                    text_color=NexusTheme.STATUS_EMERALD
                )
                self.latency_badge.configure(
                    text=f"Latency: {latency_str} | Rows: {result.row_count:,}",
                    text_color=NexusTheme.TEXT_SECONDARY
                )
            self._render_results_grid(result)

        elif status == "REJECTED":
            self.export_csv_btn.configure(state="disabled")
            self.export_xlsx_btn.configure(state="disabled")
            self.view_mode_switch.set("Text")
            self._show_text_view()

            err_msg = data.get("error", "Security violation detected.")
            viol_type = data.get("violation_type", "SECURITY_VIOLATION")
            sql = data.get("sql", "")
            self._show_security_banner(err_msg)
            self.query_status_label.configure(
                text=f"Blocked: {viol_type}",
                text_color=NexusTheme.STATUS_CRIMSON
            )
            self.results_textbox.configure(state="normal")
            self.results_textbox.delete("1.0", "end")
            self.results_textbox.insert(
                "1.0",
                f"-- QUERY REJECTED BY NEXUS SECURITY LAYER --\n\n"
                f"Violation: {err_msg}\n"
                f"Offending Query:\n{sql}\n\n"
                f"The engine blocked this query before it could modify the database."
            )
            self.results_textbox.configure(state="disabled")

        else:  # FAILED
            self.export_csv_btn.configure(state="disabled")
            self.export_xlsx_btn.configure(state="disabled")
            self.view_mode_switch.set("Text")
            self._show_text_view()

            err_msg = data.get("error", "Unknown SQL error.")
            self.query_status_label.configure(
                text="SQL Execution Failed.",
                text_color=NexusTheme.STATUS_CRIMSON
            )
            self.results_textbox.configure(state="normal")
            self.results_textbox.delete("1.0", "end")
            self.results_textbox.insert("1.0", f"-- RUNTIME SQL ERROR --\n\n{err_msg}")
            self.results_textbox.configure(state="disabled")

    def _on_query_worker_error(self, exc: Exception) -> None:
        if not self.winfo_exists():
            return
        self.execute_btn.configure(state="normal")
        self.export_csv_btn.configure(state="disabled")
        self.export_xlsx_btn.configure(state="disabled")
        self.view_mode_switch.set("Text")
        self._show_text_view()

        logger.error(f"Worker thread error during query execution: {exc}")
        self.query_status_label.configure(
            text="Query worker error.",
            text_color=NexusTheme.STATUS_CRIMSON
        )
        self.results_textbox.configure(state="normal")
        self.results_textbox.delete("1.0", "end")
        self.results_textbox.insert("1.0", f"-- WORKER THREAD FAILURE --\n\n{exc}")
        self.results_textbox.configure(state="disabled")

    # --------------------------------------------------------------------------
    # RENDERING & HELPER UTILITIES
    # --------------------------------------------------------------------------

    def _render_results_grid(self, result: QueryResult) -> None:
        """Formats QueryResult into both high-density Treeview grid and ASCII text view."""
        self._last_result = result
        self._sort_state.clear()

        # 1. Update export buttons state
        has_data = bool(result.columns and result.row_count > 0)
        export_state = "normal" if has_data else "disabled"
        self.export_csv_btn.configure(state=export_state)
        self.export_xlsx_btn.configure(state=export_state)

        # 2. Populate text view (Backward Compatibility Invariant)
        if not result.columns:
            rendered = "(Statement executed successfully. No return rows.)\n"
        elif result.row_count == 0:
            rendered = " | ".join(f"{col}" for col in result.columns) + "\n" + "-" * 60 + "\n(0 rows returned)\n"
        else:
            rendered = format_ascii_table(
                columns=result.columns,
                rows=result.rows,
                max_rows=1000,
                truncated=getattr(result, "truncated", False)
            )

        self.results_textbox.configure(state="normal")
        self.results_textbox.delete("1.0", "end")
        self.results_textbox.insert("1.0", rendered)
        self.results_textbox.configure(state="disabled")

        # 3. Setup Treeview Columns
        self._active_columns = list(result.columns)
        self.results_tree["columns"] = self._active_columns
        self.results_tree["show"] = "headings"

        for col in self._active_columns:
            self.results_tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
            col_width = max(len(col) * 11, 90)
            self.results_tree.column(col, width=col_width, minwidth=60, anchor="w")

        # 4. Cache rows and populate grid (capped at 1,000 rows in UI)
        self._all_display_rows = [
            tuple(r[i] if i < len(r) else None for i in range(len(self._active_columns)))
            for r in result.rows
        ] if result.rows else []

        if hasattr(self, "grid_search_entry"):
            self.grid_search_entry.delete(0, "end")
        self.filter_grid("")

        # 5. Display Mode Handling
        if not self._user_selected_text_mode:
            self.view_mode_switch.set("Grid")
            self._show_grid_view()

    def filter_grid(self, search_text: str = "") -> int:
        """
        Filters displayed rows in self.results_tree case-insensitively across all columns.
        Returns matching row count.
        """
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        query = (search_text or "").strip().lower()

        matching_count = 0
        for idx, row in enumerate(self._all_display_rows):
            row_vals_str = [str(val).lower() if val is not None else "" for val in row]
            if query and not any(query in s for s in row_vals_str):
                continue

            matching_count += 1
            if matching_count <= 1000:
                tag = "evenrow" if (matching_count % 2 == 0) else "oddrow"
                display_vals = [format_cell_value(val) for val in row]
                self.results_tree.insert("", "end", values=display_vals, tags=(tag,))

        return matching_count

    def sort_by_column(self, col_name: str, descending: Optional[bool] = None) -> None:
        """
        Sorts displayed rows in self.results_tree by col_name.
        Uses numeric sorting if all non-None values parse as float, else string sort.
        None values always sort last.
        Displays ▲ / ▼ on active column header.
        """
        if not self._active_columns or col_name not in self._active_columns:
            return

        col_idx = self._active_columns.index(col_name)

        if descending is None:
            current_desc = self._sort_state.get(col_name, False)
            descending = not current_desc
        self._sort_state = {col_name: descending}

        # Check if non-None values can be parsed as float
        is_numeric = True
        has_non_none = False
        for r in self._all_display_rows:
            val = r[col_idx] if col_idx < len(r) else None
            if val is not None:
                has_non_none = True
                try:
                    float(val)
                except (ValueError, TypeError):
                    is_numeric = False
                    break

        if not has_non_none:
            is_numeric = False

        # Partition into valid and None items
        valid_rows = []
        none_rows = []
        for r in self._all_display_rows:
            val = r[col_idx] if col_idx < len(r) else None
            if val is None:
                none_rows.append(r)
            else:
                valid_rows.append(r)

        if is_numeric:
            valid_rows.sort(key=lambda r: float(r[col_idx]), reverse=descending)
        else:
            valid_rows.sort(key=lambda r: str(r[col_idx]).lower(), reverse=descending)

        self._all_display_rows = valid_rows + none_rows

        # Update column headers with sort arrow
        for col in self._active_columns:
            if col == col_name:
                arrow = " ▼" if descending else " ▲"
                self.results_tree.heading(col, text=f"{col}{arrow}", command=lambda c=col: self.sort_by_column(c))
            else:
                self.results_tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))

        # Re-apply current search filter to update the rendered Treeview items
        search_query = self.grid_search_entry.get() if hasattr(self, "grid_search_entry") else ""
        self.filter_grid(search_query)

    def export_last_result(
        self,
        output_path: Union[str, Path],
        fmt: str = "csv",
        on_complete: Optional[Callable[[Path], None]] = None
    ) -> None:
        """
        Programmatically exports all rows of the last query result to CSV or Excel.
        Executes via AsyncWorkerManager if available, otherwise synchronously.
        """
        if not self._last_result or not self._last_result.columns:
            raise ValueError("No query results available to export.")

        cols = list(self._last_result.columns)
        rows = list(self._last_result.rows)
        dest_path = Path(output_path).resolve()

        def _do_export() -> Path:
            if fmt.lower() in ("xlsx", "excel"):
                return DataExportEngine.export_excel(cols, rows, dest_path)
            else:
                return DataExportEngine.export_csv(cols, rows, dest_path)

        def _on_success(out_path: Path) -> None:
            if self.winfo_exists():
                self.query_status_label.configure(
                    text=f"✓ Exported {len(rows):,} rows to {out_path.name}",
                    text_color=NexusTheme.STATUS_EMERALD
                )
            if callable(on_complete):
                on_complete(out_path)

        def _on_error(exc: Exception) -> None:
            logger.error(f"Export failed: {exc}")
            if self.winfo_exists():
                self.query_status_label.configure(
                    text=f"❌ Export failed: {exc}",
                    text_color=NexusTheme.STATUS_CRIMSON
                )

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _do_export,
                on_success=_on_success,
                on_error=_on_error,
                task_name=f"ExportResults-{fmt}"
            )
        else:
            try:
                res = _do_export()
                _on_success(res)
            except Exception as exc:
                _on_error(exc)

    def _handle_export_csv(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export Results as CSV",
            defaultextension=".csv",
            filetypes=[("CSV File", "*.csv"), ("All Files", "*.*")]
        )
        if path:
            self.export_last_result(path, fmt="csv")

    def _handle_export_xlsx(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self,
            title="Export Results as Excel",
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook", "*.xlsx"), ("All Files", "*.*")]
        )
        if path:
            self.export_last_result(path, fmt="xlsx")

    def _show_security_banner(self, message: str) -> None:
        self.alert_label.configure(text=f"SECURITY INTERCEPT: {message}")
        self.alert_frame.grid(row=1, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(0, 4))

    def _dismiss_security_banner(self) -> None:
        self.alert_frame.grid_forget()

    def _set_scratchpad_sql(self, sql: str) -> None:
        self.sql_textbox.delete("1.0", "end")
        self.sql_textbox.insert("1.0", sql)

    def load_and_execute_sql(self, sql: str) -> None:
        """
        Loads SQL into the scratchpad editor and triggers asynchronous guarded execution.
        Public API for cross-tab workflows (e.g. from ChatAnalystTab).
        """
        self._set_scratchpad_sql(sql)
        self.execute_current_query()

    def _clear_scratchpad(self) -> None:
        self.sql_textbox.delete("1.0", "end")
        self.query_status_label.configure(
            text="Scratchpad cleared.",
            text_color=NexusTheme.TEXT_MUTED
        )
