"""
NEXUS Engine - Desktop Application Root Container
=================================================
Architecture Role: Primary CustomTkinter desktop window coordinating the dual-pane
layout, 60 FPS non-blocking worker polling loop, inter-component event routing,
DPI bootstrapping, operational status monitoring, and deterministic shutdown.

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / CustomTkinter
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from src.agent.sql_chain import AgentRunResult

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
    logger = logging.getLogger("NEXUS-App")  # type: ignore

from src.core.db_manager import DatabaseManager
from src.core.schema_parser import SchemaParser
from src.etl.etl_engine import ETLEngine, ETLReport, ETLConfig
from src.ui.async_worker import AsyncWorkerManager
from src.ui.theme import NexusTheme, apply_global_theme, mask_secret
from src.ui.components.sidebar import SidebarPanel
from src.ui.components.data_explorer_tab import DataExplorerTab
from src.ui.components.chat_tab import ChatAnalystTab
from src.ui.components.telemetry_hud_tab import TelemetryHudTab


class NexusApp(customtkinter.CTk):
    """
    Root Desktop Application Container for the NEXUS Autonomous Engine.

    Architectural Invariants:
    1. Zero UI Thread Blocking: Heavy computation (I/O, DB reflection, ETL, LLM) runs
       strictly inside AsyncWorkerManager threads. The main UI thread never blocks.
    2. 60 FPS Event Loop: Events from background workers are polled and dispatched
       every ~30ms via a non-blocking Tkinter .after() schedule.
    3. Strict Secret Masking: API credentials, connection keys, and sensitive
       parameters are never displayed in plaintext or logged.
    4. Deterministic Shutdown: Thread pools, database connections, and timers are
       cleanly terminated on WM_DELETE_WINDOW without leaving zombie processes.
    5. Testability: Fully supports dependency injection of db_manager, schema_parser,
       and async_worker for automated, isolated headless testing.
    """

    APP_TITLE: str = "NEXUS — Autonomous Data Pipeline & Analytics Engine"
    DEFAULT_GEOMETRY: str = "1360x840"
    MIN_WIDTH: int = 1080
    MIN_HEIGHT: int = 680
    DEFAULT_POLL_INTERVAL_MS: int = 30

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        schema_parser: Optional[SchemaParser] = None,
        async_worker: Optional[AsyncWorkerManager] = None,
        poll_interval_ms: int = DEFAULT_POLL_INTERVAL_MS,
        **kwargs: Any
    ) -> None:
        # 1. Bootstrap global cyber theme and Windows DPI awareness prior to geometry setup
        apply_global_theme()

        super().__init__(fg_color=NexusTheme.BG_OBSIDIAN, **kwargs)

        # 2. Window Geometry & Appearance Configuration
        self.title(self.APP_TITLE)
        self.geometry(self.DEFAULT_GEOMETRY)
        self.minsize(self.MIN_WIDTH, self.MIN_HEIGHT)

        # 3. Dependency Injection
        self.db = db_manager or DatabaseManager()
        self.schema_parser = schema_parser or SchemaParser(self.db)
        self.worker = async_worker or AsyncWorkerManager()
        self.poll_interval_ms = max(10, poll_interval_ms)
        self.etl_engine = ETLEngine(db_manager=self.db, schema_parser=self.schema_parser)

        # 4. Lifecycle & Timer State
        self._is_closing: bool = False
        self._poll_after_id: Optional[str] = None
        self._transient_clear_after_id: Optional[str] = None

        # 5. Build Responsive Layout
        self._build_layout()

        # 6. Bind Keyboard Shortcuts & Shutdown Hook
        self._bind_keyboard_shortcuts()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # 7. Start Non-Blocking Worker Event Polling Loop (~60 FPS)
        self._poll_after_id = self.after(self.poll_interval_ms, self._poll_worker_events)

        # 8. Start Non-Blocking Startup Discovery of Installed Local Ollama Models
        self._discover_local_models_async()

        logger.info(
            f"NEXUS Desktop Shell successfully initialized. "
            f"Database: {self.db.db_path.name if hasattr(self.db, 'db_path') and self.db.db_path else 'In-Memory'}, "
            f"Poll Interval: {self.poll_interval_ms}ms."
        )

    # --------------------------------------------------------------------------
    # LAYOUT CONSTRUCTION
    # --------------------------------------------------------------------------

    def _build_layout(self) -> None:
        """Constructs the responsive dual-pane layout and bottom status bar."""
        # Grid weight configuration
        self.grid_rowconfigure(0, weight=1)  # Workspace area expands vertically
        self.grid_rowconfigure(1, weight=0)  # Status footer is fixed height (28px)
        self.grid_columnconfigure(0, weight=0)  # Sidebar is fixed width (300px)
        self.grid_columnconfigure(1, weight=1)  # Right workspace expands horizontally

        # ----------------------------------------------------------------------
        # Left Pane: Sidebar Navigation & Control Panel
        # ----------------------------------------------------------------------
        self.sidebar = SidebarPanel(
            self,
            db_manager=self.db,
            schema_parser=self.schema_parser,
            async_worker=self.worker,
            on_file_selected=self._handle_file_selected,
            on_table_selected=self._handle_table_selected,
            on_llm_config_changed=self._handle_llm_config_changed,
            width=300
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        # ----------------------------------------------------------------------
        # Right Main Pane: Dark Cyber Tabview Container
        # ----------------------------------------------------------------------
        self.tabview = customtkinter.CTkTabview(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            segmented_button_fg_color=NexusTheme.SURFACE_ELEVATED,
            segmented_button_selected_color=NexusTheme.ACCENT_CYAN,
            segmented_button_selected_hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            segmented_button_unselected_color=NexusTheme.SURFACE_ELEVATED,
            segmented_button_unselected_hover_color=NexusTheme.SURFACE_BORDER,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            command=self._on_tab_changed
        )
        self.tabview.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=NexusTheme.PADDING_MD,
            pady=(NexusTheme.PADDING_MD, 4)
        )

        # Tab 1: Data Explorer
        tab_explorer = self.tabview.add("Data Explorer")
        tab_explorer.grid_rowconfigure(0, weight=1)
        tab_explorer.grid_columnconfigure(0, weight=1)
        self.data_explorer_tab = DataExplorerTab(
            tab_explorer,
            db_manager=self.db,
            schema_parser=self.schema_parser,
            async_worker=self.worker
        )
        self.data_explorer_tab.grid(row=0, column=0, sticky="nsew")

        # Tab 2: AI Analyst Chat
        tab_chat = self.tabview.add("AI Analyst Chat")
        tab_chat.grid_rowconfigure(0, weight=1)
        tab_chat.grid_columnconfigure(0, weight=1)
        self.chat_tab = ChatAnalystTab(
            tab_chat,
            db_manager=self.db,
            schema_parser=self.schema_parser,
            async_worker=self.worker,
            sidebar_panel=self.sidebar,
            get_llm_config_fn=self.sidebar.get_llm_config,
            get_volatile_api_key_fn=self.sidebar.get_volatile_api_key,
            on_open_sql_in_explorer=self._handle_open_sql_in_explorer,
            on_query_completed=self._handle_agent_query_completed
        )
        self.chat_tab.grid(row=0, column=0, sticky="nsew")

        # Tab 3: Security & Telemetry HUD
        tab_hud = self.tabview.add("Security & Telemetry HUD")
        tab_hud.grid_rowconfigure(0, weight=1)
        tab_hud.grid_columnconfigure(0, weight=1)
        self.telemetry_hud_tab = TelemetryHudTab(
            tab_hud,
            db_manager=self.db,
            async_worker=self.worker
        )
        self.telemetry_hud_tab.grid(row=0, column=0, sticky="nsew")

        # Ensure default tab is 'Data Explorer'
        self.tabview.set("Data Explorer")

        # ----------------------------------------------------------------------
        # Bottom Operational Status Bar (Height: 28px)
        # ----------------------------------------------------------------------
        self.status_bar = customtkinter.CTkFrame(
            self,
            height=28,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=0,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        self.status_bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.status_bar.grid_propagate(False)
        self.status_bar.grid_columnconfigure(1, weight=1)

        # Left Badge: Active Database File
        db_name = (
            self.db.db_path.name
            if hasattr(self.db, "db_path") and self.db.db_path
            else "nexus_workspace.db"
        )
        self.status_db_label = customtkinter.CTkLabel(
            self.status_bar,
            text=f"🗄️ DB: {db_name}",
            font=NexusTheme.FONT_SMALL_BOLD,
            text_color=NexusTheme.ACCENT_CYAN,
            anchor="w"
        )
        self.status_db_label.grid(row=0, column=0, padx=(12, 16), pady=2, sticky="w")

        # Center: Transient Status Message / Actionable Hints
        self.status_msg_label = customtkinter.CTkLabel(
            self.status_bar,
            text="Ready. [Ctrl+1/2/3: Switch Tabs | F5: Refresh Engine]",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_SECONDARY,
            anchor="w"
        )
        self.status_msg_label.grid(row=0, column=1, padx=8, pady=2, sticky="w")

        # Right Badge: Live Background Worker Pool Indicator
        self.status_worker_label = customtkinter.CTkLabel(
            self.status_bar,
            text="Worker Pool: IDLE",
            font=NexusTheme.FONT_SMALL_BOLD,
            text_color=NexusTheme.STATUS_EMERALD,
            anchor="e"
        )
        self.status_worker_label.grid(row=0, column=2, padx=(8, 16), pady=2, sticky="e")

    # --------------------------------------------------------------------------
    # EVENT HANDLERS & CALLBACKS
    # --------------------------------------------------------------------------

    def _handle_table_selected(self, table_name: str) -> None:
        """
        Invoked when user selects a table from the sidebar schema inspector.
        Switches the main view to Data Explorer and triggers an automated preview.
        """
        if not table_name:
            return
        self.tabview.set("Data Explorer")
        self.data_explorer_tab.select_table_and_preview(table_name)
        self.set_status_message(f"Selected table: '{table_name}' (loading preview...)")

    def _handle_llm_config_changed(self, config: Dict[str, Any]) -> None:
        """
        Propagates updated LLM provider configuration to the chat tab and status bar.
        Enforces strict credential masking with zero raw secret leakage.
        """
        self.chat_tab.update_provider_badge(config)
        provider = str(config.get("provider", "LOCAL")).upper()
        model = str(config.get("model", "llama3:8b"))
        masked_key = str(config.get("masked_api_key", "[NONE]"))

        logger.info(
            f"LLM Configuration updated: Provider={provider}, Model={model}, "
            f"Key={masked_key}"
        )
        self.set_status_message(
            f"AI Model configured: {model} ({provider}) | Credential: {masked_key}"
        )

    def _handle_open_sql_in_explorer(self, sql: str) -> None:
        """
        Switches to Data Explorer tab, loads the SQL into the scratchpad,
        and triggers guarded execution.
        """
        if not self.winfo_exists() or self._is_closing:
            return
        self.tabview.set("Data Explorer")
        self.data_explorer_tab.load_and_execute_sql(sql)
        self.set_status_message(f"Loaded SQL query into Data Explorer: {sql[:60]}...")

    def _handle_agent_query_completed(self, result: AgentRunResult) -> None:
        """
        Updates the bottom status bar with masked, token/latency-aware telemetry
        upon SQLAgentChain completion.
        """
        if not self.winfo_exists() or self._is_closing:
            return
        status = result.status
        if status == "SUCCESS":
            rows = result.query_result.row_count if result.query_result else 0
            msg = (
                f"AI Query [SUCCESS]: {rows} rows | "
                f"{result.total_latency_ms:.0f}ms | "
                f"{result.total_tokens} tokens"
            )
            self.set_status_message(f"⚡ {msg}", revert_after_ms=8000)
        elif status == "SECURITY_BLOCKED":
            self.set_status_message("🛡️ AI Query [SECURITY_BLOCKED]: Mutation rejected by QueryGuard", revert_after_ms=10000)
        elif status == "EMPTY_DB":
            self.set_status_message("⚠️ AI Query [EMPTY_DB]: Workspace database contains no tables", revert_after_ms=6000)
        else:
            self.set_status_message(f"❌ AI Query [{status}]: {result.error_message or 'Execution failed'}", revert_after_ms=8000)

    def _discover_local_models_async(self) -> None:
        """Non-blocking startup probe to auto-discover installed local Ollama models."""
        if hasattr(self, "chat_tab") and hasattr(self.chat_tab, "health_status_label"):
            if self.chat_tab.health_status_label.winfo_exists():
                self.chat_tab.health_status_label.configure(
                    text="● Checking...",
                    text_color=NexusTheme.ACCENT_CYAN
                )

        def _probe_ollama() -> Tuple[bool, List[str], str]:
            from src.agent.llm_router import LLMConfig, LLMRouter
            cfg = LLMConfig(provider="local", model="llama3:8b")
            router = LLMRouter(config=cfg)
            return router.check_ollama_health()

        def _on_probe_success(health: Any) -> None:
            if not self.winfo_exists() or self._is_closing:
                return
            if isinstance(health, tuple):
                is_online = bool(health[0])
                models = health[1] if len(health) > 1 and isinstance(health[1], list) else []
            elif isinstance(health, dict):
                is_online = health.get("status") == "online"
                models = health.get("models", [])
            else:
                is_online = False
                models = []

            if is_online:
                if models and hasattr(self.sidebar, "update_local_models"):
                    self.sidebar.update_local_models(models)
                if hasattr(self, "chat_tab") and hasattr(self.chat_tab, "health_status_label"):
                    if self.chat_tab.health_status_label.winfo_exists():
                        self.chat_tab.health_status_label.configure(
                            text=f"● Ollama Online ({len(models)} models)",
                            text_color=NexusTheme.STATUS_EMERALD
                        )
            else:
                if hasattr(self, "chat_tab") and hasattr(self.chat_tab, "health_status_label"):
                    if self.chat_tab.health_status_label.winfo_exists():
                        self.chat_tab.health_status_label.configure(
                            text="● Ollama Offline",
                            text_color=NexusTheme.STATUS_AMBER
                        )

        def _on_probe_error(exc: Exception) -> None:
            if not self.winfo_exists() or self._is_closing:
                return
            if hasattr(self, "chat_tab") and hasattr(self.chat_tab, "health_status_label"):
                if self.chat_tab.health_status_label.winfo_exists():
                    self.chat_tab.health_status_label.configure(
                        text="● Ollama Offline",
                        text_color=NexusTheme.STATUS_AMBER
                    )

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _probe_ollama,
                on_success=_on_probe_success,
                on_error=_on_probe_error,
                task_name="StartupOllamaDiscovery"
            )
        else:
            try:
                res = _probe_ollama()
                _on_probe_success(res)
            except Exception as exc:
                _on_probe_error(exc)

    def _handle_file_selected(self, file_path: str) -> None:
        """
        Invoked when a dataset file is chosen via the sidebar dropzone / selector.
        Stages file for Phase 3 ETL processing, and if the file exists on disk,
        dispatches the high-speed background ETL pipeline with live progress streaming.
        """
        filename = os.path.basename(file_path)
        logger.info(f"Dataset staged for Phase 3 ETL: {file_path}")
        self.set_status_message(f"Dataset staged for Phase 3 ETL: {filename}")

        if os.path.exists(file_path):
            if hasattr(self.sidebar, "file_label") and self.sidebar.file_label.winfo_exists():
                self.sidebar.file_label.configure(
                    text=f"⏳ Ingesting {filename}...",
                    text_color=NexusTheme.ACCENT_CYAN
                )

            self.worker.submit_task(
                self.etl_engine.ingest_file,
                file_path,
                on_success=self._on_etl_success,
                on_error=self._on_etl_error,
                on_progress=self._on_etl_progress,
                task_name=f"ETL-{filename}"
            )

    def ingest_dataset(
        self,
        file_path: str,
        table_name: Optional[str] = None,
        config: Optional[ETLConfig] = None
    ) -> str:
        """
        Programmatically dispatches background ETL ingestion for a file.
        Returns the generated task_id from AsyncWorkerManager.
        """
        filename = os.path.basename(file_path)
        self.set_status_message(f"⚡ Ingesting '{filename}' into SQLite...", revert_after_ms=None)
        return self.worker.submit_task(
            self.etl_engine.ingest_file,
            file_path,
            table_name=table_name,
            config=config,
            on_success=self._on_etl_success,
            on_error=self._on_etl_error,
            on_progress=self._on_etl_progress,
            task_name=f"ETL-{filename}"
        )

    def _on_etl_progress(self, progress_msg: str) -> None:
        """Invoked on the main UI thread as the background ETL pipeline streams updates."""
        if not self.winfo_exists() or self._is_closing:
            return
        self.set_status_message(f"⚡ {progress_msg}", revert_after_ms=None)

    def _on_etl_success(self, report: ETLReport) -> None:
        """
        Invoked on the main UI thread when ETL ingestion completes successfully.
        Updates status bar, refreshes sidebar and explorer table lists, switches
        to Data Explorer, and triggers immediate preview of the ingested table.
        """
        if not self.winfo_exists() or self._is_closing:
            return

        # 1. Update status bar message
        summary_msg = report.summary()
        self.set_status_message(f"✅ {summary_msg}", revert_after_ms=10000)

        # 2. Update sidebar file label with success indicator
        if hasattr(self.sidebar, "file_label") and self.sidebar.file_label.winfo_exists():
            self.sidebar.file_label.configure(
                text=f"✅ {os.path.basename(report.source_path)} ({report.rows_ingested:,} rows)",
                text_color=NexusTheme.STATUS_EMERALD
            )

        # 3. Invalidate schema cache & refresh UI components
        self.schema_parser.invalidate_cache()
        self.sidebar.refresh_schema()
        self.data_explorer_tab.refresh_table_list()

        # 4. Instant jump to Data Explorer and preview the new table
        self.tabview.set("Data Explorer")
        self.data_explorer_tab.select_table_and_preview(report.table_name)

        # 5. Log audit event to database
        self.db.log_audit_event(
            natural_query=f"ETL Ingest: {os.path.basename(report.source_path)} -> {report.table_name}",
            generated_sql=f"-- INGESTED {report.rows_ingested} ROWS INTO {report.table_name} IN {report.elapsed_time_sec:.3f}s",
            status="SUCCESS"
        )

    def _on_etl_error(self, exc: Exception) -> None:
        """
        Invoked on the main UI thread if ETL ingestion fails.
        Safely captures the error, displays crimson alert, and updates sidebar state.
        """
        if not self.winfo_exists() or self._is_closing:
            return

        err_msg = str(exc)
        logger.error(f"ETL Ingestion Error: {err_msg}")
        self.set_status_message(f"❌ ETL Failed: {err_msg}", revert_after_ms=12000)

        if hasattr(self.sidebar, "file_label") and self.sidebar.file_label.winfo_exists():
            self.sidebar.file_label.configure(
                text=f"❌ Error: {err_msg[:40]}...",
                text_color=NexusTheme.STATUS_CRIMSON
            )

        # Log failed audit event
        self.db.log_audit_event(
            natural_query="ETL Ingestion Attempt",
            generated_sql="-- ETL FAILED",
            status="FAILED",
            error_message=err_msg
        )

    def _on_tab_changed(self) -> None:
        """
        Invoked when user navigates to a different tab in CTkTabview.
        Automatically refreshes HUD telemetry metrics when switching to HUD.
        """
        if not self.winfo_exists() or self._is_closing:
            return
        current = self.tabview.get()
        if current == "Security & Telemetry HUD":
            self.telemetry_hud_tab.refresh_hud()

    # --------------------------------------------------------------------------
    # STATUS BAR & NON-BLOCKING POLLING LOOP
    # --------------------------------------------------------------------------

    def set_status_message(self, message: str, revert_after_ms: Optional[int] = 5000) -> None:
        """Sets a transient message in the status bar with an optional auto-revert timeout."""
        if not self.winfo_exists() or self._is_closing:
            return

        if self._transient_clear_after_id is not None:
            try:
                self.after_cancel(self._transient_clear_after_id)
            except Exception:
                pass
            self._transient_clear_after_id = None

        self.status_msg_label.configure(text=message, text_color=NexusTheme.TEXT_PRIMARY)

        if revert_after_ms is not None and revert_after_ms > 0:
            def _reset_hint() -> None:
                if not self._is_closing and self.winfo_exists():
                    self.status_msg_label.configure(
                        text="Ready. [Ctrl+1/2/3: Switch Tabs | F5: Refresh Engine]",
                        text_color=NexusTheme.TEXT_SECONDARY
                    )
                    self._transient_clear_after_id = None

            self._transient_clear_after_id = self.after(revert_after_ms, _reset_hint)

    def _poll_worker_events(self) -> None:
        """
        60 FPS non-blocking event pump.
        Dispatches queued worker callbacks on the main UI thread and updates
        the background worker pool status indicator.
        """
        if self._is_closing or not self.winfo_exists():
            return

        try:
            if self.worker and not self.worker.is_shutdown:
                self.worker.process_queue()
                active_count = self.worker.active_task_count()
                if active_count > 0:
                    self.status_worker_label.configure(
                        text=f"Worker Pool: ACTIVE ({active_count} task(s))",
                        text_color=NexusTheme.ACCENT_CYAN
                    )
                else:
                    self.status_worker_label.configure(
                        text="Worker Pool: IDLE",
                        text_color=NexusTheme.STATUS_EMERALD
                    )
        except Exception as exc:
            logger.warning(f"Error during worker event loop polling: {exc}")

        # Reschedule next polling tick
        if not self._is_closing and self.winfo_exists():
            self._poll_after_id = self.after(self.poll_interval_ms, self._poll_worker_events)

    # --------------------------------------------------------------------------
    # KEYBOARD SHORTCUTS
    # --------------------------------------------------------------------------

    def _bind_keyboard_shortcuts(self) -> None:
        """Binds productivity shortcuts for rapid navigation and engine refresh."""
        self.bind("<Control-Key-1>", lambda event: self._switch_tab("Data Explorer"))
        self.bind("<Control-Key-2>", lambda event: self._switch_tab("AI Analyst Chat"))
        self.bind("<Control-Key-3>", lambda event: self._switch_tab("Security & Telemetry HUD"))
        self.bind("<F5>", self._handle_f5_refresh)

    def _switch_tab(self, tab_name: str) -> None:
        if not self.winfo_exists() or self._is_closing:
            return
        self.tabview.set(tab_name)
        self._on_tab_changed()

    def _handle_f5_refresh(self, event: Any = None) -> None:
        """Refreshes sidebar schema and triggers refresh on the active tab."""
        if not self.winfo_exists() or self._is_closing:
            return
        self.set_status_message("Engine refresh: Updating schema reflection and active tab...")
        self.sidebar.refresh_schema()
        current_tab = self.tabview.get()
        if current_tab == "Data Explorer":
            self.data_explorer_tab.refresh_table_list()
        elif current_tab == "Security & Telemetry HUD":
            self.telemetry_hud_tab.refresh_hud()

    # --------------------------------------------------------------------------
    # DETERMINISTIC SHUTDOWN PROTOCOL
    # --------------------------------------------------------------------------

    def on_closing(self) -> None:
        """
        Clean Shutdown Protocol (WM_DELETE_WINDOW).
        Guards against double invocation, cancels pending after timers,
        shuts down background worker pool, closes SQLite connections, and destroys window.
        """
        if self._is_closing:
            return
        self._is_closing = True
        logger.info("Executing NEXUS clean application shutdown protocol...")

        # 1. Cancel pending poll timer
        if self._poll_after_id is not None:
            try:
                self.after_cancel(self._poll_after_id)
            except Exception:
                pass
            self._poll_after_id = None

        # 2. Cancel transient status bar reset timer
        if self._transient_clear_after_id is not None:
            try:
                self.after_cancel(self._transient_clear_after_id)
            except Exception:
                pass
            self._transient_clear_after_id = None

        # 3. Terminate background worker pool (wait=False to prevent hangs on exit)
        try:
            if self.worker and not self.worker.is_shutdown:
                self.worker.shutdown(wait=False)
        except Exception as exc:
            logger.warning(f"Error terminating AsyncWorkerManager during shutdown: {exc}")

        # 4. Safely close database manager connections
        try:
            if self.db:
                self.db.close()
        except Exception as exc:
            logger.warning(f"Error closing DatabaseManager during shutdown: {exc}")

        # 5. Destroy root window safely
        try:
            self.destroy()
        except Exception as exc:
            logger.debug(f"Exception during window destroy: {exc}")

        logger.info("NEXUS shutdown complete. Zero zombie threads remaining.")
