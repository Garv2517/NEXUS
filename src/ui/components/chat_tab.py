"""
NEXUS Engine - Conversational AI Data Analyst Tab
=================================================
Architecture Role: Interactive chat interface for natural language analytics.
Provides message bubble history, schema context extraction, clipboard export,
embedded dark Matplotlib charts, and asynchronous SQLAgentChain execution
with live progress feedback and zero UI thread blocking.

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / CustomTkinter
"""

from __future__ import annotations

import io
from pathlib import Path
import re
import time
from tkinter import filedialog
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import customtkinter
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# Resilient logging initialization
try:
    from loguru import logger
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("NEXUS-ChatAnalyst")  # type: ignore

from src.agent.chart_engine import ChartEngine, ChartSpec
from src.agent.llm_router import (
    LLMAuthenticationError,
    LLMConfig,
    LLMConnectionError,
    LLMResponse,
    LLMRouter,
    LLMRouterError,
    LLMTimeoutError,
)
from src.agent.sql_chain import (
    AgentRunResult,
    ConversationTurn,
    SQLAgentChain,
    extract_sql_from_response,
    generate_starter_questions,
)
from src.core.db_manager import DatabaseManager, QueryResult
from src.core.export_engine import DataExportEngine, ExecutiveBriefExporter
from src.core.schema_parser import SchemaParser, default_parser
from src.core.session_store import ChatSessionStore
from src.ui.async_worker import AsyncWorkerManager
from src.ui.formatters import format_ascii_table
from src.ui.theme import NexusTheme, mask_secret


class ChatAnalystTab(customtkinter.CTkFrame):
    """
    Conversational AI Data Analyst interface powered by SQLAgentChain.

    Key Features:
    1. Scrollable chat feed with distinct user, progress, and agent message bubbles.
    2. Header with active model badge, async Ollama health ping, and Chart toggle.
    3. Thread-safe snapshotting of LLM config on the main UI thread.
    4. Asynchronous SQLAgentChain execution with live progress reporting.
    5. Pure OO Matplotlib embedded dark cyber charts with Save PNG capability.
    6. Action row in response cards to Open in Data Explorer or Copy SQL.
    7. Deterministic cleanup of active Figure instances on destroy().
    """

    WELCOME_MESSAGE = (
        "👋 Welcome to NEXUS Autonomous Data Analyst.\n\n"
        "Ask questions about your data in natural English (e.g. 'Show top 5 customers by revenue', "
        "'Plot sales by product as a bar chart').\n\n"
        "• All Text-to-SQL queries are verified through QueryGuard before execution.\n"
        "• Modifying or destructive commands (DROP, DELETE, UPDATE) are strictly blocked.\n"
        "• Toggle '📊 Chart' or ask for charts directly to generate embedded visualizations."
    )

    def __init__(
        self,
        master: Any,
        db_manager: Optional[DatabaseManager] = None,
        schema_parser: Optional[SchemaParser] = None,
        async_worker: Optional[AsyncWorkerManager] = None,
        sidebar_panel: Optional[Any] = None,
        get_llm_config_fn: Optional[Callable[[], Dict[str, Any]]] = None,
        get_volatile_api_key_fn: Optional[Callable[[], Optional[str]]] = None,
        on_open_sql_in_explorer: Optional[Callable[[str], None]] = None,
        on_query_completed: Optional[Callable[[AgentRunResult], None]] = None,
        llm_router_factory: Optional[Callable[[LLMConfig, Optional[Callable[[], Optional[str]]]], LLMRouter]] = None,
        session_store: Optional[ChatSessionStore] = None,
        **kwargs: Any
    ) -> None:
        worker = async_worker or kwargs.pop("worker_manager", None)
        llm_config_fn = get_llm_config_fn or kwargs.pop("get_llm_config_fn", None)
        super().__init__(
            master,
            fg_color=NexusTheme.BG_OBSIDIAN,
            corner_radius=0,
            **kwargs
        )

        self.db = db_manager or DatabaseManager()
        self.schema_parser = schema_parser or default_parser
        self.worker = worker
        self.sidebar_panel = sidebar_panel
        self.get_llm_config_fn = llm_config_fn
        self.get_volatile_api_key_fn = get_volatile_api_key_fn or (
            getattr(sidebar_panel, "get_volatile_api_key", None) if sidebar_panel else None
        )
        self.on_open_sql_in_explorer = on_open_sql_in_explorer
        self.on_query_completed = on_query_completed
        self.llm_router_factory = llm_router_factory or (
            lambda cfg, key_fn: LLMRouter(config=cfg, api_key_provider=key_fn)
        )
        self.session_store = session_store
        self._active_session_id: Optional[str] = None
        self._session_label_to_id: Dict[str, str] = {}

        # Matplotlib, memory and progress state
        self._embedded_figures: List[Figure] = []
        self._conversation_history: List[ConversationTurn] = []
        self._active_progress_frame: Optional[customtkinter.CTkFrame] = None
        self._active_progress_label: Optional[customtkinter.CTkLabel] = None
        self.export_csv_btn: Optional[customtkinter.CTkButton] = None
        self.export_brief_btn: Optional[customtkinter.CTkButton] = None

        self._build_ui()

        # Cross-compatibility aliases
        self.feed_scroll = self.chat_feed
        self.chat_feed_scroll = self.chat_feed
        self.send_user_message = self.send_user_message
        self._handle_send_query = self.send_user_message
        self._handle_copy_schema_context = self.copy_schema_context_to_clipboard

        if self.session_store is not None:
            self._initialize_sessions()
        else:
            self._post_welcome_bubble()
            self.refresh_starter_questions()

    # --------------------------------------------------------------------------
    # UI CONSTRUCTION
    # --------------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Constructs layout: header bar, session bar, scrollable message feed, starter chips, and input bar."""
        self.grid_rowconfigure(2, weight=1)  # Chat feed expands
        self.grid_columnconfigure(0, weight=1)

        # 1. Header & Context Utility Bar
        self._build_header_bar()

        # 2. Compact Session Switcher Bar (U4)
        self._build_session_bar()

        # 3. Scrollable Chat Message Feed
        self._build_chat_feed()

        # 4. Starter Question Chips Row (U2.5)
        self._build_starter_chips_bar()

        # 5. Bottom Natural Language Input Bar
        self._build_input_bar()

    def _build_header_bar(self) -> None:
        header_frame = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        header_frame.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=NexusTheme.PADDING_MD,
            pady=(NexusTheme.PADDING_MD, 8)
        )
        header_frame.grid_columnconfigure(0, weight=1)

        # Left: Active Model Badge
        self.llm_badge = customtkinter.CTkLabel(
            header_frame,
            text="AI Model: llama3:8b [Local (Ollama)]",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.ACCENT_CYAN,
            anchor="w"
        )
        self.llm_badge.grid(row=0, column=0, sticky="w", padx=NexusTheme.PADDING_MD, pady=NexusTheme.PADDING_SM)

        # Right Controls Container
        controls_frame = customtkinter.CTkFrame(header_frame, fg_color="transparent")
        controls_frame.grid(row=0, column=1, sticky="e", padx=NexusTheme.PADDING_MD, pady=NexusTheme.PADDING_SM)

        # Ollama Health Pill
        self.health_status_label = customtkinter.CTkLabel(
            controls_frame,
            text="● Ollama: Unchecked",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_MUTED
        )
        self.health_status_label.pack(side="left", padx=(0, 6))

        # Check Health Button
        self.check_health_btn = customtkinter.CTkButton(
            controls_frame,
            text="Ping Ollama",
            font=NexusTheme.FONT_SMALL,
            width=78,
            height=26,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self._check_ollama_health_async
        )
        self.check_health_btn.pack(side="left", padx=(0, 10))

        # Memory Status Pill (U2)
        self.memory_status_label = customtkinter.CTkLabel(
            controls_frame,
            text="Memory: 0/4 turns",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_MUTED
        )
        self.memory_status_label.pack(side="left", padx=(0, 6))

        # Clear Chat Button (U2)
        self.clear_chat_btn = customtkinter.CTkButton(
            controls_frame,
            text="🧹 Clear Chat",
            font=NexusTheme.FONT_SMALL,
            width=85,
            height=26,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self.clear_conversation
        )
        self.clear_chat_btn.pack(side="left", padx=(0, 10))

        # Include Chart Toggle
        self.chart_toggle_var = customtkinter.BooleanVar(value=False)
        self.chart_switch = customtkinter.CTkSwitch(
            controls_frame,
            text="📊 Chart",
            variable=self.chart_toggle_var,
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_SECONDARY,
            progress_color=NexusTheme.ACCENT_CYAN,
            button_color=NexusTheme.ACCENT_CYAN_HOVER,
            button_hover_color=NexusTheme.ACCENT_CYAN,
            width=42
        )
        self.chart_switch.pack(side="left", padx=(0, 10))

        # Copy Schema Context Action Button
        self.copy_schema_btn = customtkinter.CTkButton(
            controls_frame,
            text="📋 Copy Schema",
            font=NexusTheme.FONT_SMALL,
            width=100,
            height=26,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self.copy_schema_context_to_clipboard
        )
        self.copy_schema_btn.pack(side="left")

    def _build_session_bar(self) -> None:
        """Constructs compact session bar directly below the header bar."""
        self.session_bar = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER,
            height=34
        )
        self.session_bar.grid(
            row=1,
            column=0,
            sticky="ew",
            padx=NexusTheme.PADDING_MD,
            pady=(0, 4)
        )

        # Session Label
        session_lbl = customtkinter.CTkLabel(
            self.session_bar,
            text="Session:",
            font=NexusTheme.FONT_SMALL_BOLD,
            text_color=NexusTheme.TEXT_SECONDARY
        )
        session_lbl.pack(side="left", padx=(NexusTheme.PADDING_SM, 6), pady=4)

        # Dropdown
        self.session_selector = customtkinter.CTkOptionMenu(
            self.session_bar,
            values=["New Session"],
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            button_color=NexusTheme.ACCENT_CYAN_MUTED,
            button_hover_color=NexusTheme.ACCENT_CYAN,
            text_color=NexusTheme.TEXT_PRIMARY,
            width=240,
            height=24,
            command=self._on_session_dropdown_selected
        )
        self.session_selector.pack(side="left", padx=(0, 6), pady=4)

        # + New Button
        self.new_session_btn = customtkinter.CTkButton(
            self.session_bar,
            text="＋ New",
            font=NexusTheme.FONT_SMALL,
            width=65,
            height=24,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=lambda: self.start_new_session()
        )
        self.new_session_btn.pack(side="left", padx=(0, 6), pady=4)

        # Rename Button
        self.rename_session_btn = customtkinter.CTkButton(
            self.session_bar,
            text="✏️",
            font=NexusTheme.FONT_SMALL,
            width=32,
            height=24,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self._handle_rename_session_click
        )
        self.rename_session_btn.pack(side="left", padx=(0, 6), pady=4)

        # Delete Button
        self.delete_session_btn = customtkinter.CTkButton(
            self.session_bar,
            text="🗑️",
            font=NexusTheme.FONT_SMALL,
            width=32,
            height=24,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.STATUS_CRIMSON,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self._handle_delete_session_click
        )
        self.delete_session_btn.pack(side="left", padx=(0, 6), pady=4)

        if self.session_store is None:
            self.session_bar.grid_remove()

    def _build_chat_feed(self) -> None:
        self.chat_feed = customtkinter.CTkScrollableFrame(
            self,
            fg_color=NexusTheme.BG_OBSIDIAN,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        self.chat_feed.grid(row=2, column=0, sticky="nsew", padx=NexusTheme.PADDING_MD, pady=4)
        self.chat_feed.grid_columnconfigure(0, weight=1)

    def _build_starter_chips_bar(self) -> None:
        """Row holding clickable zero-LLM starter question chips."""
        self.starter_frame = customtkinter.CTkFrame(
            self,
            fg_color="transparent"
        )
        self.starter_frame.grid(
            row=3,
            column=0,
            sticky="ew",
            padx=NexusTheme.PADDING_MD,
            pady=(2, 2)
        )
        self._starter_buttons: List[customtkinter.CTkButton] = []

    def _build_input_bar(self) -> None:
        input_container = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        input_container.grid(
            row=4,
            column=0,
            sticky="ew",
            padx=NexusTheme.PADDING_MD,
            pady=(4, NexusTheme.PADDING_MD)
        )
        input_container.grid_columnconfigure(0, weight=1)

        # Query Entry Field
        self.query_entry = customtkinter.CTkEntry(
            input_container,
            placeholder_text="Ask a question about your database (e.g. 'Show total sales by region')...",
            font=NexusTheme.FONT_BODY,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            text_color=NexusTheme.TEXT_PRIMARY,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER,
            corner_radius=NexusTheme.CORNER_RADIUS_SM
        )
        self.query_entry.grid(row=0, column=0, sticky="ew", padx=(NexusTheme.PADDING_MD, 8), pady=NexusTheme.PADDING_MD)
        self.query_entry.bind("<Return>", lambda event: self.send_user_message())

        # Send Button
        self.send_btn = customtkinter.CTkButton(
            input_container,
            text="Send ➔",
            width=90,
            font=NexusTheme.FONT_BODY_BOLD,
            fg_color=NexusTheme.ACCENT_CYAN,
            hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self.send_user_message
        )
        self.send_btn.grid(row=0, column=1, sticky="e", padx=(0, NexusTheme.PADDING_MD), pady=NexusTheme.PADDING_MD)

    # --------------------------------------------------------------------------
    # OLLAMA HEALTH CHECK
    # --------------------------------------------------------------------------

    def _check_ollama_health_async(self) -> None:
        """Asynchronously pings Ollama without blocking the main UI thread."""
        self.check_health_btn.configure(text="Pinging...", state="disabled")
        self.health_status_label.configure(text="● Checking...", text_color=NexusTheme.ACCENT_CYAN)

        llm_config = self._get_current_llm_config()

        def _ping() -> Any:
            router = self.llm_router_factory(llm_config, self.get_volatile_api_key_fn)
            return router.check_ollama_health()

        def _on_success(health: Any) -> None:
            if not self.winfo_exists():
                return
            self.check_health_btn.configure(text="Ping Ollama", state="normal")
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
                count = len(models)
                self.health_status_label.configure(
                    text=f"● Ollama Online ({count} models)",
                    text_color=NexusTheme.STATUS_EMERALD
                )
                if self.sidebar_panel and hasattr(self.sidebar_panel, "update_local_models") and models:
                    self.sidebar_panel.update_local_models(models)
            else:
                self.health_status_label.configure(
                    text="● Ollama Offline",
                    text_color=NexusTheme.STATUS_AMBER
                )

        def _on_error(exc: Exception) -> None:
            if not self.winfo_exists():
                return
            self.check_health_btn.configure(text="Ping Ollama", state="normal")
            self.health_status_label.configure(
                text="● Ollama Offline",
                text_color=NexusTheme.STATUS_AMBER
            )

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _ping,
                on_success=_on_success,
                on_error=_on_error,
                task_name="CheckOllamaHealth"
            )
        else:
            try:
                res = _ping()
                _on_success(res)
            except Exception as e:
                _on_error(e)

    # --------------------------------------------------------------------------
    # CONFIGURATION & SNAPSHOTTING
    # --------------------------------------------------------------------------

    def _get_current_llm_config(self) -> LLMConfig:
        """Retrieves and normalizes LLMConfig on the main UI thread."""
        if callable(self.get_llm_config_fn):
            raw = self.get_llm_config_fn()
        elif self.sidebar_panel and hasattr(self.sidebar_panel, "get_llm_config"):
            raw = self.sidebar_panel.get_llm_config()
        else:
            raw = {
                "provider": "local",
                "model": "llama3:8b",
                "masked_api_key": "[NONE]",
                "has_api_key": False
            }
        return LLMConfig.from_sidebar_dict(raw)

    # --------------------------------------------------------------------------
    # MESSAGE BUBBLE RENDERING
    # --------------------------------------------------------------------------

    def _post_welcome_bubble(self) -> None:
        self._post_agent_bubble("⚡ NEXUS Core", self.WELCOME_MESSAGE)

    def _post_user_bubble(self, text: str) -> None:
        bubble_frame = customtkinter.CTkFrame(
            self.chat_feed,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.ACCENT_CYAN_MUTED
        )
        bubble_frame.pack(fill="x", padx=(60, 4), pady=6, anchor="e")

        header = customtkinter.CTkLabel(
            bubble_frame,
            text="👤 You",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.ACCENT_CYAN,
            anchor="w"
        )
        header.pack(fill="x", padx=12, pady=(8, 2))

        msg = customtkinter.CTkLabel(
            bubble_frame,
            text=text,
            font=NexusTheme.FONT_BODY,
            text_color=NexusTheme.TEXT_PRIMARY,
            wraplength=620,
            justify="left",
            anchor="w"
        )
        msg.pack(fill="x", padx=12, pady=(2, 10))
        self._scroll_to_bottom()

    def _post_progress_bubble(self, message: str) -> None:
        """Renders temporary progress bubble with status text."""
        self._remove_progress_bubble()
        self._active_progress_frame = customtkinter.CTkFrame(
            self.chat_feed,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        self._active_progress_frame.pack(fill="x", padx=(4, 60), pady=6, anchor="w")

        self._active_progress_label = customtkinter.CTkLabel(
            self._active_progress_frame,
            text=f"⚡ {message}",
            font=NexusTheme.FONT_BODY,
            text_color=NexusTheme.ACCENT_CYAN,
            anchor="w",
            justify="left"
        )
        self._active_progress_label.pack(fill="x", padx=12, pady=10)
        self._scroll_to_bottom()

    def _remove_progress_bubble(self) -> None:
        if self._active_progress_frame and self._active_progress_frame.winfo_exists():
            try:
                self._active_progress_frame.destroy()
            except Exception:
                pass
        self._active_progress_frame = None
        self._active_progress_label = None

    def _on_pipeline_progress(self, message: str) -> None:
        """Worker progress hook updating the live progress bubble."""
        if not self.winfo_exists():
            return
        if self._active_progress_label and self._active_progress_label.winfo_exists():
            self._active_progress_label.configure(text=f"⚡ {message}")

    def _post_agent_bubble(self, title: str, text: str, is_error: bool = False) -> None:
        accent = NexusTheme.STATUS_CRIMSON if is_error else NexusTheme.STATUS_EMERALD

        bubble_frame = customtkinter.CTkFrame(
            self.chat_feed,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        bubble_frame.pack(fill="x", padx=(4, 60), pady=6, anchor="w")

        header = customtkinter.CTkLabel(
            bubble_frame,
            text=title,
            font=NexusTheme.FONT_SMALL,
            text_color=accent,
            anchor="w"
        )
        header.pack(fill="x", padx=12, pady=(8, 2))

        msg = customtkinter.CTkLabel(
            bubble_frame,
            text=text,
            font=NexusTheme.FONT_BODY,
            text_color=NexusTheme.TEXT_PRIMARY,
            wraplength=620,
            justify="left",
            anchor="w"
        )
        msg.pack(fill="x", padx=12, pady=(2, 10))
        self._scroll_to_bottom()

    def _scroll_to_bottom(self) -> None:
        """Auto-scrolls the chat feed to the most recent message."""
        try:
            self.chat_feed._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass

    # --------------------------------------------------------------------------
    # CHAT PIPELINE EXECUTION
    # --------------------------------------------------------------------------

    def send_user_message(self) -> None:
        """Handles sending user query and dispatches the live SQLAgentChain pipeline."""
        user_text = self.query_entry.get().strip()
        if not user_text:
            return

        self._post_user_bubble(user_text)
        self.query_entry.delete(0, "end")
        self.send_btn.configure(state="disabled")

        # Capture configuration snapshot synchronously on main thread
        llm_config = self._get_current_llm_config()
        request_chart_flag = True if self.chart_toggle_var.get() else None

        # Auto-persist user message if session_store is present
        if self.session_store is not None:
            if not self._active_session_id:
                s = self.session_store.create_session("New Session")
                self._active_session_id = s.session_id
            self.session_store.append_message(
                self._active_session_id,
                role="user",
                natural_query=user_text,
                status="SUBMITTED"
            )

        # Capture conversation history snapshot synchronously on main thread (Thread Safety)
        history_snapshot = list(self._conversation_history)

        # Display live progress bubble
        self._post_progress_bubble(f"Synthesizing query via {llm_config.model}...")

        def _execute_pipeline(progress_callback=None) -> Dict[str, Any]:
            router = self.llm_router_factory(llm_config, self.get_volatile_api_key_fn)
            chain = SQLAgentChain(
                db_manager=self.db,
                schema_parser=self.schema_parser,
                llm_router=router
            )
            result: AgentRunResult = chain.run(
                natural_query=user_text,
                request_chart=request_chart_flag,
                progress_callback=progress_callback,
                conversation_history=history_snapshot
            )

            # Safely render Matplotlib figure in worker thread
            figure = None
            if (
                result.status == "SUCCESS"
                and result.chart_spec is not None
                and result.query_result is not None
                and result.query_result.row_count > 0
            ):
                try:
                    figure = ChartEngine.render_figure(result.query_result, result.chart_spec)
                except Exception as chart_err:
                    logger.warning(f"Failed to render chart figure: {chart_err}")
                    figure = None

            return {
                "result": result,
                "figure": figure,
                "user_text": user_text,
                "llm_config": llm_config,
            }

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _execute_pipeline,
                on_success=self._on_pipeline_success,
                on_error=self._on_pipeline_error,
                on_progress=self._on_pipeline_progress,
                task_name="SQLAgentPipeline"
            )
        else:
            try:
                payload = _execute_pipeline()
                self._on_pipeline_success(payload)
            except Exception as exc:
                self._on_pipeline_error(exc)

    def _on_pipeline_success(self, data: Dict[str, Any]) -> None:
        """Main thread callback for successful pipeline completion."""
        if not self.winfo_exists():
            return
        self.send_btn.configure(state="normal")
        self._remove_progress_bubble()

        result: AgentRunResult = data["result"]
        figure: Optional[Figure] = data.get("figure")

        if callable(self.on_query_completed):
            try:
                self.on_query_completed(result)
            except Exception as hook_err:
                logger.warning(f"Error in on_query_completed hook: {hook_err}")

        # Render response bubble per status
        status = result.status
        if self.session_store is not None and self._active_session_id:
            row_cnt = result.query_result.row_count if result.query_result else 0
            self.session_store.append_message(
                self._active_session_id,
                role="assistant",
                natural_query=result.natural_query,
                generated_sql=result.generated_sql,
                answer_markdown=result.answer_markdown,
                status=result.status,
                provider=result.provider,
                model=result.model,
                row_count=row_cnt,
                execution_time_ms=result.total_latency_ms,
                tables_used=result.tables_in_context
            )
            self.refresh_session_list()

        if status == "SUCCESS":
            # Strict Memory Hygiene: only append SUCCESS turns into conversation history
            turn = ConversationTurn(
                natural_query=result.natural_query,
                generated_sql=result.generated_sql,
                answer_summary=result.answer_markdown[:240],
                tables_used=result.tables_in_context
            )
            self._conversation_history.append(turn)
            if len(self._conversation_history) > 10:
                self._conversation_history = self._conversation_history[-10:]

            disp_count = min(len(self._conversation_history), 4)
            if hasattr(self, "memory_status_label") and self.memory_status_label.winfo_exists():
                self.memory_status_label.configure(
                    text=f"Memory: {disp_count}/4 turns",
                    text_color=NexusTheme.ACCENT_CYAN if disp_count > 0 else NexusTheme.TEXT_MUTED
                )

            self._render_success_bubble(result, figure)
        elif status == "SECURITY_BLOCKED":
            self._render_security_blocked_bubble(result)
        elif status == "EMPTY_DB":
            self._render_empty_db_bubble(result)
        else:
            self._render_failed_bubble(result)

        self._scroll_to_bottom()

    def _on_pipeline_error(self, exc: Exception) -> None:
        """Main thread callback for unhandled worker errors."""
        if not self.winfo_exists():
            return
        self.send_btn.configure(state="normal")
        self._remove_progress_bubble()

        err_msg = str(exc)
        logger.error(f"SQLAgentPipeline error: {err_msg}")

        # Remediate offline Ollama gracefully
        if "connection" in err_msg.lower() or "offline" in err_msg.lower():
            err_msg = (
                "Could not connect to Ollama. Ensure Ollama is running "
                "('ollama serve' in PowerShell) or switch to Cloud API in the sidebar."
            )

        failed_result = AgentRunResult(
            natural_query="",
            generated_sql="",
            query_result=None,
            answer_markdown=err_msg,
            status="LLM_ERROR",
            error_message=err_msg
        )
        if self.session_store is not None and self._active_session_id:
            self.session_store.append_message(
                self._active_session_id,
                role="assistant",
                natural_query="",
                generated_sql="",
                answer_markdown=err_msg,
                status="LLM_ERROR"
            )
            self.refresh_session_list()

        self._render_failed_bubble(failed_result)
        self._scroll_to_bottom()

    # --------------------------------------------------------------------------
    # STATUS-AWARE BUBBLE RENDERERS
    # --------------------------------------------------------------------------

    def _render_success_bubble(self, result: AgentRunResult, figure: Optional[Figure]) -> None:
        """Renders rich success card with SQL block, preview table, action buttons, and chart."""
        bubble = customtkinter.CTkFrame(
            self.chat_feed,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        bubble.pack(fill="x", padx=(4, 60), pady=6, anchor="w")

        # 1. Header (Emerald) & Pruning Tag
        row_count = result.query_result.row_count if result.query_result else 0
        provider_tag = f"[{result.provider.upper()}]" if result.provider else ""
        header_text = (
            f"⚡ NEXUS Analyst • {result.model} {provider_tag} • "
            f"{result.total_latency_ms:.1f}ms • {result.total_tokens} tok • {row_count} rows"
        )
        header = customtkinter.CTkLabel(
            bubble,
            text=header_text,
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.STATUS_EMERALD,
            anchor="w"
        )
        header.pack(fill="x", padx=12, pady=(10, 4))

        if result.was_pruned:
            pruned_tag = customtkinter.CTkLabel(
                bubble,
                text=f"⚡ Context Pruned: {len(result.tables_in_context)} tables",
                font=NexusTheme.FONT_SMALL,
                text_color=NexusTheme.ACCENT_CYAN,
                anchor="w"
            )
            pruned_tag.pack(fill="x", padx=12, pady=(0, 4))

        # Row-Cap Warning Badge (if query result was truncated for RAM safety)
        if result.query_result and getattr(result.query_result, "truncated", False):
            row_cap_badge = customtkinter.CTkLabel(
                bubble,
                text=f"⚠️ Results capped at {result.query_result.row_count:,} rows for RAM safety",
                font=NexusTheme.FONT_SMALL,
                text_color=NexusTheme.STATUS_AMBER,
                anchor="w"
            )
            row_cap_badge.pack(fill="x", padx=12, pady=(2, 4))

        # 2. Executive Answer Markdown
        msg = customtkinter.CTkLabel(
            bubble,
            text=result.answer_markdown,
            font=NexusTheme.FONT_BODY,
            text_color=NexusTheme.TEXT_PRIMARY,
            wraplength=640,
            justify="left",
            anchor="w"
        )
        msg.pack(fill="x", padx=12, pady=(2, 8))

        # 3. Generated SQL Block
        if result.generated_sql:
            sql_title = customtkinter.CTkLabel(
                bubble,
                text="Generated SQLite Query:",
                font=NexusTheme.FONT_SMALL,
                text_color=NexusTheme.TEXT_MUTED,
                anchor="w"
            )
            sql_title.pack(fill="x", padx=12, pady=(4, 2))

            sql_lines = result.generated_sql.strip().count("\n") + 1
            box_height = min(120, max(45, sql_lines * 18 + 10))
            sql_box = customtkinter.CTkTextbox(
                bubble,
                font=NexusTheme.FONT_CODE,
                fg_color=NexusTheme.SURFACE_ELEVATED,
                text_color=NexusTheme.ACCENT_CYAN,
                border_width=1,
                border_color=NexusTheme.SURFACE_BORDER,
                corner_radius=NexusTheme.CORNER_RADIUS_SM,
                height=box_height
            )
            sql_box.insert("1.0", result.generated_sql)
            sql_box.configure(state="disabled")
            sql_box.pack(fill="x", padx=12, pady=(2, 8))

        # 4. Compact Data Preview Table (Top 10 rows)
        if result.query_result and result.query_result.row_count > 0:
            preview_count = min(10, result.query_result.row_count)
            preview_title = customtkinter.CTkLabel(
                bubble,
                text=f"Data Preview (Top {preview_count} of {result.query_result.row_count:,} rows):",
                font=NexusTheme.FONT_SMALL,
                text_color=NexusTheme.TEXT_MUTED,
                anchor="w"
            )
            preview_title.pack(fill="x", padx=12, pady=(4, 2))

            table_text = format_ascii_table(
                result.query_result.columns,
                result.query_result.rows,
                max_rows=10,
                truncated=result.query_result.truncated
            )
            table_lines = table_text.strip().count("\n") + 1
            table_height = min(180, max(50, table_lines * 18 + 10))

            table_box = customtkinter.CTkTextbox(
                bubble,
                font=NexusTheme.FONT_CODE,
                fg_color=NexusTheme.SURFACE_ELEVATED,
                text_color=NexusTheme.TEXT_PRIMARY,
                border_width=1,
                border_color=NexusTheme.SURFACE_BORDER,
                corner_radius=NexusTheme.CORNER_RADIUS_SM,
                height=table_height
            )
            table_box.insert("1.0", table_text)
            table_box.configure(state="disabled")
            table_box.pack(fill="x", padx=12, pady=(2, 8))

        # 5. Action Row Buttons
        actions_frame = customtkinter.CTkFrame(bubble, fg_color="transparent")
        actions_frame.pack(fill="x", padx=12, pady=(4, 8))

        open_btn = customtkinter.CTkButton(
            actions_frame,
            text="🔍 Open in Data Explorer",
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=lambda sql=result.generated_sql: self._handle_open_in_explorer(sql)
        )
        open_btn.pack(side="left", padx=(0, 8))

        copy_btn = customtkinter.CTkButton(
            actions_frame,
            text="📋 Copy SQL",
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=lambda sql=result.generated_sql, b=actions_frame: self._copy_sql_to_clipboard(sql)
        )
        copy_btn.pack(side="left", padx=(0, 8))

        export_csv_btn = customtkinter.CTkButton(
            actions_frame,
            text="📊 Export CSV",
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            state="normal" if (result.query_result and result.query_result.row_count > 0) else "disabled",
            command=lambda r=result: self._handle_chat_export_csv(r)
        )
        export_csv_btn.pack(side="left", padx=(0, 8))

        export_brief_btn = customtkinter.CTkButton(
            actions_frame,
            text="📑 Export Brief",
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=lambda r=result, fig=figure: self._handle_chat_export_brief(r, fig)
        )
        export_brief_btn.pack(side="left")

        actions_frame.export_csv_btn = export_csv_btn
        actions_frame.export_brief_btn = export_brief_btn
        self.export_csv_btn = export_csv_btn
        self.export_brief_btn = export_brief_btn

        # 6. Embedded Matplotlib Dark Chart Card
        if figure is not None:
            self._render_embedded_chart(bubble, figure)

    def _render_embedded_chart(self, parent_frame: customtkinter.CTkFrame, figure: Figure) -> None:
        """Embeds a dark-theme Matplotlib figure canvas with a Save PNG button."""
        chart_card = customtkinter.CTkFrame(
            parent_frame,
            fg_color=NexusTheme.BG_OBSIDIAN,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        chart_card.pack(fill="both", expand=True, padx=12, pady=(6, 10))

        # Track active figure for deterministic cleanup
        self._embedded_figures.append(figure)

        # Mount FigureCanvasTkAgg strictly on the main UI thread
        canvas = FigureCanvasTkAgg(figure, master=chart_card)
        canvas.draw()
        canvas_widget = canvas.get_tk_widget()
        canvas_widget.configure(bg=NexusTheme.BG_OBSIDIAN, highlightthickness=0)
        canvas_widget.pack(fill="both", expand=True, padx=8, pady=(8, 4))

        # Action footer inside chart card
        chart_footer = customtkinter.CTkFrame(chart_card, fg_color="transparent")
        chart_footer.pack(fill="x", padx=8, pady=(2, 6))

        save_btn = customtkinter.CTkButton(
            chart_footer,
            text="💾 Save PNG",
            width=90,
            height=24,
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=lambda fig=figure: self._save_chart_png(fig)
        )
        save_btn.pack(side="right")

    def _save_chart_png(self, figure: Figure) -> None:
        """Prompts user to save the Matplotlib chart to a local PNG file."""
        try:
            path = filedialog.asksaveasfilename(
                title="Save Chart as PNG",
                defaultextension=".png",
                filetypes=[("PNG Image", "*.png"), ("All Files", "*.*")]
            )
            if path:
                ChartEngine.save_figure(figure, path)
                logger.info(f"Chart successfully saved to {path}")
        except Exception as exc:
            logger.error(f"Failed to save chart PNG: {exc}")

    def _handle_chat_export_csv(self, result: AgentRunResult) -> None:
        """Prompts for save path and asynchronously exports query result to CSV."""
        if not result.query_result or result.query_result.row_count == 0:
            return
        file_path = filedialog.asksaveasfilename(
            title="Export Query Result as CSV",
            defaultextension=".csv",
            filetypes=[("CSV File", "*.csv"), ("All Files", "*.*")]
        )
        if not file_path:
            return
        self.export_result_csv(result, file_path)

    def _handle_chat_export_brief(self, result: AgentRunResult, figure: Optional[Any] = None) -> None:
        """Prompts for save path and asynchronously exports executive brief."""
        file_path = filedialog.asksaveasfilename(
            title="Export Executive Brief",
            defaultextension=".html",
            filetypes=[("Executive HTML Brief", "*.html"), ("Markdown Brief", "*.md"), ("All Files", "*.*")]
        )
        if not file_path:
            return
        self.export_executive_brief(result, file_path, figure=figure)

    def export_result_csv(
        self,
        result: AgentRunResult,
        output_path: Union[str, Path],
        on_complete: Optional[Callable[[Path], None]] = None
    ) -> None:
        """
        Exports the agent run result's query data to CSV.
        Runs asynchronously if an AsyncWorkerManager is available, otherwise synchronously.
        """
        if result.query_result is None:
            raise ValueError("Cannot export CSV: AgentRunResult has no query_result")

        path_obj = Path(output_path)
        cols = list(result.query_result.columns)
        rows = list(result.query_result.rows)

        def _worker_task() -> Path:
            return DataExportEngine.export_csv(cols, rows, path_obj)

        def _on_success(exported_path: Path) -> None:
            logger.info(f"Chat result successfully exported to CSV: {exported_path}")
            if callable(on_complete):
                try:
                    on_complete(exported_path)
                except Exception as e:
                    logger.warning(f"Error in on_complete callback: {e}")

        def _on_error(exc: Exception) -> None:
            logger.error(f"Failed to export chat result to CSV: {exc}")

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _worker_task,
                on_success=_on_success,
                on_error=_on_error,
                task_name="ChatExportCSV"
            )
        else:
            try:
                res_path = _worker_task()
                _on_success(res_path)
            except Exception as exc:
                _on_error(exc)
                raise

    def export_executive_brief(
        self,
        result: AgentRunResult,
        output_path: Union[str, Path],
        figure: Optional[Any] = None,
        on_complete: Optional[Callable[[Path], None]] = None
    ) -> None:
        """
        Exports an executive brief (HTML or Markdown) of the conversation turn.
        Runs asynchronously if an AsyncWorkerManager is available, otherwise synchronously.
        """
        path_obj = Path(output_path)
        ext = path_obj.suffix.lower()

        def _worker_task() -> Path:
            if ext in (".html", ".htm"):
                return ExecutiveBriefExporter.export_html(result, path_obj, figure=figure)
            else:
                return ExecutiveBriefExporter.export_markdown(result, path_obj)

        def _on_success(exported_path: Path) -> None:
            logger.info(f"Executive brief successfully exported: {exported_path}")
            if callable(on_complete):
                try:
                    on_complete(exported_path)
                except Exception as e:
                    logger.warning(f"Error in on_complete callback: {e}")

        def _on_error(exc: Exception) -> None:
            logger.error(f"Failed to export executive brief: {exc}")

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _worker_task,
                on_success=_on_success,
                on_error=_on_error,
                task_name="ChatExportBrief"
            )
        else:
            try:
                res_path = _worker_task()
                _on_success(res_path)
            except Exception as exc:
                _on_error(exc)
                raise

    def _handle_open_in_explorer(self, sql: str) -> None:
        """Navigates to Data Explorer tab and loads the generated SQL."""
        if callable(self.on_open_sql_in_explorer):
            self.on_open_sql_in_explorer(sql)

    def _copy_sql_to_clipboard(self, sql: str) -> None:
        """Copies the SQL query to the clipboard."""
        try:
            self.clipboard_clear()
            self.clipboard_append(sql)
            self.update()
        except Exception as exc:
            logger.warning(f"Could not copy SQL to clipboard: {exc}")

    def _render_security_blocked_bubble(self, result: AgentRunResult) -> None:
        """Renders prominent Crimson Security Intercept Card."""
        bubble = customtkinter.CTkFrame(
            self.chat_feed,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.STATUS_CRIMSON
        )
        bubble.pack(fill="x", padx=(4, 60), pady=6, anchor="w")

        header = customtkinter.CTkLabel(
            bubble,
            text="🛡️ SECURITY BLOCKED BY QUERYGUARD",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.STATUS_CRIMSON,
            anchor="w"
        )
        header.pack(fill="x", padx=12, pady=(10, 4))

        explanation = (
            "The synthesized SQL query was intercepted and blocked before execution. "
            "Modifying statements (DROP, INSERT, UPDATE, DELETE, ALTER, PRAGMA) are strictly prohibited."
        )
        if result.error_message:
            explanation += f"\n\nViolation Reason: {result.error_message}"

        msg = customtkinter.CTkLabel(
            bubble,
            text=explanation,
            font=NexusTheme.FONT_BODY,
            text_color=NexusTheme.TEXT_PRIMARY,
            wraplength=640,
            justify="left",
            anchor="w"
        )
        msg.pack(fill="x", padx=12, pady=(2, 6))

        if result.generated_sql:
            sql_box = customtkinter.CTkTextbox(
                bubble,
                font=NexusTheme.FONT_CODE,
                fg_color=NexusTheme.SURFACE_ELEVATED,
                text_color=NexusTheme.STATUS_CRIMSON,
                border_width=1,
                border_color=NexusTheme.STATUS_CRIMSON,
                corner_radius=NexusTheme.CORNER_RADIUS_SM,
                height=50
            )
            sql_box.insert("1.0", result.generated_sql)
            sql_box.configure(state="disabled")
            sql_box.pack(fill="x", padx=12, pady=(2, 10))

    def _render_empty_db_bubble(self, result: AgentRunResult) -> None:
        """Renders amber guidance card prompting dataset ingestion."""
        bubble = customtkinter.CTkFrame(
            self.chat_feed,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.STATUS_AMBER
        )
        bubble.pack(fill="x", padx=(4, 60), pady=6, anchor="w")

        header = customtkinter.CTkLabel(
            bubble,
            text="⚠️ Workspace Database Empty",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.STATUS_AMBER,
            anchor="w"
        )
        header.pack(fill="x", padx=12, pady=(10, 4))

        msg = customtkinter.CTkLabel(
            bubble,
            text=result.answer_markdown,
            font=NexusTheme.FONT_BODY,
            text_color=NexusTheme.TEXT_PRIMARY,
            wraplength=640,
            justify="left",
            anchor="w"
        )
        msg.pack(fill="x", padx=12, pady=(2, 10))

    def _render_failed_bubble(self, result: AgentRunResult) -> None:
        """Renders diagnostic card for SQL execution or LLM transport errors."""
        bubble = customtkinter.CTkFrame(
            self.chat_feed,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.STATUS_AMBER
        )
        bubble.pack(fill="x", padx=(4, 60), pady=6, anchor="w")

        header = customtkinter.CTkLabel(
            bubble,
            text=f"⚠️ Query Execution Diagnostic [{result.status}]",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.STATUS_AMBER,
            anchor="w"
        )
        header.pack(fill="x", padx=12, pady=(10, 4))

        raw_body = result.answer_markdown or result.error_message or "Query execution failed."

        # Clean literal markdown asterisks from CTkLabel diagnostic bubbles
        cleaned_body = re.sub(r"\*\*AI Provider Error\*\*:\s*", "AI Provider Error: ", raw_body)
        cleaned_body = re.sub(r"\*\*(.*?)\*\*", r"\1", cleaned_body)

        lower_body = cleaned_body.lower()
        # Actionable guidance for HTTP 404 / Model not found
        if "404" in lower_body or "not found" in lower_body:
            cleaned_body += (
                "\n\n💡 Actionable Step: Model is not installed in Ollama. "
                "Select an installed model from the sidebar or run: ollama pull <model>"
            )
        # Actionable guidance for offline Ollama
        elif "connection" in lower_body or "offline" in lower_body:
            cleaned_body += (
                "\n\n💡 Actionable Step: Start Ollama with 'ollama serve' in PowerShell, "
                "or switch to Cloud API in the sidebar."
            )

        msg = customtkinter.CTkLabel(
            bubble,
            text=cleaned_body,
            font=NexusTheme.FONT_BODY,
            text_color=NexusTheme.TEXT_PRIMARY,
            wraplength=640,
            justify="left",
            anchor="w"
        )
        msg.pack(fill="x", padx=12, pady=(2, 10))

    # --------------------------------------------------------------------------
    # FORMATTING UTILITIES
    # --------------------------------------------------------------------------

    def _format_preview_table(self, qr: QueryResult, limit: int = 10) -> str:
        """Formats QueryResult into a clean monospace text grid preview."""
        if not qr.columns or not qr.rows:
            return "(No data rows returned)"
        return format_ascii_table(
            columns=qr.columns,
            rows=qr.rows,
            max_rows=limit,
            truncated=getattr(qr, "truncated", False)
        )

    # --------------------------------------------------------------------------
    # MULTI-TURN MEMORY & STARTER QUESTION CONTROLS (U2 & U2.5)
    # --------------------------------------------------------------------------

    def clear_conversation(self) -> None:
        """
        Public method to clear conversation memory and reset chat UI:
        - If session_store is attached and current session already has messages, starts a clean
          new session non-destructively so past saved sessions remain intact in the dropdown.
        - Otherwise, clears conversation memory, active figures, and resets feed to welcome card.
        """
        if self.session_store is not None and self._active_session_id:
            msgs = self.session_store.get_messages(self._active_session_id, limit=1)
            if msgs:
                self.start_new_session("New Session")
                return

        self._conversation_history.clear()

        # Deterministic cleanup of active figures (prevents GDI resource leaks)
        for fig in self._embedded_figures:
            try:
                fig.clear()
            except Exception:
                pass
        self._embedded_figures.clear()

        # Remove dynamic chat bubbles from scroll feed
        for child in self.chat_feed.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass

        # Reset memory status pill
        if hasattr(self, "memory_status_label") and self.memory_status_label.winfo_exists():
            self.memory_status_label.configure(
                text="Memory: 0/4 turns",
                text_color=NexusTheme.TEXT_MUTED
            )

        # Re-render welcome card
        self._post_welcome_bubble()

        # Refresh starter question chips
        self.refresh_starter_questions()

    # --------------------------------------------------------------------------
    # MULTI-SESSION PERSISTENCE & RESTORATION (U4)
    # --------------------------------------------------------------------------

    def _initialize_sessions(self) -> None:
        """Initializes multi-session state from session store."""
        if self.session_store is None:
            return
        sessions = self.session_store.list_sessions(limit=50)
        if sessions:
            self.load_session(sessions[0].session_id)
        else:
            new_sess = self.session_store.create_session("New Session")
            self.load_session(new_sess.session_id)

    def refresh_session_list(self) -> None:
        """Refreshes the session selector dropdown with current sessions."""
        if self.session_store is None:
            return
        sessions = self.session_store.list_sessions(limit=50)
        self._session_label_to_id.clear()
        labels: List[str] = []
        for s in sessions:
            base_label = f"{s.title} ({s.message_count} msgs)"
            label = base_label
            if label in self._session_label_to_id:
                label = f"{s.title} ({s.message_count} msgs) #{s.session_id[:4]}"
            self._session_label_to_id[label] = s.session_id
            labels.append(label)

        if not labels:
            labels = ["New Session"]

        if hasattr(self, "session_selector") and self.session_selector.winfo_exists():
            self.session_selector.configure(values=labels)
            if self._active_session_id:
                matching = [lbl for lbl, sid in self._session_label_to_id.items() if sid == self._active_session_id]
                if matching:
                    self.session_selector.set(matching[0])
                elif labels:
                    self.session_selector.set(labels[0])

    def _on_session_dropdown_selected(self, chosen_label: str) -> None:
        """Handles session dropdown selection change."""
        sess_id = self._session_label_to_id.get(chosen_label)
        if sess_id and sess_id != self._active_session_id:
            self.load_session(sess_id)

    def load_session(self, session_id: str) -> None:
        """
        Loads and renders a session:
        - Clears embedded figures (prevents GDI leaks)
        - Clears message feed
        - Sets active session ID
        - Restores chat bubbles
        - Restores verified SUCCESS memory turns into self._conversation_history
        - Syncs dropdown and starter chips
        """
        # Clear embedded figures
        for fig in self._embedded_figures:
            try:
                fig.clear()
            except Exception:
                pass
        self._embedded_figures.clear()

        # Clear existing dynamic chat bubbles
        for child in self.chat_feed.winfo_children():
            try:
                child.destroy()
            except Exception:
                pass

        self._active_session_id = session_id

        if self.session_store is not None:
            messages = self.session_store.get_messages(session_id)
            if not messages:
                self._post_welcome_bubble()
            else:
                for m in messages:
                    if m.role == "user":
                        self._post_user_bubble(m.natural_query or "")
                    else:
                        res = AgentRunResult(
                            natural_query=m.natural_query or "",
                            generated_sql=m.generated_sql or "",
                            answer_markdown=m.answer_markdown or "",
                            status=m.status,
                            provider=m.provider or "",
                            model=m.model or "",
                            query_result=QueryResult(
                                columns=[],
                                rows=[],
                                row_count=m.row_count,
                                execution_time_ms=m.execution_time_ms,
                                sql=m.generated_sql or ""
                            ),
                            total_latency_ms=m.execution_time_ms,
                            tables_in_context=m.tables_used
                        )
                        if m.status == "SUCCESS":
                            self._render_success_bubble(res, figure=None)
                        elif m.status == "SECURITY_BLOCKED":
                            self._render_security_blocked_bubble(res)
                        elif m.status == "EMPTY_DB":
                            self._render_empty_db_bubble(res)
                        else:
                            self._render_failed_bubble(res)

            # Strict Memory Hygiene: only SUCCESS turns enter _conversation_history
            self._conversation_history = list(self.session_store.load_conversation_turns(session_id, limit=4))
            disp_count = min(len(self._conversation_history), 4)
            if hasattr(self, "memory_status_label") and self.memory_status_label.winfo_exists():
                self.memory_status_label.configure(
                    text=f"Memory: {disp_count}/4 turns",
                    text_color=NexusTheme.ACCENT_CYAN if disp_count > 0 else NexusTheme.TEXT_MUTED
                )
            self.refresh_session_list()
        else:
            self._post_welcome_bubble()

        self.refresh_starter_questions()
        self._scroll_to_bottom()

    def start_new_session(self, title: str = "New Session") -> Optional[str]:
        """Creates a new session in session store and loads it."""
        if self.session_store is None:
            self.clear_conversation()
            return None
        sess = self.session_store.create_session(title=title)
        self.load_session(sess.session_id)
        return sess.session_id

    def rename_active_session(self, new_title: str) -> bool:
        """Renames the active session in session store and refreshes selector."""
        if self.session_store is None or not self._active_session_id:
            return False
        ok = self.session_store.rename_session(self._active_session_id, new_title)
        if ok:
            self.refresh_session_list()
        return ok

    def _handle_rename_session_click(self) -> None:
        """Opens CTkInputDialog to prompt user for a new session title."""
        dialog = customtkinter.CTkInputDialog(
            text="Enter new session title:",
            title="Rename Session"
        )
        new_title = dialog.get_input()
        if new_title and new_title.strip():
            self.rename_active_session(new_title.strip())

    def delete_active_session(self) -> bool:
        """Deletes active session and cascades associated messages."""
        if self.session_store is None or not self._active_session_id:
            return False
        target_id = self._active_session_id
        ok = self.session_store.delete_session(target_id)
        if not ok:
            return False
        remaining = self.session_store.list_sessions(limit=50)
        if remaining:
            self.load_session(remaining[0].session_id)
        else:
            new_sess = self.session_store.create_session("New Session")
            self.load_session(new_sess.session_id)
        return True

    def _handle_delete_session_click(self) -> None:
        """Prompts confirmation dialog before deleting active session."""
        from tkinter import messagebox
        confirmed = messagebox.askyesno(
            title="Confirm Delete Session",
            message="Are you sure you want to permanently delete this chat session?\nAll associated messages will be deleted."
        )
        if confirmed:
            self.delete_active_session()

    def refresh_starter_questions(self) -> None:
        """
        Asynchronously queries schema to generate up to 3 starter questions
        with zero GUI thread blocking.
        """
        def _fetch_questions() -> List[str]:
            return generate_starter_questions(self.schema_parser, max_questions=3)

        def _on_success(questions: List[str]) -> None:
            if not self.winfo_exists():
                return
            self.set_starter_questions(questions)

        def _on_error(exc: Exception) -> None:
            logger.debug(f"Failed to generate starter questions: {exc}")
            if self.winfo_exists():
                self.set_starter_questions([])

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _fetch_questions,
                on_success=_on_success,
                on_error=_on_error,
                task_name="GenerateStarterQuestions"
            )
        else:
            try:
                qs = _fetch_questions()
                _on_success(qs)
            except Exception as e:
                _on_error(e)

    def set_starter_questions(self, questions: List[str]) -> None:
        """
        Renders up to 3 concise, clickable starter question chips.
        If questions is empty, hides starter_frame.
        """
        if not self.winfo_exists():
            return

        for btn in self._starter_buttons:
            try:
                btn.destroy()
            except Exception:
                pass
        self._starter_buttons.clear()

        clean_questions = [q.strip() for q in questions if q and q.strip()][:3]
        if not clean_questions:
            self.starter_frame.grid_remove()
            return

        self.starter_frame.grid()
        for q in clean_questions:
            btn = customtkinter.CTkButton(
                self.starter_frame,
                text=f"💡 {q}",
                font=NexusTheme.FONT_SMALL,
                fg_color=NexusTheme.SURFACE_SLATE,
                hover_color=NexusTheme.ACCENT_CYAN_MUTED,
                text_color=NexusTheme.ACCENT_CYAN,
                border_width=1,
                border_color=NexusTheme.SURFACE_BORDER,
                corner_radius=NexusTheme.CORNER_RADIUS_SM,
                height=26,
                command=lambda prompt=q: self._handle_starter_click(prompt)
            )
            btn.pack(side="left", padx=(0, 8), pady=2)
            self._starter_buttons.append(btn)

    def _handle_starter_click(self, prompt: str) -> None:
        """Populates query entry and immediately sends the query."""
        self.query_entry.delete(0, "end")
        self.query_entry.insert(0, prompt)
        self.send_user_message()

    # --------------------------------------------------------------------------
    # SCHEMA CONTEXT CLIPBOARD UTILITY
    # --------------------------------------------------------------------------

    def copy_schema_context_to_clipboard(self) -> None:
        """Asynchronously compiles schema markdown and copies it to Windows clipboard."""
        self.copy_schema_btn.configure(text="Generating...", state="disabled")

        def _generate_markdown() -> str:
            return self.schema_parser.generate_markdown(include_samples=False)

        def _on_success(markdown_str: str) -> None:
            if not self.winfo_exists():
                return
            self.copy_schema_btn.configure(text="✓ Copied!", state="normal")
            try:
                self.clipboard_clear()
                self.clipboard_append(markdown_str)
                self.update()
            except Exception as exc:
                logger.warning(f"Could not write to clipboard: {exc}")

            self.after(2000, lambda: self._reset_copy_btn())

        def _on_error(exc: Exception) -> None:
            if not self.winfo_exists():
                return
            self.copy_schema_btn.configure(text="Failed to Copy", state="normal")
            logger.error(f"Markdown generation failed: {exc}")
            self.after(2000, lambda: self._reset_copy_btn())

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _generate_markdown,
                on_success=_on_success,
                on_error=_on_error,
                task_name="GenerateSchemaMarkdown"
            )
        else:
            try:
                md = _generate_markdown()
                _on_success(md)
            except Exception as exc:
                _on_error(exc)

    def _reset_copy_btn(self) -> None:
        if self.winfo_exists():
            self.copy_schema_btn.configure(text="📋 Copy Schema")

    # --------------------------------------------------------------------------
    # BADGE SYNCING
    # --------------------------------------------------------------------------

    def update_provider_badge(self, config: Dict[str, Any]) -> None:
        """Public method to update the active LLM provider/model badge."""
        if not self.winfo_exists():
            return
        provider = config.get("provider") or config.get("provider_name") or ("cloud" if config.get("mode") == "cloud" else "local")
        provider_str = str(provider).upper()
        model = config.get("model") or config.get("selected_model") or "llama3:8b"
        masked_key = config.get("masked_api_key") or config.get("masked_key") or "[NONE]"
        self.llm_badge.configure(
            text=f"AI Engine: {model} [{provider_str}] | Key: {masked_key}"
        )

    def update_llm_badge(self, config: Dict[str, Any]) -> None:
        """Public alias to sync badge with Sidebar changes."""
        self.update_provider_badge(config)

    # --------------------------------------------------------------------------
    # DETERMINISTIC CLEANUP
    # --------------------------------------------------------------------------

    def destroy(self) -> None:
        """Deterministic cleanup: clears all active Matplotlib figures before destruction."""
        for fig in self._embedded_figures:
            try:
                fig.clear()
            except Exception:
                pass
        self._embedded_figures.clear()
        super().destroy()
