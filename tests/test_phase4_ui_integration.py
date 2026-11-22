"""
NEXUS Engine - Phase 4 GUI & Agent Pipeline Integration Test Suite
==================================================================
End-to-end headless GUI integration tests validating:
1. End-to-end chat query -> SQLAgentChain -> SQL card + rows + executive answer.
2. Declarative Charting query -> Embedded Matplotlib FigureCanvasTkAgg widget + Figure tracking + cleanup.
3. 'Open in Data Explorer' -> Tab switch -> Scratchpad populate -> Guarded execution.
4. Adversarial LLM mutation (DROP TABLE) -> Crimson Security Block card -> 0 mutations -> REJECTED audit.
5. Offline Ollama (LLMConnectionError) -> Graceful actionable guidance -> UI recovery.
6. Cloud API key propagation -> Volatile memory transport -> Zero raw key leakage.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import customtkinter
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.chart_engine import ChartEngine, ChartSpec
from src.agent.llm_router import (
    LLMConfig,
    LLMConnectionError,
    LLMResponse,
    LLMRouter,
    LLMRouterError,
)
from src.agent.sql_chain import AgentRunResult, SQLAgentChain
from src.core.db_manager import DatabaseManager
from src.core.schema_parser import SchemaParser
from src.ui.app import NexusApp
from src.ui.async_worker import AsyncWorkerManager
from src.ui.components.chat_tab import ChatAnalystTab
from src.ui.components.data_explorer_tab import DataExplorerTab
from src.ui.components.sidebar import SidebarPanel


class TestPhase4UIIntegration(unittest.TestCase):
    """Rigorous end-to-end integration tests for Phase 4 GUI, Agent, and Charting."""

    @classmethod
    def setUpClass(cls):
        # Create hidden root window for CTk widget instantiation in headless test run
        cls.root = customtkinter.CTk()
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.root.destroy()
        except Exception:
            pass

    def setUp(self):
        DatabaseManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_phase4.db"
        self.db = DatabaseManager(self.db_path)
        self.parser = SchemaParser(self.db)
        self.worker = AsyncWorkerManager(max_workers=2)

        # Seed sample business tables
        self.db.execute_write("""
            CREATE TABLE customers (
                customer_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                region TEXT NOT NULL,
                revenue REAL DEFAULT 0.0
            );
        """)
        self.db.execute_write("""
            INSERT INTO customers (name, region, revenue) VALUES
                ('Nexus Labs', 'North America', 25000.0),
                ('Cyber Dyne', 'Europe', 18500.0),
                ('Omni Corp', 'Asia Pacific', 32000.0),
                ('Bio Synth', 'North America', 12000.0);
        """)

    def tearDown(self):
        self.worker.shutdown(wait=True)
        self.db.close()
        DatabaseManager.reset_instance()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # --------------------------------------------------------------------------
    # 1. END-TO-END TEXT-TO-SQL CHAT PIPELINE
    # --------------------------------------------------------------------------

    def test_end_to_end_chat_query_rendering(self):
        """
        Validates:
        User asks natural language question -> SQLAgentChain generates SQL ->
        Query executes -> ChatAnalystTab renders SQL card, preview table, and answer.
        """
        def mock_factory(cfg, key_fn):
            mock_router = MagicMock(spec=LLMRouter)
            mock_router.config = cfg
            # Step 1: SQL response
            mock_router.invoke.return_value = LLMResponse(
                content="```sql\nSELECT name, revenue FROM customers ORDER BY revenue DESC;\n```",
                provider="local",
                model=cfg.model,
                prompt_tokens=80,
                completion_tokens=20,
                total_tokens=100,
                latency_ms=85.0
            )
            # Step 2: Insight response
            mock_router.generate.return_value = LLMResponse(
                content="Total of 4 customers retrieved. Omni Corp leads with $32,000 in revenue.",
                provider="local",
                model=cfg.model,
                prompt_tokens=60,
                completion_tokens=25,
                total_tokens=85,
                latency_ms=50.0
            )
            return mock_router

        completed_results: List[AgentRunResult] = []

        chat = ChatAnalystTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            on_query_completed=lambda res: completed_results.append(res),
            llm_router_factory=mock_factory
        )

        chat.query_entry.insert(0, "Who are our top customers by revenue?")
        chat.send_user_message()

        # Let background worker execute pipeline
        for _ in range(50):
            self.worker.process_queue()
            if len(completed_results) > 0:
                break
            time.sleep(0.05)

        # Verify on_query_completed hook fired
        self.assertEqual(len(completed_results), 1)
        res = completed_results[0]
        self.assertEqual(res.status, "SUCCESS")
        self.assertEqual(res.query_result.row_count, 4)

        # Verify chat feed contains the success bubble
        bubbles = chat.chat_feed.winfo_children()
        agent_bubble = bubbles[-1]

        # Inspect CTkLabels inside the agent bubble
        labels = [c for c in agent_bubble.winfo_children() if isinstance(c, customtkinter.CTkLabel)]
        label_texts = " ".join(lbl.cget("text") for lbl in labels)
        self.assertIn("NEXUS Analyst", label_texts)
        self.assertIn("Omni Corp leads with $32,000", label_texts)
        self.assertIn("4 rows", label_texts)

        # Inspect textboxes (SQL block and preview table)
        textboxes = [c for c in agent_bubble.winfo_children() if isinstance(c, customtkinter.CTkTextbox)]
        self.assertGreaterEqual(len(textboxes), 2)  # SQL box + Table preview box
        combined_tb_text = " ".join(tb.get("1.0", "end") for tb in textboxes)
        self.assertIn("SELECT name, revenue FROM customers", combined_tb_text)
        self.assertIn("Omni Corp", combined_tb_text)

        chat.destroy()

    # --------------------------------------------------------------------------
    # 2. EMBEDDED MATPLOTLIB CHARTING & FIGURE CLEANUP
    # --------------------------------------------------------------------------

    def test_declarative_chart_query_and_figure_tracking(self):
        """
        Validates:
        User requests chart -> SQLAgentChain synthesizes ChartSpec ->
        Matplotlib Figure is rendered and mounted via FigureCanvasTkAgg inside
        chat bubble -> Figure is tracked in chat._embedded_figures ->
        chat.destroy() cleanly frees figure.
        """
        def mock_chart_factory(cfg, key_fn):
            mock_router = MagicMock(spec=LLMRouter)
            mock_router.config = cfg
            mock_router.invoke.return_value = LLMResponse(
                content="```sql\nSELECT name, revenue FROM customers;\n```",
                provider="local",
                model=cfg.model,
                prompt_tokens=70,
                completion_tokens=15,
                total_tokens=85,
                latency_ms=60.0
            )
            # Step 2: Insight response
            insight_resp = LLMResponse(
                content="Revenue breakdown across customers.",
                provider="local",
                model=cfg.model,
                prompt_tokens=50,
                completion_tokens=10,
                total_tokens=60,
                latency_ms=40.0
            )
            # Step 3: ChartSpec JSON response
            chart_resp = LLMResponse(
                content=json.dumps({
                    "chart_type": "bar",
                    "x_column": "name",
                    "y_column": "revenue",
                    "title": "Customer Revenue Breakdown",
                    "top_n": 10
                }),
                provider="local",
                model=cfg.model,
                prompt_tokens=80,
                completion_tokens=30,
                total_tokens=110,
                latency_ms=50.0
            )
            mock_router.generate.side_effect = [insight_resp, chart_resp]
            return mock_router

        chat = ChatAnalystTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            llm_router_factory=mock_chart_factory
        )

        # Trigger chart query with chart intent keyword
        chat.query_entry.insert(0, "Plot revenue by customer as a bar chart")
        chat.send_user_message()

        for _ in range(50):
            self.worker.process_queue()
            if len(chat._embedded_figures) > 0:
                break
            time.sleep(0.05)

        # Verify active figure is tracked in chat._embedded_figures
        self.assertEqual(len(chat._embedded_figures), 1)
        tracked_fig = chat._embedded_figures[0]
        self.assertIsNotNone(tracked_fig)

        # Verify canvas widget was mounted inside the bubble
        bubbles = chat.chat_feed.winfo_children()
        agent_bubble = bubbles[-1]
        all_children = agent_bubble.winfo_children()

        # Find the chart card container frame (contains the Save PNG button)
        save_buttons = [
            b for c in all_children if isinstance(c, customtkinter.CTkFrame)
            for footer in c.winfo_children() if isinstance(footer, customtkinter.CTkFrame)
            for b in footer.winfo_children() if isinstance(b, customtkinter.CTkButton) and "Save PNG" in b.cget("text")
        ]
        self.assertTrue(len(save_buttons) > 0)

        # Test deterministic cleanup on destroy()
        chat.destroy()
        self.assertEqual(len(chat._embedded_figures), 0)

    # --------------------------------------------------------------------------
    # 3. INTER-TAB NAVIGATION: OPEN IN DATA EXPLORER
    # --------------------------------------------------------------------------

    def test_open_sql_in_data_explorer_integration(self):
        """
        Validates:
        NexusApp receives _handle_open_sql_in_explorer -> switches tabview to
        'Data Explorer' -> populates scratchpad -> executes guarded query.
        """
        app = NexusApp(
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker
        )
        app.withdraw()

        target_sql = "SELECT name, region FROM customers WHERE revenue > 20000;"

        # Simulate clicking 'Open in Data Explorer' from chat tab
        app._handle_open_sql_in_explorer(target_sql)

        # Verify tabview switched to 'Data Explorer'
        self.assertEqual(app.tabview.get(), "Data Explorer")

        # Verify SQL editor was populated
        editor_text = app.data_explorer_tab.sql_textbox.get("1.0", "end-1c").strip()
        self.assertEqual(editor_text, target_sql)

        # Allow worker to execute query in DataExplorerTab
        for _ in range(50):
            app.worker.process_queue()
            if "Nexus Labs" in app.data_explorer_tab.results_textbox.get("1.0", "end"):
                break
            time.sleep(0.05)

        # Verify results were rendered in DataExplorerTab results viewer
        results_content = app.data_explorer_tab.results_textbox.get("1.0", "end")
        self.assertIn("Nexus Labs", results_content)
        self.assertIn("Omni Corp", results_content)
        self.assertNotIn("Bio Synth", results_content)  # Revenue < 20000

        app.destroy()

    # --------------------------------------------------------------------------
    # 4. ADVERSARIAL QUERY INTERCEPTION & AUDIT PERSISTENCE
    # --------------------------------------------------------------------------

    def test_adversarial_mutation_blocked_with_crimson_card(self):
        """
        Validates:
        Adversarial LLM generates DROP TABLE -> QueryGuard raises SecurityException ->
        Zero retries -> Crimson SECURITY BLOCKED card rendered -> Table remains intact ->
        _nexus_query_audit logs REJECTED.
        """
        def mock_adversarial_factory(cfg, key_fn):
            mock_router = MagicMock(spec=LLMRouter)
            mock_router.config = cfg
            mock_router.invoke.return_value = LLMResponse(
                content="```sql\nDROP TABLE customers;\n```",
                provider="local",
                model=cfg.model,
                prompt_tokens=50,
                completion_tokens=10,
                total_tokens=60,
                latency_ms=40.0
            )
            return mock_router

        chat = ChatAnalystTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            llm_router_factory=mock_adversarial_factory
        )

        chat.query_entry.insert(0, "Drop the customers table")
        chat.send_user_message()

        for _ in range(50):
            self.worker.process_queue()
            if chat.send_btn.cget("state") == "normal":
                break
            time.sleep(0.05)

        # Check chat feed contains the prominent Crimson Security Card
        bubbles = chat.chat_feed.winfo_children()
        agent_bubble = bubbles[-1]

        labels = [c for c in agent_bubble.winfo_children() if isinstance(c, customtkinter.CTkLabel)]
        label_text = " ".join(lbl.cget("text") for lbl in labels)
        self.assertIn("SECURITY BLOCKED BY QUERYGUARD", label_text)
        self.assertIn("Prohibited SQL statement type: 'DROP'", label_text)

        # Verify customers table still exists in SQLite
        check_res = self.db.execute_query("SELECT count(*) FROM customers;")
        self.assertEqual(check_res.rows[0][0], 4)

        # Verify audit ledger has REJECTED record
        audit = self.db.execute_query(
            "SELECT status, generated_sql FROM _nexus_query_audit ORDER BY query_id DESC LIMIT 1;"
        )
        self.assertEqual(audit.rows[0][0], "REJECTED")
        self.assertIn("DROP", audit.rows[0][1].upper())

        chat.destroy()

    # --------------------------------------------------------------------------
    # 5. OFFLINE OLLAMA GRACEFUL REMEDIATION
    # --------------------------------------------------------------------------

    def test_offline_ollama_graceful_guidance(self):
        """
        Validates:
        Ollama offline (LLMConnectionError) -> Renders diagnostic card with
        clear guidance ('ollama serve') -> Send button re-enabled -> No crash.
        """
        def mock_offline_factory(cfg, key_fn):
            mock_router = MagicMock(spec=LLMRouter)
            mock_router.config = cfg
            mock_router.invoke.side_effect = LLMConnectionError(
                "Failed to connect to Ollama at http://127.0.0.1:11434. Connection refused."
            )
            return mock_router

        chat = ChatAnalystTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            llm_router_factory=mock_offline_factory
        )

        chat.query_entry.insert(0, "List all customers")
        chat.send_user_message()

        for _ in range(50):
            self.worker.process_queue()
            if chat.send_btn.cget("state") == "normal":
                break
            time.sleep(0.05)

        # Verify send button is re-enabled
        self.assertEqual(chat.send_btn.cget("state"), "normal")

        # Verify diagnostic bubble
        bubbles = chat.chat_feed.winfo_children()
        agent_bubble = bubbles[-1]
        labels = [c for c in agent_bubble.winfo_children() if isinstance(c, customtkinter.CTkLabel)]
        bubble_text = " ".join(lbl.cget("text") for lbl in labels)

        self.assertIn("Query Execution Diagnostic", bubble_text)
        self.assertIn("ollama serve", bubble_text)

        chat.destroy()

    # --------------------------------------------------------------------------
    # 6. CLOUD API KEY PROPAGATION & ZERO RAW LEAKAGE
    # --------------------------------------------------------------------------

    def test_cloud_api_key_volatile_propagation_and_zero_leakage(self):
        """
        Validates:
        Sidebar in cloud mode with volatile API key -> key passed into LLMRouter
        transport on-demand -> Raw key NEVER appears in chat bubble text or UI labels.
        """
        raw_secret_key = "AIzaSy-StrictSecretCloudKey-48291"
        volatile_key_calls = []

        def get_volatile_key() -> Optional[str]:
            volatile_key_calls.append(raw_secret_key)
            return raw_secret_key

        captured_router_provider = None

        def mock_cloud_factory(cfg, key_fn):
            nonlocal captured_router_provider
            captured_router_provider = key_fn
            mock_router = MagicMock(spec=LLMRouter)
            mock_router.config = cfg

            # When invoked, simulate transport accessing key_fn()
            def fake_invoke(messages, **kwargs):
                if key_fn:
                    key = key_fn()
                    if key != raw_secret_key:
                        raise ValueError("Transport received corrupted API key")
                return LLMResponse(
                    content="```sql\nSELECT count(*) FROM customers;\n```",
                    provider="cloud",
                    model="gemini-1.5-pro",
                    prompt_tokens=40,
                    completion_tokens=10,
                    total_tokens=50,
                    latency_ms=90.0
                )

            mock_router.invoke.side_effect = fake_invoke
            mock_router.generate.return_value = LLMResponse(
                content="Total customer count is 4.",
                provider="cloud",
                model="gemini-1.5-pro",
                prompt_tokens=30,
                completion_tokens=10,
                total_tokens=40,
                latency_ms=40.0
            )
            return mock_router

        cloud_config = {
            "provider": "cloud",
            "model": "gemini-1.5-pro",
            "masked_api_key": "••••••••8291",
            "has_api_key": True
        }

        chat = ChatAnalystTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            get_llm_config_fn=lambda: cloud_config,
            get_volatile_api_key_fn=get_volatile_key,
            llm_router_factory=mock_cloud_factory
        )

        chat.query_entry.insert(0, "How many customers exist?")
        chat.send_user_message()

        for _ in range(50):
            self.worker.process_queue()
            if chat.send_btn.cget("state") == "normal":
                break
            time.sleep(0.05)

        # Verify key_fn was provided to router and called at transport time
        self.assertIsNotNone(captured_router_provider)
        self.assertGreaterEqual(len(volatile_key_calls), 1)

        # STRICT SECURITY AUDIT: Verify raw secret key NEVER leaked into any chat bubble or widget
        bubbles = chat.chat_feed.winfo_children()
        agent_bubble = bubbles[-1]

        all_text = ""
        for child in agent_bubble.winfo_children():
            if isinstance(child, customtkinter.CTkLabel):
                all_text += " " + child.cget("text")
            elif isinstance(child, customtkinter.CTkTextbox):
                all_text += " " + child.get("1.0", "end")

        self.assertNotIn(raw_secret_key, all_text)
        self.assertNotIn("StrictSecretCloudKey", all_text)

        chat.destroy()

    # --------------------------------------------------------------------------
    # 7. LOCAL MODEL DISCOVERY & REASONING / ERROR CARD ENHANCEMENTS
    # --------------------------------------------------------------------------

    def test_sidebar_update_local_models_filtering_and_preferred_selection(self):
        """
        Validates:
        SidebarPanel.update_local_models(['nomic-embed-text:latest', 'phi4-mini:latest', 'gemma3:4b'])
        filters out embedding model 'nomic-embed-text:latest', updates options to
        ['phi4-mini:latest', 'gemma3:4b'], selects preferred model 'phi4-mini:latest',
        and notifies subscribers.
        """
        config_notifications = []
        sidebar = SidebarPanel(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            on_llm_config_changed=lambda cfg: config_notifications.append(cfg)
        )

        discovered = ["nomic-embed-text:latest", "phi4-mini:latest", "gemma3:4b"]
        sidebar.update_local_models(discovered)

        # Verify dropdown values exclude nomic-embed-text:latest
        values = sidebar.model_selector.cget("values")
        self.assertNotIn("nomic-embed-text:latest", values)
        self.assertIn("phi4-mini:latest", values)
        self.assertIn("gemma3:4b", values)

        # Verify phi4-mini:latest was automatically selected
        current_selection = sidebar.model_selector.get()
        self.assertEqual(current_selection, "phi4-mini:latest")

        # Verify notification was sent with new model
        self.assertGreaterEqual(len(config_notifications), 1)
        self.assertEqual(config_notifications[-1]["model"], "phi4-mini:latest")

        sidebar.destroy()

    def test_chat_tab_clean_error_formatting_and_http_404_guidance(self):
        """
        Validates:
        1. Asterisks (**AI Provider Error**) are stripped cleanly for CTkLabel bubbles.
        2. HTTP 404 / not found errors trigger actionable guidance:
           'Model is not installed in Ollama. Select an installed model from the sidebar or run: ollama pull <model>'
        """
        def mock_404_factory(cfg, key_fn):
            mock_router = MagicMock(spec=LLMRouter)
            mock_router.config = cfg
            mock_router.invoke.side_effect = LLMRouterError(
                "HTTP Error 404: model 'deepseek-r1:8b' not found"
            )
            return mock_router

        chat = ChatAnalystTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            llm_router_factory=mock_404_factory
        )

        chat.query_entry.insert(0, "Count all customers")
        chat.send_user_message()

        for _ in range(50):
            self.worker.process_queue()
            if chat.send_btn.cget("state") == "normal":
                break
            time.sleep(0.05)

        # Check diagnostic bubble
        bubbles = chat.chat_feed.winfo_children()
        agent_bubble = bubbles[-1]
        labels = [c for c in agent_bubble.winfo_children() if isinstance(c, customtkinter.CTkLabel)]
        bubble_text = " ".join(lbl.cget("text") for lbl in labels)

        # Asterisks must be stripped
        self.assertNotIn("**", bubble_text)
        # Actionable 404 guidance must be appended
        self.assertIn("Model is not installed in Ollama", bubble_text)
        self.assertIn("ollama pull <model>", bubble_text)

        chat.destroy()

    def test_chat_tab_ollama_health_check_online_and_offline(self):
        """
        Validates ChatAnalystTab._check_ollama_health_async:
        1. Online tuple (True, ['llama3:8b', 'phi4-mini:latest'], 'Online') updates
           health_status_label to '● Ollama Online (2 models)' in emerald and updates sidebar.
        2. Offline tuple (False, [], 'Offline') updates health_status_label to '● Ollama Offline' in amber.
        """
        mock_router = MagicMock(spec=LLMRouter)
        mock_router.check_ollama_health.return_value = (True, ["llama3:8b", "phi4-mini:latest"], "Online")

        sidebar = SidebarPanel(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker
        )

        chat = ChatAnalystTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            sidebar_panel=sidebar,
            llm_router_factory=lambda cfg, key_fn: mock_router
        )

        # Trigger health check (online)
        chat._check_ollama_health_async()
        time.sleep(0.1)
        self.worker.process_queue()

        self.assertIn("● Ollama Online (2 models)", chat.health_status_label.cget("text"))
        self.assertIn("phi4-mini:latest", sidebar.model_selector.cget("values"))

        # Trigger health check (offline)
        mock_router.check_ollama_health.return_value = (False, [], "Daemon offline")
        chat._check_ollama_health_async()
        time.sleep(0.1)
        self.worker.process_queue()

        self.assertEqual("● Ollama Offline", chat.health_status_label.cget("text"))

        chat.destroy()
        sidebar.destroy()

    def test_nexus_app_startup_ollama_discovery_online_and_offline(self):
        """
        Validates NexusApp._discover_local_models_async:
        1. Online: updates chat_tab.health_status_label to '● Ollama Online (N models)' and updates sidebar.
        2. Offline / error: updates chat_tab.health_status_label to '● Ollama Offline' (never stuck on Checking...).
        """
        # Test Online Discovery
        with patch("src.agent.llm_router.LLMRouter.check_ollama_health", return_value=(True, ["granite4.1:3b", "gemma3:4b"], "Online")):
            app = NexusApp(
                db_manager=self.db,
                schema_parser=self.parser,
                async_worker=self.worker,
                poll_interval_ms=20
            )
            app.withdraw()
            time.sleep(0.2)
            self.worker.process_queue()
            self.assertIn("● Ollama Online (2 models)", app.chat_tab.health_status_label.cget("text"))
            self.assertIn("granite4.1:3b", app.sidebar.model_selector.cget("values"))
            app.on_closing()

        # Test Offline Discovery
        worker2 = AsyncWorkerManager(max_workers=2)
        with patch("src.agent.llm_router.LLMRouter.check_ollama_health", return_value=(False, [], "Connection refused")):
            app2 = NexusApp(
                db_manager=self.db,
                schema_parser=self.parser,
                async_worker=worker2,
                poll_interval_ms=20
            )
            app2.withdraw()
            time.sleep(0.2)
            worker2.process_queue()
            self.assertEqual("● Ollama Offline", app2.chat_tab.health_status_label.cget("text"))
            app2.on_closing()


if __name__ == "__main__":
    unittest.main()
