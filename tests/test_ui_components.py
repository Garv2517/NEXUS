"""
NEXUS Engine - Phase 2 UI Modular Components Test Suite
=======================================================
Validates:
1. SidebarPanel: Brand header, file selector callback, schema reflection,
   model toggles, and secure volatile API key handling with mask_secret.
2. DataExplorerTab: Table selection, quick preview generator, QueryGuard
   interception of non-SELECT queries, crimson alert banner, and execution.
3. TelemetryHudTab: 4 KPI metric cards, interactive SQLi simulation attack,
   and persistent audit ledger rendering.
4. ChatAnalystTab: Message bubble feed, schema context markdown generation,
   and conversational query dispatching.
"""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import customtkinter

from unittest.mock import MagicMock

from src.agent.llm_router import LLMConfig, LLMResponse, LLMRouter
from src.core.db_manager import DatabaseManager
from src.core.query_guard import QueryGuard, SecurityException, guard_query
from src.core.schema_parser import SchemaParser
from src.ui.async_worker import AsyncWorkerManager
from src.ui.components.sidebar import SidebarPanel
from src.ui.components.data_explorer_tab import DataExplorerTab
from src.ui.components.telemetry_hud_tab import TelemetryHudTab
from src.ui.components.chat_tab import ChatAnalystTab
from src.ui.theme import NexusTheme, mask_secret


class TestUIComponents(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create hidden root window for CTk widget instantiation in headless testing
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
        self.db_path = Path(self.temp_dir.name) / "test_ui.db"
        self.db = DatabaseManager(self.db_path)
        self.parser = SchemaParser(self.db)
        self.worker = AsyncWorkerManager(max_workers=2)

        # Seed sample tables for testing
        self.db.execute_write("""
            CREATE TABLE test_customers (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                revenue REAL DEFAULT 0.0
            );
        """)
        self.db.execute_write("INSERT INTO test_customers (name, revenue) VALUES ('Acme Corp', 5400.0);")

    def tearDown(self):
        self.worker.shutdown(wait=True)
        self.db.close()
        DatabaseManager.reset_instance()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    # --------------------------------------------------------------------------
    # 1. SIDEBAR PANEL TESTS
    # --------------------------------------------------------------------------

    def test_sidebar_initialization_and_brand_badge(self):
        sidebar = SidebarPanel(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker
        )
        self.assertIn("WAL MODE", sidebar.status_badge.cget("text"))
        self.assertEqual(sidebar._active_provider, "local")

        # Allow worker thread to fetch stats
        time.sleep(0.1)
        self.worker.process_queue()

        # Requirement 8.1: Assert sidebar.stats_lbl.cget("text") contains "Tables: 1" (not "Tables: 0")
        self.assertIn("Tables: 1", sidebar.stats_lbl.cget("text"))
        self.assertNotIn("Tables: 0", sidebar.stats_lbl.cget("text"))
        sidebar.destroy()

    def test_sidebar_llm_provider_and_secret_redaction(self):
        config_history = []
        sidebar = SidebarPanel(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            on_llm_config_changed=lambda cfg: config_history.append(cfg)
        )

        # Switch to Cloud API
        sidebar._handle_provider_change("Cloud API")
        self.assertEqual(sidebar._active_provider, "cloud")
        self.assertIn("gemini", sidebar.model_selector.cget("values")[0])

        # Apply a secret API key
        test_key = "sk-ant-api03-abcdef12345678"
        sidebar.api_key_entry.insert(0, test_key)
        sidebar._handle_apply_api_key()

        # 1. Raw key stored in volatile memory
        self.assertEqual(sidebar.get_volatile_api_key(), test_key)

        # 2. Public config exposes ONLY masked secret
        config = sidebar.get_llm_config()
        self.assertEqual(config["provider"], "cloud")
        self.assertTrue(config["has_api_key"])
        self.assertEqual(config["masked_api_key"], "••••••••5678")
        self.assertNotIn("abcdef1234", config["masked_api_key"])

        # 3. UI label displays masked key
        self.assertIn("••••••••5678", sidebar.key_status_label.cget("text"))

        # Verify on_llm_config_changed was notified
        self.assertGreaterEqual(len(config_history), 2)
        sidebar.destroy()

    def test_sidebar_schema_refresh_and_table_click(self):
        clicked_tables = []
        sidebar = SidebarPanel(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            on_table_selected=lambda t: clicked_tables.append(t)
        )

        # Allow worker thread to fetch stats
        time.sleep(0.1)
        self.worker.process_queue()

        # Verify summary label updated and contains Tables: 1
        self.assertIn("Tables: 1", sidebar.stats_lbl.cget("text"))

        # Trigger click on first discovered table button
        children = sidebar.table_scroll_frame.winfo_children()
        self.assertGreaterEqual(len(children), 1)
        children[0].invoke()

        self.assertEqual(clicked_tables, ["test_customers"])
        sidebar.destroy()

    # --------------------------------------------------------------------------
    # 2. DATA EXPLORER TAB TESTS
    # --------------------------------------------------------------------------

    def test_data_explorer_query_execution_success(self):
        explorer = DataExplorerTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker
        )

        # Execute safe SELECT query
        explorer._set_scratchpad_sql("SELECT id, name, revenue FROM test_customers;")
        explorer.execute_current_query()

        # Let async worker process
        time.sleep(0.1)
        self.worker.process_queue()

        # Check results in textbox
        results_content = explorer.results_textbox.get("1.0", "end")
        self.assertIn("Acme Corp", results_content)
        self.assertIn("5400.0", results_content)
        self.assertIn("1 rows", explorer.query_status_label.cget("text"))

        # Verify SUCCESS logged in _nexus_query_audit
        with self.db.readonly() as cur:
            cur.execute("SELECT status, generated_sql FROM _nexus_query_audit ORDER BY query_id DESC LIMIT 1;")
            row = cur.fetchone()
            self.assertEqual(row["status"], "SUCCESS")
        explorer.destroy()

    def test_data_explorer_security_guard_blocks_destructive_sql(self):
        explorer = DataExplorerTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker
        )

        # Attempt destructive SQL injection
        destructive_sql = "DROP TABLE test_customers;"
        explorer._set_scratchpad_sql(destructive_sql)
        explorer.execute_current_query()

        # Let async worker process background validation and audit logging
        time.sleep(0.1)
        self.worker.process_queue()

        # QueryGuard must catch and reject
        self.assertIn("Blocked", explorer.query_status_label.cget("text"))
        self.assertIn("SECURITY INTERCEPT", explorer.alert_label.cget("text"))

        # Verify database was NOT touched
        res = self.db.execute_query("SELECT COUNT(*) FROM test_customers;")
        self.assertEqual(res.rows[0][0], 1)

        # Verify audit ledger recorded the REJECTED attempt
        with self.db.readonly() as cur:
            cur.execute("SELECT status, generated_sql, error_message FROM _nexus_query_audit ORDER BY query_id DESC LIMIT 1;")
            audit_row = cur.fetchone()
            self.assertEqual(audit_row["status"], "REJECTED")
            self.assertEqual(audit_row["generated_sql"], destructive_sql)
            self.assertIsNotNone(audit_row["error_message"])

        explorer.destroy()

    def test_data_explorer_select_table_and_preview(self):
        explorer = DataExplorerTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker
        )

        explorer.select_table_and_preview("test_customers")

        # Let async worker execute preview
        time.sleep(0.1)
        self.worker.process_queue()

        self.assertIn('SELECT * FROM "test_customers" LIMIT 100;', explorer.sql_textbox.get("1.0", "end"))
        results_content = explorer.results_textbox.get("1.0", "end")
        self.assertIn("Acme Corp", results_content)

        # Verify SUCCESS audit log
        with self.db.readonly() as cur:
            cur.execute("SELECT status, generated_sql FROM _nexus_query_audit ORDER BY query_id DESC LIMIT 1;")
            audit_row = cur.fetchone()
            self.assertEqual(audit_row["status"], "SUCCESS")

        explorer.destroy()

    # --------------------------------------------------------------------------
    # 3. TELEMETRY HUD TAB TESTS
    # --------------------------------------------------------------------------

    def test_telemetry_hud_metrics_and_sqli_simulator(self):
        hud = TelemetryHudTab(
            self.root,
            db_manager=self.db,
            async_worker=self.worker
        )

        # Initial refresh
        time.sleep(0.1)
        self.worker.process_queue()

        # Requirement 8.2: Assert hud.total_q_lbl, hud.p95_lbl, and hud.blocks_lbl update accurately via get_metrics()
        metrics = self.db.telemetry.get_metrics()
        self.assertEqual(hud.total_q_lbl.cget("text"), str(metrics["total_queries"]))
        self.assertEqual(hud.p95_lbl.cget("text"), f"{metrics['p95_execution_ms']:.2f} ms")

        # Record total_queries count before refresh
        q_count_before = metrics["total_queries"]

        # Call refresh_hud() again
        hud.refresh_hud()
        time.sleep(0.1)
        self.worker.process_queue()

        # Assert refreshing HUD does NOT increment total_queries in db.telemetry (ZERO telemetry pollution)
        self.assertEqual(self.db.telemetry.get_metrics()["total_queries"], q_count_before)

        initial_security_blocks = int(hud.blocks_lbl.cget("text").replace(",", ""))

        # Trigger simulated SQLi attack
        hud.simulate_sqli_attack()
        time.sleep(0.1)
        self.worker.process_queue()

        # Allow secondary refresh_hud in worker to complete
        time.sleep(0.1)
        self.worker.process_queue()

        # Deflection status updated
        self.assertIn("Deflected", hud.attack_status_label.cget("text"))

        # Counter incremented
        new_security_blocks = int(hud.blocks_lbl.cget("text").replace(",", ""))
        self.assertEqual(new_security_blocks, initial_security_blocks + 1)

        # Verify ledger text contains deflected attack record
        ledger_text = hud.ledger_textbox.get("1.0", "end")
        self.assertIn("[REJECTED]", ledger_text)
        hud.destroy()

    def test_telemetry_hud_adversarial_payloads_all_blocked(self):
        # Requirement 8.3: Assert every single payload in TelemetryHudTab.ADVERSARIAL_PAYLOADS raises SecurityException in guard_query()
        self.assertGreaterEqual(len(TelemetryHudTab.ADVERSARIAL_PAYLOADS), 6)
        for name, payload in TelemetryHudTab.ADVERSARIAL_PAYLOADS:
            with self.subTest(payload_name=name):
                with self.assertRaises(SecurityException, msg=f"Payload '{name}' did not raise SecurityException: {payload}"):
                    guard_query(payload)

    # --------------------------------------------------------------------------
    # 4. CHAT ANALYST TAB TESTS
    # --------------------------------------------------------------------------

    def test_chat_analyst_tab_message_and_schema_context(self):
        sidebar = SidebarPanel(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker
        )

        def mock_factory(cfg, key_fn):
            mock_router = MagicMock()
            mock_router.config = cfg
            mock_router.invoke.return_value = LLMResponse(
                content="```sql\nSELECT name, revenue FROM test_customers WHERE name = 'Acme Corp';\n```",
                provider="local",
                model=cfg.model,
                prompt_tokens=50,
                completion_tokens=15,
                total_tokens=65,
                latency_ms=45.0
            )
            mock_router.generate.return_value = LLMResponse(
                content="Acme Corp generated $5,400.0 in revenue from test_customers.",
                provider="local",
                model=cfg.model,
                prompt_tokens=40,
                completion_tokens=15,
                total_tokens=55,
                latency_ms=30.0
            )
            return mock_router

        chat = ChatAnalystTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            sidebar_panel=sidebar,
            llm_router_factory=mock_factory
        )

        # 1. Test welcome message exists in feed
        self.assertGreaterEqual(len(chat.chat_feed.winfo_children()), 1)

        # 2. Test user message input and asynchronous response
        chat.query_entry.insert(0, "How much revenue did Acme Corp generate?")
        chat.send_user_message()

        time.sleep(0.15)
        self.worker.process_queue()

        # Feed should now have welcome bubble + user bubble + agent response bubble
        bubbles = chat.chat_feed.winfo_children()
        self.assertGreaterEqual(len(bubbles), 3)

        # Agent response should mention Acme Corp and active model
        agent_bubble = bubbles[-1]
        msg_labels = [c for c in agent_bubble.winfo_children() if isinstance(c, customtkinter.CTkLabel)]
        bubble_text = " ".join(lbl.cget("text") for lbl in msg_labels)
        self.assertIn("Acme Corp", bubble_text)
        self.assertIn("llama3:8b", bubble_text)

        # 3. Test badge update
        chat.update_provider_badge({"provider": "cloud", "model": "gemini-1.5-pro", "masked_api_key": "••••••••1234"})
        self.assertIn("gemini-1.5-pro", chat.llm_badge.cget("text"))
        self.assertIn("••••••••1234", chat.llm_badge.cget("text"))

        sidebar.destroy()
        chat.destroy()

    def test_chat_analyst_tab_kwargs_and_thread_safe_config_snapshot(self):
        """
        Verify that all UI components accept worker_manager in kwargs cleanly without
        TypeError, that get_llm_config_fn is safely invoked on the main UI thread,
        and that immutable config snapshots are passed into background worker tasks.
        """
        # Test kwargs forwarding for all 4 components
        sidebar = SidebarPanel(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            worker_manager=self.worker
        )
        self.assertIs(sidebar.worker, self.worker)

        explorer = DataExplorerTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            worker_manager=self.worker
        )
        self.assertIs(explorer.worker, self.worker)

        hud = TelemetryHudTab(
            self.root,
            db_manager=self.db,
            worker_manager=self.worker
        )
        self.assertIs(hud.worker, self.worker)

        # Test ChatAnalystTab with explicit get_llm_config_fn and worker_manager in kwargs
        captured_calls = []
        def mock_llm_config() -> Dict[str, Any]:
            captured_calls.append("called_on_main_thread")
            return {
                "provider": "cloud",
                "model": "claude-3-5-sonnet",
                "masked_api_key": "••••••••9999",
                "has_api_key": True
            }

        def mock_factory_cloud(cfg, key_fn):
            mock_router = MagicMock()
            mock_router.config = cfg
            mock_router.invoke.return_value = LLMResponse(
                content="```sql\nSELECT name, revenue FROM test_customers;\n```",
                provider="cloud",
                model=cfg.model,
                prompt_tokens=60,
                completion_tokens=20,
                total_tokens=80,
                latency_ms=50.0
            )
            mock_router.generate.return_value = LLMResponse(
                content="Customer revenue totals: Acme Corp generated $5,400.",
                provider="cloud",
                model=cfg.model,
                prompt_tokens=40,
                completion_tokens=15,
                total_tokens=55,
                latency_ms=30.0
            )
            return mock_router

        chat = ChatAnalystTab(
            self.root,
            db_manager=self.db,
            schema_parser=self.parser,
            worker_manager=self.worker,
            get_llm_config_fn=mock_llm_config,
            llm_router_factory=mock_factory_cloud
        )
        self.assertIs(chat.worker, self.worker)
        self.assertIs(chat.get_llm_config_fn, mock_llm_config)

        # Send user query and verify thread-safe config snapshotting
        chat.query_entry.insert(0, "Show customer revenue totals")
        chat.send_user_message()

        # The mock config provider should have been called synchronously on main thread
        self.assertEqual(len(captured_calls), 1)

        # Allow worker thread to finish processing context
        time.sleep(0.15)
        self.worker.process_queue()

        # Check response bubble contains data from config snapshot
        bubbles = chat.chat_feed.winfo_children()
        agent_bubble = bubbles[-1]
        msg_labels = [c for c in agent_bubble.winfo_children() if isinstance(c, customtkinter.CTkLabel)]
        bubble_text = " ".join(lbl.cget("text") for lbl in msg_labels)
        self.assertIn("CLOUD", bubble_text)
        self.assertIn("claude-3-5-sonnet", bubble_text)

        sidebar.destroy()
        explorer.destroy()
        hud.destroy()
        chat.destroy()


if __name__ == "__main__":
    unittest.main()
