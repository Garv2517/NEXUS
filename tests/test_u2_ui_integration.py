"""
NEXUS Engine - Upgrade U2 & U2.5 Gate 2 Headless UI Integration Test Suite
==========================================================================
Comprehensive headless validation of the U2 UI upgrades:
1. Multi-turn memory lifecycle and strict security hygiene (SUCCESS appends,
   SECURITY_BLOCKED / failed queries never append, memory pill updates,
   snapshots passed thread-safely, clear_conversation cleans figures and history).
2. Clickable starter chips (set_starter_questions renders up to 3 buttons,
   clicking populates input bar and dispatches query).
3. Clean numeric and tabular formatting across DataExplorerTab and ChatAnalystTab
   (float artifacts stripped, integers preserved without commas).
4. Safety cap truncation notices and schema pruning badges in Explorer and Chat.
5. Post-ETL starter question refresh reflecting newly ingested schema.

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import customtkinter
from matplotlib.figure import Figure

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.llm_router import LLMConfig, LLMRouter
from src.agent.sql_chain import AgentRunResult, ConversationTurn, SQLAgentChain
from src.core.db_manager import DatabaseManager, QueryResult
from src.core.schema_parser import SchemaParser
from src.etl.etl_engine import ETLReport
from src.ui.app import NexusApp
from src.ui.async_worker import AsyncWorkerManager
from src.ui.components.chat_tab import ChatAnalystTab
from src.ui.components.data_explorer_tab import DataExplorerTab


class TestU2UIIntegration(unittest.TestCase):
    """Rigorous headless integration test suite for U2 & U2.5 Gate 2 UI features."""

    @classmethod
    def setUpClass(cls) -> None:
        DatabaseManager.reset_instance()
        cls.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.db_path = Path(cls.temp_dir.name) / "test_u2_ui.db"
        cls.db = DatabaseManager(cls.db_path)
        cls.parser = SchemaParser(cls.db)
        cls.worker = AsyncWorkerManager(max_workers=2)

        # Single persistent NexusApp instance in headless mode for clean Windows Tcl resource isolation
        cls.app = NexusApp(
            db_manager=cls.db,
            schema_parser=cls.parser,
            async_worker=cls.worker,
            poll_interval_ms=20,
        )
        cls.app.withdraw()

        # Let startup initialization settle cleanly
        time.sleep(0.3)
        cls.worker.process_queue()
        cls.app.update_idletasks()

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "app") and not cls.app._is_closing:
            cls.app.on_closing()
        if hasattr(cls, "worker") and not cls.worker.is_shutdown:
            cls.worker.shutdown(wait=True)
        if hasattr(cls, "db"):
            cls.db.close()
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass
        DatabaseManager.reset_instance()

    def setUp(self) -> None:
        self.app = self.__class__.app
        self.db = self.__class__.db
        self.parser = self.__class__.parser
        self.worker = self.__class__.worker

        # Clear state
        self.app.chat_tab.clear_conversation()
        self.worker.process_queue()
        self.app.update_idletasks()

    # --------------------------------------------------------------------------
    # 1. MULTI-TURN MEMORY LIFECYCLE & SECURITY HYGIENE
    # --------------------------------------------------------------------------

    def test_multi_turn_memory_lifecycle_and_security_hygiene(self) -> None:
        """
        Validates:
        - Turn 1 SUCCESS appends ConversationTurn to _conversation_history and updates memory pill.
        - Turn 2 receives thread-safe snapshot of history in chain.run().
        - Turn 3 SECURITY_BLOCKED never pollutes memory.
        - clear_conversation() resets history, resets memory pill, and frees figures.
        """
        chat_tab: ChatAnalystTab = self.app.chat_tab
        self.assertEqual(len(chat_tab._conversation_history), 0)
        self.assertIn("0/4 turns", chat_tab.memory_status_label.cget("text"))

        # Turn 1: SUCCESS
        result_1 = AgentRunResult(
            status="SUCCESS",
            natural_query="What are our top customer revenues?",
            generated_sql="SELECT name, revenue FROM customers ORDER BY revenue DESC;",
            answer_markdown="Top customer is Omni Corp with $32,000 revenue.",
            tables_in_context=["customers"],
        )
        chat_tab._on_pipeline_success({
            "result": result_1,
            "figure": None,
            "user_text": result_1.natural_query,
            "llm_config": None,
        })

        self.assertEqual(len(chat_tab._conversation_history), 1)
        self.assertEqual(chat_tab._conversation_history[0].natural_query, result_1.natural_query)
        self.assertEqual(chat_tab._conversation_history[0].generated_sql, result_1.generated_sql)
        self.assertIn("1/4 turns", chat_tab.memory_status_label.cget("text"))

        # Turn 2: Dispatch and verify history snapshot passed to chain.run
        captured_history: List[List[ConversationTurn]] = []

        def mock_chain_run(*args, **kwargs) -> AgentRunResult:
            hist = kwargs.get("conversation_history")
            captured_history.append(list(hist) if hist else [])
            return AgentRunResult(
                status="SUCCESS",
                natural_query="Filter for North America only",
                generated_sql="SELECT name, revenue FROM customers WHERE region = 'North America';",
                answer_markdown="North America customers are Nexus Labs and Bio Synth.",
                tables_in_context=["customers"],
            )

        with patch.object(SQLAgentChain, "run", side_effect=mock_chain_run):
            chat_tab.query_entry.delete(0, "end")
            chat_tab.query_entry.insert(0, "Filter for North America only")
            chat_tab.send_user_message()

            # Process worker queue
            time.sleep(0.1)
            self.worker.process_queue()
            self.app.update_idletasks()

        self.assertEqual(len(captured_history), 1)
        self.assertEqual(len(captured_history[0]), 1)
        self.assertEqual(captured_history[0][0].natural_query, result_1.natural_query)

        # After Turn 2 completed, history count should be 2
        self.assertEqual(len(chat_tab._conversation_history), 2)
        self.assertIn("2/4 turns", chat_tab.memory_status_label.cget("text"))

        # Turn 3: SECURITY_BLOCKED -> MUST NOT pollute history
        result_blocked = AgentRunResult(
            status="SECURITY_BLOCKED",
            natural_query="DROP TABLE customers",
            generated_sql="DROP TABLE customers",
            error_message="DROP TABLE rejected by QueryGuard",
            tables_in_context=["customers"],
        )
        chat_tab._on_pipeline_success({
            "result": result_blocked,
            "figure": None,
            "user_text": result_blocked.natural_query,
            "llm_config": None,
        })

        # Length remains 2
        self.assertEqual(len(chat_tab._conversation_history), 2)
        self.assertIn("2/4 turns", chat_tab.memory_status_label.cget("text"))

        # Turn 4: FAILED -> MUST NOT pollute history
        result_failed = AgentRunResult(
            status="SQL_FAILED",
            natural_query="SELECT nonexistent FROM bad_table",
            generated_sql="SELECT nonexistent FROM bad_table",
            error_message="no such table: bad_table",
        )
        chat_tab._on_pipeline_success({
            "result": result_failed,
            "figure": None,
            "user_text": result_failed.natural_query,
            "llm_config": None,
        })
        self.assertEqual(len(chat_tab._conversation_history), 2)

        # Verify figure tracking and clear_conversation cleanup
        test_fig = Figure()
        chat_tab._embedded_figures.append(test_fig)
        self.assertEqual(len(chat_tab._embedded_figures), 1)

        chat_tab.clear_conversation()
        self.assertEqual(len(chat_tab._conversation_history), 0)
        self.assertEqual(len(chat_tab._embedded_figures), 0)
        self.assertIn("0/4 turns", chat_tab.memory_status_label.cget("text"))

    # --------------------------------------------------------------------------
    # 2. CLICKABLE STARTER CHIPS
    # --------------------------------------------------------------------------

    def test_clickable_starter_chips(self) -> None:
        """
        Validates:
        - set_starter_questions renders up to 3 clickable buttons.
        - Clicking a starter chip populates query entry and calls send_user_message.
        """
        chat_tab: ChatAnalystTab = self.app.chat_tab
        questions = ["Show total revenue by region", "What is the average transaction?"]
        chat_tab.set_starter_questions(questions)

        self.assertEqual(len(chat_tab._starter_buttons), 2)
        btn0_text = chat_tab._starter_buttons[0].cget("text")
        self.assertIn("Show total revenue by region", btn0_text)

        # Intercept send_user_message
        sent_queries: List[str] = []
        original_send = chat_tab.send_user_message

        def mock_send() -> None:
            sent_queries.append(chat_tab.query_entry.get())

        with patch.object(chat_tab, "send_user_message", side_effect=mock_send):
            # Trigger chip click via its bound callback
            chat_tab._starter_buttons[0].cget("command")()

        self.assertEqual(len(sent_queries), 1)
        self.assertEqual(sent_queries[0], "Show total revenue by region")

    # --------------------------------------------------------------------------
    # 3. CLEAN NUMERIC & TABULAR FORMATTING (CHAT + EXPLORER)
    # --------------------------------------------------------------------------

    def test_clean_numeric_formatting_chat_and_explorer(self) -> None:
        """
        Validates:
        - Floats with binary floating point artifacts (e.g. 239365.96000000002) render cleanly as '239,365.96'.
        - Integers (e.g. 1001) render without thousand separators.
        - Raw IEEE-754 precision noise is absent from both DataExplorerTab and ChatAnalystTab.
        """
        self.db.execute_write("""
            CREATE TABLE IF NOT EXISTS format_test (
                record_id INTEGER PRIMARY KEY,
                gross_amount REAL
            );
        """)
        self.db.execute_write("DELETE FROM format_test;")
        self.db.execute_write("INSERT INTO format_test VALUES (1001, 239365.96000000002);")

        qr: QueryResult = self.db.execute_query("SELECT record_id, gross_amount FROM format_test;")
        self.assertEqual(qr.row_count, 1)

        # 1. Test in DataExplorerTab
        explorer: DataExplorerTab = self.app.data_explorer_tab
        explorer._render_results_grid(qr)

        explorer_text = explorer.results_textbox.get("1.0", "end")
        self.assertIn("1001", explorer_text)
        self.assertIn("239,365.96", explorer_text)
        self.assertNotIn("239365.96000000002", explorer_text)

        # 2. Test in ChatAnalystTab preview table
        chat_tab: ChatAnalystTab = self.app.chat_tab
        res = AgentRunResult(
            status="SUCCESS",
            natural_query="Check table formatting",
            generated_sql="SELECT record_id, gross_amount FROM format_test;",
            query_result=qr,
            answer_markdown="Formatted successfully.",
        )
        chat_tab._render_success_bubble(res, figure=None)

        # Inspect all textbox widgets in chat_feed for rendered table
        feed_children = chat_tab.chat_feed.winfo_children()
        found_rendered_table = False
        for card in feed_children:
            for child in card.winfo_children():
                if isinstance(child, customtkinter.CTkTextbox):
                    content = child.get("1.0", "end")
                    if "239,365.96" in content:
                        found_rendered_table = True
                        self.assertIn("1001", content)
                        self.assertNotIn("239365.96000000002", content)

        self.assertTrue(found_rendered_table, "Preview table in ChatAnalystTab did not contain clean formatted values.")

    # --------------------------------------------------------------------------
    # 4. TRUNCATION & PRUNING INDICATORS
    # --------------------------------------------------------------------------

    def test_truncation_and_pruning_indicators(self) -> None:
        """
        Validates:
        - QueryResult with truncated=True renders amber banner in DataExplorerTab and ChatAnalystTab.
        - AgentRunResult with was_pruned=True renders cyan '⚡ Context Pruned: X tables' badge.
        """
        # 1. Explorer truncation
        explorer: DataExplorerTab = self.app.data_explorer_tab
        qr_capped = QueryResult(
            columns=["id", "val"],
            rows=[(1, 10.0)],
            row_count=10000,
            execution_time_ms=8.5,
            sql="SELECT * FROM big_table",
            truncated=True,
        )
        explorer._on_query_completed({
            "status": "SUCCESS",
            "result": qr_capped,
            "sql": qr_capped.sql,
        })

        status_text = explorer.query_status_label.cget("text")
        latency_text = explorer.latency_badge.cget("text")
        self.assertIn("⚠️ Capped at 10,000 rows for RAM safety", status_text)
        self.assertIn("(capped)", latency_text)

        # 2. Chat truncation and pruning badge
        chat_tab: ChatAnalystTab = self.app.chat_tab
        res_pruned_and_capped = AgentRunResult(
            status="SUCCESS",
            natural_query="Select from massive dataset",
            generated_sql="SELECT * FROM big_table;",
            query_result=qr_capped,
            answer_markdown="Returned large dataset capped at safety limit.",
            tables_in_context=["big_table", "lookup_table"],
            was_pruned=True,
        )
        chat_tab._render_success_bubble(res_pruned_and_capped, figure=None)

        # Inspect chat feed widgets for badges
        feed_children = chat_tab.chat_feed.winfo_children()
        latest_card = feed_children[-1]

        badge_texts: List[str] = []
        for child in latest_card.winfo_children():
            if isinstance(child, customtkinter.CTkLabel):
                badge_texts.append(child.cget("text"))
            elif isinstance(child, customtkinter.CTkFrame):
                for subchild in child.winfo_children():
                    if isinstance(subchild, customtkinter.CTkLabel):
                        badge_texts.append(subchild.cget("text"))

        combined_badges = " ".join(badge_texts)
        self.assertIn("⚡ Context Pruned: 2 tables", combined_badges)
        self.assertIn("⚠️ Results capped at 10,000 rows for RAM safety", combined_badges)

    # --------------------------------------------------------------------------
    # 5. POST-ETL STARTER REFRESH
    # --------------------------------------------------------------------------

    def test_post_etl_starter_refresh(self) -> None:
        """
        Validates:
        - When ETL completes, _on_etl_success triggers chat_tab.refresh_starter_questions().
        - Starter questions are asynchronously generated matching the newly ingested table schema.
        """
        self.db.execute_write("""
            CREATE TABLE IF NOT EXISTS u2_inventory (
                item_id INTEGER PRIMARY KEY,
                product_name TEXT NOT NULL,
                stock_quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL
            );
        """)
        self.parser.invalidate_cache()

        report = ETLReport(
            table_name="u2_inventory",
            source_path="mock_inventory.csv",
            file_format="csv",
            total_rows_read=50,
            rows_ingested=50,
            duplicate_rows_dropped=0,
            null_cells_imputed=0,
            inferred_schema={"item_id": "INTEGER", "product_name": "TEXT", "stock_quantity": "INTEGER", "unit_price": "REAL"},
            elapsed_time_sec=0.15,
            throughput_rows_per_sec=333.3,
        )

        # Trigger ETL completion handler
        self.app._on_etl_success(report)

        # Allow worker thread to fetch starter questions and update UI
        time.sleep(0.15)
        self.worker.process_queue()
        self.app.update_idletasks()

        chat_tab: ChatAnalystTab = self.app.chat_tab
        self.assertGreaterEqual(len(chat_tab._starter_buttons), 1)

        # Verify button text reflects the ingested table or its columns
        button_texts = [btn.cget("text") for btn in chat_tab._starter_buttons]
        expected_tokens = ["u2_inventory", "inventory", "product_name", "stock_quantity", "unit_price"]
        has_schema_mention = any(
            any(tok in txt.lower() for tok in expected_tokens)
            for txt in button_texts
        )
        self.assertTrue(
            has_schema_mention,
            f"Expected starter questions to reference schema tokens {expected_tokens}, got: {button_texts}"
        )


if __name__ == "__main__":
    unittest.main()
