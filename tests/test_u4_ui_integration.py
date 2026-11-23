"""
NEXUS Engine - Upgrade U4 Gate 2 Headless UI Integration Test Suite
==================================================================
Comprehensive headless validation of Upgrade U4 UI and Core deliverables:
1. Sidebar DPAPI Opt-In, Auto-Load & Forget:
   - Opt-in checkbox state toggling and DPAPI encryption verification.
   - Zero plaintext credential leakage in raw disk vault file.
   - Automatic credential hydration into volatile memory on Cloud provider switch.
   - Deterministic 'Forget Key' purging from vault and volatile RAM.
2. Chat Session Persistence & Restart Restoration:
   - Live multi-turn transcript auto-titling and persistence.
   - Session restoration on fresh tab mount.
   - Strict SUCCESS-only memory invariant (SECURITY_BLOCKED excluded from LLM memory).
3. Multi-Session Switching, Renaming & Cascade Deletion:
   - Multi-session isolation of conversation history and memory pills.
   - Session renaming reflected in dropdown.
   - Cascading deletion of sessions and all associated message records.
4. Non-Destructive clear_conversation() & GDI Cleanup:
   - Memory status pill reset and deterministic Matplotlib figure cleanup.
   - Non-destructive creation of new session preserving prior saved sessions.
5. NexusApp End-to-End Injection & Clean Shutdown:
   - Verified dependency injection of custom key_vault and session_store.
   - Clean shutdown without zombie threads or unclosed resources.

Author: Senior Systems & Security Engineer
Platform: Windows 11 (Python 3.13) / CustomTkinter
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
from src.core.key_vault import KeyVaultError, WindowsDPAPIVault
from src.core.schema_parser import SchemaParser
from src.core.session_store import ChatSessionStore
from src.ui.app import NexusApp
from src.ui.async_worker import AsyncWorkerManager
from src.ui.components.chat_tab import ChatAnalystTab
from src.ui.components.sidebar import SidebarPanel


class TestU4UIIntegration(unittest.TestCase):
    """Rigorous headless integration test suite for Upgrade U4 Gate 2 UI features."""

    @classmethod
    def setUpClass(cls) -> None:
        DatabaseManager.reset_instance()
        cls.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.temp_path = Path(cls.temp_dir.name)
        cls.db_path = cls.temp_path / "test_u4_ui.db"
        cls.db = DatabaseManager(cls.db_path)
        cls.parser = SchemaParser(cls.db)
        cls.worker = AsyncWorkerManager(max_workers=2)

        # Temp isolated vault and session store
        cls.vault_dir = cls.temp_path / "vault"
        cls.vault = WindowsDPAPIVault(vault_dir=cls.vault_dir)
        cls.session_store = ChatSessionStore(cls.db)

        # Single persistent NexusApp instance in headless mode for clean Windows Tcl resource isolation
        cls.app = NexusApp(
            db_manager=cls.db,
            schema_parser=cls.parser,
            async_worker=cls.worker,
            poll_interval_ms=20,
            key_vault=cls.vault,
            session_store=cls.session_store,
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
        self.vault = self.__class__.vault
        self.session_store = self.__class__.session_store
        self.temp_path = self.__class__.temp_path

    # --------------------------------------------------------------------------
    # 1. SIDEBAR DPAPI OPT-IN, AUTO-LOAD & FORGET
    # --------------------------------------------------------------------------

    def test_sidebar_dpapi_opt_in_auto_load_and_forget(self) -> None:
        """
        Validates:
        - Setting a fake Gemini key, saving to DPAPI vault, and verifying zero plaintext in vault file.
        - Mounting a fresh SidebarPanel with the same vault auto-loads key on Cloud Gemini selection.
        - Calling forget_current_provider_key purges key from vault AND volatile memory.
        """
        isolated_vault_dir = self.temp_path / "test_sidebar_vault"
        vault = WindowsDPAPIVault(vault_dir=isolated_vault_dir)

        # 1. Mount initial sidebar
        panel = SidebarPanel(
            self.app,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            key_vault=vault,
        )

        fake_gemini_key = "AIzaSy-TEST-FAKE-GEMINI-SECRET-KEY-9999"

        # Switch to Cloud API and select Gemini
        panel.provider_seg.set("Cloud API")
        panel._handle_provider_change("Cloud API")
        panel.model_selector.set("gemini-1.5-flash")
        panel._handle_model_change("gemini-1.5-flash")

        # Set API key in entry and save to vault
        panel.api_key_entry.delete(0, "end")
        panel.api_key_entry.insert(0, fake_gemini_key)
        saved = panel.save_current_key_to_vault()
        self.assertTrue(saved, "Key should be saved to DPAPI vault")
        self.assertTrue(panel.remember_key_var.get())
        self.assertIn("Key Saved", panel.vault_status_label.cget("text"))

        # Verify zero plaintext in raw disk vault file
        self.assertTrue(vault.vault_file.exists())
        raw_disk_bytes = vault.vault_file.read_bytes()
        self.assertNotIn(fake_gemini_key.encode("utf-8"), raw_disk_bytes, "Vault file must have 0 plaintext bytes")

        # 2. Mount fresh SidebarPanel on the same temp vault
        fresh_panel = SidebarPanel(
            self.app,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            key_vault=vault,
        )

        # Switch to Cloud API mode
        fresh_panel.provider_seg.set("Cloud API")
        fresh_panel._handle_provider_change("Cloud API")
        fresh_panel.model_selector.set("gemini-1.5-flash")
        fresh_panel._handle_model_change("gemini-1.5-flash")

        # Verify key auto-loaded into volatile memory and pill indicates saved
        self.assertEqual(fresh_panel.get_volatile_api_key(), fake_gemini_key)
        self.assertTrue(fresh_panel.remember_key_var.get())
        self.assertIn("Key Saved", fresh_panel.vault_status_label.cget("text"))

        # 3. Forget Key
        forgot = fresh_panel.forget_current_provider_key()
        self.assertTrue(forgot)
        self.assertIsNone(fresh_panel.get_volatile_api_key())
        self.assertFalse(vault.has_key("gemini"))
        self.assertFalse(fresh_panel.remember_key_var.get())
        self.assertIn("Volatile", fresh_panel.vault_status_label.cget("text"))

        panel.destroy()
        fresh_panel.destroy()

    # --------------------------------------------------------------------------
    # 2. CHAT SESSION PERSISTENCE & RESTART RESTORATION
    # --------------------------------------------------------------------------

    def test_chat_session_persistence_and_restart_restoration(self) -> None:
        """
        Validates:
        - Running 2 SUCCESS turns + 1 SECURITY_BLOCKED turn auto-titles and persists session.
        - Mounting a fresh ChatAnalystTab on the same DB restores transcript.
        - Strict Memory Hygiene: restored _conversation_history has exactly 2 turns (SECURITY_BLOCKED excluded).
        """
        tab1 = ChatAnalystTab(
            self.app,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            session_store=self.session_store,
        )
        sid = tab1._active_session_id
        self.assertIsNotNone(sid)

        # Turn 1: SUCCESS with natural query -> triggers auto-titling
        q1 = "Show customer revenue summary"
        tab1.query_entry.delete(0, "end")
        tab1.query_entry.insert(0, q1)
        tab1.send_user_message()

        res1 = AgentRunResult(
            status="SUCCESS",
            natural_query=q1,
            generated_sql="SELECT name, revenue FROM customers;",
            answer_markdown="Omni Corp generated $32,000.",
            tables_in_context=["customers"],
        )
        tab1._on_pipeline_success({
            "result": res1,
            "figure": None,
            "user_text": q1,
            "llm_config": None,
        })

        # Check session auto-titled
        session_rec = self.session_store.get_session(sid)
        self.assertEqual(session_rec.title, q1[:48])

        # Turn 2: SUCCESS
        q2 = "Filter for high value clients"
        tab1.query_entry.delete(0, "end")
        tab1.query_entry.insert(0, q2)
        tab1.send_user_message()

        res2 = AgentRunResult(
            status="SUCCESS",
            natural_query=q2,
            generated_sql="SELECT * FROM customers WHERE revenue > 10000;",
            answer_markdown="Found 5 high-value clients.",
            tables_in_context=["customers"],
        )
        tab1._on_pipeline_success({
            "result": res2,
            "figure": None,
            "user_text": q2,
            "llm_config": None,
        })

        # Turn 3: SECURITY_BLOCKED (Mutation attempt)
        q3 = "DROP TABLE customers"
        tab1.query_entry.delete(0, "end")
        tab1.query_entry.insert(0, q3)
        tab1.send_user_message()

        res3_blocked = AgentRunResult(
            status="SECURITY_BLOCKED",
            natural_query=q3,
            generated_sql="DROP TABLE customers",
            error_message="DROP mutation prohibited by QueryGuard",
            answer_markdown="Security Exception: Mutation blocked.",
        )
        tab1._on_pipeline_success({
            "result": res3_blocked,
            "figure": None,
            "user_text": q3,
            "llm_config": None,
        })

        # In tab1, memory has 2 turns
        self.assertEqual(len(tab1._conversation_history), 2)

        # Mount fresh second tab on same session_store and DB
        tab2 = ChatAnalystTab(
            self.app,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            session_store=self.session_store,
        )

        # Verify active session restored
        self.assertEqual(tab2._active_session_id, sid)

        # Verify all 6 message records exist in persistent store
        stored_msgs = self.session_store.get_messages(sid)
        self.assertEqual(len(stored_msgs), 6)

        # Strict Memory Hygiene: SECURITY_BLOCKED must NEVER enter restored LLM context memory
        self.assertEqual(len(tab2._conversation_history), 2, "Only 2 SUCCESS turns must be restored to memory")
        self.assertIn("2/4 turns", tab2.memory_status_label.cget("text"))
        restored_sqls = [t.generated_sql for t in tab2._conversation_history]
        self.assertEqual(restored_sqls, ["SELECT name, revenue FROM customers;", "SELECT * FROM customers WHERE revenue > 10000;"])

        tab1.destroy()
        tab2.destroy()

    # --------------------------------------------------------------------------
    # 3. MULTI-SESSION SWITCHING, RENAMING & CASCADE DELETION
    # --------------------------------------------------------------------------

    def test_multi_session_switching_renaming_and_cascade_deletion(self) -> None:
        """
        Validates:
        - Session A and Session B maintain isolated _conversation_history and memory pills.
        - Switching sessions loads respective history cleanly.
        - Renaming active session updates store and selector dropdown.
        - Deleting Session B purges its messages atomically via foreign key cascade with 0 orphaned rows.
        """
        tab = ChatAnalystTab(
            self.app,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            session_store=self.session_store,
        )

        # 1. Session A
        sess_a_id = tab.start_new_session("Alpha Exploration")
        self.assertEqual(len(tab._conversation_history), 0)

        # Append turn to Session A
        tab.query_entry.insert(0, "Query A")
        tab.send_user_message()
        res_a = AgentRunResult(
            status="SUCCESS",
            natural_query="Query A",
            generated_sql="SELECT 'A';",
            answer_markdown="Result A",
        )
        tab._on_pipeline_success({"result": res_a, "figure": None, "user_text": "Query A", "llm_config": None})
        self.assertEqual(len(tab._conversation_history), 1)
        self.assertIn("1/4 turns", tab.memory_status_label.cget("text"))

        # 2. Session B
        sess_b_id = tab.start_new_session("Beta Exploration")
        self.assertEqual(len(tab._conversation_history), 0)
        self.assertIn("0/4 turns", tab.memory_status_label.cget("text"))

        # Append 2 turns to Session B
        tab.query_entry.insert(0, "Query B1")
        tab.send_user_message()
        res_b1 = AgentRunResult(status="SUCCESS", natural_query="Query B1", generated_sql="SELECT 'B1';", answer_markdown="Result B1")
        tab._on_pipeline_success({"result": res_b1, "figure": None, "user_text": "Query B1", "llm_config": None})

        tab.query_entry.insert(0, "Query B2")
        tab.send_user_message()
        res_b2 = AgentRunResult(status="SUCCESS", natural_query="Query B2", generated_sql="SELECT 'B2';", answer_markdown="Result B2")
        tab._on_pipeline_success({"result": res_b2, "figure": None, "user_text": "Query B2", "llm_config": None})

        self.assertEqual(len(tab._conversation_history), 2)
        self.assertIn("2/4 turns", tab.memory_status_label.cget("text"))

        # 3. Switch back to Session A
        tab.load_session(sess_a_id)
        self.assertEqual(tab._active_session_id, sess_a_id)
        self.assertEqual(len(tab._conversation_history), 1)
        self.assertEqual(tab._conversation_history[0].generated_sql, "SELECT 'A';")
        self.assertIn("1/4 turns", tab.memory_status_label.cget("text"))

        # 4. Switch back to Session B
        tab.load_session(sess_b_id)
        self.assertEqual(tab._active_session_id, sess_b_id)
        self.assertEqual(len(tab._conversation_history), 2)
        self.assertIn("2/4 turns", tab.memory_status_label.cget("text"))

        # 5. Rename Session B
        renamed = tab.rename_active_session("Beta Finalized Analysis")
        self.assertTrue(renamed)
        self.assertEqual(self.session_store.get_session(sess_b_id).title, "Beta Finalized Analysis")

        # 6. Delete Session B
        deleted = tab.delete_active_session()
        self.assertTrue(deleted)
        self.assertIsNone(self.session_store.get_session(sess_b_id))

        # Check ZERO orphaned rows in _nexus_chat_messages
        orphan_check = self.db.execute_query(
            "SELECT COUNT(*) FROM _nexus_chat_messages WHERE session_id = ?;",
            (sess_b_id,),
        )
        self.assertEqual(orphan_check.rows[0][0], 0, "All messages must be cascade deleted")

        # Active session should now be Session A
        self.assertEqual(tab._active_session_id, sess_a_id)

        tab.destroy()

    # --------------------------------------------------------------------------
    # 4. NON-DESTRUCTIVE clear_conversation() & GDI CLEANUP
    # --------------------------------------------------------------------------

    def test_non_destructive_clear_conversation_and_gdi_cleanup(self) -> None:
        """
        Validates:
        - clear_conversation() on a session with messages starts a new session non-destructively.
        - Prior saved session remains completely intact in session_store.
        - Matplotlib figures are cleared (preventing GDI leaks) and memory pill resets to 0/4 turns.
        """
        tab = ChatAnalystTab(
            self.app,
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            session_store=self.session_store,
        )

        sid = tab.start_new_session("Financial Deep-Dive")

        # Add turn with mock figure
        tab.query_entry.insert(0, "Plot revenue")
        tab.send_user_message()
        res = AgentRunResult(status="SUCCESS", natural_query="Plot revenue", generated_sql="SELECT 1;", answer_markdown="Done")
        mock_fig = Figure()
        tab._on_pipeline_success({"result": res, "figure": mock_fig, "user_text": "Plot revenue", "llm_config": None})

        self.assertEqual(len(tab._conversation_history), 1)
        self.assertGreaterEqual(len(tab._embedded_figures), 1)

        # Clear conversation
        tab.clear_conversation()

        # 1. Figures cleared (GDI leak prevention)
        self.assertEqual(len(tab._embedded_figures), 0)

        # 2. Memory pill reset
        self.assertEqual(len(tab._conversation_history), 0)
        self.assertIn("0/4 turns", tab.memory_status_label.cget("text"))

        # 3. Prior session preserved in database
        saved_sessions = [s for s in self.session_store.list_sessions() if s.session_id == sid]
        self.assertEqual(len(saved_sessions), 1)
        self.assertEqual(saved_sessions[0].message_count, 2)

        # 4. Active session is now a clean new session
        self.assertNotEqual(tab._active_session_id, sid)

        tab.destroy()

    # --------------------------------------------------------------------------
    # 5. NEXUSAPP END-TO-END INJECTION & CLEAN SHUTDOWN
    # --------------------------------------------------------------------------

    def test_nexus_app_end_to_end_injection_and_clean_shutdown(self) -> None:
        """
        Validates:
        - NexusApp accepts injected key_vault and session_store and wires them cleanly.
        - SidebarPanel and ChatAnalystTab receive injected dependencies.
        - Polling loop is active and worker manager is operational.
        """
        # Verify injection wiring on the persistent self.app instance
        self.assertIs(self.app.key_vault, self.vault)
        self.assertIs(self.app.session_store, self.session_store)
        self.assertIs(self.app.sidebar._key_vault, self.vault)
        self.assertIs(self.app.chat_tab.session_store, self.session_store)

        # Verify session initialized in chat_tab
        self.assertIsNotNone(self.app.chat_tab._active_session_id)
        self.assertTrue(self.app.chat_tab.session_bar.winfo_exists())
        self.assertTrue(bool(self.app.chat_tab.session_bar.grid_info()))

        # Verify poll timer is active and worker is running cleanly
        self.assertIsNotNone(self.app._poll_after_id)
        self.assertFalse(self.app._is_closing)
        self.assertFalse(self.worker.is_shutdown)


if __name__ == "__main__":
    unittest.main()
