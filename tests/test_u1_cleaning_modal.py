"""
NEXUS Engine - Upgrade U1 Gate 2 Headless Integration Test Suite
================================================================
Comprehensive headless validation of the U1 AI Smart Clean subsystem:
1. CleaningPlanModal rendering, health scorecard badge, PII Shield security banner,
   and dynamic checkbox filtering for get_selected_executor_payload().
2. SidebarPanel AI Smart Clean toggle state and 100% backward compatibility default.
3. End-to-end NexusApp flow with ai_clean=True + mocked LLMRouter:
   async profiling -> CleaningPlanModal -> confirm_apply() -> SQLite ingestion with
   cleaning plan applied -> sidebar schema refresh -> DataExplorer table selection.
4. Modal confirm_skip() executing fast raw ingestion and modal cancel() executing
   zero database writes.
5. Offline Ollama (LLMConnectionError) graceful degradation to heuristic fallback
   without GUI crashes or unhandled exceptions.
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
from unittest.mock import MagicMock

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import customtkinter as ctk

from src.agent.llm_router import (
    LLMConfig,
    LLMConnectionError,
    LLMResponse,
    LLMRouter,
)
from src.core.db_manager import DatabaseManager
from src.core.schema_parser import SchemaParser
from src.etl.ai_profiler import (
    CleaningStep,
    ColumnProfile,
    DatasetProfile,
    PIIFinding,
    ProposedCleaningPlan,
)
from src.ui.app import NexusApp
from src.ui.async_worker import AsyncWorkerManager
from src.ui.components.cleaning_modal import CleaningPlanModal
from src.ui.components.sidebar import SidebarPanel


class TestU1CleaningModalIntegration(unittest.TestCase):
    """Rigorous headless test suite for U1 AI Smart Clean and CleaningPlanModal."""

    @classmethod
    def setUpClass(cls) -> None:
        DatabaseManager.reset_instance()
        cls.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.db_path = Path(cls.temp_dir.name) / "test_u1.db"
        cls.db = DatabaseManager(cls.db_path)
        cls.parser = SchemaParser(cls.db)
        cls.worker = AsyncWorkerManager(max_workers=2)

        # Single persistent app instance in headless mode for clean Windows Tcl resource isolation
        cls.app = NexusApp(
            db_manager=cls.db,
            schema_parser=cls.parser,
            async_worker=cls.worker,
            poll_interval_ms=20,
        )
        cls.app.withdraw()

        # Allow startup model discovery to settle cleanly
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

        # Reset state before each test
        self.app.sidebar.set_ai_clean_enabled(False)
        self.app._active_cleaning_modal = None
        self.worker.process_queue()
        self.app.update_idletasks()

    def tearDown(self) -> None:
        if hasattr(self.app, "_active_cleaning_modal") and self.app._active_cleaning_modal is not None:
            try:
                self.app._active_cleaning_modal.destroy()
            except Exception:
                pass
            self.app._active_cleaning_modal = None

    def _table_exists(self, table_name: str) -> bool:
        result = self.db.execute_query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name = ?;",
            (table_name,)
        )
        return result.row_count > 0

    # --------------------------------------------------------------------------
    # 1. MODAL RENDERING & SELECTION UNIT TESTS
    # --------------------------------------------------------------------------

    def test_cleaning_modal_rendering_and_checkbox_selection(self) -> None:
        """Verify CleaningPlanModal renders health badge, PII shield, and filters unchecked steps."""
        profile = DatasetProfile(
            file_path="C:/data/customers.csv",
            file_name="customers.csv",
            sampled_rows=500,
            estimated_total_rows=2500,
            duplicate_rows_in_sample=12,
            health_score=78,
            health_grade="B",
            pii_findings=[
                PIIFinding(column="email", pii_type="EMAIL", match_count=3),
                PIIFinding(column="ssn", pii_type="SSN", match_count=1),
            ],
            columns=[
                ColumnProfile(
                    raw_name="email",
                    sanitized_name="email",
                    inferred_dtype="TEXT",
                    null_count=0,
                    null_pct=0.0,
                    unique_count=500,
                    has_ragged_whitespace=False,
                    has_mixed_dates=False,
                    sample_values=["[REDACTED_EMAIL]"],
                )
            ],
            anomalies=["Detected 12 duplicate rows in sample", "Detected 1 mixed date format(s)"],
        )

        plan = ProposedCleaningPlan(
            summary="Deduplicate and normalize customers",
            steps=[
                CleaningStep(
                    action="drop_duplicates",
                    params={},
                    reason="Remove duplicate rows from dataset",
                ),
                CleaningStep(
                    action="strip_whitespace",
                    params={"columns": ["name"]},
                    reason="Trim whitespace from customer names",
                ),
            ],
            source="llm",
            model_used="llama3:8b",
        )

        applied_payload: List[Dict[str, Any]] = []

        def _on_apply(payload: List[Dict[str, Any]]) -> None:
            applied_payload.extend(payload)

        modal = CleaningPlanModal(
            master=self.app,
            profile=profile,
            plan=plan,
            on_apply=_on_apply,
            on_skip=lambda: None,
        )

        # 1. Health scorecard badge
        self.assertIn("Health: 78/100 • Grade B", modal.health_badge.cget("text"))

        # 2. PII Shield security banner
        self.assertIsNotNone(modal.pii_banner)
        pii_banner_text = modal.pii_banner.cget("text")
        self.assertIn("PII Shield Active", pii_banner_text)
        self.assertIn("3 EMAIL", pii_banner_text)
        self.assertIn("1 SSN", pii_banner_text)

        # 3. Step selection tracking
        all_steps = modal.get_selected_steps()
        self.assertEqual(len(all_steps), 2)

        # Uncheck step 0 (drop_duplicates)
        modal._step_vars[0].set(False)

        selected_after = modal.get_selected_steps()
        self.assertEqual(len(selected_after), 1)
        self.assertEqual(selected_after[0].action, "strip_whitespace")

        payload = modal.get_selected_executor_payload()
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["action"], "strip_whitespace")
        self.assertEqual(payload[0]["columns"], ["name"])

        # Confirm apply invokes callback and destroys modal
        modal.confirm_apply()
        self.assertEqual(len(applied_payload), 1)
        self.assertEqual(applied_payload[0]["action"], "strip_whitespace")

    # --------------------------------------------------------------------------
    # 2. SIDEBAR TOGGLE BACKWARD COMPATIBILITY TEST
    # --------------------------------------------------------------------------

    def test_sidebar_ai_clean_toggle(self) -> None:
        """Verify SidebarPanel.is_ai_clean_enabled() defaults to False and toggles cleanly."""
        sidebar = self.app.sidebar

        # Invariant: Must default to False for Phase 2/3 test compatibility
        self.assertFalse(sidebar.is_ai_clean_enabled())

        # Toggle to True
        sidebar.set_ai_clean_enabled(True)
        self.assertTrue(sidebar.is_ai_clean_enabled())

        # Toggle back to False
        sidebar.set_ai_clean_enabled(False)
        self.assertFalse(sidebar.is_ai_clean_enabled())

    # --------------------------------------------------------------------------
    # 3. END-TO-END AI SMART CLEAN APPLY FLOW
    # --------------------------------------------------------------------------

    def test_end_to_end_ai_clean_apply_flow(self) -> None:
        """Verify end-to-end NexusApp async profiling -> modal confirm_apply() -> SQLite ingestion."""
        # 1. Create dirty CSV with duplicate row and ragged whitespace
        dirty_csv = Path(self.temp_dir.name) / "sales_dirty.csv"
        with open(dirty_csv, "w", encoding="utf-8") as f:
            f.write("order_id,customer_name,amount\n")
            f.write("1,Acme Corp ,100.50\n")
            f.write("2,Beta LLC,250.00\n")
            f.write("2,Beta LLC,250.00\n")  # Exact duplicate

        # 2. Mock LLMRouter to return a valid cleaning plan
        mock_router = MagicMock(spec=LLMRouter)
        mock_router.invoke.return_value = LLMResponse(
            content=json.dumps({
                "summary": "Clean sales data: deduplicate and strip whitespace",
                "steps": [
                    {
                        "action": "drop_duplicates",
                        "params": {},
                        "reason": "Remove duplicate order 2",
                    },
                    {
                        "action": "strip_whitespace",
                        "params": {"columns": ["customer_name"]},
                        "reason": "Trim whitespace in customer_name",
                    },
                ],
            }),
            provider="local",
            model="llama3:8b",
            prompt_tokens=150,
            completion_tokens=60,
            total_tokens=210,
            latency_ms=18.5,
        )

        self.app.ai_profiler_router_factory = lambda cfg, key_fn: mock_router
        self.app.sidebar.set_ai_clean_enabled(True)

        # Trigger file staging
        self.app._handle_file_selected(str(dirty_csv))

        # Drain worker queue for async profiling task
        timeout = time.time() + 3.0
        while time.time() < timeout and self.app._active_cleaning_modal is None:
            time.sleep(0.05)
            self.worker.process_queue()
            self.app.update_idletasks()

        # Modal should now be active
        modal = self.app._active_cleaning_modal
        self.assertIsNotNone(modal, "CleaningPlanModal should be opened upon profiling completion.")
        self.assertIsInstance(modal, CleaningPlanModal)
        self.assertEqual(len(modal.get_selected_steps()), 2)

        # Confirm apply
        modal.confirm_apply()

        # Drain worker queue for ETL ingestion task
        timeout = time.time() + 3.0
        target_table = "sales_dirty"
        while time.time() < timeout:
            time.sleep(0.05)
            self.worker.process_queue()
            self.app.update_idletasks()
            if self._table_exists(target_table):
                break

        # Verify table exists in SQLite
        self.assertTrue(self._table_exists(target_table))

        # Verify duplicate row was dropped: exactly 2 rows remain
        result = self.db.execute_query(f"SELECT * FROM {target_table};")
        self.assertEqual(result.row_count, 2)

        # Verify whitespace was stripped
        rows = result.to_dicts()
        names = [r["customer_name"] for r in rows]
        self.assertIn("Acme Corp", names)
        self.assertNotIn("Acme Corp ", names)

        # Verify Data Explorer tab is active
        current_tab = self.app.tabview.get()
        self.assertEqual(current_tab, "Data Explorer")

    # --------------------------------------------------------------------------
    # 4. MODAL CONFIRM_SKIP & CANCEL PROTOCOLS
    # --------------------------------------------------------------------------

    def test_modal_confirm_skip_runs_raw_ingestion(self) -> None:
        """Verify confirm_skip() ignores proposed plan and performs raw ingestion."""
        skip_csv = Path(self.temp_dir.name) / "skip_test.csv"
        with open(skip_csv, "w", encoding="utf-8") as f:
            f.write("code,description\n")
            f.write("A1,First\n")
            f.write("A2,Second\n")

        mock_router = MagicMock(spec=LLMRouter)
        mock_router.invoke.return_value = LLMResponse(
            content=json.dumps({
                "summary": "Deduplicate",
                "steps": [{"action": "drop_duplicates", "params": {}, "reason": "Drop dups"}],
            }),
            provider="local",
            model="llama3:8b",
            prompt_tokens=100,
            completion_tokens=40,
            total_tokens=140,
            latency_ms=10.0,
        )

        self.app.ai_profiler_router_factory = lambda cfg, key_fn: mock_router
        self.app.sidebar.set_ai_clean_enabled(True)

        self.app._handle_file_selected(str(skip_csv))

        # Wait for modal
        timeout = time.time() + 3.0
        while time.time() < timeout and self.app._active_cleaning_modal is None:
            time.sleep(0.05)
            self.worker.process_queue()
            self.app.update_idletasks()

        modal = self.app._active_cleaning_modal
        self.assertIsNotNone(modal)

        # Skip plan (raw ingest without CleaningPlanExecutor)
        modal.confirm_skip()

        timeout = time.time() + 3.0
        target_table = "skip_test"
        while time.time() < timeout:
            time.sleep(0.05)
            self.worker.process_queue()
            self.app.update_idletasks()
            if self._table_exists(target_table):
                break

        self.assertTrue(self._table_exists(target_table))
        result = self.db.execute_query(f"SELECT * FROM {target_table};")
        self.assertGreaterEqual(result.row_count, 1)

    def test_modal_cancel_performs_zero_database_writes(self) -> None:
        """Verify modal.cancel() stops the ingestion pipeline and writes nothing to SQLite."""
        cancel_csv = Path(self.temp_dir.name) / "cancel_test.csv"
        with open(cancel_csv, "w", encoding="utf-8") as f:
            f.write("col_a,col_b\n")
            f.write("val1,val2\n")

        mock_router = MagicMock(spec=LLMRouter)
        mock_router.invoke.return_value = LLMResponse(
            content=json.dumps({
                "summary": "Clean",
                "steps": [
                    {
                        "action": "strip_whitespace",
                        "params": {"columns": ["col_a"]},
                        "reason": "Trim whitespace",
                    }
                ],
            }),
            provider="local",
            model="llama3:8b",
            prompt_tokens=50,
            completion_tokens=20,
            total_tokens=70,
            latency_ms=10.0,
        )

        self.app.ai_profiler_router_factory = lambda cfg, key_fn: mock_router
        self.app.sidebar.set_ai_clean_enabled(True)

        self.app._handle_file_selected(str(cancel_csv))

        # Wait for modal
        timeout = time.time() + 3.0
        while time.time() < timeout and self.app._active_cleaning_modal is None:
            time.sleep(0.05)
            self.worker.process_queue()
            self.app.update_idletasks()

        modal = self.app._active_cleaning_modal
        self.assertIsNotNone(modal)

        # Cancel ingestion
        modal.cancel()
        self.worker.process_queue()
        self.app.update_idletasks()

        # Verify table was never written to SQLite
        self.assertFalse(self._table_exists("cancel_test"))
        self.assertIsNone(self.app._active_cleaning_modal)
        self.assertIn("cancelled", self.app.status_msg_label.cget("text").lower())

    # --------------------------------------------------------------------------
    # 5. OFFLINE OLLAMA FALLBACK TEST
    # --------------------------------------------------------------------------

    def test_offline_ollama_graceful_heuristic_fallback(self) -> None:
        """Verify offline Ollama raises LLMConnectionError but gracefully degrades to heuristic plan."""
        offline_csv = Path(self.temp_dir.name) / "offline_test.csv"
        with open(offline_csv, "w", encoding="utf-8") as f:
            f.write("id,title,score\n")
            f.write("1,Alpha ,10\n")
            f.write("1,Alpha ,10\n")  # duplicate

        def _offline_router(cfg: LLMConfig, key_fn: Any) -> LLMRouter:
            router = MagicMock(spec=LLMRouter)
            router.invoke.side_effect = LLMConnectionError("Ollama daemon is unreachable on port 11434")
            return router

        self.app.ai_profiler_router_factory = _offline_router
        self.app.sidebar.set_ai_clean_enabled(True)

        self.app._handle_file_selected(str(offline_csv))

        # Wait for modal
        timeout = time.time() + 3.0
        while time.time() < timeout and self.app._active_cleaning_modal is None:
            time.sleep(0.05)
            self.worker.process_queue()
            self.app.update_idletasks()

        modal = self.app._active_cleaning_modal
        self.assertIsNotNone(modal, "Modal should open even when Ollama is offline via heuristic fallback.")
        self.assertEqual(modal.plan.source, "heuristic_fallback")
        self.assertIsNotNone(modal.plan.warning_message)

        # Apply heuristic plan
        modal.confirm_apply()

        timeout = time.time() + 3.0
        target_table = "offline_test"
        while time.time() < timeout:
            time.sleep(0.05)
            self.worker.process_queue()
            self.app.update_idletasks()
            if self._table_exists(target_table):
                break

        self.assertTrue(self._table_exists(target_table))
        result = self.db.execute_query(f"SELECT * FROM {target_table};")
        self.assertEqual(result.row_count, 1)  # Deduplicated via heuristic fallback!
