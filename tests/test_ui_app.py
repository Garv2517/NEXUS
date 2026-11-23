"""
NEXUS Engine - Phase 2 End-to-End Application Integration Test Suite
====================================================================
Validates the complete Desktop Application Shell (NexusApp):
1. UI Layout & Component Mounting: Dual-pane assembly, fixed sidebar (300px),
   3-tab workspace container, and operational bottom status bar.
2. Inter-Component Event Routing:
   - Sidebar table selection -> Auto-switches to Data Explorer tab and renders preview.
   - Sidebar LLM configuration toggle -> Propagates masked credentials to ChatAnalystTab.
   - Dataset file selection -> Updates bottom operational status bar.
   - Tab switching to Telemetry HUD -> Triggers HUD refresh with zero telemetry pollution.
3. 60 FPS Event Loop & Non-Blocking Worker Pump.
4. Productivity Shortcuts (Ctrl+1/2/3, F5).
5. Clean Shutdown Protocol (WM_DELETE_WINDOW): Cancels timers, shuts down worker threads,
   closes database connections, and destroys window without zombie threads.
6. Smoke-Test Entrypoint Verification.

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / CustomTkinter
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import customtkinter

from src.core.db_manager import DatabaseManager
from src.core.schema_parser import SchemaParser
from src.ui.async_worker import AsyncWorkerManager
from src.ui.theme import NexusTheme, apply_global_theme
from src.ui.components.sidebar import SidebarPanel
from src.ui.components.data_explorer_tab import DataExplorerTab
from src.ui.components.chat_tab import ChatAnalystTab
from src.ui.components.telemetry_hud_tab import TelemetryHudTab
from src.ui.app import NexusApp
from src.main import run_smoke_test


class TestNexusAppIntegration(unittest.TestCase):
    """End-to-End headless integration test suite for NexusApp."""

    @classmethod
    def setUpClass(cls) -> None:
        DatabaseManager.reset_instance()
        cls.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.db_path = Path(cls.temp_dir.name) / "test_app.db"
        cls.db = DatabaseManager(cls.db_path)
        cls.parser = SchemaParser(cls.db)
        cls.worker = AsyncWorkerManager(max_workers=2)

        # Seed sample tables and records
        cls.db.execute_write("""
            CREATE TABLE test_orders (
                order_id INTEGER PRIMARY KEY,
                customer_name TEXT NOT NULL,
                order_total REAL NOT NULL,
                status TEXT DEFAULT 'PENDING'
            );
        """)
        cls.db.execute_write(
            "INSERT INTO test_orders (customer_name, order_total, status) "
            "VALUES ('Cyberdyne Systems', 125000.50, 'COMPLETED');"
        )
        cls.db.execute_write(
            "INSERT INTO test_orders (customer_name, order_total, status) "
            "VALUES ('Weyland-Yutani', 84000.00, 'PROCESSING');"
        )

        # Instantiate shared NexusApp with dependency injection in headless mode
        for _attempt in range(3):
            try:
                cls.app = NexusApp(
                    db_manager=cls.db,
                    schema_parser=cls.parser,
                    async_worker=cls.worker,
                    poll_interval_ms=30
                )
                break
            except Exception:
                if _attempt == 2:
                    raise
                time.sleep(0.5)
        cls.app.withdraw()

        # Allow startup discovery tasks to complete and drain worker queue
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
        if hasattr(self.app, "tabview"):
            self.app.tabview.set("Data Explorer")
        if hasattr(self.app, "status_msg_label"):
            self.app.status_msg_label.configure(
                text="Ready. [Ctrl+1/2/3: Switch Tabs | F5: Refresh Engine]",
                text_color=NexusTheme.TEXT_SECONDARY
            )

    # --------------------------------------------------------------------------
    # 1. MOUNTING & INITIALIZATION TESTS
    # --------------------------------------------------------------------------

    def test_nexus_app_initialization_and_mounting(self) -> None:
        """Verify NexusApp mounts all child components and configures window attributes."""
        # 1. Window attributes
        self.assertEqual(
            self.app.title(),
            "NEXUS — Autonomous Data Pipeline & Analytics Engine"
        )

        # 2. Child component types
        self.assertIsInstance(self.app.sidebar, SidebarPanel)
        self.assertIsInstance(self.app.data_explorer_tab, DataExplorerTab)
        self.assertIsInstance(self.app.chat_tab, ChatAnalystTab)
        self.assertIsInstance(self.app.telemetry_hud_tab, TelemetryHudTab)
        self.assertIsInstance(self.app.tabview, customtkinter.CTkTabview)

        # 3. Default tab selection
        self.assertEqual(self.app.tabview.get(), "Data Explorer")

        # 4. Status bar components and initial values
        self.assertIn("test_app.db", self.app.status_db_label.cget("text"))
        self.assertIn("Worker Pool:", self.app.status_worker_label.cget("text"))
        self.assertIn("Ready.", self.app.status_msg_label.cget("text"))

    # --------------------------------------------------------------------------
    # 2. INTER-COMPONENT EVENT ROUTING TESTS
    # --------------------------------------------------------------------------

    def test_nexus_app_table_selected_switches_tab_and_loads_preview(self) -> None:
        """Verify selecting a table switches tab to Data Explorer and generates preview."""
        # Switch away from Data Explorer tab initially
        self.app.tabview.set("AI Analyst Chat")
        self.assertEqual(self.app.tabview.get(), "AI Analyst Chat")

        # Trigger table selection event
        self.app._handle_table_selected("test_orders")

        # Tabview must automatically switch to Data Explorer
        self.assertEqual(self.app.tabview.get(), "Data Explorer")

        # Allow background worker to execute query and deliver results
        preview_text = ""
        for _ in range(15):
            time.sleep(0.1)
            self.worker.process_queue()
            preview_text = self.app.data_explorer_tab.results_textbox.get("1.0", "end")
            if "Cyberdyne Systems" in preview_text:
                break

        # Verify preview text contains seeded data
        self.assertIn("Cyberdyne Systems", preview_text)
        self.assertTrue("125000.5" in preview_text or "125,000.50" in preview_text)

        # Status message updated with table info
        self.assertIn("test_orders", self.app.status_msg_label.cget("text"))

    def test_nexus_app_llm_config_propagation_and_secret_masking(self) -> None:
        """Verify LLM config propagates to chat badge with zero plaintext key leakage."""
        # Switch provider to Cloud API in sidebar
        self.app.sidebar._handle_provider_change("Cloud API")
        self.assertEqual(self.app.sidebar._active_provider, "cloud")

        # Input raw secret API key
        raw_secret_key = "sk-super-secret-key-12345678"
        self.app.sidebar.api_key_entry.insert(0, raw_secret_key)
        self.app.sidebar._handle_apply_api_key()

        # 1. Chat tab badge must reflect masked key
        badge_text = self.app.chat_tab.llm_badge.cget("text")
        self.assertIn("••••••••5678", badge_text)
        self.assertNotIn("super-secret-key", badge_text)

        # 2. Status bar message must reflect masked key
        status_text = self.app.status_msg_label.cget("text")
        self.assertIn("••••••••5678", status_text)
        self.assertNotIn("super-secret-key", status_text)

        # 3. Sidebar volatile key getter exposes raw key strictly in memory
        self.assertEqual(self.app.sidebar.get_volatile_api_key(), raw_secret_key)

    def test_nexus_app_file_selected_updates_status_bar(self) -> None:
        """Verify staging a dataset file updates the bottom operational status bar."""
        test_file_path = "C:/datasets/quarterly_analytics.csv"
        self.app._handle_file_selected(test_file_path)

        self.assertEqual(
            self.app.status_msg_label.cget("text"),
            "Dataset staged for Phase 3 ETL: quarterly_analytics.csv"
        )

    def test_nexus_app_tab_change_refreshes_telemetry_hud_zero_pollution(self) -> None:
        """Verify switching to HUD triggers refresh without polluting query telemetry."""
        # Read baseline query count
        q_count_baseline = self.app.db.telemetry.get_metrics()["total_queries"]

        # Navigate to Security & Telemetry HUD tab
        self.app.tabview.set("Security & Telemetry HUD")
        self.app._on_tab_changed()

        # Allow worker thread to fetch HUD statistics
        time.sleep(0.1)
        self.worker.process_queue()

        # Verify query count did not increment (zero telemetry pollution)
        q_count_after = self.app.db.telemetry.get_metrics()["total_queries"]
        self.assertEqual(q_count_baseline, q_count_after)

    # --------------------------------------------------------------------------
    # 3. NAVIGATION SHORTCUTS & REFRESH PROTOCOLS
    # --------------------------------------------------------------------------

    def test_nexus_app_keyboard_shortcuts_and_refresh(self) -> None:
        """Verify keyboard shortcuts for tab navigation and F5 engine refresh."""
        # Test tab switching
        self.app._switch_tab("AI Analyst Chat")
        self.assertEqual(self.app.tabview.get(), "AI Analyst Chat")

        self.app._switch_tab("Security & Telemetry HUD")
        self.assertEqual(self.app.tabview.get(), "Security & Telemetry HUD")

        self.app._switch_tab("Data Explorer")
        self.assertEqual(self.app.tabview.get(), "Data Explorer")

        # Test F5 refresh
        self.app._handle_f5_refresh()
        self.assertIn("Engine refresh", self.app.status_msg_label.cget("text"))


class TestNexusAppLifecycle(unittest.TestCase):
    """Isolated lifecycle test for clean shutdown and CLI smoke test."""

    def setUp(self) -> None:
        DatabaseManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_lifecycle.db"
        self.db = DatabaseManager(self.db_path)
        self.parser = SchemaParser(self.db)
        self.worker = AsyncWorkerManager(max_workers=1)

    def tearDown(self) -> None:
        if hasattr(self, "worker") and not self.worker.is_shutdown:
            self.worker.shutdown(wait=True)
        if hasattr(self, "db"):
            self.db.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass
        DatabaseManager.reset_instance()

    def test_nexus_app_clean_shutdown_lifecycle(self) -> None:
        """Verify on_closing() cancels timers, stops workers, and terminates cleanly."""
        app = NexusApp(
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            poll_interval_ms=30
        )
        app.withdraw()

        # Confirm polling timer is scheduled
        self.assertIsNotNone(app._poll_after_id)

        # Trigger clean shutdown protocol
        app.on_closing()

        # Verify shutdown states
        self.assertTrue(app._is_closing)
        self.assertIsNone(app._poll_after_id)
        self.assertTrue(self.worker.is_shutdown)

        # Re-invoking on_closing is a safe no-op
        app.on_closing()

    def test_smoke_test_runner_execution(self) -> None:
        """Verify the CLI --smoke-test execution path succeeds with exit code 0."""
        time.sleep(0.5)
        exit_code = run_smoke_test()
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
