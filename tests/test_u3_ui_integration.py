"""
NEXUS Engine - Upgrade U3 & U3.5 Gate 2 Headless UI Integration Test Suite
==========================================================================
Comprehensive headless validation of U3 & U3.5 UI and Core enhancements:
1. Sortable and Searchable Treeview Grid (DataExplorerTab):
   - Scoped dark ttk.Treeview with alternating row tags.
   - Numeric-aware ascending/descending column sorting with heading glyphs.
   - Live search filter across columns with synchronized ASCII textbox fallback.
2. Explorer CSV and XLSX Export (DataExplorerTab):
   - Asynchronous export of QueryResult to CSV and XLSX.
   - OWASP formula injection neutralization in exported cells.
3. Chat Tab Export Actions (ChatAnalystTab):
   - Action buttons for CSV and Executive Brief export.
   - XSS-sanitized HTML and structured Markdown output.
4. Multi-Sheet Excel Ingestion Flow (NexusApp & SheetPickerModal):
   - Multi-sheet workbook detection and modal dialog surfacing.
   - Sheet selection routing into AI profiler and ETL engine.
5. Guarded Table Rename and Drop (NexusApp & SidebarPanel & TableManager):
   - Table selection tracking and action button state management.
   - Namespace-guarded drop and rename protecting _nexus_* and sqlite_*.

Author: Senior Systems & Security Engineer
Platform: Windows 11 (Python 3.13) / CustomTkinter / ttk
"""

from __future__ import annotations

import html
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import customtkinter
import openpyxl

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.sql_chain import AgentRunResult
from src.core.db_manager import DatabaseManager, QueryResult
from src.core.export_engine import DataExportEngine, ExecutiveBriefExporter
from src.core.schema_parser import SchemaParser
from src.core.table_manager import TableManager, TableManagerError
from src.etl.etl_engine import ETLEngine, ETLReport
from src.ui.app import NexusApp
from src.ui.async_worker import AsyncWorkerManager
from src.ui.components.chat_tab import ChatAnalystTab
from src.ui.components.data_explorer_tab import DataExplorerTab
from src.ui.components.sheet_picker_modal import SheetPickerModal
from src.ui.components.sidebar import SidebarPanel


class TestU3UIIntegration(unittest.TestCase):
    """Rigorous headless integration test suite for U3 & U3.5 Gate 2 features."""

    @classmethod
    def setUpClass(cls) -> None:
        DatabaseManager.reset_instance()
        cls.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        cls.db_path = Path(cls.temp_dir.name) / "test_u3_ui.db"
        cls.db = DatabaseManager(cls.db_path)
        cls.parser = SchemaParser(cls.db)
        cls.worker = AsyncWorkerManager(max_workers=2)

        # Seed test items table with mixed numeric, string, and dangerous formula data
        cls.db.execute_write("""
            CREATE TABLE IF NOT EXISTS inventory_items (
                item_id INTEGER PRIMARY KEY,
                product_name TEXT NOT NULL,
                unit_price REAL NOT NULL,
                category TEXT
            );
        """)
        cls.db.execute_write("DELETE FROM inventory_items;")
        cls.db.execute_write("INSERT INTO inventory_items VALUES (1, 'Alpha Widget', 10.50, 'Hardware');")
        cls.db.execute_write("INSERT INTO inventory_items VALUES (2, 'Beta Gadget', 99.90, 'Electronics');")
        cls.db.execute_write("INSERT INTO inventory_items VALUES (3, 'Gamma Device', 5.25, 'Hardware');")

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
        if hasattr(self.app, "tabview"):
            self.app.tabview.set("Data Explorer")

    # --------------------------------------------------------------------------
    # 1. SORTABLE AND SEARCHABLE TREEVIEW GRID
    # --------------------------------------------------------------------------

    def test_sortable_and_searchable_treeview_grid(self) -> None:
        """
        Validates DataExplorerTab's sortable and searchable ttk.Treeview grid:
        1. Correct columns and headings rendered.
        2. Numeric-aware ascending and descending sorting.
        3. Real-time grid row filtering while preserving ASCII textbox synchronization.
        """
        explorer = self.app.data_explorer_tab

        # Seed test items table with mixed numeric, string, and dangerous formula data
        self.db.execute_write("""
            CREATE TABLE IF NOT EXISTS inventory_items (
                item_id INTEGER PRIMARY KEY,
                product_name TEXT NOT NULL,
                unit_price REAL NOT NULL,
                category TEXT
            );
        """)
        self.db.execute_write("DELETE FROM inventory_items;")
        self.db.execute_write("INSERT INTO inventory_items VALUES (1, 'Alpha Widget', 10.50, 'Hardware');")
        self.db.execute_write("INSERT INTO inventory_items VALUES (2, 'Beta Gadget', 99.90, 'Electronics');")
        self.db.execute_write("INSERT INTO inventory_items VALUES (3, 'Gamma Device', 5.25, 'Hardware');")

        # Execute query via scratchpad
        explorer.load_and_execute_sql("SELECT item_id, product_name, unit_price, category FROM inventory_items ORDER BY item_id ASC;")

        for _ in range(15):
            time.sleep(0.1)
            self.worker.process_queue()
            if explorer.results_tree.get_children():
                break

        self.app.update_idletasks()

        # 1. Verify Treeview Columns & Initial Rows
        children = explorer.results_tree.get_children()
        self.assertEqual(len(children), 3)

        first_vals = explorer.results_tree.item(children[0])["values"]
        self.assertEqual(first_vals[0], 1)
        self.assertEqual(first_vals[1], "Alpha Widget")

        # 2. Test Numeric-Aware Sorting on unit_price column
        # Ascending: Gamma Device (5.25) should be first
        explorer.sort_by_column("unit_price", descending=False)
        self.app.update_idletasks()
        sorted_asc = explorer.results_tree.get_children()
        first_asc_vals = explorer.results_tree.item(sorted_asc[0])["values"]
        self.assertEqual(first_asc_vals[1], "Gamma Device")

        # Descending: Beta Gadget (99.90) should be first
        explorer.sort_by_column("unit_price", descending=True)
        self.app.update_idletasks()
        sorted_desc = explorer.results_tree.get_children()
        first_desc_vals = explorer.results_tree.item(sorted_desc[0])["values"]
        self.assertEqual(first_desc_vals[1], "Beta Gadget")

        # 3. Test Real-Time Grid Filtering
        # Filter for 'Electronics' -> only Beta Gadget remains
        match_count = explorer.filter_grid("Electronics")
        self.assertEqual(match_count, 1)
        filtered_children = explorer.results_tree.get_children()
        self.assertEqual(len(filtered_children), 1)
        filtered_vals = explorer.results_tree.item(filtered_children[0])["values"]
        self.assertEqual(filtered_vals[1], "Beta Gadget")

        # Verify results_textbox remains populated and synchronized
        textbox_content = explorer.results_textbox.get("1.0", "end")
        self.assertIn("Beta Gadget", textbox_content)

        # Clear filter -> all 3 rows restored
        all_count = explorer.filter_grid("")
        self.assertEqual(all_count, 3)
        self.assertEqual(len(explorer.results_tree.get_children()), 3)

    # --------------------------------------------------------------------------
    # 2. EXPLORER CSV AND XLSX EXPORT
    # --------------------------------------------------------------------------

    def test_explorer_csv_and_xlsx_export(self) -> None:
        """
        Validates DataExplorerTab export_last_result helper:
        1. Exports QueryResult to CSV with formula neutralization.
        2. Exports QueryResult to XLSX with valid openpyxl readable workbook.
        """
        explorer = self.app.data_explorer_tab

        # Seed formula-injected row
        self.db.execute_write("INSERT INTO inventory_items VALUES (4, '=CMD|\" /C calc\"!A0', 0.0, 'Dangerous');")
        explorer.load_and_execute_sql("SELECT item_id, product_name, unit_price FROM inventory_items WHERE item_id = 4;")

        for _ in range(15):
            time.sleep(0.1)
            self.worker.process_queue()
            if explorer._last_result is not None and explorer._last_result.row_count > 0:
                break

        self.app.update_idletasks()
        self.assertIsNotNone(explorer._last_result)

        # Export CSV
        csv_path = Path(self.temp_dir.name) / "test_explorer_export.csv"
        explorer.export_last_result(str(csv_path), fmt="csv")

        # Drain worker queue for async export
        for _ in range(10):
            time.sleep(0.05)
            self.worker.process_queue()
            if csv_path.exists():
                break

        self.assertTrue(csv_path.exists())
        csv_text = csv_path.read_text(encoding="utf-8")
        self.assertIn("'=CMD", csv_text)

        # Export XLSX
        xlsx_path = Path(self.temp_dir.name) / "test_explorer_export.xlsx"
        explorer.export_last_result(str(xlsx_path), fmt="xlsx")

        for _ in range(10):
            time.sleep(0.05)
            self.worker.process_queue()
            if xlsx_path.exists():
                break

        self.assertTrue(xlsx_path.exists())
        wb = openpyxl.load_workbook(xlsx_path)
        ws = wb.active
        self.assertIsNotNone(ws)
        # Check formula neutralization in cell
        found_cell = False
        for row in ws.iter_rows(values_only=True):
            for cell in row:
                if isinstance(cell, str) and "=CMD" in cell:
                    self.assertTrue(cell.startswith("'=CMD"))
                    found_cell = True
        self.assertTrue(found_cell)
        wb.close()

    # --------------------------------------------------------------------------
    # 3. CHAT EXECUTIVE BRIEF & CSV EXPORT
    # --------------------------------------------------------------------------

    def test_chat_executive_brief_export(self) -> None:
        """
        Validates ChatAnalystTab export actions:
        1. export_executive_brief (HTML): XSS-safe executive summary.
        2. export_executive_brief (Markdown): Structured markdown summary.
        3. export_result_csv: Turn data tabular CSV export.
        """
        chat = self.app.chat_tab

        # Construct simulated AgentRunResult with malicious script tags to test XSS sanitization
        query_res = QueryResult(
            sql="SELECT metric, value FROM metrics WHERE value > 1000;",
            columns=("metric", "value"),
            rows=[("Revenue", 150000.00), ("MaliciousTag", "<script>alert('xss')</script>")],
            row_count=2,
            execution_time_ms=1.45,
        )
        agent_result = AgentRunResult(
            natural_query="Summarize quarterly metrics & <script>doBad()</script>",
            generated_sql="SELECT metric, value FROM metrics WHERE value > 1000;",
            query_result=query_res,
            answer_markdown="Executive Overview:\n- Revenue achieved **$150,000.00**.\n- Alert: <script>steal()</script>",
            status="SUCCESS",
            model="llama3:8b",
            provider="local",
            total_latency_ms=120.5,
            total_tokens=65,
        )

        # 1. HTML Brief Export
        html_path = Path(self.temp_dir.name) / "chat_brief.html"
        chat.export_executive_brief(agent_result, html_path)

        for _ in range(10):
            time.sleep(0.05)
            self.worker.process_queue()
            if html_path.exists():
                break

        self.assertTrue(html_path.exists())
        html_content = html_path.read_text(encoding="utf-8")
        self.assertIn("NEXUS Executive Brief", html_content)
        self.assertIn("SELECT metric, value FROM metrics", html_content)
        # XSS defenses: raw script tags must NOT appear
        self.assertNotIn("<script>doBad()</script>", html_content)
        self.assertNotIn("<script>alert('xss')</script>", html_content)
        self.assertIn("&lt;script&gt;doBad()&lt;/script&gt;", html_content)

        # 2. Markdown Brief Export
        md_path = Path(self.temp_dir.name) / "chat_brief.md"
        chat.export_executive_brief(agent_result, md_path)

        for _ in range(10):
            time.sleep(0.05)
            self.worker.process_queue()
            if md_path.exists():
                break

        self.assertTrue(md_path.exists())
        md_content = md_path.read_text(encoding="utf-8")
        self.assertIn("# NEXUS Analytical Executive Brief", md_content)
        self.assertIn("```sql", md_content)
        self.assertIn("Revenue", md_content)

        # 3. CSV Export
        csv_path = Path(self.temp_dir.name) / "chat_result.csv"
        chat.export_result_csv(agent_result, csv_path)

        for _ in range(10):
            time.sleep(0.05)
            self.worker.process_queue()
            if csv_path.exists():
                break

        self.assertTrue(csv_path.exists())
        csv_lines = csv_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(csv_lines[0].lstrip("\ufeff").strip(), "metric,value")
        self.assertIn("Revenue,150000.0", csv_lines[1])

    # --------------------------------------------------------------------------
    # 4. MULTI-SHEET EXCEL INGESTION FLOW
    # --------------------------------------------------------------------------

    def test_multi_sheet_excel_picker_flow(self) -> None:
        """
        Validates multi-sheet Excel selection flow:
        1. Detects multi-sheet .xlsx workbook upon selection.
        2. Surfaces SheetPickerModal without blocking.
        3. Ingests chosen sheet ('Financials') into SQLite with collision-safe table name.
        """
        # Create multi-sheet workbook fixture
        wb = openpyxl.Workbook()
        ws1 = wb.active
        ws1.title = "Overview"
        ws1.append(["Title", "Status"])
        ws1.append(["Project Titan", "Active"])

        ws2 = wb.create_sheet(title="Financials")
        ws2.append(["Quarter", "NetProfit", "MarginPct"])
        ws2.append(["Q1", 450000.0, 0.24])
        ws2.append(["Q2", 520000.0, 0.28])

        workbook_path = Path(self.temp_dir.name) / "corporate_q2.xlsx"
        wb.save(workbook_path)
        wb.close()

        # Disable AI Smart Clean toggle for direct ETL verification
        self.app.sidebar.set_ai_clean_enabled(False)

        # Trigger file selection
        self.app._handle_file_selected(str(workbook_path))

        # Modal should be surfaced
        self.assertIsNotNone(self.app._active_sheet_modal)
        modal = self.app._active_sheet_modal
        self.assertEqual(modal.sheet_names, ["Overview", "Financials"])

        # Select 'Financials' worksheet
        modal.confirm_select("Financials")
        self.assertIsNone(self.app._active_sheet_modal)

        # Allow background ETL ingestion to complete
        for _ in range(25):
            time.sleep(0.1)
            self.worker.process_queue()
            tables = self.parser.get_table_names()
            if any("financials" in t.lower() for t in tables):
                break

        self.app.update_idletasks()

        # Verify ingested table in database
        tables = self.parser.get_table_names()
        matching_tables = [t for t in tables if "financials" in t.lower()]
        self.assertTrue(len(matching_tables) > 0, f"Expected table with 'financials' in name, got: {tables}")

        financials_table = matching_tables[0]
        schema = self.parser.inspect_table(financials_table)
        col_names = [c.name.lower() for c in schema.columns]
        self.assertIn("quarter", col_names)
        self.assertIn("netprofit", col_names)
        self.assertIn("marginpct", col_names)

    # --------------------------------------------------------------------------
    # 5. GUARDED TABLE RENAME AND DROP
    # --------------------------------------------------------------------------

    def test_guarded_table_rename_and_drop(self) -> None:
        """
        Validates table management lifecycle & security safeguards:
        1. Tracks table selection in SidebarPanel.
        2. Renames user table asynchronously and invalidates schema cache.
        3. Drops user table asynchronously.
        4. Defends protected namespaces (_nexus_*, sqlite_*) against drop/rename attempts.
        """
        # Create user table
        self.db.execute_write("""
            CREATE TABLE IF NOT EXISTS customer_leads (
                lead_id INTEGER PRIMARY KEY,
                company_name TEXT NOT NULL
            );
        """)
        self.db.execute_write("INSERT INTO customer_leads VALUES (1, 'Cyberdyne');")

        self.app.sidebar.refresh_schema()
        for _ in range(10):
            time.sleep(0.05)
            self.worker.process_queue()

        self.app.update_idletasks()

        # Select table in sidebar
        self.app.sidebar._handle_table_click("customer_leads")
        self.assertEqual(self.app.sidebar.get_selected_table(), "customer_leads")
        self.assertEqual(self.app.sidebar.rename_table_btn.cget("state"), "normal")
        self.assertEqual(self.app.sidebar.drop_table_btn.cget("state"), "normal")

        # 1. Rename table: customer_leads -> active_leads
        self.app._handle_rename_table("customer_leads", "active_leads")

        for _ in range(15):
            time.sleep(0.1)
            self.worker.process_queue()
            tables = self.parser.get_table_names()
            if "active_leads" in tables:
                break

        self.app.update_idletasks()
        tables = self.parser.get_table_names()
        self.assertIn("active_leads", tables)
        self.assertNotIn("customer_leads", tables)

        # 2. Drop table: active_leads
        self.app._handle_drop_table("active_leads")

        for _ in range(15):
            time.sleep(0.1)
            self.worker.process_queue()
            tables = self.parser.get_table_names()
            if "active_leads" not in tables:
                break

        self.app.update_idletasks()
        tables = self.parser.get_table_names()
        self.assertNotIn("active_leads", tables)

        # 3. Security Safeguards: Attempting to modify protected tables
        # Attempt to select protected table
        self.app.sidebar._handle_table_click("_nexus_query_audit")
        self.assertEqual(self.app.sidebar.get_selected_table(), "_nexus_query_audit")
        # Action buttons must be disabled for protected tables
        self.assertEqual(self.app.sidebar.rename_table_btn.cget("state"), "disabled")
        self.assertEqual(self.app.sidebar.drop_table_btn.cget("state"), "disabled")

        # Direct TableManager drop attempt on _nexus_query_audit must raise TableManagerError
        with self.assertRaises(TableManagerError):
            self.app.table_manager.drop_table("_nexus_query_audit")

        # Direct TableManager rename attempt on _nexus_query_audit must raise TableManagerError
        with self.assertRaises(TableManagerError):
            self.app.table_manager.rename_table("_nexus_query_audit", "hacked_audit")

        # Verify _nexus_query_audit table remains intact and functional
        audit_check = self.db.execute_query("SELECT COUNT(*) FROM _nexus_query_audit;")
        self.assertEqual(audit_check.row_count, 1)


if __name__ == "__main__":
    unittest.main()
