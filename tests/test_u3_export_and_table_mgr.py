"""
NEXUS Engine - Upgrade U3 & U3.5 Gate 1 Test Suite
===================================================
Comprehensive unit & integration tests covering:
1. OWASP CSV/Excel Formula Injection Defense (CSV & XLSX exports).
2. Standalone Executive Brief export (Markdown & XSS-hardened HTML with Base64 chart embedding).
3. TableManager lifecycle (safe drop, safe rename, cache invalidation, audit logging,
   and strict protection of _nexus_* / sqlite_* internal tables).
4. Multi-sheet Excel inspection and collision-proof ingestion (ETLEngine & AIDataProfiler).

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import csv
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, List

import openpyxl
from matplotlib.figure import Figure

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.sql_chain import AgentRunResult
from src.core.db_manager import DatabaseManager, QueryResult
from src.core.export_engine import (
    DataExportEngine,
    ExecutiveBriefExporter,
    sanitize_spreadsheet_cell,
)
from src.core.schema_parser import SchemaParser
from src.core.table_manager import TableManager, TableManagerError
from src.etl.ai_profiler import AIDataProfiler
from src.etl.etl_engine import ETLEngine


class TestU3ExportAndTableManager(unittest.TestCase):
    """Rigorous verification suite for Upgrade U3 + U3.5 core deliverables."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "test_u3.db"
        self.db = DatabaseManager(self.db_path)
        self.parser = SchemaParser(self.db)
        self.table_mgr = TableManager(self.db, self.parser)
        self.etl = ETLEngine(self.db, self.parser)
        self.profiler = AIDataProfiler()

    def tearDown(self) -> None:
        self.db.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass
        DatabaseManager.reset_instance()

    # --------------------------------------------------------------------------
    # 1. OWASP FORMULA INJECTION DEFENSE (CSV & XLSX)
    # --------------------------------------------------------------------------

    def test_sanitize_spreadsheet_cell_rules(self) -> None:
        """Validates all OWASP formula injection neutralization rules."""
        # 1. Dangerous formula triggers neutralized
        self.assertEqual(sanitize_spreadsheet_cell("=SUM(A1:A5)"), "'=SUM(A1:A5)")
        self.assertEqual(sanitize_spreadsheet_cell("+cmd|' /C calc'!A0"), "'+cmd|' /C calc'!A0")
        self.assertEqual(sanitize_spreadsheet_cell("-2+3"), "'-2+3")
        self.assertEqual(sanitize_spreadsheet_cell("@HYPERLINK('http://evil.com')"), "'@HYPERLINK('http://evil.com')")
        self.assertEqual(sanitize_spreadsheet_cell("\tTabTrigger"), "'\tTabTrigger")
        self.assertEqual(sanitize_spreadsheet_cell("\rReturnTrigger"), "'\rReturnTrigger")

        # Leading whitespace before trigger still caught
        self.assertEqual(sanitize_spreadsheet_cell("   =DANGEROUS()"), "'   =DANGEROUS()")

        # 2. Genuine numbers (int, float) preserved without single quotes
        self.assertEqual(sanitize_spreadsheet_cell(-42.5), -42.5)
        self.assertIsInstance(sanitize_spreadsheet_cell(-42.5), float)
        self.assertEqual(sanitize_spreadsheet_cell(-100), -100)
        self.assertIsInstance(sanitize_spreadsheet_cell(-100), int)
        self.assertEqual(sanitize_spreadsheet_cell(0), 0)

        # 3. Safe values preserved
        self.assertEqual(sanitize_spreadsheet_cell("Acme Corp"), "Acme Corp")
        self.assertEqual(sanitize_spreadsheet_cell(None), None)
        self.assertEqual(sanitize_spreadsheet_cell(True), True)
        self.assertEqual(sanitize_spreadsheet_cell(False), False)

    def test_export_csv_and_excel_formula_injection_defense(self) -> None:
        """
        Validates CSV and XLSX exports neutralize dangerous formulas while
        preserving genuine numeric values.
        """
        columns = ["id", "name", "amount", "formula_calc", "formula_sum", "formula_link", "formula_minus"]
        rows = [
            [101, "Acme Corp", -42.5, "+cmd|' /C calc'!A0", "=SUM(A1:A5)", "@HYPERLINK('http://evil.com')", "-2+3"],
            [102, "Beta LLC", 1500.0, "normal", "plain text", "user@nexus.ai", -10],
        ]

        # --- A. CSV Export ---
        csv_file = self.temp_path / "exports" / "test_export.csv"
        out_csv = DataExportEngine.export_csv(columns, rows, csv_file, neutralize_formulas=True)
        self.assertTrue(out_csv.exists())

        # Verify UTF-8 with BOM and formula neutralization
        with open(out_csv, mode="r", encoding="utf-8-sig") as f:
            reader = list(csv.reader(f))
            header = reader[0]
            row1 = reader[1]
            row2 = reader[2]

            self.assertEqual(header, columns)
            # Row 1: string formulas neutralized
            self.assertEqual(row1[3], "'+cmd|' /C calc'!A0")
            self.assertEqual(row1[4], "'=SUM(A1:A5)")
            self.assertEqual(row1[5], "'@HYPERLINK('http://evil.com')")
            self.assertEqual(row1[6], "'-2+3")
            # Genuine negative float preserved as string of number
            self.assertEqual(row1[2], "-42.5")

        # --- B. Excel Export ---
        xlsx_file = self.temp_path / "exports" / "test_export.xlsx"
        out_xlsx = DataExportEngine.export_excel(columns, rows, xlsx_file, sheet_name="Security_Audit")
        self.assertTrue(out_xlsx.exists())

        wb = openpyxl.load_workbook(out_xlsx)
        self.assertIn("Security_Audit", wb.sheetnames)
        ws = wb["Security_Audit"]

        # Freeze panes verified
        self.assertEqual(ws.freeze_panes, "A2")

        # Verify values in sheet
        self.assertEqual(ws["D2"].value, "'+cmd|' /C calc'!A0")
        self.assertEqual(ws["E2"].value, "'=SUM(A1:A5)")
        self.assertEqual(ws["F2"].value, "'@HYPERLINK('http://evil.com')")
        self.assertEqual(ws["G2"].value, "'-2+3")
        # Genuine numeric values in Excel
        self.assertEqual(ws["C2"].value, -42.5)
        self.assertIsInstance(ws["C2"].value, (int, float))
        self.assertEqual(ws["G3"].value, -10)
        self.assertIsInstance(ws["G3"].value, (int, float))

        # Header styling verified
        header_cell = ws["A1"]
        self.assertTrue(header_cell.font.bold)

        # Column widths auto-fitted and clamped to [10, 48]
        for col_letter, dim in ws.column_dimensions.items():
            if dim.width is not None:
                self.assertGreaterEqual(dim.width, 10)
                self.assertLessEqual(dim.width, 48)

        wb.close()

    # --------------------------------------------------------------------------
    # 2. EXECUTIVE BRIEF XSS DEFENSE & BASE64 CHART EMBEDDING (U3.5)
    # --------------------------------------------------------------------------

    def test_executive_brief_xss_and_base64_chart_embedding(self) -> None:
        """
        Validates:
        - HTML export strictly escapes all dynamic content via html.escape(..., quote=True).
        - Zero unescaped <script> tags present anywhere in the HTML document.
        - Dark Matplotlib figure rendered to Base64 data URI and embedded directly.
        - Markdown export contains metadata, SQL block, and formatted table preview.
        """
        # Create dark Matplotlib Figure
        fig = Figure(figsize=(5, 3))
        ax = fig.add_subplot(111)
        ax.plot([1, 2, 3], [10, 25, 40], color="#00F0FF")
        ax.set_title("Test Chart")

        qr = QueryResult(
            columns=["order_id", "xss_col<script>"],
            rows=[
                (1001, "<script>alert('cell_xss')</script>"),
                (1002, 239365.96000000002),
            ],
            row_count=2,
            execution_time_ms=12.5,
            sql="SELECT order_id, gross_amount FROM orders;",
            truncated=False,
        )

        result = AgentRunResult(
            natural_query="Show total sales <script>alert('xss_query')</script>",
            generated_sql="SELECT order_id, gross_amount FROM orders WHERE status = 'OK';",
            query_result=qr,
            answer_markdown="Executive analysis showing <script>document.cookie</script> and total revenue.",
            model="llama3:8b",
            provider="local",
            status="SUCCESS",
            total_latency_ms=85.4,
            total_tokens=120,
            tables_in_context=("orders",),
            was_pruned=False,
        )

        # --- A. HTML Brief Export ---
        html_file = self.temp_path / "reports" / "brief.html"
        out_html = ExecutiveBriefExporter.export_html(result, html_file, figure=fig)
        self.assertTrue(out_html.exists())

        with open(out_html, mode="r", encoding="utf-8") as f:
            html_content = f.read()

        # Strict XSS Assertions:
        self.assertNotIn("<script>", html_content)
        self.assertNotIn("</script>", html_content)
        self.assertIn("&lt;script&gt;alert(&#x27;xss_query&#x27;)&lt;/script&gt;", html_content)
        self.assertIn("&lt;script&gt;alert(&#x27;cell_xss&#x27;)&lt;/script&gt;", html_content)
        self.assertIn("&lt;script&gt;document.cookie&lt;/script&gt;", html_content)

        # Base64 chart embedding verified
        self.assertIn("data:image/png;base64,", html_content)
        self.assertIn('class="chart-img"', html_content)

        # Clean numeric formatting verified (IEEE-754 noise stripped)
        self.assertIn("239,365.96", html_content)
        self.assertNotIn("239365.96000000002", html_content)

        # --- B. Markdown Brief Export ---
        md_file = self.temp_path / "reports" / "brief.md"
        out_md = ExecutiveBriefExporter.export_markdown(result, md_file)
        self.assertTrue(out_md.exists())

        with open(out_md, mode="r", encoding="utf-8") as f:
            md_content = f.read()

        self.assertIn("# NEXUS Analytical Executive Brief", md_content)
        self.assertIn("llama3:8b", md_content)
        self.assertIn("85.40 ms", md_content)
        self.assertIn("SELECT order_id, gross_amount FROM orders", md_content)
        self.assertIn("239,365.96", md_content)

    # --------------------------------------------------------------------------
    # 3. TABLE MANAGER SECURITY & LIFECYCLE
    # --------------------------------------------------------------------------

    def test_table_manager_security_and_lifecycle(self) -> None:
        """
        Validates:
        - rename_table sanitizes names, updates schema, invalidates cache, and logs audit.
        - drop_table safely removes tables and views, invalidates cache, and logs audit.
        - Protected system tables (_nexus_*, sqlite_*) cannot be dropped or renamed.
        - Collision detection prevents renaming over an existing table.
        """
        # Seed test table
        self.db.execute_write("""
            CREATE TABLE raw_sales (
                order_id INTEGER PRIMARY KEY,
                item_name TEXT NOT NULL,
                revenue REAL NOT NULL
            );
        """)
        self.db.execute_write("INSERT INTO raw_sales VALUES (1, 'Widget Alpha', 500.0);")
        self.parser.invalidate_cache()
        self.assertIn("raw_sales", self.parser.get_table_names())

        # 1. Valid Table Rename
        sanitized_name = self.table_mgr.rename_table("raw_sales", "Clean Sales 2026")
        self.assertEqual(sanitized_name, "clean_sales_2026")
        self.assertNotIn("raw_sales", self.parser.get_table_names())
        self.assertIn("clean_sales_2026", self.parser.get_table_names())

        # Verify audit log recorded the rename
        with self.db.readonly() as cur:
            cur.execute("SELECT natural_query, status FROM _nexus_query_audit ORDER BY query_id DESC LIMIT 1;")
            audit_row = cur.fetchone()
            self.assertIn("Rename table raw_sales -> clean_sales_2026", audit_row["natural_query"])
            self.assertEqual(audit_row["status"], "SUCCESS")

        # 2. Collision Rejection
        self.db.execute_write("CREATE TABLE existing_table (id INTEGER);")
        self.parser.invalidate_cache()
        with self.assertRaises(TableManagerError) as ctx:
            self.table_mgr.rename_table("clean_sales_2026", "existing_table")
        self.assertIn("already exists", str(ctx.exception))

        # 3. Valid Table Drop
        dropped = self.table_mgr.drop_table("clean_sales_2026")
        self.assertEqual(dropped, "clean_sales_2026")
        self.assertNotIn("clean_sales_2026", self.parser.get_table_names())

        # Verify audit log recorded the drop
        with self.db.readonly() as cur:
            cur.execute("SELECT natural_query, status FROM _nexus_query_audit ORDER BY query_id DESC LIMIT 1;")
            audit_row = cur.fetchone()
            self.assertIn("Drop table clean_sales_2026", audit_row["natural_query"])
            self.assertEqual(audit_row["status"], "SUCCESS")

        # 4. Protected Namespace Violations Strictly Rejected
        with self.assertRaises(TableManagerError):
            self.table_mgr.drop_table("_nexus_query_audit")

        with self.assertRaises(TableManagerError):
            self.table_mgr.drop_table("sqlite_master")

        with self.assertRaises(TableManagerError):
            self.table_mgr.drop_table("sqlite_schema")

        with self.assertRaises(TableManagerError):
            self.table_mgr.rename_table("existing_table", "_nexus_injected_table")

        with self.assertRaises(TableManagerError):
            self.table_mgr.rename_table("sqlite_sequence", "hacked_seq")

        # Verify dropping non-existent table raises TableManagerError
        with self.assertRaises(TableManagerError):
            self.table_mgr.drop_table("nonexistent_table_xyz")

        # Verify internal audit table is completely intact
        audit_res = self.db.execute_query("SELECT COUNT(*) FROM _nexus_query_audit;")
        self.assertGreaterEqual(audit_res.rows[0][0], 1)

    # --------------------------------------------------------------------------
    # 4. MULTI-SHEET EXCEL INSPECTION & INGESTION
    # --------------------------------------------------------------------------

    def test_multi_sheet_excel_inspection_and_ingestion(self) -> None:
        """
        Validates:
        - ETLEngine.list_excel_sheets returns sheet names without reading full data into RAM.
        - ETLEngine.list_excel_sheets returns [] for non-Excel files.
        - Multiple sheets can be ingested without naming collisions.
        - AIDataProfiler.profile_file profiles specific sheet requested via sheet_name.
        """
        xlsx_path = self.temp_path / "multi_sheet_book.xlsx"

        # Build multi-sheet Excel file
        wb = openpyxl.Workbook()
        ws_q1 = wb.active
        ws_q1.title = "Q1_Sales"
        ws_q1.append(["item_name", "q1_revenue"])
        ws_q1.append(["Widget Alpha", 15000.0])
        ws_q1.append(["Widget Beta", 22000.0])

        ws_q2 = wb.create_sheet(title="Q2_Sales")
        ws_q2.append(["item_name", "q2_revenue", "growth_rate"])
        ws_q2.append(["Widget Gamma", 31000.0, 0.25])
        ws_q2.append(["Widget Delta", 45000.0, 0.45])

        wb.save(xlsx_path)
        wb.close()

        # 1. List Sheets
        sheets = ETLEngine.list_excel_sheets(xlsx_path)
        self.assertEqual(sheets, ["Q1_Sales", "Q2_Sales"])

        # Non-Excel returns empty list
        csv_dummy = self.temp_path / "dummy.csv"
        csv_dummy.write_text("a,b\n1,2", encoding="utf-8")
        self.assertEqual(ETLEngine.list_excel_sheets(csv_dummy), [])

        # 2. Ingest Sheet 1 without collision
        report_q1 = self.etl.ingest_file(xlsx_path, sheet_name="Q1_Sales")
        self.assertEqual(report_q1.table_name, "multi_sheet_book_q1_sales")
        self.assertEqual(report_q1.rows_ingested, 2)
        self.assertIn("q1_revenue", report_q1.inferred_schema)

        # 3. Ingest Sheet 2 without collision
        report_q2 = self.etl.ingest_file(xlsx_path, sheet_name="Q2_Sales")
        self.assertEqual(report_q2.table_name, "multi_sheet_book_q2_sales")
        self.assertEqual(report_q2.rows_ingested, 2)
        self.assertIn("q2_revenue", report_q2.inferred_schema)

        # Verify both tables coexist in the database
        active_tables = self.parser.get_table_names()
        self.assertIn("multi_sheet_book_q1_sales", active_tables)
        self.assertIn("multi_sheet_book_q2_sales", active_tables)

        # 4. Profile specific sheet with AIDataProfiler
        profile_q2 = self.profiler.profile_file(xlsx_path, sheet_name="Q2_Sales")
        col_names = [c.raw_name for c in profile_q2.columns]
        self.assertIn("q2_revenue", col_names)
        self.assertIn("growth_rate", col_names)
        self.assertNotIn("q1_revenue", col_names)
        self.assertEqual(profile_q2.sampled_rows, 2)


if __name__ == "__main__":
    unittest.main()
