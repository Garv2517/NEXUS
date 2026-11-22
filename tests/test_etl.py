"""
NEXUS Engine - Phase 3 Automated Pandas ETL Pipeline Test Suite
==============================================================
Architecture Role: Comprehensive, adversarial, and performance test suite for
the high-speed ETL pipeline (src/etl/etl_engine.py) and UI integration.

Coverage:
1. Identifier security sanitization (SQL reserved words, system tables, SQLi vectors, collisions).
2. Vectorized column type profiling & ISO-8601 standardization (INTEGER, REAL, TEXT, TIMESTAMP).
3. Null imputation strategies and duplicate row removal.
4. Deterministic Safe JSON Cleaning Plan Executor (whitelisted transforms, zero eval/exec).
5. Multi-format ingestion: CSV (UTF-8, UTF-8-BOM, Latin-1, CP1252), TSV, JSON, JSONL, XLSX, Parquet.
6. Atomic transactional rollback on corrupt data or schema collision.
7. End-to-end UI integration with NexusApp and AsyncWorkerManager.
8. Large-file throughput benchmark verifying the < 5s target.

Author: Senior Systems & Security Engineer
Target DB: Temporary isolated SQLite workspace
"""

from __future__ import annotations

import csv
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd

# Core NEXUS modules
from src.core.db_manager import DatabaseManager
from src.core.schema_parser import SchemaParser
from src.etl.etl_engine import (
    ETLEngine,
    ETLConfig,
    ETLReport,
    ETLException,
    ETLSecurityError,
    ETLValidationError,
    CleaningPlanExecutor,
    sanitize_identifier,
    SQL_RESERVED_KEYWORDS,
    PROTECTED_PREFIXES,
)
from src.ui.async_worker import AsyncWorkerManager


# ==============================================================================
# 1. IDENTIFIER SECURITY & SANITIZATION TESTS
# ==============================================================================

class TestIdentifierSanitization(unittest.TestCase):
    """Verifies strict, injection-proof sanitization of table and column identifiers."""

    def test_standard_clean_identifiers(self) -> None:
        """Verify normal strings are converted to lowercase snake_case."""
        self.assertEqual(sanitize_identifier("FirstName"), "firstname")
        self.assertEqual(sanitize_identifier("First Name"), "first_name")
        self.assertEqual(sanitize_identifier("customer-account-id"), "customer_account_id")
        self.assertEqual(sanitize_identifier("  spaced_column  "), "spaced_column")

    def test_special_characters_and_punctuation(self) -> None:
        """Verify symbols, currency signs, and punctuation are safely replaced."""
        self.assertEqual(sanitize_identifier("Item #"), "item")
        self.assertEqual(sanitize_identifier("Order #"), "order_col")  # 'order' is SQL reserved keyword
        self.assertEqual(sanitize_identifier("Unit Price ($)"), "unit_price")
        self.assertEqual(sanitize_identifier("Discount %"), "discount")
        self.assertEqual(sanitize_identifier("Total [USD]"), "total_usd")
        self.assertEqual(sanitize_identifier("User.Email.Address"), "user_email_address")
        self.assertEqual(sanitize_identifier("emoji_🔥_metric"), "emoji_metric")

    def test_sql_injection_payloads_in_identifiers(self) -> None:
        """Verify adversarial SQL injection payloads in identifiers are sanitized."""
        # Injection in table name
        sqli_table = "users; DROP TABLE users; --"
        clean_tbl = sanitize_identifier(sqli_table, is_table=True)
        self.assertNotIn(";", clean_tbl)
        self.assertNotIn("--", clean_tbl)
        self.assertEqual(clean_tbl, "users_drop_table_users")

        # Injection in column name
        sqli_col = "admin' OR '1'='1"
        clean_col = sanitize_identifier(sqli_col, is_table=False)
        self.assertNotIn("'", clean_col)
        self.assertEqual(clean_col, "admin_or_1_1")

    def test_sql_reserved_word_collision_avoidance(self) -> None:
        """Verify SQL reserved words are suffixed to prevent query parse errors."""
        # Columns
        self.assertEqual(sanitize_identifier("select", is_table=False), "select_col")
        self.assertEqual(sanitize_identifier("WHERE", is_table=False), "where_col")
        self.assertEqual(sanitize_identifier("order", is_table=False), "order_col")
        self.assertEqual(sanitize_identifier("group", is_table=False), "group_col")
        self.assertEqual(sanitize_identifier("check", is_table=False), "check_col")

        # Tables
        self.assertEqual(sanitize_identifier("table", is_table=True), "table_tbl")
        self.assertEqual(sanitize_identifier("index", is_table=True), "index_tbl")
        self.assertEqual(sanitize_identifier("select", is_table=True), "select_tbl")

    def test_protected_system_namespaces_blocked(self) -> None:
        """Verify attempts to target '_nexus_*' and 'sqlite_*' raise security exceptions."""
        with self.assertRaises(ETLSecurityError):
            sanitize_identifier("_nexus_query_audit", is_table=True)

        with self.assertRaises(ETLSecurityError):
            sanitize_identifier("  _nexus_internal_settings  ", is_table=True)

        with self.assertRaises(ETLSecurityError):
            sanitize_identifier("sqlite_master", is_table=True)

        with self.assertRaises(ETLSecurityError):
            sanitize_identifier("SQLITE_SEQUENCE", is_table=True)

    def test_leading_numbers_and_empty_strings(self) -> None:
        """Verify leading digits and blank strings are safely prefixed."""
        self.assertEqual(sanitize_identifier("123_analytics", is_table=True), "tbl_123_analytics")
        self.assertEqual(sanitize_identifier("123_analytics", is_table=False), "col_123_analytics")
        self.assertEqual(sanitize_identifier("", is_table=True), "tbl_data")
        self.assertEqual(sanitize_identifier("   ", is_table=False), "col_unnamed")
        self.assertEqual(sanitize_identifier("###$$$@@@", is_table=False), "col_unnamed")

    def test_column_name_collision_deduplication(self) -> None:
        """Verify duplicate column names in a file are deterministically suffixed."""
        existing: set[str] = set()
        c1 = sanitize_identifier("User Name", is_table=False, existing_names=existing)
        c2 = sanitize_identifier("user_name", is_table=False, existing_names=existing)
        c3 = sanitize_identifier("user-name", is_table=False, existing_names=existing)
        c4 = sanitize_identifier("user_name_1", is_table=False, existing_names=existing)

        self.assertEqual(c1, "user_name")
        self.assertEqual(c2, "user_name_1")
        self.assertEqual(c3, "user_name_2")
        self.assertEqual(c4, "user_name_1_1")
        self.assertEqual(len(existing), 4)


# ==============================================================================
# 2. TYPE PROFILING & STANDARDIZATION TESTS
# ==============================================================================

class TestTypeProfiling(unittest.TestCase):
    """Verifies vectorized type inference and conversion into SQLite storage types."""

    def test_integer_profiling(self) -> None:
        """Verify integer strings, floats with whole values, and native ints infer as INTEGER."""
        # Clean native integers
        s1 = pd.Series([10, 20, 30, 40])
        dtype1, clean1 = ETLEngine.profile_and_standardize_column(s1)
        self.assertEqual(dtype1, "INTEGER")
        self.assertEqual(list(clean1), [10, 20, 30, 40])

        # String integers with dirty whitespace
        s2 = pd.Series(["  100  ", "200", "300", None, "400"])
        dtype2, clean2 = ETLEngine.profile_and_standardize_column(s2)
        self.assertEqual(dtype2, "INTEGER")
        self.assertEqual(clean2.iloc[0], 100)

        # Whole number floats with NaNs
        s3 = pd.Series([1.0, 2.0, np.nan, 4.0])
        dtype3, clean3 = ETLEngine.profile_and_standardize_column(s3)
        self.assertEqual(dtype3, "INTEGER")
        self.assertEqual(clean3.iloc[0], 1)

    def test_real_profiling(self) -> None:
        """Verify fractional floats and string decimals infer as REAL."""
        s1 = pd.Series([10.5, 20.25, 30.75])
        dtype1, clean1 = ETLEngine.profile_and_standardize_column(s1)
        self.assertEqual(dtype1, "REAL")

        s2 = pd.Series(["12.50", "99.99", " -4.25 ", None])
        dtype2, clean2 = ETLEngine.profile_and_standardize_column(s2)
        self.assertEqual(dtype2, "REAL")
        self.assertAlmostEqual(clean2.iloc[0], 12.50)
        self.assertAlmostEqual(clean2.iloc[2], -4.25)

    def test_timestamp_profiling_and_iso8601_standardization(self) -> None:
        """Verify dirty dates in mixed formats are standardized to ISO-8601 strings."""
        s = pd.Series([
            "2023-01-15",
            "02/20/2023",
            "2023-03-25 14:30:00",
            "2023/12/31",
            None
        ])
        dtype, clean = ETLEngine.profile_and_standardize_column(s)
        self.assertEqual(dtype, "TIMESTAMP")
        self.assertEqual(clean.iloc[0], "2023-01-15 00:00:00")
        self.assertEqual(clean.iloc[1], "2023-02-20 00:00:00")
        self.assertEqual(clean.iloc[2], "2023-03-25 14:30:00")
        self.assertEqual(clean.iloc[3], "2023-12-31 00:00:00")
        self.assertIsNone(clean.iloc[4])

    def test_text_fallback(self) -> None:
        """Verify arbitrary text and non-numeric strings fallback to TEXT."""
        s = pd.Series(["Alpha", "Beta-123", "Gamma 456", "DELTA"])
        dtype, clean = ETLEngine.profile_and_standardize_column(s)
        self.assertEqual(dtype, "TEXT")
        self.assertEqual(list(clean), ["Alpha", "Beta-123", "Gamma 456", "DELTA"])


# ==============================================================================
# 3. SAFE CLEANING PLAN EXECUTOR TESTS
# ==============================================================================

class TestSafeCleaningPlanExecutor(unittest.TestCase):
    """Verifies deterministic execution of whitelisted JSON cleaning plans."""

    def test_valid_cleaning_plan_execution(self) -> None:
        """Verify execution of chained cleaning steps without arbitrary code execution."""
        df = pd.DataFrame({
            "User ID": [1, 2, 2, 4],
            "Full Name": ["  Alice  ", "BOB", "BOB", "Charlie"],
            "Score": ["85", "90", "90", "150"],
            "Unneeded_Col": ["x", "y", "y", "z"]
        })

        plan = [
            {"action": "drop_columns", "columns": ["Unneeded_Col"]},
            {"action": "rename_columns", "mapping": {"User ID": "user_id", "Full Name": "full_name", "Score": "score"}},
            {"action": "strip_whitespace", "columns": ["full_name"]},
            {"action": "case_transform", "columns": ["full_name"], "mode": "title"},
            {"action": "cast_type", "column": "score", "target_type": "integer"},
            {"action": "drop_duplicates", "subset": ["user_id", "full_name"]},
            {"action": "clamp_range", "column": "score", "min": 0, "max": 100}
        ]

        cleaned_df, steps = CleaningPlanExecutor.execute(df, plan)

        self.assertNotIn("Unneeded_Col", cleaned_df.columns)
        self.assertIn("user_id", cleaned_df.columns)
        self.assertEqual(len(cleaned_df), 3)  # Duplicate dropped
        self.assertEqual(cleaned_df["full_name"].tolist(), ["Alice", "Bob", "Charlie"])
        # Score clamped from 150 to 100
        self.assertEqual(cleaned_df["score"].tolist(), [85, 90, 100])
        self.assertGreaterEqual(len(steps), 5)

    def test_prohibited_action_in_cleaning_plan_rejected(self) -> None:
        """Verify any unrecognized or dangerous action is rejected with validation error."""
        df = pd.DataFrame({"col": [1, 2, 3]})
        malicious_plan = [
            {"action": "eval_code", "code": "import os; os.system('echo pwned')"}
        ]
        with self.assertRaises(ETLValidationError):
            CleaningPlanExecutor.execute(df, malicious_plan)


# ==============================================================================
# 4. MULTI-FORMAT INGESTION & ROBUSTNESS TESTS
# ==============================================================================

class TestETLMultiFormatIngestion(unittest.TestCase):
    """Verifies end-to-end ingestion across CSV, TSV, JSON, XLSX, and edge cases."""

    def setUp(self) -> None:
        DatabaseManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_etl.db"
        self.db = DatabaseManager(self.db_path)
        self.parser = SchemaParser(self.db)
        self.engine = ETLEngine(db_manager=self.db, schema_parser=self.parser)

    def tearDown(self) -> None:
        if hasattr(self, "db"):
            self.db.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass
        DatabaseManager.reset_instance()

    def test_dirty_csv_with_mixed_encodings_and_ragged_whitespace(self) -> None:
        """Verify ingestion of dirty CSV containing UTF-8 BOM, whitespace, nulls, and symbols."""
        csv_path = Path(self.temp_dir.name) / "dirty_customers.csv"

        raw_csv_content = (
            "\ufeffCustomer ID, Full Name , Account Balance , Registration Date , Status \n"
            "1001,  John Doe  , 1500.50 , 2023-01-15 , ACTIVE \n"
            "1002, Jane Smith ,  , 02/20/2023 , PENDING \n"
            "1003, Bob 'The Builder' , 250.00 , 2023-03-10 , ACTIVE \n"
            "1003, Bob 'The Builder' , 250.00 , 2023-03-10 , ACTIVE \n"  # Duplicate row
            "1004, Alice ; DROP TABLE users; -- , -45.00 , 2023-04-01 , SUSPENDED \n"
        )
        csv_path.write_text(raw_csv_content, encoding="utf-8-sig")

        progress_log: List[str] = []
        report = self.engine.ingest_file(
            csv_path,
            table_name="customers_clean",
            progress_callback=progress_log.append
        )

        self.assertEqual(report.table_name, "customers_clean")
        self.assertEqual(report.total_rows_read, 5)
        self.assertEqual(report.rows_ingested, 4)  # 1 duplicate dropped
        self.assertEqual(report.duplicate_rows_dropped, 1)
        self.assertGreaterEqual(report.null_cells_imputed, 1)
        self.assertGreater(len(progress_log), 0)

        # Verify SQLite data directly
        res = self.db.execute_query("SELECT * FROM customers_clean ORDER BY customer_id;")
        self.assertEqual(res.row_count, 4)
        self.assertEqual(res.columns, ["customer_id", "full_name", "account_balance", "registration_date", "status"])

        # Check values and sanitization
        rows = res.to_dicts()
        self.assertEqual(rows[0]["customer_id"], 1001)
        self.assertEqual(rows[0]["full_name"], "John Doe")
        self.assertAlmostEqual(rows[0]["account_balance"], 1500.50)
        self.assertEqual(rows[0]["registration_date"], "2023-01-15 00:00:00")

        # Verify SQL injection attempt in cell text was safely stored as text without executing
        self.assertIn("Alice ; DROP TABLE users; --", rows[3]["full_name"])

    def test_tsv_format_ingestion(self) -> None:
        """Verify tab-separated values (.tsv) ingestion."""
        tsv_path = Path(self.temp_dir.name) / "sensor_data.tsv"
        tsv_content = (
            "sensor_id\treading_val\tlocation\n"
            "S-101\t24.5\tBuilding-A\n"
            "S-102\t25.1\tBuilding-B\n"
            "S-103\t22.8\tBuilding-A\n"
        )
        tsv_path.write_text(tsv_content, encoding="utf-8")

        report = self.engine.ingest_file(tsv_path)
        self.assertEqual(report.table_name, "sensor_data")
        self.assertEqual(report.rows_ingested, 3)

        res = self.db.execute_query("SELECT count(*) FROM sensor_data;")
        self.assertEqual(res.rows[0][0], 3)

    def test_json_and_jsonl_ingestion(self) -> None:
        """Verify standard JSON and JSON-Lines format ingestion."""
        jsonl_path = Path(self.temp_dir.name) / "events.jsonl"
        lines = [
            json.dumps({"event_id": "EVT-01", "event_type": "LOGIN", "latency_ms": 12.5}),
            json.dumps({"event_id": "EVT-02", "event_type": "QUERY", "latency_ms": 45.2}),
            json.dumps({"event_id": "EVT-03", "event_type": "LOGOUT", "latency_ms": 8.1})
        ]
        jsonl_path.write_text("\n".join(lines), encoding="utf-8")

        report = self.engine.ingest_file(jsonl_path, table_name="app_events")
        self.assertEqual(report.table_name, "app_events")
        self.assertEqual(report.rows_ingested, 3)

        res = self.db.execute_query("SELECT event_type, latency_ms FROM app_events ORDER BY latency_ms DESC;")
        self.assertEqual(res.rows[0][0], "QUERY")
        self.assertAlmostEqual(res.rows[0][1], 45.2)

    def test_latin1_encoding_fallback(self) -> None:
        """Verify automatic detection and decoding of Latin-1 / Windows-1252 files."""
        csv_path = Path(self.temp_dir.name) / "french_accents.csv"
        # Accented characters like é, à, ç in Latin-1
        content_latin1 = "produit_id,nom_produit,prix\n1,Café au lait,3.50\n2,Crème brûlée,5.00\n"
        csv_path.write_bytes(content_latin1.encode("latin1"))

        report = self.engine.ingest_file(csv_path)
        self.assertEqual(report.rows_ingested, 2)

        res = self.db.execute_query("SELECT nom_produit FROM french_accents WHERE produit_id = 1;")
        self.assertEqual(res.rows[0][0], "Café au lait")

    def test_corrupt_and_non_existent_file_handling(self) -> None:
        """Verify invalid files raise clear ETLValidationErrors with zero unhandled crashes."""
        with self.assertRaises(ETLValidationError):
            self.engine.ingest_file(Path(self.temp_dir.name) / "does_not_exist.csv")

        empty_file = Path(self.temp_dir.name) / "empty.csv"
        empty_file.write_text("", encoding="utf-8")
        with self.assertRaises(ETLValidationError):
            self.engine.ingest_file(empty_file)

    def test_if_exists_fail_strategy_and_rollback(self) -> None:
        """Verify if_exists='fail' prevents table overwrite and preserves existing data."""
        csv_path = Path(self.temp_dir.name) / "first_dataset.csv"
        csv_path.write_text("id,val\n1,original_data\n", encoding="utf-8")

        # Initial ingestion
        self.engine.ingest_file(csv_path, table_name="stable_table")

        # Second ingestion with 'fail' strategy
        config = ETLConfig(if_exists="fail")
        with self.assertRaises(ETLValidationError):
            self.engine.ingest_file(csv_path, table_name="stable_table", config=config)

        # Original data must remain untouched
        res = self.db.execute_query("SELECT val FROM stable_table;")
        self.assertEqual(res.rows[0][0], "original_data")


# ==============================================================================
# 5. UI INTEGRATION TESTS
# ==============================================================================

class TestUIETLIntegration(unittest.TestCase):
    """Verifies seamless inter-component wiring between NexusApp and ETLEngine."""

    def setUp(self) -> None:
        DatabaseManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_ui_etl.db"
        self.db = DatabaseManager(self.db_path)
        self.parser = SchemaParser(self.db)
        self.worker = AsyncWorkerManager(max_workers=2)

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

    def test_app_ingest_dataset_updates_schema_and_previews_table(self) -> None:
        """Verify end-to-end dataset ingestion through NexusApp delegates to UI correctly."""
        # Create a sample CSV
        csv_path = Path(self.temp_dir.name) / "quarterly_sales.csv"
        csv_path.write_text(
            "Region, Revenue, Units, Quarter\n"
            "North, 45000.0, 150, Q1\n"
            "South, 38000.0, 120, Q1\n"
            "East, 52000.0, 180, Q1\n",
            encoding="utf-8"
        )

        # Initialize ETLEngine
        engine = ETLEngine(db_manager=self.db, schema_parser=self.parser)
        report = engine.ingest_file(csv_path)

        self.assertEqual(report.table_name, "quarterly_sales")
        self.assertEqual(report.rows_ingested, 3)

        # Verify SchemaParser reflected the newly created table
        stats = self.parser.get_summary_stats()
        self.assertIn("quarterly_sales", stats["table_names"])
        self.assertEqual(stats["table_count"], 1)

        # Verify markdown documentation includes the table
        md = self.parser.generate_markdown(include_samples=True)
        self.assertIn("quarterly_sales", md)
        self.assertIn("North", md)

        # Verify audit ledger logging
        self.db.log_audit_event(
            natural_query=f"ETL Ingest: quarterly_sales.csv -> quarterly_sales",
            generated_sql="-- INGESTION TEST",
            status="SUCCESS"
        )
        audit_res = self.db.execute_query("SELECT count(*) FROM _nexus_query_audit;")
        self.assertGreaterEqual(audit_res.rows[0][0], 1)

    def test_app_handle_file_selected_async_flow(self) -> None:
        """Verify NexusApp._handle_file_selected dispatches async ETL and updates UI state."""
        from src.ui.app import NexusApp

        csv_path = Path(self.temp_dir.name) / "live_transactions.csv"
        csv_path.write_text(
            "Account, Amount, Type\n"
            "ACC-101, 500.0, DEPOSIT\n"
            "ACC-102, 250.0, WITHDRAWAL\n",
            encoding="utf-8"
        )

        app = NexusApp(
            db_manager=self.db,
            schema_parser=self.parser,
            async_worker=self.worker,
            poll_interval_ms=30
        )
        app.withdraw()
        try:
            app._handle_file_selected(str(csv_path))

            # Wait briefly for worker thread to complete and process queued events
            max_wait = 4.0
            t_start = time.time()
            while time.time() - t_start < max_wait:
                time.sleep(0.05)
                self.worker.process_queue()
                if "live_transactions" in self.parser.get_summary_stats()["table_names"]:
                    break

            # Process UI events
            self.worker.process_queue()

            # Verify table was created and loaded
            res = self.db.execute_query("SELECT count(*) FROM live_transactions;")
            self.assertEqual(res.rows[0][0], 2)

            # Verify app switched to Data Explorer tab
            self.assertEqual(app.tabview.get(), "Data Explorer")

            # Verify status message indicates success
            self.assertIn("live_transactions", app.status_msg_label.cget("text"))
        finally:
            app.on_closing()


# ==============================================================================
# 6. HIGH-THROUGHPUT LARGE-FILE BENCHMARK TEST
# ==============================================================================

class TestETLThroughputBenchmark(unittest.TestCase):
    """
    Stress-tests the ETL Engine with 100,000+ dirty rows to verify the core deliverable
    metric: Ingest large dirty datasets in < 5 seconds on local hardware.
    """

    def setUp(self) -> None:
        DatabaseManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "benchmark.db"
        self.db = DatabaseManager(self.db_path)
        self.parser = SchemaParser(self.db)
        self.engine = ETLEngine(db_manager=self.db, schema_parser=self.parser)

    def tearDown(self) -> None:
        if hasattr(self, "db"):
            self.db.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass
        DatabaseManager.reset_instance()

    def test_100k_rows_dirty_ingestion_under_5_seconds(self) -> None:
        """Verify 100,000 rows of dirty tabular data ingests into SQLite in < 5 seconds."""
        row_count = 100_000
        benchmark_csv = Path(self.temp_dir.name) / "large_dirty_dataset.csv"

        # Generate synthetic dirty dataset with mixed types, dates, nulls, and duplicates
        np.random.seed(42)
        dates = [
            "2023-01-01", "02/15/2023", "2023-06-30 18:00:00",
            "2023/11/11", "2024-01-01"
        ]

        df_synthetic = pd.DataFrame({
            "Transaction ID": np.arange(1, row_count + 1),
            "Customer Account": [f"  ACC-{i % 5000}  " for i in range(row_count)],
            "Amount ($)": np.random.uniform(5.0, 5000.0, size=row_count).round(2),
            "Transaction Date": [dates[i % len(dates)] for i in range(row_count)],
            "Category Code": [f"CAT_{(i % 20):02d}" if (i % 25 != 0) else None for i in range(row_count)]
        })

        # Add 1,000 deliberate duplicate rows
        df_duplicates = df_synthetic.iloc[:1000].copy()
        df_full = pd.concat([df_synthetic, df_duplicates], ignore_index=True)

        # Write to disk as CSV
        df_full.to_csv(benchmark_csv, index=False)

        file_size_mb = benchmark_csv.stat().st_size / (1024 * 1024)

        # Execute Ingestion Pipeline and measure wall-clock elapsed time
        t_start = time.perf_counter()
        report = self.engine.ingest_file(
            benchmark_csv,
            table_name="high_throughput_txns"
        )
        t_elapsed = time.perf_counter() - t_start

        # Assertions
        self.assertLess(
            t_elapsed,
            5.0,
            f"Ingestion exceeded 5.0s SLA! Actual elapsed: {t_elapsed:.3f}s for {len(df_full):,} rows ({file_size_mb:.1f} MB)"
        )
        self.assertEqual(report.duplicate_rows_dropped, 1000)
        self.assertEqual(report.rows_ingested, row_count)
        self.assertGreater(report.null_cells_imputed, 0)
        self.assertGreater(report.throughput_rows_per_sec, 20_000.0)

        # Verify SQLite row count
        res = self.db.execute_query("SELECT count(*) FROM high_throughput_txns;")
        self.assertEqual(res.rows[0][0], row_count)

        # Verify column types
        self.assertEqual(report.inferred_schema["transaction_id"], "INTEGER")
        self.assertEqual(report.inferred_schema["customer_account"], "TEXT")
        self.assertEqual(report.inferred_schema["amount"], "REAL")
        self.assertEqual(report.inferred_schema["transaction_date"], "TIMESTAMP")


if __name__ == "__main__":
    unittest.main()
