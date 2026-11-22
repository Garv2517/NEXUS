"""
NEXUS Engine - Autonomous Agent & Chart Pipeline Verification Suite
===================================================================
Rigorous verification suite for Phase 4 Gate 2:
1. Safe Declarative Chart Engine (ChartSpec, ChartEngine, rendering, zero-eval/exec).
2. SQL Extraction utility (code fences, JSON payloads, CTEs, raw SQL).
3. SQLAgentChain end-to-end execution:
   - Success path (Text -> SQL -> Execution -> Insight).
   - Zero-retry security blocking (QueryGuard blocks mutation -> 0 retries -> Audit REJECTED).
   - Bounded self-healing repair loop (Syntax error -> LLM repair -> Success).
   - Repair exhaustion (Max repair attempts exceeded -> SQL_FAILED -> Audit FAILED).
   - Empty DB short-circuit (0 tables -> immediate return, 0 LLM calls).
   - Chart intent detection and ChartSpec synthesis.
   - Engine-level read-only violation protection.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from matplotlib.figure import Figure

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.chart_engine import ChartEngine, ChartSpec, ChartValidationError
from src.agent.llm_router import LLMConfig, LLMResponse, LLMRouter, LLMRouterError
from src.agent.sql_chain import (
    AgentRunResult,
    SQLAgentChain,
    extract_sql_from_response,
)
from src.core.db_manager import DatabaseManager, QueryResult
from src.core.schema_parser import SchemaParser


class TestSQLAgentExtraction(unittest.TestCase):
    """Validates robust extraction of SQL queries from heterogeneous LLM outputs."""

    def test_extract_sql_markdown_fence(self):
        text = "Here is the query:\n```sql\nSELECT product, SUM(amount) FROM sales GROUP BY product;\n```\nEnjoy!"
        extracted = extract_sql_from_response(text)
        self.assertEqual(extracted, "SELECT product, SUM(amount) FROM sales GROUP BY product;")

    def test_extract_sql_generic_fence(self):
        text = "```\nSELECT * FROM customers WHERE active = 1;\n```"
        extracted = extract_sql_from_response(text)
        self.assertEqual(extracted, "SELECT * FROM customers WHERE active = 1;")

    def test_extract_sql_cte_fence(self):
        text = "```\nWITH regional AS (SELECT * FROM sales WHERE region = 'US') SELECT * FROM regional;\n```"
        extracted = extract_sql_from_response(text)
        self.assertTrue(extracted.startswith("WITH regional AS"))

    def test_extract_sql_json_payload(self):
        text = '{"sql": "SELECT id, email FROM users;", "explanation": "Queries all users"}'
        extracted = extract_sql_from_response(text)
        self.assertEqual(extracted, "SELECT id, email FROM users;")

    def test_extract_sql_raw_text(self):
        text = "SELECT count(*) FROM orders;"
        extracted = extract_sql_from_response(text)
        self.assertEqual(extracted, "SELECT count(*) FROM orders;")

    def test_extract_sql_empty(self):
        self.assertEqual(extract_sql_from_response(""), "")
        self.assertEqual(extract_sql_from_response("   "), "")

    def test_extract_sql_with_think_reasoning_tags(self):
        text = (
            "<think>\n"
            "The user wants total revenue by product.\n"
            "We should query sales table: SELECT product, sum(revenue) FROM sales;\n"
            "</think>\n"
            "```sql\n"
            "SELECT product, SUM(revenue) FROM sales GROUP BY product;\n"
            "```"
        )
        extracted = extract_sql_from_response(text)
        self.assertEqual(extracted, "SELECT product, SUM(revenue) FROM sales GROUP BY product;")

    def test_extract_sql_raw_with_think_tags(self):
        text = (
            "<think>Thinking process here...</think>\n"
            "SELECT * FROM customers WHERE active = 1;"
        )
        extracted = extract_sql_from_response(text)
        self.assertEqual(extracted, "SELECT * FROM customers WHERE active = 1;")


class TestChartEngine(unittest.TestCase):
    """Validates ChartSpec validation, zero-eval parsing, and thread-safe OO rendering."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_chart_spec_sanitization_and_clamping(self):
        # top_n clamping to [1, 50]
        spec_low = ChartSpec(chart_type="bar", x_column="a", y_column="b", top_n=-10)
        self.assertEqual(spec_low.top_n, 1)

        spec_high = ChartSpec(chart_type="bar", x_column="a", y_column="b", top_n=999)
        self.assertEqual(spec_high.top_n, 50)

        # Title sanitization and length capping (max 100)
        long_title = "A" * 150
        spec_title = ChartSpec(chart_type="line", x_column="x", y_column="y", title=long_title)
        self.assertEqual(len(spec_title.title), 100)

        # Control characters stripped
        spec_ctrl = ChartSpec(chart_type="line", x_column="x", y_column="y", title="Clean\x00Title\x1fTest")
        self.assertEqual(spec_ctrl.title, "CleanTitleTest")

    def test_parse_chart_spec_from_json_and_fences(self):
        available = ["region", "revenue", "cost"]

        # Fenced JSON payload
        raw_fenced = """```json
        {
            "chart_type": "bar",
            "x_column": "REGION",
            "y_column": "revenue",
            "title": "Revenue by Region",
            "top_n": 15
        }
        ```"""
        spec = ChartEngine.parse_chart_spec(raw_fenced, available)
        self.assertEqual(spec.chart_type, "bar")
        self.assertEqual(spec.x_column, "region")  # Case-resolved
        self.assertEqual(spec.y_column, "revenue")
        self.assertEqual(spec.top_n, 15)

        # Dictionary payload
        raw_dict = {
            "chart_type": "line",
            "x_column": "region",
            "y_column": "cost",
            "title": "Cost Line"
        }
        spec_dict = ChartEngine.parse_chart_spec(raw_dict, available)
        self.assertEqual(spec_dict.chart_type, "line")

    def test_parse_chart_spec_with_think_tags(self):
        available = ["region", "revenue"]
        payload = (
            "<think>\n"
            "I will generate a bar chart for region vs revenue.\n"
            "</think>\n"
            "```json\n"
            "{\n"
            '    "chart_type": "bar",\n'
            '    "x_column": "region",\n'
            '    "y_column": "revenue",\n'
            '    "title": "Regional Revenue"\n'
            "}\n"
            "```"
        )
        spec = ChartEngine.parse_chart_spec(payload, available)
        self.assertEqual(spec.chart_type, "bar")
        self.assertEqual(spec.x_column, "region")
        self.assertEqual(spec.y_column, "revenue")

    def test_parse_chart_spec_validation_errors(self):
        available = ["category", "sales"]

        # Invalid JSON
        with self.assertRaises(ChartValidationError):
            ChartEngine.parse_chart_spec("NOT VALID JSON", available)

        # Missing column
        with self.assertRaises(ChartValidationError):
            ChartEngine.parse_chart_spec(
                {"chart_type": "bar", "x_column": "nonexistent", "y_column": "sales"},
                available
            )

        # Missing required axis for bar chart
        with self.assertRaises(ChartValidationError):
            ChartEngine.parse_chart_spec(
                {"chart_type": "bar", "x_column": "category", "y_column": None},
                available
            )

        # Invalid chart type
        with self.assertRaises(ChartValidationError):
            ChartEngine.parse_chart_spec(
                {"chart_type": "3d_donut", "x_column": "category", "y_column": "sales"},
                available
            )

    def test_render_all_geometries_and_save(self):
        cols = ["product", "sales"]
        rows = [
            ("Alpha", 150.0),
            ("Beta", 230.5),
            ("Gamma", 80.0),
            ("Delta", 310.2),
        ]
        qr = QueryResult(columns=cols, rows=rows, row_count=len(rows), execution_time_ms=5.0, sql="SELECT product, sales FROM t;")

        for c_type in ["bar", "line", "scatter", "pie", "hist"]:
            spec = ChartSpec(
                chart_type=c_type,  # type: ignore
                x_column="product",
                y_column="sales",
                title=f"Test {c_type.title()} Chart"
            )
            fig = ChartEngine.render_figure(qr, spec)
            self.assertIsInstance(fig, Figure)

            # Persist to disk
            out_file = self.output_dir / f"test_{c_type}.png"
            saved_path = ChartEngine.save_figure(fig, out_file)
            self.assertTrue(saved_path.exists())
            self.assertGreater(saved_path.stat().st_size, 0)

    def test_render_empty_query_result(self):
        qr = QueryResult(columns=["col_a", "col_b"], rows=[], row_count=0, execution_time_ms=1.0, sql="SELECT col_a, col_b FROM t;")
        spec = ChartSpec(chart_type="bar", x_column="col_a", y_column="col_b", title="Empty Test")
        fig = ChartEngine.render_figure(qr, spec)
        self.assertIsInstance(fig, Figure)


class TestSQLAgentChain(unittest.TestCase):
    """End-to-end integration and security tests for SQLAgentChain."""

    def setUp(self):
        DatabaseManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_workspace.db"
        self.db = DatabaseManager(self.db_path)
        self.parser = SchemaParser(self.db)

        # Populate sample business data
        self.db.execute_write("""
            CREATE TABLE sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product TEXT NOT NULL,
                region TEXT NOT NULL,
                revenue REAL NOT NULL,
                units INTEGER NOT NULL
            );
        """)
        self.db.execute_write("""
            INSERT INTO sales (product, region, revenue, units) VALUES
                ('Quantum Core', 'North America', 12000.0, 10),
                ('Neural Link', 'Europe', 8500.0, 5),
                ('Nexus Gateway', 'Asia Pacific', 15400.0, 12),
                ('Cyber Mesh', 'North America', 4300.0, 4);
        """)

        # Mock LLMRouter
        self.mock_router = MagicMock(spec=LLMRouter)
        self.mock_router.config = LLMConfig(provider="local", model="qwen2.5-coder:7b")

        self.chain = SQLAgentChain(
            db_manager=self.db,
            schema_parser=self.parser,
            llm_router=self.mock_router,
            max_repair_attempts=2
        )

    def tearDown(self):
        self.db.close()
        DatabaseManager.reset_instance()
        self.temp_dir.cleanup()

    def test_end_to_end_text_to_sql_success(self):
        """
        Validates:
        Natural language -> LLM SQL -> Query execution -> LLM summary -> SUCCESS.
        """
        # Step 1: LLM outputs SQL query inside ```sql fence
        sql_response = LLMResponse(
            content="```sql\nSELECT product, revenue FROM sales ORDER BY revenue DESC;\n```",
            provider="local",
            model="qwen2.5-coder:7b",
            prompt_tokens=150,
            completion_tokens=25,
            total_tokens=175,
            latency_ms=120.0
        )
        self.mock_router.invoke.return_value = sql_response

        # Step 2: LLM generates analytical summary
        summary_response = LLMResponse(
            content="Top generating product is **Nexus Gateway** with $15,400 in revenue.",
            provider="local",
            model="qwen2.5-coder:7b",
            prompt_tokens=100,
            completion_tokens=20,
            total_tokens=120,
            latency_ms=80.0
        )
        self.mock_router.generate.return_value = summary_response

        progress_log = []
        result = self.chain.run(
            "What is our top revenue product?",
            progress_callback=lambda msg: progress_log.append(msg)
        )

        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.repair_attempts, 0)
        self.assertIsNotNone(result.query_result)
        self.assertEqual(result.query_result.row_count, 4)
        self.assertIn("Nexus Gateway", result.answer_markdown)
        self.assertGreater(result.total_tokens, 0)
        self.assertTrue(len(progress_log) > 0)

        # Verify audit ledger
        audit_records = self.db.execute_query(
            "SELECT natural_query, generated_sql, status FROM _nexus_query_audit ORDER BY query_id DESC LIMIT 1;"
        )
        self.assertEqual(audit_records.rows[0][2], "SUCCESS")

    def test_zero_retry_security_block(self):
        """
        CRITICAL SECURITY REQUIREMENT:
        LLM outputs DROP TABLE -> QueryGuard raises SecurityException ->
        Chain aborts immediately with status='SECURITY_BLOCKED' ->
        invoke.call_count == 1 (ZERO repair retries on security violations!) ->
        Audit ledger records REJECTED -> Table remains intact.
        """
        adversarial_response = LLMResponse(
            content="```sql\nDROP TABLE sales;\n```",
            provider="local",
            model="qwen2.5-coder:7b",
            prompt_tokens=120,
            completion_tokens=10,
            total_tokens=130,
            latency_ms=50.0
        )
        self.mock_router.invoke.return_value = adversarial_response

        result = self.chain.run("Delete all sales data")

        self.assertEqual(result.status, "SECURITY_BLOCKED")
        self.assertIn("Security Policy Enforcement", result.answer_markdown)
        self.assertIsNone(result.query_result)

        # STRICT ASSERTION: Exactly 1 invocation! ZERO repair retries for security violations!
        self.assertEqual(self.mock_router.invoke.call_count, 1)

        # Verify audit ledger records REJECTED
        audit = self.db.execute_query(
            "SELECT status, generated_sql, error_message FROM _nexus_query_audit ORDER BY query_id DESC LIMIT 1;"
        )
        self.assertEqual(audit.rows[0][0], "REJECTED")
        self.assertIn("DROP", audit.rows[0][1].upper())

        # Verify table still exists in DB
        check_table = self.db.execute_query("SELECT count(*) FROM sales;")
        self.assertEqual(check_table.rows[0][0], 4)

    def test_self_healing_repair_loop_success(self):
        """
        Validates:
        Attempt 1: Bad column name -> SQLite error -> Attempt 2: Repaired SQL ->
        Execution SUCCESS -> repair_attempts == 1 -> Audit ledger records SUCCESS.
        """
        # Attempt 1: bad column 'non_existent_column'
        attempt1 = LLMResponse(
            content="```sql\nSELECT non_existent_column FROM sales;\n```",
            provider="local",
            model="qwen2.5-coder:7b",
            prompt_tokens=150,
            completion_tokens=20,
            total_tokens=170,
            latency_ms=90.0
        )
        # Attempt 2 (repair): fixed column 'product'
        attempt2 = LLMResponse(
            content="```sql\nSELECT product, revenue FROM sales;\n```",
            provider="local",
            model="qwen2.5-coder:7b",
            prompt_tokens=200,
            completion_tokens=25,
            total_tokens=225,
            latency_ms=110.0
        )
        self.mock_router.invoke.side_effect = [attempt1, attempt2]

        self.mock_router.generate.return_value = LLMResponse(
            content="Data retrieved successfully.",
            provider="local",
            model="qwen2.5-coder:7b",
            prompt_tokens=50,
            completion_tokens=10,
            total_tokens=60,
            latency_ms=40.0
        )

        result = self.chain.run("Show products and revenue")

        self.assertEqual(result.status, "SUCCESS")
        self.assertEqual(result.repair_attempts, 1)
        self.assertEqual(self.mock_router.invoke.call_count, 2)
        self.assertIsNotNone(result.query_result)
        self.assertEqual(result.query_result.row_count, 4)

        # Verify audit ledger recorded SUCCESS
        audit = self.db.execute_query(
            "SELECT status FROM _nexus_query_audit ORDER BY query_id DESC LIMIT 1;"
        )
        self.assertEqual(audit.rows[0][0], "SUCCESS")

    def test_repair_exhaustion(self):
        """
        Validates:
        Repeated bad queries exceed max_repair_attempts (2) ->
        Chain terminates with status='SQL_FAILED' -> repair_attempts == 2 ->
        Audit ledger records FAILED.
        """
        bad_resp = LLMResponse(
            content="```sql\nSELECT bad_col FROM sales;\n```",
            provider="local",
            model="qwen2.5-coder:7b",
            prompt_tokens=100,
            completion_tokens=15,
            total_tokens=115,
            latency_ms=50.0
        )
        # 1 initial + 2 repair attempts = 3 invocations
        self.mock_router.invoke.side_effect = [bad_resp, bad_resp, bad_resp]

        result = self.chain.run("Query broken columns")

        self.assertEqual(result.status, "SQL_FAILED")
        self.assertEqual(result.repair_attempts, 2)
        self.assertEqual(self.mock_router.invoke.call_count, 3)
        self.assertIn("SQL Execution Failed", result.answer_markdown)

        # Verify audit ledger recorded FAILED
        audit = self.db.execute_query(
            "SELECT status, error_message FROM _nexus_query_audit ORDER BY query_id DESC LIMIT 1;"
        )
        self.assertEqual(audit.rows[0][0], "FAILED")

    def test_empty_db_short_circuit(self):
        """
        Validates:
        Empty DB (0 tables) -> Chain immediately returns status='EMPTY_DB'
        without making ANY LLM calls (invoke.call_count == 0).
        """
        # Create a fresh empty database
        DatabaseManager.reset_instance()
        empty_db_path = Path(self.temp_dir.name) / "empty_workspace.db"
        empty_db = DatabaseManager(empty_db_path)
        empty_parser = SchemaParser(empty_db)

        empty_chain = SQLAgentChain(
            db_manager=empty_db,
            schema_parser=empty_parser,
            llm_router=self.mock_router
        )

        result = empty_chain.run("How many total sales were made?")

        self.assertEqual(result.status, "EMPTY_DB")
        self.assertIn("Workspace Database Empty", result.answer_markdown)
        self.assertEqual(self.mock_router.invoke.call_count, 0)
        self.assertEqual(self.mock_router.generate.call_count, 0)

        empty_db.close()

    def test_agent_chain_chart_intent_detection(self):
        """
        Validates:
        Natural language prompt with 'bar chart' triggers declarative ChartSpec
        synthesis via json_mode, returning validated ChartSpec on result.
        """
        # Step 1: SQL generation
        self.mock_router.invoke.return_value = LLMResponse(
            content="```sql\nSELECT product, revenue FROM sales;\n```",
            provider="local",
            model="qwen2.5-coder:7b",
            prompt_tokens=100,
            completion_tokens=20,
            total_tokens=120,
            latency_ms=60.0
        )

        # Step 2: Insight response + Step 3: ChartSpec JSON response
        insight_resp = LLMResponse(
            content="Revenue breakdown by product.",
            provider="local",
            model="qwen2.5-coder:7b",
            prompt_tokens=50,
            completion_tokens=15,
            total_tokens=65,
            latency_ms=40.0
        )
        chart_resp = LLMResponse(
            content=json.dumps({
                "chart_type": "bar",
                "x_column": "product",
                "y_column": "revenue",
                "title": "Product Revenue Bar Chart",
                "top_n": 10
            }),
            provider="local",
            model="qwen2.5-coder:7b",
            prompt_tokens=80,
            completion_tokens=30,
            total_tokens=110,
            latency_ms=50.0
        )
        self.mock_router.generate.side_effect = [insight_resp, chart_resp]

        result = self.chain.run("Generate a bar chart of product revenue")

        self.assertEqual(result.status, "SUCCESS")
        self.assertIsNotNone(result.chart_spec)
        self.assertEqual(result.chart_spec.chart_type, "bar")
        self.assertEqual(result.chart_spec.x_column, "product")
        self.assertEqual(result.chart_spec.y_column, "revenue")
        self.assertEqual(result.chart_spec.title, "Product Revenue Bar Chart")

        # Verify ChartEngine can render the produced spec
        fig = ChartEngine.render_figure(result.query_result, result.chart_spec)
        self.assertIsInstance(fig, Figure)

    def test_empty_natural_query(self):
        result = self.chain.run("   ")
        self.assertEqual(result.status, "SQL_FAILED")
        self.assertEqual(self.mock_router.invoke.call_count, 0)

    def test_agent_run_result_to_dict(self):
        qr = QueryResult(columns=["col1"], rows=[("val1",)], row_count=1, execution_time_ms=1.5, sql="SELECT col1 FROM t;")
        spec = ChartSpec(chart_type="bar", x_column="col1", y_column="col1", title="Title")
        res = AgentRunResult(
            natural_query="Test query",
            generated_sql="SELECT col1 FROM t;",
            query_result=qr,
            answer_markdown="Markdown",
            chart_spec=spec,
            status="SUCCESS",
            repair_attempts=1,
            total_tokens=100,
            total_latency_ms=50.0,
            provider="local",
            model="test-m"
        )
        d = res.to_dict()
        self.assertEqual(d["natural_query"], "Test query")
        self.assertEqual(d["row_count"], 1)
        self.assertEqual(d["chart_spec"]["chart_type"], "bar")


if __name__ == "__main__":
    unittest.main()
