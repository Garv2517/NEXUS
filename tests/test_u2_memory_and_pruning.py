"""
NEXUS Engine - Upgrade U2 & U2.5 Verification Suite
==================================================
Comprehensive test suite verifying:
1. Row-Cap Guard (db_manager.py):
   - Truncation flag and bounded fetchmany row limits.
2. Smart Schema Pruning + FK Expansion (schema_parser.py):
   - Tokenization, weighted scoring, and 1-hop FK neighbor preservation.
3. Bounded Multi-Turn Memory (sql_chain.py):
   - Prompt context injection bounded to recent 4 turns.
   - Zero-retry immediate abort on adversarial follow-ups (SECURITY_BLOCKED).
4. Follow-Up-Aware Schema Pruning Integration (sql_chain.py):
   - Automatic schema pruning on >8 tables with context persistence.
5. Zero-LLM Starter Questions (sql_chain.py):
   - Deterministic, heuristic-based prompt generation with chart intent.
6. IEEE-754 Float & Tabular Formatting (formatters.py):
   - Binary artifact stripping and monospace ASCII table rendering.

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import math
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.llm_router import LLMConfig, LLMResponse, LLMRouter
from src.agent.sql_chain import (
    AgentRunResult,
    ConversationTurn,
    SQLAgentChain,
    generate_starter_questions,
)
from src.core.db_manager import DatabaseManager, QueryResult
from src.core.schema_parser import SchemaParser
from src.ui.formatters import format_ascii_table, format_cell_value


def _make_llm_response(content: str, provider: str = "local", model: str = "phi4-mini:latest") -> LLMResponse:
    """Helper creating a fully populated LLMResponse fixture."""
    return LLMResponse(
        content=content,
        provider=provider,
        model=model,
        prompt_tokens=15,
        completion_tokens=25,
        total_tokens=40,
        latency_ms=30.0
    )


class TestUpgradeU2Verification(unittest.TestCase):
    """Rigorous verification suite for Upgrade U2 and U2.5 components."""

    def setUp(self):
        DatabaseManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_u2.db"
        self.db = DatabaseManager(self.db_path)
        self.parser = SchemaParser(self.db)

    def tearDown(self):
        self.db.close()
        DatabaseManager.reset_instance()
        self.temp_dir.cleanup()

    # ==========================================================================
    # 1. Safe Row-Cap Guard
    # ==========================================================================

    def test_row_cap_guard(self):
        """
        Insert 25 rows into items table:
        - execute_query with max_rows=10 -> row_count == 10, truncated is True.
        - execute_query with max_rows=50 -> row_count == 25, truncated is False.
        - execute_query with max_rows=None -> row_count == 25, truncated is False.
        """
        self.db.execute_write("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);")
        for i in range(1, 26):
            self.db.execute_write(f"INSERT INTO items (id, name) VALUES ({i}, 'Item {i}');")

        # Cap at 10
        res_capped = self.db.execute_query("SELECT * FROM items ORDER BY id;", max_rows=10)
        self.assertEqual(res_capped.row_count, 10)
        self.assertEqual(len(res_capped.rows), 10)
        self.assertTrue(res_capped.truncated)

        # Cap at 50 (exceeds total rows)
        res_uncapped = self.db.execute_query("SELECT * FROM items ORDER BY id;", max_rows=50)
        self.assertEqual(res_uncapped.row_count, 25)
        self.assertEqual(len(res_uncapped.rows), 25)
        self.assertFalse(res_uncapped.truncated)

        # None (unbounded legacy mode)
        res_none = self.db.execute_query("SELECT * FROM items ORDER BY id;", max_rows=None)
        self.assertEqual(res_none.row_count, 25)
        self.assertFalse(res_none.truncated)

    # ==========================================================================
    # 2. Smart Schema Pruning + FK Expansion
    # ==========================================================================

    def test_smart_schema_pruning_with_fk_expansion(self):
        """
        Build a 20-table temp SQLite DB where orders has a foreign key to customers,
        plus 18 unrelated sensor tables (sensor_01..sensor_18).
        Assert select_relevant_tables("total order amount by customer", max_tables=4)
        includes BOTH 'orders' and 'customers' and returns <= 4 tables.
        """
        self.db.execute_write("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT);")
        self.db.execute_write("""
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY,
                customer_id INTEGER,
                amount REAL,
                FOREIGN KEY (customer_id) REFERENCES customers(id)
            );
        """)

        # 18 unrelated tables
        for i in range(1, 19):
            t_name = f"sensor_{i:02d}"
            self.db.execute_write(f"CREATE TABLE {t_name} (id INTEGER PRIMARY KEY, reading REAL);")

        all_tables = self.parser.get_table_names()
        self.assertEqual(len(all_tables), 20)

        selected = self.parser.select_relevant_tables(
            "total order amount by customer",
            max_tables=4
        )

        self.assertLessEqual(len(selected), 4)
        self.assertIn("orders", selected)
        self.assertIn("customers", selected)

    # ==========================================================================
    # 3. Bounded Multi-Turn Memory & Security Gate
    # ==========================================================================

    def test_bounded_multi_turn_memory(self):
        """
        Run SQLAgentChain.run('Now filter to West only', conversation_history=[6 turns]):
        - Mock LLMRouter.
        - Assert prompt sent to router.invoke includes Turn 6 and Turn 3-6.
        - Assert prompt excludes Turn 1 and Turn 2 (proving 4-turn VRAM bound).
        - Confirm adversarial follow-ups still trigger SECURITY_BLOCKED with 0 retries.
        """
        self.db.execute_write("""
            CREATE TABLE sales (
                id INTEGER PRIMARY KEY,
                region TEXT,
                revenue REAL
            );
        """)
        self.db.execute_write("INSERT INTO sales VALUES (1, 'West', 5000.0), (2, 'East', 3000.0);")

        mock_router = MagicMock(spec=LLMRouter)
        mock_router.config = LLMConfig(provider="local", model="phi4-mini:latest")

        chain = SQLAgentChain(
            db_manager=self.db,
            schema_parser=self.parser,
            llm_router=mock_router,
            max_repair_attempts=2,
            max_schema_tables=8,
            max_history_turns=4
        )

        history = [
            ConversationTurn(
                natural_query=f"Natural question {i}",
                generated_sql=f"SELECT id, region, revenue FROM sales WHERE id = {i};",
                answer_summary=f"Summary of findings for turn {i}",
                tables_used=("sales",)
            )
            for i in range(1, 7)
        ]

        # 1. Success path on follow-up
        mock_router.invoke.return_value = _make_llm_response(
            "```sql\nSELECT * FROM sales WHERE region = 'West';\n```"
        )
        mock_router.generate.return_value = _make_llm_response(
            "West region has total revenue of $5,000.00."
        )

        result = chain.run("Now filter to West only", conversation_history=history)
        self.assertEqual(result.status, "SUCCESS")

        # Inspect prompt passed to invoke
        call_messages = mock_router.invoke.call_args[0][0]
        system_content = call_messages[0].content

        # Turns 3, 4, 5, 6 MUST be present
        self.assertIn("Turn 3:", system_content)
        self.assertIn("Turn 6:", system_content)
        self.assertIn("Natural question 6", system_content)

        # Turns 1 and 2 MUST be excluded
        self.assertNotIn("Turn 1:", system_content)
        self.assertNotIn("Turn 2:", system_content)
        self.assertNotIn("Natural question 1", system_content)
        self.assertNotIn("Natural question 2", system_content)

        # 2. Adversarial follow-up query: QueryGuard 8-layer filter MUST block with 0 retries
        mock_router.invoke.return_value = _make_llm_response(
            "```sql\nDROP TABLE sales;\n```"
        )

        adv_result = chain.run("Delete all data", conversation_history=history)
        self.assertEqual(adv_result.status, "SECURITY_BLOCKED")
        self.assertEqual(adv_result.repair_attempts, 0)
        self.assertIn("DROP", adv_result.error_message.upper())

    # ==========================================================================
    # 4. Follow-Up Schema Pruning Integration
    # ==========================================================================

    def test_follow_up_schema_pruning_integration(self):
        """
        Verify SQLAgentChain.run(...) on a 12-table DB:
        - Sets result.was_pruned is True.
        - len(result.tables_in_context) <= 8.
        """
        for i in range(1, 13):
            t_name = f"table_{i:02d}"
            self.db.execute_write(f"CREATE TABLE {t_name} (id INTEGER PRIMARY KEY, val REAL);")
            self.db.execute_write(f"INSERT INTO {t_name} VALUES (1, {i * 10.0});")

        all_tables = self.parser.get_table_names()
        self.assertEqual(len(all_tables), 12)

        mock_router = MagicMock(spec=LLMRouter)
        mock_router.config = LLMConfig(provider="local", model="phi4-mini:latest")
        mock_router.invoke.return_value = _make_llm_response(
            "```sql\nSELECT * FROM table_01;\n```"
        )
        mock_router.generate.return_value = _make_llm_response(
            "Data from table_01 retrieved successfully."
        )

        chain = SQLAgentChain(
            db_manager=self.db,
            schema_parser=self.parser,
            llm_router=mock_router,
            max_schema_tables=8,
            max_history_turns=4
        )

        res = chain.run("Show data from table_01")
        self.assertEqual(res.status, "SUCCESS")
        self.assertTrue(res.was_pruned)
        self.assertLessEqual(len(res.tables_in_context), 8)
        self.assertIn("table_01", res.tables_in_context)

    # ==========================================================================
    # 5. Zero-LLM Starter Questions
    # ==========================================================================

    def test_zero_llm_starter_questions(self):
        """
        Verify generate_starter_questions():
        - Returns [] on an empty DB (0 tables).
        - Returns 3 relevant questions (including chart phrasing) on a sales table
          with region/date/revenue columns.
        """
        # 1. Empty database
        empty_questions = generate_starter_questions(self.parser)
        self.assertEqual(empty_questions, [])

        # 2. Sales table with region, date, revenue
        self.db.execute_write("""
            CREATE TABLE sales (
                id INTEGER PRIMARY KEY,
                region TEXT NOT NULL,
                sale_date TEXT NOT NULL,
                revenue REAL NOT NULL
            );
        """)
        self.db.execute_write("""
            INSERT INTO sales VALUES
                (1, 'North', '2026-01-15', 12000.0),
                (2, 'South', '2026-02-10', 9500.0);
        """)

        # Reset schema parser cache to reflect new table
        self.parser.invalidate_cache()
        questions = generate_starter_questions(self.parser, max_questions=3)

        self.assertEqual(len(questions), 3)

        # Verify chart phrasing presence across starter questions
        has_chart_phrasing = any(
            any(kw in q.lower() for kw in ("chart", "bar", "line", "trend"))
            for q in questions
        )
        self.assertTrue(has_chart_phrasing, f"Expected chart phrasing in starter questions: {questions}")

        # Check references to column names
        all_q_text = " ".join(questions).lower()
        self.assertIn("revenue", all_q_text)
        self.assertIn("region", all_q_text)

    # ==========================================================================
    # 6. IEEE-754 Float & Cell / Tabular Formatter
    # ==========================================================================

    def test_ieee754_float_and_cell_formatter(self):
        """
        Verify format_cell_value():
        - format_cell_value(239365.96000000002) == "239,365.96"
        - format_cell_value(1160577.8800000001) == "1,160,577.88"
        - format_cell_value(0.4089) == "0.4089"
        - format_cell_value(1001) == "1001"
        - format_cell_value(None) == "NULL"
        - format_cell_value(True) == "True"
        - format_cell_value(False) == "False"
        - format_cell_value(0.0) == "0.00"
        - format_cell_value(float('nan')) == "NaN"
        - format_cell_value(float('inf')) == "Infinity"
        """
        self.assertEqual(format_cell_value(239365.96000000002), "239,365.96")
        self.assertEqual(format_cell_value(1160577.8800000001), "1,160,577.88")
        self.assertEqual(format_cell_value(0.4089), "0.4089")
        self.assertEqual(format_cell_value(1001), "1001")
        self.assertEqual(format_cell_value(None), "NULL")
        self.assertEqual(format_cell_value(True), "True")
        self.assertEqual(format_cell_value(False), "False")
        self.assertEqual(format_cell_value(0.0), "0.00")
        self.assertEqual(format_cell_value(float("nan")), "NaN")
        self.assertEqual(format_cell_value(float("inf")), "Infinity")
        self.assertEqual(format_cell_value(float("-inf")), "-Infinity")

    def test_format_ascii_table(self):
        """Verify format_ascii_table alignment and truncation footers."""
        columns = ["id", "amount", "notes"]
        rows = [
            [1001, 239365.96000000002, "First\nNote"],
            [1002, 1160577.8800000001, "Second Note"],
            [1003, 0.4089, "Third Note"],
        ]

        # Normal rendering (all rows displayed)
        table_full = format_ascii_table(columns, rows, max_rows=10, truncated=False)
        self.assertIn("1001", table_full)
        self.assertIn("239,365.96", table_full)
        self.assertIn("1,160,577.88", table_full)
        self.assertIn("0.4089", table_full)
        self.assertNotIn("truncated", table_full.lower())

        # Truncated by safety limit (max_rows=1)
        table_truncated = format_ascii_table(columns, rows, max_rows=1, truncated=False)
        self.assertIn("1001", table_truncated)
        self.assertNotIn("1002", table_truncated)
        self.assertIn("truncated", table_truncated.lower())

        # Explicitly marked truncated by database safety guard
        table_flagged = format_ascii_table(columns, rows[:2], max_rows=10, truncated=True)
        self.assertIn("truncated", table_flagged.lower())


if __name__ == "__main__":
    unittest.main()
