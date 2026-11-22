"""
NEXUS Engine - Security Test Suite
==================================
Unit tests verifying that QueryGuard strictly rejects 100% of non-SELECT
queries, handles complex injection obfuscations, and allows valid SELECTs.
"""

import sys
import unittest
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.query_guard import QueryGuard, SecurityException


class TestQueryGuardSecurity(unittest.TestCase):

    def setUp(self):
        self.guard = QueryGuard()

    # --------------------------------------------------------------------------
    # 1. POSITIVE TESTS: Legitimate SELECT Queries Must Pass
    # --------------------------------------------------------------------------

    def test_simple_select_passes(self):
        sql = "SELECT id, name, email FROM users WHERE active = 1;"
        result = self.guard.validate(sql)
        self.assertTrue(result.startswith("SELECT"))

    def test_complex_join_and_aggregation_passes(self):
        sql = """
        SELECT u.id, u.username, COUNT(o.order_id) AS total_orders, SUM(o.amount) AS total_spent
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.country = 'US'
        GROUP BY u.id, u.username
        HAVING COUNT(o.order_id) > 5
        ORDER BY total_spent DESC
        LIMIT 10;
        """
        result = self.guard.validate(sql)
        self.assertIn("total_orders", result)

    def test_valid_cte_passes(self):
        sql = """
        WITH regional_sales AS (
            SELECT region, SUM(amount) AS total_sales
            FROM orders
            GROUP BY region
        ),
        top_regions AS (
            SELECT region
            FROM regional_sales
            WHERE total_sales > 10000
        )
        SELECT * FROM top_regions;
        """
        result = self.guard.validate(sql)
        self.assertTrue(result.startswith("WITH"))

    def test_nested_subquery_select_passes(self):
        sql = """
        SELECT username
        FROM users
        WHERE id IN (
            SELECT user_id FROM orders WHERE amount > 500
        );
        """
        result = self.guard.validate(sql)
        self.assertIn("IN", result)

    # --------------------------------------------------------------------------
    # 2. FALSE POSITIVE PREVENTION: Words inside strings or column names
    # --------------------------------------------------------------------------

    def test_keyword_inside_string_literal_passes(self):
        sql = "SELECT * FROM orders WHERE status = 'dropped' AND action = 'DELETE_RECORD';"
        result = self.guard.validate(sql)
        self.assertIn("'dropped'", result)

    def test_keyword_substrings_in_identifiers_passes(self):
        sql = "SELECT user_id, is_deleted, last_updated, alter_ego FROM accounts;"
        result = self.guard.validate(sql)
        self.assertIn("is_deleted", result)

    def test_table_name_containing_keyword_substring_passes(self):
        sql = "SELECT * FROM drop_shipments WHERE status = 'in_transit';"
        result = self.guard.validate(sql)
        self.assertIn("drop_shipments", result)

    def test_comments_inside_string_literals_passes(self):
        sql = "SELECT * FROM notes WHERE text = 'This is -- not a comment and /* not block */';"
        result = self.guard.validate(sql)
        self.assertIn("-- not a comment", result)

    # --------------------------------------------------------------------------
    # 3. DIRECT NON-SELECT STATEMENTS: Must Be Strictly Blocked
    # --------------------------------------------------------------------------

    def test_reject_insert(self):
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate("INSERT INTO users (username) VALUES ('hacker');")
        self.assertIn("INSERT", str(ctx.exception))

    def test_reject_update(self):
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate("UPDATE users SET is_admin = 1 WHERE id = 5;")
        self.assertIn("UPDATE", str(ctx.exception))

    def test_reject_delete(self):
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate("DELETE FROM users WHERE 1=1;")
        self.assertIn("DELETE", str(ctx.exception))

    def test_reject_drop(self):
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate("DROP TABLE users;")
        self.assertIn("DROP", str(ctx.exception))

    def test_reject_alter(self):
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate("ALTER TABLE users ADD COLUMN backdoor TEXT;")
        self.assertIn("ALTER", str(ctx.exception))

    def test_reject_truncate(self):
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate("TRUNCATE TABLE logs;")
        self.assertIn("TRUNCATE", str(ctx.exception))

    def test_reject_exec(self):
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate("EXEC xp_cmdshell 'dir';")
        self.assertIn("EXEC", str(ctx.exception))

    def test_reject_pragma(self):
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate("PRAGMA writable_schema = 1;")
        self.assertIn("PRAGMA", str(ctx.exception))

    def test_reject_replace_into(self):
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate("REPLACE INTO users (id, name) VALUES (1, 'bad');")
        self.assertIn("REPLACE", str(ctx.exception))

    def test_reject_upsert_merge(self):
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate("MERGE INTO target_table USING source_table ON 1=1 WHEN MATCHED THEN DELETE;")
        self.assertIn("MERGE", str(ctx.exception))

    # --------------------------------------------------------------------------
    # 4. COMPLEX & NESTED ATTACKS: Multi-statement, Obfuscation, CTE Exploits
    # --------------------------------------------------------------------------

    def test_reject_multi_statement_semicolon(self):
        sql = "SELECT * FROM users; DROP TABLE orders;"
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate(sql)
        self.assertIn("MULTI_STATEMENT_DETECTED", str(ctx.exception))

    def test_reject_stacked_statement_with_comments(self):
        sql = "SELECT 1; -- comment\nDELETE FROM users;"
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate(sql)
        self.assertTrue(
            "MULTI_STATEMENT_DETECTED" in str(ctx.exception) or "DELETE" in str(ctx.exception)
        )

    def test_reject_block_comment_obfuscation(self):
        sql = "/* Harmless comment */ DROP TABLE users;"
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate(sql)
        self.assertIn("DROP", str(ctx.exception))

    def test_reject_destructive_cte_suffix(self):
        sql = "WITH cte AS (SELECT * FROM orders) DELETE FROM orders;"
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate(sql)
        self.assertTrue(
            "DELETE" in str(ctx.exception) or "CTE" in str(ctx.exception)
        )

    def test_reject_destructive_cte_embedded(self):
        sql = "WITH deleted AS (DELETE FROM users RETURNING *) SELECT * FROM deleted;"
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate(sql)
        self.assertIn("DELETE", str(ctx.exception))

    def test_reject_nested_subquery_mutation(self):
        sql = "SELECT * FROM (INSERT INTO logs VALUES ('probe'))"
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate(sql)
        self.assertIn("INSERT", str(ctx.exception))

    def test_reject_select_into(self):
        sql = "SELECT * INTO new_table FROM users;"
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate(sql)
        self.assertIn("INTO", str(ctx.exception))

    def test_reject_attach_database(self):
        sql = "ATTACH DATABASE 'malicious.db' AS evil;"
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate(sql)
        self.assertTrue("ATTACH" in str(ctx.exception) or "NON_SELECT" in str(ctx.exception))

    def test_reject_vacuum_into(self):
        sql = "VACUUM INTO 'exploit.db';"
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate(sql)
        self.assertTrue("VACUUM" in str(ctx.exception) or "NON_SELECT" in str(ctx.exception))

    def test_reject_null_byte_injection(self):
        sql = "SELECT * FROM users\x00; DROP TABLE users;"
        with self.assertRaises(SecurityException) as ctx:
            self.guard.validate(sql)
        self.assertIn("NULL_BYTE_INJECTION", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
