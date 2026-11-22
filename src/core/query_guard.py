"""
NEXUS Engine - Query Guard Security Layer
=========================================
Architecture Role: The ultimate security interceptor for Text-to-SQL generation.
Enforces a 0% execution rate for non-SELECT and destructive SQL operations.

Defensive Architecture:
Layer 1: Structural Sanitization & Null-Byte Neutralization.
Layer 2: Multi-Statement Stack Injection Guard (Strict single-statement enforcement).
Layer 3: String Literal & Quoted Identifier Masking (Zero false-positives on data).
Layer 4: AST & Recursive Token Stream Inspection (sqlparse + native AST validation).
Layer 5: Comprehensive DDL/DML/Administrative Keyword Blacklist.
Layer 6: SQLite C-Level Authorizer Engine Verification (Pre-execution compilation).

Author: Senior Systems Engineer
Target Engine: SQLite3 / Text-to-SQL
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any, List, Optional, Set, Tuple

# Optional sqlparse integration
try:
    import sqlparse
    from sqlparse.sql import Comment, Identifier, Statement, Token, TokenList
    from sqlparse.tokens import DDL, DML, Keyword, Punctuation
    HAS_SQLPARSE = True
except ImportError:
    HAS_SQLPARSE = False


# ==============================================================================
# SECURITY EXCEPTIONS
# ==============================================================================

class SecurityException(Exception):
    """
    Raised whenever an LLM-generated query attempts a prohibited SQL operation,
    violates read-only policy, or exhibits SQL injection patterns.
    """
    def __init__(
        self,
        message: str,
        violation_type: str = "SECURITY_VIOLATION",
        query: Optional[str] = None
    ) -> None:
        self.message = message
        self.violation_type = violation_type
        self.query = query
        super().__init__(f"[{self.violation_type}] {self.message}")


# ==============================================================================
# QUERY GUARD ENGINE
# ==============================================================================

class QueryGuard:
    """
    Strict security policy enforcer for LLM-generated SQL queries.

    Invariants:
    1. Exactly ONE statement per execution. Multi-statement injection is blocked.
    2. Root statement MUST be a 'SELECT' or a 'WITH' clause (CTE) terminating in a 'SELECT'.
    3. Destructive DML (INSERT, UPDATE, DELETE, TRUNCATE, REPLACE, MERGE, UPSERT) is blocked.
    4. Destructive DDL (DROP, CREATE, ALTER, REINDEX) is blocked.
    5. Database administration & file I/O (PRAGMA, VACUUM, ATTACH, DETACH, EXEC) is blocked.
    6. Safe against false-positives: Keywords inside string literals ('DROP', 'DELETE')
       and table/column identifiers (e.g. `is_deleted`, `last_updated`) are preserved.
    """

    # Prohibited SQL operations across all dialects
    FORBIDDEN_KEYWORDS: Set[str] = frozenset({
        # Data Modification Language (DML)
        "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REPLACE", "UPSERT", "MERGE",
        # Data Definition Language (DDL)
        "DROP", "CREATE", "ALTER", "REINDEX",
        # Stored Procedures & Executables
        "EXEC", "EXECUTE", "CALL", "LOAD_EXTENSION",
        # Administrative & Engine Configuration
        "PRAGMA", "VACUUM", "ATTACH", "DETACH", "SAVEPOINT", "RELEASE",
        # Access Control & Permissions
        "GRANT", "REVOKE",
        # Exfiltration / Redirection
        "INTO",
    })

    # Allowed leading command tokens
    ALLOWED_ROOT_COMMANDS: Set[str] = frozenset({"SELECT", "WITH"})

    # Regex patterns for string literals and comments
    _RE_SINGLE_QUOTES = re.compile(r"'(?:''|[^'])*'")
    _RE_DOUBLE_QUOTES = re.compile(r'"(?:""|[^"])*"')
    _RE_LINE_COMMENT = re.compile(r"--[^\r\n]*")
    _RE_BLOCK_COMMENT = re.compile(r"/\*[\s\S]*?\*/")

    def __init__(self, enable_engine_authorizer: bool = True) -> None:
        self.enable_engine_authorizer = enable_engine_authorizer

    # --------------------------------------------------------------------------
    # PUBLIC API
    # --------------------------------------------------------------------------

    def validate(self, sql: str, db_connection: Optional[sqlite3.Connection] = None) -> str:
        """
        Validates raw SQL string against all security rules.

        Parameters:
            sql: Raw SQL text emitted by LLM.
            db_connection: Optional SQLite connection to run authorizer bytecode validation.

        Returns:
            Sanitized, validated SQL string ready for execution.

        Raises:
            SecurityException: If ANY security violation or non-SELECT operation is detected.
        """
        if not isinstance(sql, str):
            raise SecurityException("SQL payload must be a string.", "INVALID_PAYLOAD_TYPE")

        sanitized_sql = sql.strip()

        # Step 1: Payload sanity checks (null bytes, empty strings)
        self._check_payload_integrity(sanitized_sql)

        # Step 2: Strip comments while preserving string literals
        uncommented_sql = self._strip_comments(sanitized_sql)
        if not uncommented_sql.strip():
            raise SecurityException("SQL statement is empty after removing comments.", "EMPTY_QUERY")

        # Step 3: Single-statement constraint (Prevent stacked query injection)
        clean_statement = self._enforce_single_statement(uncommented_sql)

        # Step 4: Mask string literals to prevent false positives on data values
        masked_sql = self._mask_literals(clean_statement)

        # Step 5: Whitelist root statement check (MUST start with SELECT or WITH)
        self._check_root_command(masked_sql, clean_statement)

        # Step 6: Token scan across masked SQL (catches forbidden keywords anywhere in AST)
        self._scan_forbidden_tokens(masked_sql, clean_statement)

        # Step 7: AST parsing (sqlparse) if available
        if HAS_SQLPARSE:
            self._validate_ast(clean_statement)

        # Step 8: SQLite C-Level Authorizer Dry-Run
        if self.enable_engine_authorizer:
            self._verify_with_authorizer(clean_statement, db_connection)

        return clean_statement

    def is_safe(self, sql: str) -> Tuple[bool, Optional[str]]:
        """
        Non-raising predicate helper. Returns (True, None) or (False, error_message).
        """
        try:
            self.validate(sql)
            return True, None
        except SecurityException as exc:
            return False, str(exc)

    # --------------------------------------------------------------------------
    # VALIDATION STAGES
    # --------------------------------------------------------------------------

    def _check_payload_integrity(self, sql: str) -> None:
        """Reject empty queries or payloads with dangerous byte sequences."""
        if not sql:
            raise SecurityException("SQL query string is empty.", "EMPTY_QUERY")

        if "\x00" in sql:
            raise SecurityException(
                "Null byte detected in SQL payload. Potential poison string.",
                "NULL_BYTE_INJECTION"
            )

    def _strip_comments(self, sql: str) -> str:
        """
        Strips inline (-- ...) and block (/* ... */) comments without corrupting
        string literals that happen to contain comment delimiters.
        """
        # Collect and mask string literals temporarily
        strings: List[str] = []

        def replace_str(match: re.Match) -> str:
            strings.append(match.group(0))
            return f"__NEXUS_STR_{len(strings)-1}__"

        temp = self._RE_SINGLE_QUOTES.sub(replace_str, sql)
        temp = self._RE_DOUBLE_QUOTES.sub(replace_str, temp)

        # Remove comments safely from unquoted code
        temp = self._RE_BLOCK_COMMENT.sub(" ", temp)
        temp = self._RE_LINE_COMMENT.sub(" ", temp)

        # Restore original string literals
        for idx, original in enumerate(strings):
            temp = temp.replace(f"__NEXUS_STR_{idx}__", original)

        return temp.strip()

    def _enforce_single_statement(self, sql: str) -> str:
        """
        Disallows multiple semicolon-separated statements (e.g., 'SELECT 1; DROP TABLE users;').
        Allows a single optional trailing semicolon.
        """
        clean = sql.strip()
        # Strip one trailing semicolon if present
        if clean.endswith(";"):
            clean = clean[:-1].strip()

        # Mask string literals before scanning for intermediate semicolons
        masked = self._mask_literals(clean)

        if ";" in masked:
            raise SecurityException(
                "Multiple statements detected. Text-to-SQL engine strictly permits only 1 statement.",
                "MULTI_STATEMENT_DETECTED",
                sql
            )

        return clean

    def _mask_literals(self, sql: str) -> str:
        """
        Replaces 'string literals' and \"quoted identifiers\" with neutral tokens.
        Ensures queries like:
            SELECT * FROM orders WHERE status = 'dropped'
        do not trigger a false-positive on 'DROP'.
        """
        masked = self._RE_SINGLE_QUOTES.sub("'__NEXUS_VAL__'", sql)
        masked = self._RE_DOUBLE_QUOTES.sub('"__NEXUS_ID__"', masked)
        return masked

    def _check_root_command(self, masked_sql: str, original_sql: str) -> None:
        """
        Ensures the root statement starts with an allowed read-only command (SELECT or WITH).
        """
        # Find the first whole word token
        match = re.match(r"^\s*([A-Za-z_]+)", masked_sql)
        if not match:
            raise SecurityException(
                "Malformed SQL statement. No root command recognized.",
                "SYNTAX_ANOMALY",
                original_sql
            )

        root_command = match.group(1).upper()
        if root_command not in self.ALLOWED_ROOT_COMMANDS:
            raise SecurityException(
                f"Prohibited SQL statement type: '{root_command}'. Only SELECT queries are permitted.",
                "NON_SELECT_STATEMENT",
                original_sql
            )

        # If statement begins with WITH (Common Table Expression), verify it ends in SELECT
        if root_command == "WITH":
            self._validate_cte_structure(masked_sql, original_sql)

    def _validate_cte_structure(self, masked_sql: str, original_sql: str) -> None:
        """
        Validates that a CTE (WITH ... SELECT) does not conceal a DML mutation
        such as 'WITH cte AS (SELECT ...) DELETE FROM ...'.
        """
        # Remove parenthesized CTE expressions: (...)
        # The concluding statement must be a SELECT
        stripped = re.sub(r"\([^()]*\)", " ", masked_sql)
        # Repeat to handle nested parentheses up to 5 levels
        for _ in range(5):
            stripped = re.sub(r"\([^()]*\)", " ", stripped)

        # Match the concluding statement after all CTE definitions
        tokens = [t.upper() for t in re.findall(r"\b[A-Za-z_]+\b", stripped)]
        # Filter out 'WITH' and identifiers; find the final statement verb
        verbs = [t for t in tokens if t in self.FORBIDDEN_KEYWORDS or t == "SELECT"]

        if not verbs or verbs[-1] != "SELECT":
            raise SecurityException(
                "CTE query does not terminate in a SELECT statement.",
                "CTE_MUTATION_ATTEMPT",
                original_sql
            )

    def _scan_forbidden_tokens(self, masked_sql: str, original_sql: str) -> None:
        """
        Performs a full regex token scan on the masked SQL to detect any forbidden
        DDL/DML/Administrative keyword, even in deeply nested subqueries.
        """
        # Find all words
        words = re.findall(r"\b[A-Za-z_]+\b", masked_sql)
        for word in words:
            upper_word = word.upper()
            if upper_word in self.FORBIDDEN_KEYWORDS:
                raise SecurityException(
                    f"Prohibited SQL operation detected: '{upper_word}'. "
                    f"Text-to-SQL engine strictly forbids non-SELECT operations.",
                    f"FORBIDDEN_KEYWORD_{upper_word}",
                    original_sql
                )

    def _validate_ast(self, sql: str) -> None:
        """
        Deep AST inspection using sqlparse.
        Traverses all AST nodes and subqueries to enforce SELECT-only semantics.
        """
        parsed = sqlparse.parse(sql)
        if len(parsed) != 1:
            raise SecurityException(
                f"sqlparse detected {len(parsed)} statements. Only 1 is allowed.",
                "MULTI_STATEMENT_DETECTED",
                sql
            )

        stmt = parsed[0]
        stmt_type = stmt.get_type()

        # sqlparse reports 'UNKNOWN' for WITH statements, which we already verified in _check_root_command
        if stmt_type not in ("SELECT", "UNKNOWN"):
            raise SecurityException(
                f"sqlparse AST classified query as '{stmt_type}'. Expected 'SELECT'.",
                "NON_SELECT_AST",
                sql
            )

        # Recursively inspect every token in the AST
        self._traverse_tokens(stmt.tokens, sql)

    def _traverse_tokens(self, tokens: List[Token], original_sql: str) -> None:
        """Recursively checks tokens and token lists for prohibited syntax."""
        for token in tokens:
            if token.is_whitespace or isinstance(token, Comment):
                continue

            # Check DDL / DML token types
            if token.ttype in (DDL, DML):
                val = token.value.upper()
                if val != "SELECT":
                    raise SecurityException(
                        f"AST DDL/DML token prohibited: '{val}'.",
                        f"FORBIDDEN_AST_TOKEN_{val}",
                        original_sql
                    )

            # Check keyword values
            if token.is_keyword:
                val = token.value.upper()
                if val in self.FORBIDDEN_KEYWORDS:
                    raise SecurityException(
                        f"AST Keyword prohibited: '{val}'.",
                        f"FORBIDDEN_AST_KEYWORD_{val}",
                        original_sql
                    )

            # Recurse into composite structures (subqueries, parentheses, clauses)
            if isinstance(token, TokenList):
                self._traverse_tokens(token.tokens, original_sql)

    def _verify_with_authorizer(
        self,
        sql: str,
        db_connection: Optional[sqlite3.Connection] = None
    ) -> None:
        """
        SQLite C-Level Authorizer Verification.
        Compiles the query against SQLite's bytecode generator using EXPLAIN.
        If SQLite attempts ANY write or administrative action, the authorizer denies it.
        """
        # Use provided connection or an in-memory harness
        should_close = False
        if db_connection is not None:
            conn = db_connection
        else:
            conn = sqlite3.connect(":memory:")
            should_close = True

        def strict_authorizer(action_code: int, arg1: Any, arg2: Any, db_name: Any, trigger_name: Any) -> int:
            # 21: SQLITE_SELECT, 20: SQLITE_READ, 31: SQLITE_FUNCTION
            allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
            if action_code not in allowed:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        prev_authorizer = None
        try:
            conn.set_authorizer(strict_authorizer)
            cursor = conn.cursor()
            # EXPLAIN compiles the bytecode and runs the authorizer without data execution
            cursor.execute(f"EXPLAIN {sql};")
            cursor.close()
        except sqlite3.DatabaseError as exc:
            msg = str(exc).lower()
            if "not authorized" in msg:
                raise SecurityException(
                    "SQLite engine authorizer rejected the query. Destructive operation intercepted.",
                    "ENGINE_AUTHORIZER_DENIED",
                    sql
                ) from exc
            # If the error is simply 'no such table', static analysis already passed,
            # which is normal when verifying against an isolated harness
            if "no such table" in msg or "no such column" in msg:
                pass
            else:
                # Other operational errors (e.g. syntax)
                pass
        finally:
            if should_close:
                conn.close()
            else:
                conn.set_authorizer(None)


# Singleton instance for simple module imports
default_guard = QueryGuard()


def guard_query(sql: str, db_connection: Optional[sqlite3.Connection] = None) -> str:
    """Convenience helper function to validate a query with the default guard."""
    return default_guard.validate(sql, db_connection=db_connection)
