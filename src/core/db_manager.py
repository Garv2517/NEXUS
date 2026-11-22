"""
NEXUS Engine - Core Database Manager
====================================
Architecture Role: Synchronous, high-concurrency SQLite connection wrapper
engineered for read-heavy Text-to-SQL workloads.

Core Capabilities:
1. Safe Read/Write Separation with Process-level and Engine-level Locks.
2. WAL Mode and In-Memory Optimizations for Ultra-Low Latency Reads.
3. Resilient Retry Mechanisms with Jittered Exponential Backoff for Database Lock Contention.
4. Engine-enforced Read-Only Guarantees (PRAGMA query_only = ON) for LLM Queries.
5. In-Memory Thread-Safe Telemetry Logger Tracking Latency, Row Counts, and Status.
6. Persistent Disk-Backed Query Audit Ledger (_nexus_query_audit).

Author: Senior Systems Engineer
Target DB: data/database/nexus_workspace.db
"""

from __future__ import annotations

import collections
import dataclasses
import os
import random
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

from src.core.runtime_paths import (
    get_database_dir,
    get_database_path,
    get_resource_root,
)

# Optional Pandas bridge for data manipulation
try:
    import pandas as pd
except ImportError:
    pd = None

# Structured logging with stdlib fallback
try:
    from loguru import logger
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("NEXUS-Core")  # type: ignore


# ==============================================================================
# EXCEPTIONS & DATA STRUCTURES
# ==============================================================================

class DatabaseError(Exception):
    """Base exception for all NEXUS database errors."""
    pass


class DatabaseLockedError(DatabaseError):
    """Raised when a database lock persists beyond maximum retry limits."""
    pass


class ReadOnlyViolationError(DatabaseError):
    """Raised when a write/mutation operation is attempted in a read-only context."""
    pass


class QueryExecutionError(DatabaseError):
    """Raised when SQL syntax or runtime execution fails."""
    pass


@dataclasses.dataclass(frozen=True)
class QueryTelemetry:
    """Immutable telemetry record captured for every executed SQL statement."""
    query_id: str
    sql: str
    parameters: Union[Tuple[Any, ...], Dict[str, Any]]
    execution_time_ms: float
    row_count: int
    status: str  # 'SUCCESS', 'FAILED', 'LOCK_RETRY'
    is_read_only: bool
    timestamp: float
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_id": self.query_id,
            "sql": self.sql,
            "parameters": str(self.parameters),
            "execution_time_ms": round(self.execution_time_ms, 3),
            "row_count": self.row_count,
            "status": self.status,
            "is_read_only": self.is_read_only,
            "timestamp": self.timestamp,
            "error_message": self.error_message,
        }


@dataclasses.dataclass
class QueryResult:
    """Structured response container for query executions."""
    columns: List[str]
    rows: List[Any]
    row_count: int
    execution_time_ms: float
    sql: str

    def to_dicts(self) -> List[Dict[str, Any]]:
        """Convert rows to a list of column-to-value dictionaries."""
        return [dict(zip(self.columns, row)) for row in self.rows]

    def to_dataframe(self) -> Any:
        """Convert results to a pandas DataFrame if pandas is installed."""
        if pd is None:
            raise ImportError("Pandas is not installed. Run 'pip install pandas'.")
        return pd.DataFrame(self.rows, columns=self.columns)


# ==============================================================================
# TELEMETRY ENGINE
# ==============================================================================

class TelemetryLogger:
    """
    Lightweight, thread-safe in-memory ring buffer recording query metrics.
    Zero external I/O overhead; maintains rolling history for diagnostics and UI.
    """

    def __init__(self, max_records: int = 1000) -> None:
        self._history: collections.deque[QueryTelemetry] = collections.deque(maxlen=max_records)
        self._lock = threading.Lock()
        self._query_counter: int = 0

    def next_query_id(self) -> str:
        with self._lock:
            self._query_counter += 1
            return f"Q-{self._query_counter:06d}"

    def record(self, telemetry: QueryTelemetry) -> None:
        """Append metric record and emit structured log."""
        with self._lock:
            self._history.append(telemetry)

        # High-visibility logging based on performance & status
        duration = f"{telemetry.execution_time_ms:.2f}ms"
        if telemetry.status == "SUCCESS":
            if telemetry.execution_time_ms > 1000:
                logger.warning(
                    f"[SLOW QUERY {telemetry.query_id}] ({duration}) [{telemetry.row_count} rows] "
                    f"SQL: {telemetry.sql[:120]}"
                )
            else:
                logger.debug(
                    f"[QUERY {telemetry.query_id}] ({duration}) [{telemetry.row_count} rows] "
                    f"SQL: {telemetry.sql[:80]}"
                )
        elif telemetry.status == "FAILED":
            logger.error(
                f"[QUERY FAILED {telemetry.query_id}] ({duration}) Error: {telemetry.error_message} "
                f"SQL: {telemetry.sql[:120]}"
            )

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent query history in reverse chronological order."""
        with self._lock:
            items = list(self._history)
        return [item.to_dict() for item in reversed(items[-limit:])]

    def get_metrics(self) -> Dict[str, Any]:
        """Compute aggregate performance statistics."""
        with self._lock:
            items = list(self._history)

        total = len(items)
        if total == 0:
            return {
                "total_queries": 0,
                "avg_execution_ms": 0.0,
                "p95_execution_ms": 0.0,
                "error_count": 0,
                "slow_queries_over_1s": 0,
            }

        latencies = sorted(item.execution_time_ms for item in items)
        p95_index = int(total * 0.95)
        p95 = latencies[min(p95_index, total - 1)]
        errors = sum(1 for item in items if item.status == "FAILED")
        slow = sum(1 for item in items if item.execution_time_ms > 1000)

        return {
            "total_queries": total,
            "avg_execution_ms": round(sum(latencies) / total, 3),
            "p95_execution_ms": round(p95, 3),
            "error_count": errors,
            "slow_queries_over_1s": slow,
        }

    def clear(self) -> None:
        with self._lock:
            self._history.clear()


# ==============================================================================
# CONFIGURATION & RECOVERY PARAMETERS
# ==============================================================================

class DatabaseConfigMeta(type):
    """Metaclass allowing dynamic evaluation of DatabaseConfig path properties."""

    @property
    def PROJECT_ROOT(cls) -> Path:
        return get_resource_root()

    @property
    def DEFAULT_DB_DIR(cls) -> Path:
        return get_database_dir()

    @property
    def DEFAULT_DB_PATH(cls) -> Path:
        return get_database_path()


class DatabaseConfig(metaclass=DatabaseConfigMeta):
    """Hardware and engine tuning directives for local SQLite storage."""

    @property
    def PROJECT_ROOT(self) -> Path:
        return get_resource_root()

    @property
    def DEFAULT_DB_DIR(self) -> Path:
        return get_database_dir()

    @property
    def DEFAULT_DB_PATH(self) -> Path:
        return get_database_path()

    # Concurrency and timeout limits
    BUSY_TIMEOUT_MS: int = 5000       # Engine-level busy handler wait time
    MAX_LOCK_RETRIES: int = 5          # Application-level retry iterations on lock
    INITIAL_BACKOFF_SEC: float = 0.05  # Base retry backoff
    BACKOFF_FACTOR: float = 2.0        # Exponential multiplier
    JITTER_SEC: float = 0.03           # Random delay perturbation to break lock harmonics

    # Memory and Cache tuning for Read-Heavy analytical workloads
    MMAP_SIZE_BYTES: int = 268435456   # 256MB memory-mapped I/O
    CACHE_SIZE_KB: int = -64000        # 64MB memory page cache (negative = KiB)


# ==============================================================================
# CORE DATABASE MANAGER
# ==============================================================================

class DatabaseManager:
    """
    Production-grade SQLite Connection & Lock Wrapper.

    Architectural Invariants:
    1. Read operations are concurrent, thread-isolated, and leverage WAL mode.
    2. Write operations are serialized via a threading Lock and executed using
       'BEGIN IMMEDIATE' transactions to eliminate mid-transaction lock escalation deadlocks.
    3. Engine-level 'PRAGMA query_only = ON' guarantees that read-only evaluations
       cannot mutate the database, even if an LLM generates a malicious mutation.
    4. Database lock errors are handled with exponential backoff and jitter.
    5. Every statement is measured by high-precision performance timers and logged.
    6. Critical audit events are persisted to the _nexus_query_audit disk ledger.
    """

    _instance: Optional[DatabaseManager] = None
    _singleton_lock = threading.Lock()

    @classmethod
    def reset_instance(cls) -> None:
        """Reset singleton instance (primarily for isolated unit testing)."""
        with cls._singleton_lock:
            if cls._instance is not None:
                cls._instance.close()
                cls._instance = None

    def __new__(cls, db_path: Optional[Union[Path, str]] = None) -> DatabaseManager:
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path: Optional[Union[Path, str]] = None) -> None:
        new_path = Path(db_path) if db_path else DatabaseConfig.DEFAULT_DB_PATH
        if getattr(self, "_initialized", False) and self.db_path == new_path:
            return

        self.db_path = new_path
        self._write_lock = threading.Lock()
        self._thread_local = threading.local()
        self._all_connections: set[sqlite3.Connection] = set()
        self._connections_lock = threading.Lock()
        self.telemetry = TelemetryLogger()
        self._initialized = True

        # Ensure directory exists immediately
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database_file()
        logger.info(f"DatabaseManager initialized. Active DB: {self.db_path}")

    def _configure_base_pragmas(self, conn: sqlite3.Connection) -> None:
        """Applies foundational pragmas required on every SQLite connection."""
        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.execute("PRAGMA journal_mode = WAL;")
        cursor.execute("PRAGMA synchronous = NORMAL;")
        cursor.execute(f"PRAGMA busy_timeout = {DatabaseConfig.BUSY_TIMEOUT_MS};")
        cursor.execute("PRAGMA temp_store = MEMORY;")
        cursor.execute(f"PRAGMA mmap_size = {DatabaseConfig.MMAP_SIZE_BYTES};")
        cursor.execute(f"PRAGMA cache_size = {DatabaseConfig.CACHE_SIZE_KB};")
        cursor.close()

    def _get_read_connection(self) -> sqlite3.Connection:
        """
        Thread-local connection pool for reads.
        Threads reuse their own connection, eliminating reconnect overhead.
        Enforces PRAGMA query_only = ON for absolute write safety.
        """
        conn = getattr(self._thread_local, "read_conn", None)
        if conn is not None:
            try:
                conn.execute("SELECT 1;")
            except (sqlite3.ProgrammingError, sqlite3.OperationalError):
                conn = None
                self._thread_local.read_conn = None

        if conn is None:
            conn = sqlite3.connect(
                database=str(self.db_path),
                timeout=DatabaseConfig.BUSY_TIMEOUT_MS / 1000.0,
                check_same_thread=True,
                isolation_level=None  # Explicit autocommit / manual control
            )
            conn.row_factory = sqlite3.Row
            self._configure_base_pragmas(conn)
            # Enforce read-only constraint at the SQLite engine level
            conn.execute("PRAGMA query_only = ON;")
            self._thread_local.read_conn = conn
            with self._connections_lock:
                self._all_connections.add(conn)
        return conn

    def _create_write_connection(self) -> sqlite3.Connection:
        """
        Create a dedicated connection for write transactions.
        Writes are kept strictly isolated and short-lived.
        """
        conn = sqlite3.connect(
            database=str(self.db_path),
            timeout=DatabaseConfig.BUSY_TIMEOUT_MS / 1000.0,
            check_same_thread=False,
            isolation_level=None
        )
        conn.row_factory = sqlite3.Row
        self._configure_base_pragmas(conn)
        with self._connections_lock:
            self._all_connections.add(conn)
        return conn

    def _init_database_file(self) -> None:
        """Initialize empty DB file with metadata and audit tables if missing."""
        with self.transaction() as cursor:
            # Core system metadata
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS _nexus_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Query audit ledger for Text-to-SQL governance & telemetry persistence
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS _nexus_query_audit (
                    query_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    natural_query TEXT NOT NULL,
                    generated_sql TEXT NOT NULL,
                    status TEXT NOT NULL,
                    execution_status TEXT,
                    error_message TEXT,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Schema synchronization if table existed previously under legacy schema
            cursor.execute("PRAGMA table_info(_nexus_query_audit);")
            existing_cols = {row[1] for row in cursor.fetchall()}
            if "status" not in existing_cols and len(existing_cols) > 0:
                try:
                    cursor.execute("ALTER TABLE _nexus_query_audit ADD COLUMN status TEXT;")
                    cursor.execute("UPDATE _nexus_query_audit SET status = execution_status WHERE status IS NULL;")
                except Exception:
                    pass

            cursor.execute("""
                INSERT INTO _nexus_metadata (key, value, updated_at)
                VALUES ('schema_version', '1.0.0', CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP;
            """)

    # --------------------------------------------------------------------------
    # AUDIT LOGGING PERSISTENCE
    # --------------------------------------------------------------------------

    def log_audit_event(
        self,
        natural_query: str,
        generated_sql: str,
        status: str,
        error_message: Optional[str] = None
    ) -> None:
        """
        Persists a Text-to-SQL query audit record to the SQLite disk ledger
        (_nexus_query_audit) for governance, security audits, and compliance tracking.
        """
        status_val = status.upper()
        with self.transaction() as cursor:
            cursor.execute("PRAGMA table_info(_nexus_query_audit);")
            cols = {row[1] for row in cursor.fetchall()}

            if "status" in cols and "execution_status" in cols:
                cursor.execute(
                    """
                    INSERT INTO _nexus_query_audit 
                    (natural_query, generated_sql, status, execution_status, error_message)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (natural_query, generated_sql, status_val, status_val, error_message)
                )
            elif "execution_status" in cols:
                cursor.execute(
                    """
                    INSERT INTO _nexus_query_audit 
                    (natural_query, generated_sql, execution_status, error_message)
                    VALUES (?, ?, ?, ?);
                    """,
                    (natural_query, generated_sql, status_val, error_message)
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO _nexus_query_audit 
                    (natural_query, generated_sql, status, error_message)
                    VALUES (?, ?, ?, ?);
                    """,
                    (natural_query, generated_sql, status_val, error_message)
                )

    # --------------------------------------------------------------------------
    # LOCK RECOVERY & RETRY LOGIC
    # --------------------------------------------------------------------------

    def _is_lock_error(self, exc: Exception) -> bool:
        """Detect whether an OperationalError represents a locked/busy database."""
        if not isinstance(exc, sqlite3.OperationalError):
            return False
        msg = str(exc).lower()
        return "locked" in msg or "busy" in msg

    # --------------------------------------------------------------------------
    # PUBLIC QUERY EXECUTION API
    # --------------------------------------------------------------------------

    @contextmanager
    def readonly(self) -> Generator[sqlite3.Cursor, None, None]:
        """
        Thread-safe context manager for high-throughput read-only operations.
        Yields a cursor from the cached thread-local connection (configured with
        PRAGMA query_only = ON) and safely closes the cursor upon exit without
        terminating the reusable underlying connection.
        """
        conn = self._get_read_connection()
        cursor = conn.cursor()
        try:
            yield cursor
        finally:
            cursor.close()

    def execute_query(
        self,
        sql: str,
        params: Union[Tuple[Any, ...], Dict[str, Any]] = (),
        read_only: bool = True
    ) -> QueryResult:
        """
        Primary execution method for Text-to-SQL statements.

        Parameters:
            sql: The SQL string to execute.
            params: Query parameter tuple or dict.
            read_only: If True, executes on a thread-local cached connection with
                       PRAGMA query_only = ON. If False, delegates to write pipeline.

        Returns:
            QueryResult containing column headers, rows, count, and execution time.
        """
        if not read_only:
            # Route mutations to the write transaction pipeline
            self.execute_write(sql, params)
            return QueryResult(columns=[], rows=[], row_count=0, execution_time_ms=0.0, sql=sql)

        query_id = self.telemetry.next_query_id()
        start_time = time.perf_counter()
        conn = self._get_read_connection()

        backoff = DatabaseConfig.INITIAL_BACKOFF_SEC
        for attempt in range(1, DatabaseConfig.MAX_LOCK_RETRIES + 1):
            # Fresh cursor per attempt guarantees retries do not operate on a closed cursor
            cursor = conn.cursor()
            try:
                cursor.execute(sql, params)
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                rows = cursor.fetchall()
                duration_ms = (time.perf_counter() - start_time) * 1000.0

                telemetry = QueryTelemetry(
                    query_id=query_id,
                    sql=sql,
                    parameters=params,
                    execution_time_ms=duration_ms,
                    row_count=len(rows),
                    status="SUCCESS",
                    is_read_only=True,
                    timestamp=time.time()
                )
                self.telemetry.record(telemetry)

                return QueryResult(
                    columns=columns,
                    rows=rows,
                    row_count=len(rows),
                    execution_time_ms=duration_ms,
                    sql=sql
                )

            except sqlite3.OperationalError as exc:
                if "attempt to write a readonly database" in str(exc).lower():
                    duration_ms = (time.perf_counter() - start_time) * 1000.0
                    err_msg = "Engine blocked attempted write on read-only Text-to-SQL query."
                    self.telemetry.record(QueryTelemetry(
                        query_id=query_id,
                        sql=sql,
                        parameters=params,
                        execution_time_ms=duration_ms,
                        row_count=0,
                        status="FAILED",
                        is_read_only=True,
                        timestamp=time.time(),
                        error_message=err_msg
                    ))
                    raise ReadOnlyViolationError(f"{err_msg} Query: {sql}") from exc

                if self._is_lock_error(exc):
                    if attempt == DatabaseConfig.MAX_LOCK_RETRIES:
                        duration_ms = (time.perf_counter() - start_time) * 1000.0
                        err_msg = f"Database lock timeout exceeded after {attempt} attempts."
                        self.telemetry.record(QueryTelemetry(
                            query_id=query_id,
                            sql=sql,
                            parameters=params,
                            execution_time_ms=duration_ms,
                            row_count=0,
                            status="FAILED",
                            is_read_only=True,
                            timestamp=time.time(),
                            error_message=err_msg
                        ))
                        raise DatabaseLockedError(err_msg) from exc

                    jitter = random.uniform(0, DatabaseConfig.JITTER_SEC)
                    sleep_time = backoff + jitter
                    logger.warning(
                        f"[LOCK CONTENTION] Read locked (Attempt {attempt}/{DatabaseConfig.MAX_LOCK_RETRIES}). "
                        f"Retrying in {sleep_time * 1000:.1f}ms..."
                    )
                    time.sleep(sleep_time)
                    backoff *= DatabaseConfig.BACKOFF_FACTOR
                    continue

                # Unhandled SQL/Syntax Error
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                self.telemetry.record(QueryTelemetry(
                    query_id=query_id,
                    sql=sql,
                    parameters=params,
                    execution_time_ms=duration_ms,
                    row_count=0,
                    status="FAILED",
                    is_read_only=True,
                    timestamp=time.time(),
                    error_message=str(exc)
                ))
                raise QueryExecutionError(f"SQL execution failed: {exc}") from exc

            except Exception as exc:
                duration_ms = (time.perf_counter() - start_time) * 1000.0
                self.telemetry.record(QueryTelemetry(
                    query_id=query_id,
                    sql=sql,
                    parameters=params,
                    execution_time_ms=duration_ms,
                    row_count=0,
                    status="FAILED",
                    is_read_only=True,
                    timestamp=time.time(),
                    error_message=str(exc)
                ))
                raise QueryExecutionError(f"Unexpected query failure: {exc}") from exc

            finally:
                cursor.close()

        raise DatabaseLockedError("Read retry loop exhausted.")

    def execute_write(
        self,
        sql: str,
        params: Union[Tuple[Any, ...], Dict[str, Any]] = ()
    ) -> int:
        """
        Execute an atomic mutating query (INSERT/UPDATE/DELETE/CREATE/DROP).
        Thread-safe; serialized via internal write lock.
        Returns the number of affected rows.
        """
        query_id = self.telemetry.next_query_id()
        start_time = time.perf_counter()

        with self.transaction() as cursor:
            cursor.execute(sql, params)
            row_count = cursor.rowcount if cursor.rowcount >= 0 else 0

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        self.telemetry.record(QueryTelemetry(
            query_id=query_id,
            sql=sql,
            parameters=params,
            execution_time_ms=duration_ms,
            row_count=row_count,
            status="SUCCESS",
            is_read_only=False,
            timestamp=time.time()
        ))
        return row_count

    def execute_batch(
        self,
        sql: str,
        param_list: List[Union[Tuple[Any, ...], Dict[str, Any]]]
    ) -> int:
        """
        Bulk data insertion/mutation for ETL pipelines.
        Wraps executemany in a single atomic transaction.
        """
        query_id = self.telemetry.next_query_id()
        start_time = time.perf_counter()

        with self.transaction() as cursor:
            cursor.executemany(sql, param_list)
            row_count = cursor.rowcount if cursor.rowcount >= 0 else len(param_list)

        duration_ms = (time.perf_counter() - start_time) * 1000.0
        self.telemetry.record(QueryTelemetry(
            query_id=query_id,
            sql=sql,
            parameters=(),  # Avoid bloating memory with huge batch parameter dumps
            execution_time_ms=duration_ms,
            row_count=row_count,
            status="SUCCESS",
            is_read_only=False,
            timestamp=time.time()
        ))
        return row_count

    # --------------------------------------------------------------------------
    # TRANSACTION MANAGEMENT
    # --------------------------------------------------------------------------

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Cursor, None, None]:
        """
        Context manager for write transactions.
        Acquires process write lock, uses 'BEGIN IMMEDIATE' to block concurrent writers,
        and applies jittered exponential backoff on lock contention.
        """
        with self._write_lock:
            conn = self._create_write_connection()
            cursor = conn.cursor()

            backoff = DatabaseConfig.INITIAL_BACKOFF_SEC
            in_transaction = False

            for attempt in range(1, DatabaseConfig.MAX_LOCK_RETRIES + 1):
                try:
                    cursor.execute("BEGIN IMMEDIATE;")
                    in_transaction = True
                    break
                except sqlite3.OperationalError as exc:
                    if self._is_lock_error(exc):
                        if attempt == DatabaseConfig.MAX_LOCK_RETRIES:
                            cursor.close()
                            conn.close()
                            raise DatabaseLockedError(
                                f"Failed to acquire database write lock after {attempt} attempts."
                            ) from exc
                        jitter = random.uniform(0, DatabaseConfig.JITTER_SEC)
                        time.sleep(backoff + jitter)
                        backoff *= DatabaseConfig.BACKOFF_FACTOR
                        continue
                    cursor.close()
                    conn.close()
                    raise

            try:
                yield cursor
                cursor.execute("COMMIT;")
            except Exception as exc:
                if in_transaction:
                    try:
                        cursor.execute("ROLLBACK;")
                    except Exception as rollback_err:
                        logger.error(f"Rollback failed: {rollback_err}")
                logger.error(f"Write transaction aborted: {exc}")
                raise
            finally:
                cursor.close()
                conn.close()
                if hasattr(self, "_connections_lock"):
                    with self._connections_lock:
                        self._all_connections.discard(conn)

    def close(self) -> None:
        """Clean up all cached and active connections across all threads."""
        if hasattr(self, "_connections_lock"):
            with self._connections_lock:
                for conn in list(self._all_connections):
                    try:
                        conn.close()
                    except Exception:
                        pass
                self._all_connections.clear()
        read_conn = getattr(self._thread_local, "read_conn", None)
        if read_conn is not None:
            try:
                read_conn.close()
            except Exception:
                pass
            self._thread_local.read_conn = None
        logger.info("DatabaseManager connections closed.")


# ==============================================================================
# SELF-TEST & VERIFICATION SUITE
# ==============================================================================

if __name__ == "__main__":
    print("=== Testing NEXUS Database Manager ===")
    mgr = DatabaseManager()

    # 1. Test write transaction
    mgr.execute_write("""
        CREATE TABLE IF NOT EXISTS test_users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL
        );
    """)

    # 2. Test batch write
    mgr.execute_batch(
        "INSERT OR IGNORE INTO test_users (username, role) VALUES (?, ?);",
        [("alice", "analyst"), ("bob", "engineer"), ("charlie", "admin")]
    )

    # 3. Test read execution & telemetry
    res = mgr.execute_query("SELECT * FROM test_users;")
    print(f"[+] Query Rows: {res.row_count}")
    print(f"[+] Columns: {res.columns}")
    print(f"[+] Data Dictionaries: {res.to_dicts()}")
    print(f"[+] Execution Time: {res.execution_time_ms:.3f} ms")

    # 4. Test audit ledger logging
    mgr.log_audit_event("Show all users", "SELECT * FROM test_users;", "SUCCESS")
    print("[+] Audit event logged successfully.")

    # 5. Test engine-level Read-Only protection
    try:
        mgr.execute_query("DELETE FROM test_users WHERE username = 'alice';", read_only=True)
        print("[-] ERROR: Read-only protection failed!")
    except ReadOnlyViolationError as e:
        print(f"[+] SUCCESS: Engine-level read-only violation caught: {e}")

    # 6. Output Telemetry Metrics
    metrics = mgr.telemetry.get_metrics()
    print(f"[+] Telemetry Metrics: {metrics}")
    print(f"[+] Telemetry History (Last 3): {mgr.telemetry.get_history(limit=3)}")
    mgr.close()
    print("=== All Verification Tests Passed ===")
