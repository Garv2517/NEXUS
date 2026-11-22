"""
NEXUS Engine - Core Layer Package
=================================
Exposes foundational database connectivity, dynamic schema parsing,
and query security guard components.
"""

from src.core.db_manager import (
    DatabaseConfig,
    DatabaseConfigMeta,
    DatabaseError,
    DatabaseLockedError,
    DatabaseManager,
    QueryExecutionError,
    QueryResult,
    QueryTelemetry,
    ReadOnlyViolationError,
    TelemetryLogger,
)
from src.core.query_guard import (
    QueryGuard,
    SecurityException,
    default_guard,
    guard_query,
)
from src.core.runtime_paths import (
    ensure_runtime_directories,
    get_data_root,
    get_database_dir,
    get_database_path,
    get_raw_uploads_dir,
    get_resource_path,
    get_resource_root,
    is_frozen,
    is_portable,
    set_portable_mode,
)
from src.core.schema_parser import (
    ColumnInfo,
    SchemaParser,
    TableInfo,
    default_parser,
    get_schema_markdown,
)

__all__ = [
    # Database Management & Telemetry
    "DatabaseConfig",
    "DatabaseConfigMeta",
    "DatabaseError",
    "DatabaseLockedError",
    "DatabaseManager",
    "QueryExecutionError",
    "QueryResult",
    "QueryTelemetry",
    "ReadOnlyViolationError",
    "TelemetryLogger",
    # Runtime Paths & Freeze Safety
    "ensure_runtime_directories",
    "get_data_root",
    "get_database_dir",
    "get_database_path",
    "get_raw_uploads_dir",
    "get_resource_path",
    "get_resource_root",
    "is_frozen",
    "is_portable",
    "set_portable_mode",
    # Query Guard & Security
    "QueryGuard",
    "SecurityException",
    "default_guard",
    "guard_query",
    # Schema Reflection & Formatting
    "ColumnInfo",
    "SchemaParser",
    "TableInfo",
    "default_parser",
    "get_schema_markdown",
]
