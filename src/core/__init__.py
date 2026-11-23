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
from src.core.export_engine import (
    DataExportEngine,
    ExecutiveBriefExporter,
    sanitize_spreadsheet_cell,
)
from src.core.key_vault import (
    KeyVaultError,
    WindowsDPAPIVault,
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
    get_vault_dir,
    get_writable_data_dir,
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
from src.core.session_store import (
    ChatMessageRecord,
    ChatSession,
    ChatSessionStore,
)
from src.core.table_manager import (
    TableManager,
    TableManagerError,
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
    # Data & Report Export Engine
    "DataExportEngine",
    "ExecutiveBriefExporter",
    "sanitize_spreadsheet_cell",
    # Table Workspace Manager
    "TableManager",
    "TableManagerError",
    # Runtime Paths & Freeze Safety
    "ensure_runtime_directories",
    "get_data_root",
    "get_database_dir",
    "get_database_path",
    "get_raw_uploads_dir",
    "get_resource_path",
    "get_resource_root",
    "get_vault_dir",
    "get_writable_data_dir",
    "is_frozen",
    "is_portable",
    "set_portable_mode",
    # DPAPI Key Vault
    "KeyVaultError",
    "WindowsDPAPIVault",
    # Chat Session Store
    "ChatMessageRecord",
    "ChatSession",
    "ChatSessionStore",
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
