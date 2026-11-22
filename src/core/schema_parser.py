"""
NEXUS Engine - Dynamic Schema Inspector & Markdown Formatter
============================================================
Architecture Role: Reflects live SQLite schema metadata and compiles high-density,
token-efficient Markdown schema definitions for LLM Text-to-SQL system prompts.

Key Capabilities:
1. Dynamic reflection of tables, views, columns, types, nullability, and default values.
2. Complete primary key and foreign key relational mapping (enabling accurate JOIN synthesis).
3. Zero memory bloat: Scalable to 50+ tables via streaming generator architecture.
4. Token-optimized Markdown formatting tailored for LLM context windows.
5. Pipe (|) escaping in constraints and sample rows to eliminate Markdown table injection.
6. In-memory schema caching with manual/event-driven invalidation.

Author: Senior Systems Engineer
Target Engine: SQLite3 / Text-to-SQL
"""

from __future__ import annotations

import dataclasses
import io
import re
import sqlite3
import threading
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

# Resilient logging initialization
try:
    from loguru import logger
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("NEXUS-Schema")  # type: ignore

from src.core.db_manager import DatabaseManager


# ==============================================================================
# SCHEMA METADATA DATA STRUCTURES
# ==============================================================================

@dataclasses.dataclass(frozen=True)
class ColumnInfo:
    """Metadata for a single database column."""
    name: str
    data_type: str
    is_nullable: bool
    default_value: Optional[str]
    is_primary_key: bool
    pk_order: int
    is_unique: bool = False
    foreign_key_target: Optional[str] = None  # Format: "target_table(target_col)"

    def format_constraints(self) -> str:
        """Compact string representation of constraints for LLM prompt with escaped pipes."""
        constraints = []
        if self.is_primary_key:
            constraints.append("PK" if self.pk_order == 1 else f"PK#{self.pk_order}")
        if not self.is_nullable:
            constraints.append("NOT NULL")
        if self.is_unique and not self.is_primary_key:
            constraints.append("UNIQUE")
        if self.default_value is not None:
            # Escape literal pipe characters to prevent Markdown table column corruption
            escaped_default = str(self.default_value).replace("|", "\\|")
            constraints.append(f"DEFAULT {escaped_default}")
        return ", ".join(constraints) if constraints else "-"


@dataclasses.dataclass
class TableInfo:
    """Metadata for an entire relational table or view."""
    name: str
    entity_type: str  # 'TABLE' or 'VIEW'
    columns: List[ColumnInfo]
    primary_keys: List[str]
    foreign_keys: List[Dict[str, str]]  # list of {from_column, target_table, target_column}
    estimated_rows: int = 0
    sample_records: List[Dict[str, Any]] = dataclasses.field(default_factory=list)


# ==============================================================================
# SCHEMA PARSER ENGINE
# ==============================================================================

class SchemaParser:
    """
    Reflects and formats SQLite relational metadata into structured Markdown.

    Designed for:
    - High-throughput read operations via DatabaseManager.readonly() context manager.
    - Low memory footprint: Processes tables iteratively, avoiding bulk dictionary retention.
    - Clean LLM Markdown tables with dedicated Relational Graph summary for JOIN generation.
    - Markdown injection defense: Escapes literal pipes in values, constraints, and identifiers.
    """

    # System and internal tables to ignore during reflection
    DEFAULT_EXCLUDED_PATTERNS = (
        r"^sqlite_.*",      # SQLite internal tables
        r"^_nexus_.*",      # NEXUS engine metadata and audit ledgers
    )

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        excluded_patterns: Optional[Tuple[str, ...]] = None
    ) -> None:
        self.db = db_manager or DatabaseManager()
        self.excluded_patterns = tuple(
            re.compile(p, re.IGNORECASE) for p in (excluded_patterns or self.DEFAULT_EXCLUDED_PATTERNS)
        )
        self._cache_lock = threading.Lock()
        self._cached_markdown: Optional[str] = None
        self._cached_tables: Optional[List[str]] = None

    def _is_table_excluded(self, table_name: str) -> bool:
        """Determines if a table is marked as system or internal."""
        return any(pattern.match(table_name) for pattern in self.excluded_patterns)

    @staticmethod
    def _quote_identifier(identifier: str) -> str:
        """Safely quote SQLite identifier to prevent syntax or injection errors."""
        escaped = identifier.replace('"', '""')
        return f'"{escaped}"'

    # --------------------------------------------------------------------------
    # METADATA EXTRACTION PIPELINE
    # --------------------------------------------------------------------------

    def get_table_names(self, include_views: bool = True) -> List[str]:
        """
        Retrieves a sorted list of all user tables (and views) in the database.
        """
        entity_types = "('table', 'view')" if include_views else "('table')"
        query = f"""
            SELECT name
            FROM sqlite_schema
            WHERE type IN {entity_types}
            ORDER BY name ASC;
        """
        with self.db.readonly() as cursor:
            cursor.execute(query)
            names = [
                row[0] for row in cursor.fetchall()
                if not self._is_table_excluded(row[0])
            ]
        return names

    def inspect_table(
        self,
        table_name: str,
        fetch_samples: bool = False,
        sample_limit: int = 2
    ) -> TableInfo:
        """
        Inspects a single table's schema, constraints, keys, and optional sample rows.
        """
        quoted_name = self._quote_identifier(table_name)

        with self.db.readonly() as cursor:
            # 1. Determine entity type
            cursor.execute(
                "SELECT type FROM sqlite_schema WHERE name = ?;",
                (table_name,)
            )
            entity_row = cursor.fetchone()
            entity_type = entity_row[0].upper() if entity_row else "TABLE"

            # 2. Extract Foreign Keys: PRAGMA foreign_key_list
            cursor.execute(f"PRAGMA foreign_key_list({quoted_name});")
            fk_rows = cursor.fetchall()
            fk_map: Dict[str, str] = {}
            fk_list: List[Dict[str, str]] = []
            for fk in fk_rows:
                # fk indices: 0:id, 1:seq, 2:table, 3:from, 4:to
                to_table = fk[2]
                from_col = fk[3]
                to_col = fk[4]
                target_str = f"{to_table}({to_col})"
                fk_map[from_col] = target_str
                fk_list.append({
                    "from_column": from_col,
                    "target_table": to_table,
                    "target_column": to_col,
                })

            # 3. Extract Unique Column Indexes: PRAGMA index_list & index_info
            unique_columns: Set[str] = set()
            try:
                cursor.execute(f"PRAGMA index_list({quoted_name});")
                indexes = cursor.fetchall()
                for idx in indexes:
                    # idx indices: 0:seq, 1:name, 2:unique
                    is_unique = idx[2]
                    index_name = idx[1]
                    if is_unique:
                        quoted_idx = self._quote_identifier(index_name)
                        cursor.execute(f"PRAGMA index_info({quoted_idx});")
                        idx_info = cursor.fetchall()
                        # Only single-column unique indexes marked per-column
                        if len(idx_info) == 1:
                            unique_columns.add(idx_info[0][2])
            except Exception as e:
                logger.warning(f"Failed to inspect indexes for {table_name}: {e}")

            # 4. Extract Columns: PRAGMA table_info
            cursor.execute(f"PRAGMA table_info({quoted_name});")
            col_rows = cursor.fetchall()

            columns: List[ColumnInfo] = []
            primary_keys: List[str] = []

            for col in col_rows:
                # col indices: 0:cid, 1:name, 2:type, 3:notnull, 4:dflt_value, 5:pk
                c_name = col[1]
                c_type = (col[2] or "TEXT").upper()
                c_notnull = bool(col[3])
                c_dflt = col[4]
                c_pk = col[5]

                is_pk = c_pk > 0
                if is_pk:
                    primary_keys.append(c_name)

                col_info = ColumnInfo(
                    name=c_name,
                    data_type=c_type,
                    is_nullable=not c_notnull,
                    default_value=str(c_dflt) if c_dflt is not None else None,
                    is_primary_key=is_pk,
                    pk_order=c_pk,
                    is_unique=(c_name in unique_columns),
                    foreign_key_target=fk_map.get(c_name)
                )
                columns.append(col_info)

            # 5. Row count estimate
            estimated_rows = 0
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {quoted_name};")
                estimated_rows = cursor.fetchone()[0]
            except Exception:
                pass

            # 6. Optional sample records (lightweight preview)
            sample_records: List[Dict[str, Any]] = []
            if fetch_samples and estimated_rows > 0:
                try:
                    cursor.execute(f"SELECT * FROM {quoted_name} LIMIT {sample_limit};")
                    col_names = [d[0] for d in cursor.description]
                    for row in cursor.fetchall():
                        sample_records.append(dict(zip(col_names, row)))
                except Exception as e:
                    logger.warning(f"Could not fetch sample records for {table_name}: {e}")

        return TableInfo(
            name=table_name,
            entity_type=entity_type,
            columns=columns,
            primary_keys=primary_keys,
            foreign_keys=fk_list,
            estimated_rows=estimated_rows,
            sample_records=sample_records
        )

    def iter_tables(
        self,
        tables: Optional[List[str]] = None,
        fetch_samples: bool = False,
        sample_limit: int = 2
    ) -> Generator[TableInfo, None, None]:
        """
        Memory-efficient generator yielding TableInfo records one by one.
        Ensures databases with 50+ tables do not consume unnecessary memory.
        """
        table_names = tables if tables is not None else self.get_table_names()
        for t_name in table_names:
            yield self.inspect_table(t_name, fetch_samples=fetch_samples, sample_limit=sample_limit)

    # --------------------------------------------------------------------------
    # MARKDOWN FORMATTING & PROMPT GENERATION
    # --------------------------------------------------------------------------

    def generate_markdown(
        self,
        tables: Optional[List[str]] = None,
        include_samples: bool = False,
        sample_limit: int = 2,
        use_cache: bool = True
    ) -> str:
        """
        Compiles the entire database schema into clean, token-efficient Markdown tables.
        Escapes literal pipe characters (| -> \\|) in table cells, default values, and sample data.

        Parameters:
            tables: Optional subset of table names to include. If None, inspects all tables.
            include_samples: Whether to append a lightweight row preview table.
            sample_limit: Maximum number of sample rows per table (default 2).
            use_cache: If True and full schema requested, serves from cached markdown.

        Returns:
            Structured Markdown string formatted for LLM system prompts.
        """
        # Return cached copy if available and reflecting full schema without samples
        if use_cache and tables is None and not include_samples:
            with self._cache_lock:
                if self._cached_markdown is not None:
                    return self._cached_markdown

        buffer = io.StringIO()
        target_tables = tables if tables is not None else self.get_table_names()

        buffer.write("# Database Schema Context\n\n")
        buffer.write(f"Total Tables/Views: **{len(target_tables)}**\n\n")

        all_foreign_keys: List[str] = []

        # Iterate through tables and compile Markdown blocks
        for table in self.iter_tables(target_tables, fetch_samples=include_samples, sample_limit=sample_limit):
            safe_table_name = table.name.replace("|", "\\|")
            buffer.write(f"### `{safe_table_name}` ({table.entity_type})\n")

            pk_desc = f"`{', '.join(pk.replace('|', '\\|') for pk in table.primary_keys)}`" if table.primary_keys else "None"
            buffer.write(f"- **Primary Key**: {pk_desc}\n")
            buffer.write(f"- **Total Records**: ~{table.estimated_rows:,}\n\n")

            # Markdown Table of Columns
            buffer.write("| Column | Type | Constraints | References |\n")
            buffer.write("| :--- | :--- | :--- | :--- |\n")
            for col in table.columns:
                ref_str = f"-> `{col.foreign_key_target}`" if col.foreign_key_target else "-"
                col_name_esc = col.name.replace("|", "\\|")
                col_type_esc = col.data_type.replace("|", "\\|")
                ref_esc = ref_str.replace("|", "\\|")
                buffer.write(
                    f"| `{col_name_esc}` | `{col_type_esc}` | {col.format_constraints()} | {ref_esc} |\n"
                )
            buffer.write("\n")

            # Collect FK relationships for global relationship graph
            for fk in table.foreign_keys:
                all_foreign_keys.append(
                    f"- `{table.name}.{fk['from_column']}` -> `{fk['target_table']}.{fk['target_column']}`"
                )

            # Optional sample records representation with strict pipe escaping
            if include_samples and table.sample_records:
                buffer.write("**Sample Data (Preview):**\n\n")
                sample_cols = [c.name for c in table.columns]
                escaped_headers = [c.replace("|", "\\|") for c in sample_cols]
                buffer.write("| " + " | ".join(f"`{c}`" for c in escaped_headers) + " |\n")
                buffer.write("| " + " | ".join(":---" for _ in sample_cols) + " |\n")
                for row in table.sample_records:
                    row_vals = [
                        str(row.get(c, "NULL")).replace("\n", " ").replace("|", "\\|")[:40]
                        for c in sample_cols
                    ]
                    buffer.write("| " + " | ".join(row_vals) + " |\n")
                buffer.write("\n")

            buffer.write("---\n\n")

        # Global Relational Schema Graph (Crucial for multi-table LLM JOINs)
        if all_foreign_keys:
            buffer.write("## Relational Relationships (Foreign Keys)\n\n")
            buffer.write("Use these exact relationships when synthesizing table JOINs:\n")
            for rel in all_foreign_keys:
                buffer.write(f"{rel}\n")
            buffer.write("\n")

        markdown_output = buffer.getvalue()

        # Update cache if this was a full default schema run
        if tables is None and not include_samples:
            with self._cache_lock:
                self._cached_markdown = markdown_output
                self._cached_tables = target_tables

        return markdown_output

    def invalidate_cache(self) -> None:
        """Clears cached schema Markdown (invoked after ETL or DDL migrations)."""
        with self._cache_lock:
            self._cached_markdown = None
            self._cached_tables = None
        logger.debug("SchemaParser cache invalidated.")

    def get_summary_stats(self) -> Dict[str, Any]:
        """Provides high-level statistics without generating full markdown."""
        tables = self.get_table_names()
        total_cols = 0
        total_fks = 0
        for table in self.iter_tables(tables):
            total_cols += len(table.columns)
            total_fks += len(table.foreign_keys)

        return {
            "table_count": len(tables),
            "total_columns": total_cols,
            "total_foreign_keys": total_fks,
            "table_names": tables,
        }


# Default module instance for direct use
default_parser = SchemaParser()


def get_schema_markdown(include_samples: bool = False) -> str:
    """Convenience helper to retrieve cached Markdown schema for system prompts."""
    return default_parser.generate_markdown(include_samples=include_samples)
