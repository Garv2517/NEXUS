"""
NEXUS Engine - Relational Table Lifecycle & Workspace Management
================================================================
Architecture Role: Safe schema mutation engine for workspace tables.
Enforces:
1. Strict protected internal namespace isolation (^_nexus_* and ^sqlite_*).
2. Proper identifier quoting preventing SQL injection on schema DDL.
3. Cache invalidation on SchemaParser to prevent stale context.
4. Comprehensive audit logging into _nexus_query_audit.

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

from src.core.db_manager import DatabaseManager
from src.core.schema_parser import SchemaParser

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger("NEXUS-TableManager")  # type: ignore


class TableManagerError(Exception):
    """Raised when an operation on a table violates security, existence, or naming constraints."""
    pass


PROTECTED_NAMESPACE_PATTERN = re.compile(r"^(_nexus_|sqlite_)", re.IGNORECASE)


class TableManager:
    """
    Manages user table lifecycle in the active SQLite workspace.
    Guarantees zero mutation of internal metadata/audit tables.
    """

    def __init__(self, db_manager: DatabaseManager, schema_parser: SchemaParser) -> None:
        self.db = db_manager
        self.schema_parser = schema_parser

    @staticmethod
    def is_protected_name(name: str) -> bool:
        """Checks if a table name belongs to a protected internal system namespace."""
        if not name or not name.strip():
            return True
        return bool(PROTECTED_NAMESPACE_PATTERN.search(name.strip()))

    def _assert_unprotected(self, name: str) -> None:
        """Enforces namespace protection, raising TableManagerError on violation."""
        if not name or not name.strip():
            raise TableManagerError("Table name cannot be empty.")
        if self.is_protected_name(name):
            raise TableManagerError(
                f"Security violation: Table name '{name}' belongs to a protected internal namespace "
                f"('_nexus_*' or 'sqlite_*') and cannot be altered or dropped."
            )

    def _get_entity_info(self, name: str) -> Optional[Tuple[str, str]]:
        """
        Retrieves the exact (type, name) from sqlite_schema collating case-insensitively.
        Returns None if entity does not exist.
        """
        with self.db.readonly() as cur:
            cur.execute(
                "SELECT type, name FROM sqlite_schema WHERE name = ? COLLATE NOCASE;",
                (name.strip(),)
            )
            row = cur.fetchone()
            if row:
                return (str(row[0]).lower(), str(row[1]))
        return None

    def drop_table(self, table_name: str) -> str:
        """
        Safely drops a user table or view from the database.

        Security & Integrity:
        - Rejects protected system names (_nexus_*, sqlite_*).
        - Verifies existence before executing.
        - Uses quoted identifiers to prevent SQL injection.
        - Automatically invalidates SchemaParser cache.
        - Records a SUCCESS audit entry in _nexus_query_audit.

        Returns:
            The exact name of the dropped entity.
        """
        self._assert_unprotected(table_name)

        entity_info = self._get_entity_info(table_name)
        if not entity_info:
            raise TableManagerError(f"Table or view '{table_name}' does not exist in the active database.")

        entity_type, actual_name = entity_info

        # Check if actual entity name itself is protected
        if self.is_protected_name(actual_name):
            raise TableManagerError(f"Security violation: Cannot drop internal entity '{actual_name}'.")

        escaped_name = actual_name.replace('"', '""')
        if entity_type == "view":
            sql = f'DROP VIEW "{escaped_name}";'
        else:
            sql = f'DROP TABLE "{escaped_name}";'

        try:
            self.db.execute_write(sql)
            self.schema_parser.invalidate_cache()
            self.db.log_audit_event(
                natural_query=f"[WORKSPACE] Drop {entity_type} {actual_name}",
                generated_sql=sql,
                status="SUCCESS"
            )
            logger.info(f"Successfully dropped {entity_type} '{actual_name}' from workspace database.")
            return actual_name
        except Exception as exc:
            self.db.log_audit_event(
                natural_query=f"[WORKSPACE] Drop {entity_type} {actual_name}",
                generated_sql=sql,
                status="FAILED",
                error_message=str(exc)
            )
            logger.error(f"Failed to drop {entity_type} '{actual_name}': {exc}")
            raise TableManagerError(f"Database error dropping {entity_type} '{actual_name}': {exc}") from exc

    def rename_table(self, old_name: str, new_name: str) -> str:
        """
        Safely renames a user table.

        Security & Integrity:
        - Rejects protected system names (_nexus_*, sqlite_*) for both old and new names.
        - Rejects views (SQLite does not support ALTER TABLE RENAME on views).
        - Sanitizes new_name to valid, non-colliding lowercase snake_case.
        - Verifies sanitized target name does not already exist.
        - Automatically invalidates SchemaParser cache.
        - Records a SUCCESS audit entry in _nexus_query_audit.

        Returns:
            The sanitized new table name.
        """
        self._assert_unprotected(old_name)

        entity_info = self._get_entity_info(old_name)
        if not entity_info:
            raise TableManagerError(f"Table '{old_name}' does not exist in the active database.")

        entity_type, actual_old_name = entity_info
        if entity_type == "view":
            raise TableManagerError(f"Cannot rename view '{actual_old_name}'. SQLite does not support renaming views.")

        # Sanitize new table name via ETL identifier sanitizer
        try:
            from src.etl.etl_engine import sanitize_identifier
            sanitized_new = sanitize_identifier(new_name, is_table=True)
        except Exception as exc:
            raise TableManagerError(f"Invalid target table name '{new_name}': {exc}") from exc

        self._assert_unprotected(sanitized_new)

        if sanitized_new.lower() == actual_old_name.lower():
            return actual_old_name

        existing_target = self._get_entity_info(sanitized_new)
        if existing_target:
            raise TableManagerError(
                f"Cannot rename table '{actual_old_name}' to '{sanitized_new}': "
                f"A {existing_target[0]} named '{existing_target[1]}' already exists."
            )

        old_escaped = actual_old_name.replace('"', '""')
        new_escaped = sanitized_new.replace('"', '""')
        sql = f'ALTER TABLE "{old_escaped}" RENAME TO "{new_escaped}";'

        try:
            self.db.execute_write(sql)
            self.schema_parser.invalidate_cache()
            self.db.log_audit_event(
                natural_query=f"[WORKSPACE] Rename table {actual_old_name} -> {sanitized_new}",
                generated_sql=sql,
                status="SUCCESS"
            )
            logger.info(f"Successfully renamed table '{actual_old_name}' to '{sanitized_new}'.")
            return sanitized_new
        except Exception as exc:
            self.db.log_audit_event(
                natural_query=f"[WORKSPACE] Rename table {actual_old_name} -> {sanitized_new}",
                generated_sql=sql,
                status="FAILED",
                error_message=str(exc)
            )
            logger.error(f"Failed to rename table '{actual_old_name}' to '{sanitized_new}': {exc}")
            raise TableManagerError(f"Database error renaming table '{actual_old_name}': {exc}") from exc
