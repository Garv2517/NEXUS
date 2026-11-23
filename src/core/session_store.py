"""
NEXUS Engine - Multi-Session Chat & Conversation Store
=====================================================
Architecture Role: Persistent SQLite storage and retrieval for multi-session
analytical chat histories, conversation turns, and execution metadata.

Security & Integrity Invariants:
1. Internal Namespace Isolation: All tables are prefixed with _nexus_ to guarantee
   automatic exclusion from SchemaParser and QueryGuard mutation barriers.
2. Foreign Key Cascade Enforcement: Deleting a session atomically purges all associated
   messages via SQLite ON DELETE CASCADE.
3. Strict SUCCESS-Only Memory Restoration: Only assistant turns with status == 'SUCCESS'
   and valid generated SQL are restored to conversation memory.
4. Auto-Titling: Initial "New Session" automatically re-titles to the first user query.

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from src.core.db_manager import DatabaseManager

if TYPE_CHECKING:
    from src.agent.sql_chain import ConversationTurn


# ==============================================================================
# DATA STRUCTURES
# ==============================================================================

@dataclasses.dataclass(frozen=True)
class ChatSession:
    """Immutable representation of a persistent analytical chat session."""
    session_id: str
    title: str
    created_at: str
    updated_at: str
    message_count: int = 0


@dataclasses.dataclass(frozen=True)
class ChatMessageRecord:
    """Immutable record of an individual chat message in a session."""
    message_id: int
    session_id: str
    role: str
    natural_query: Optional[str]
    generated_sql: Optional[str]
    answer_markdown: Optional[str]
    status: str
    provider: Optional[str]
    model: Optional[str]
    row_count: int
    execution_time_ms: float
    tables_used: Tuple[str, ...]
    created_at: str


# ==============================================================================
# SESSION STORE
# ==============================================================================

class ChatSessionStore:
    """
    Persistent SQLite storage and retrieval for multi-session chat histories.
    Guarantees strict namespace isolation, automatic schema initialization,
    and foreign key cascading deletion.
    """

    def __init__(self, db_manager: Optional[DatabaseManager] = None) -> None:
        self.db = db_manager or DatabaseManager()
        self._init_tables()

    def _init_tables(self) -> None:
        """Initializes internal chat persistence tables and indices if not present."""
        with self.db.transaction() as cursor:
            cursor.execute("PRAGMA foreign_keys = ON;")
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS _nexus_chat_sessions (
                    session_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS _nexus_chat_messages (
                    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
                    natural_query TEXT,
                    generated_sql TEXT,
                    answer_markdown TEXT,
                    status TEXT NOT NULL DEFAULT 'SUCCESS',
                    provider TEXT,
                    model TEXT,
                    row_count INTEGER DEFAULT 0,
                    execution_time_ms REAL DEFAULT 0.0,
                    tables_used TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES _nexus_chat_sessions(session_id) ON DELETE CASCADE
                );
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_nexus_chat_messages_session
                ON _nexus_chat_messages(session_id);
                """
            )

    def create_session(self, title: str = "New Session") -> ChatSession:
        """Creates a new chat session with a unique UUID."""
        session_id = str(uuid.uuid4())
        clean_title = (title.strip() if title else "New Session")[:80]
        with self.db.transaction() as cursor:
            cursor.execute(
                "INSERT INTO _nexus_chat_sessions (session_id, title) VALUES (?, ?);",
                (session_id, clean_title),
            )
            cursor.execute(
                "SELECT created_at, updated_at FROM _nexus_chat_sessions WHERE session_id = ?;",
                (session_id,),
            )
            row = cursor.fetchone()
            created_at = str(row[0]) if row else ""
            updated_at = str(row[1]) if row else ""

        return ChatSession(
            session_id=session_id,
            title=clean_title,
            created_at=created_at,
            updated_at=updated_at,
            message_count=0,
        )

    def list_sessions(self, limit: int = 50) -> List[ChatSession]:
        """Lists chat sessions ordered by updated_at DESC, rowid DESC."""
        result = self.db.execute_query(
            """
            SELECT 
                s.session_id,
                s.title,
                s.created_at,
                s.updated_at,
                COUNT(m.message_id) AS message_count
            FROM _nexus_chat_sessions s
            LEFT JOIN _nexus_chat_messages m ON s.session_id = m.session_id
            GROUP BY s.session_id, s.title, s.created_at, s.updated_at
            ORDER BY s.updated_at DESC, s.rowid DESC
            LIMIT ?;
            """,
            (limit,),
        )
        sessions: List[ChatSession] = []
        for r in result.rows:
            sessions.append(
                ChatSession(
                    session_id=str(r[0]),
                    title=str(r[1]),
                    created_at=str(r[2]),
                    updated_at=str(r[3]),
                    message_count=int(r[4]),
                )
            )
        return sessions

    def get_session(self, session_id: str) -> Optional[ChatSession]:
        """Retrieves a single session by session_id, or None if not found."""
        result = self.db.execute_query(
            """
            SELECT 
                s.session_id,
                s.title,
                s.created_at,
                s.updated_at,
                COUNT(m.message_id) AS message_count
            FROM _nexus_chat_sessions s
            LEFT JOIN _nexus_chat_messages m ON s.session_id = m.session_id
            WHERE s.session_id = ?
            GROUP BY s.session_id, s.title, s.created_at, s.updated_at;
            """,
            (session_id,),
        )
        if not result.rows:
            return None
        r = result.rows[0]
        return ChatSession(
            session_id=str(r[0]),
            title=str(r[1]),
            created_at=str(r[2]),
            updated_at=str(r[3]),
            message_count=int(r[4]),
        )

    def rename_session(self, session_id: str, new_title: str) -> bool:
        """Renames an existing session, updating updated_at."""
        clean_title = (new_title.strip() if new_title else "Untitled Session")[:80]
        rows = self.db.execute_write(
            "UPDATE _nexus_chat_sessions SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?;",
            (clean_title, session_id),
        )
        return rows > 0

    def delete_session(self, session_id: str) -> bool:
        """Deletes a chat session and cascades deletion of all associated messages."""
        with self.db.transaction() as cursor:
            cursor.execute("PRAGMA foreign_keys = ON;")
            cursor.execute(
                "DELETE FROM _nexus_chat_sessions WHERE session_id = ?;",
                (session_id,),
            )
            deleted = cursor.rowcount > 0
        return deleted

    def append_message(
        self,
        session_id: str,
        role: str,
        *,
        natural_query: Optional[str] = None,
        generated_sql: Optional[str] = None,
        answer_markdown: Optional[str] = None,
        status: str = "SUCCESS",
        provider: Optional[str] = None,
        model: Optional[str] = None,
        row_count: int = 0,
        execution_time_ms: float = 0.0,
        tables_used: Tuple[str, ...] = ()
    ) -> int:
        """
        Appends a new message to the session.
        Updates parent session's updated_at timestamp.
        Auto-titles the session if its current title is 'New Session' and natural_query is provided.
        """
        if role not in ("user", "assistant"):
            raise ValueError(f"Invalid role '{role}'. Must be 'user' or 'assistant'.")

        tables_json = json.dumps(list(tables_used))
        with self.db.transaction() as cursor:
            cursor.execute("PRAGMA foreign_keys = ON;")
            cursor.execute(
                """
                INSERT INTO _nexus_chat_messages (
                    session_id, role, natural_query, generated_sql, answer_markdown,
                    status, provider, model, row_count, execution_time_ms, tables_used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    session_id,
                    role,
                    natural_query,
                    generated_sql,
                    answer_markdown,
                    status,
                    provider,
                    model,
                    row_count,
                    execution_time_ms,
                    tables_json,
                ),
            )
            message_id = cursor.lastrowid

            cursor.execute(
                "UPDATE _nexus_chat_sessions SET updated_at = CURRENT_TIMESTAMP WHERE session_id = ?;",
                (session_id,),
            )

            # Smart Auto-Title: If role == "user" (or natural_query is present) and current title is "New Session"
            if natural_query and natural_query.strip():
                cursor.execute(
                    "SELECT title FROM _nexus_chat_sessions WHERE session_id = ?;",
                    (session_id,),
                )
                row = cursor.fetchone()
                if row and row[0] == "New Session":
                    auto_title = natural_query.strip()[:48]
                    cursor.execute(
                        "UPDATE _nexus_chat_sessions SET title = ?, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?;",
                        (auto_title, session_id),
                    )

        return int(message_id) if message_id is not None else 0

    def get_messages(self, session_id: str, limit: int = 200) -> List[ChatMessageRecord]:
        """Retrieves messages for a session in ascending chronological order."""
        result = self.db.execute_query(
            """
            SELECT 
                message_id, session_id, role, natural_query, generated_sql,
                answer_markdown, status, provider, model, row_count,
                execution_time_ms, tables_used, created_at
            FROM _nexus_chat_messages
            WHERE session_id = ?
            ORDER BY message_id ASC
            LIMIT ?;
            """,
            (session_id, limit),
        )
        records: List[ChatMessageRecord] = []
        for r in result.rows:
            raw_tables = r[11]
            tables_tuple: Tuple[str, ...] = ()
            if raw_tables:
                try:
                    parsed = json.loads(raw_tables)
                    if isinstance(parsed, list):
                        tables_tuple = tuple(str(x) for x in parsed)
                except Exception:
                    tables_tuple = ()

            records.append(
                ChatMessageRecord(
                    message_id=int(r[0]),
                    session_id=str(r[1]),
                    role=str(r[2]),
                    natural_query=str(r[3]) if r[3] is not None else None,
                    generated_sql=str(r[4]) if r[4] is not None else None,
                    answer_markdown=str(r[5]) if r[5] is not None else None,
                    status=str(r[6]),
                    provider=str(r[7]) if r[7] is not None else None,
                    model=str(r[8]) if r[8] is not None else None,
                    row_count=int(r[9] or 0),
                    execution_time_ms=float(r[10] or 0.0),
                    tables_used=tables_tuple,
                    created_at=str(r[12]),
                )
            )
        return records

    def load_conversation_turns(self, session_id: str, limit: int = 4) -> List[ConversationTurn]:
        """
        Loads verified SUCCESS assistant turns into ConversationTurn dataclass instances.
        Lazily imports ConversationTurn to prevent circular dependencies.
        Returns up to limit turns in chronological order (oldest to newest).
        """
        from src.agent.sql_chain import ConversationTurn

        result = self.db.execute_query(
            """
            SELECT natural_query, generated_sql, answer_markdown, tables_used
            FROM _nexus_chat_messages
            WHERE session_id = ?
              AND role = 'assistant'
              AND status = 'SUCCESS'
              AND generated_sql IS NOT NULL
              AND trim(generated_sql) != ''
            ORDER BY message_id DESC
            LIMIT ?;
            """,
            (session_id, limit),
        )

        turns: List[ConversationTurn] = []
        for row in reversed(result.rows):
            nat_query = str(row[0]) if row[0] is not None else ""
            gen_sql = str(row[1]) if row[1] is not None else ""
            ans_text = str(row[2]) if row[2] is not None else ""
            ans_summary = ans_text[:240]

            raw_tables = row[3]
            tables_tuple: Tuple[str, ...] = ()
            if raw_tables:
                try:
                    parsed = json.loads(raw_tables)
                    if isinstance(parsed, list):
                        tables_tuple = tuple(str(x) for x in parsed)
                except Exception:
                    tables_tuple = ()

            turns.append(
                ConversationTurn(
                    natural_query=nat_query,
                    generated_sql=gen_sql,
                    answer_summary=ans_summary,
                    tables_used=tables_tuple,
                )
            )
        return turns
