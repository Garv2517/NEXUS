"""
NEXUS Engine - Upgrade U4 Gate 1 Test Suite
===========================================
Comprehensive unit and integration tests covering:
1. Native Windows DPAPI Key Vault roundtrip, persistence, and zero plaintext on disk.
2. Corrupted vault file resilience and defensive error handling.
3. Multi-session chat lifecycle, message storage, and smart auto-titling.
4. Foreign key cascade deletion for chat sessions and associated messages.
5. Strict SUCCESS-only conversation memory restoration in chronological order.
6. Schema namespace isolation ensuring _nexus_chat_* tables are hidden from
   SchemaParser and guarded against TableManager mutations.

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.db_manager import DatabaseManager
from src.core.key_vault import KeyVaultError, WindowsDPAPIVault
from src.core.schema_parser import SchemaParser
from src.core.session_store import (
    ChatMessageRecord,
    ChatSession,
    ChatSessionStore,
)
from src.core.table_manager import TableManager, TableManagerError


class TestU4VaultAndSessions(unittest.TestCase):
    """Rigorous verification suite for Upgrade U4 Gate 1 deliverables."""

    def setUp(self) -> None:
        DatabaseManager.reset_instance()
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.temp_path = Path(self.temp_dir.name)
        self.db_path = self.temp_path / "test_u4.db"
        self.db = DatabaseManager(self.db_path)
        self.parser = SchemaParser(self.db)
        self.table_mgr = TableManager(self.db, self.parser)
        self.vault_dir = self.temp_path / "vault"
        self.vault = WindowsDPAPIVault(vault_dir=self.vault_dir)
        self.store = ChatSessionStore(self.db)

    def tearDown(self) -> None:
        self.db.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass
        DatabaseManager.reset_instance()

    # --------------------------------------------------------------------------
    # 1. DPAPI ENCRYPTION & ZERO PLAINTEXT ON DISK
    # --------------------------------------------------------------------------

    def test_dpapi_roundtrip_and_zero_plaintext_on_disk(self) -> None:
        """Verifies native DPAPI encryption, round-trip decryption, and zero plaintext on disk."""
        self.assertTrue(self.vault.is_supported(), "DPAPI must be supported on Windows 11")

        secret_anthropic = "sk-ant-test-secret-key-12345-very-secret"
        secret_openai = "sk-proj-test-openai-secret-67890-secure"
        secret_groq = "gsk_test_groq_secret_abcdef123456"

        self.vault.save_key("anthropic", secret_anthropic)
        self.vault.save_key("openai", secret_openai)
        self.vault.save_key("groq", secret_groq)

        # 1. Existence and retrieval
        self.assertTrue(self.vault.has_key("anthropic"))
        self.assertTrue(self.vault.has_key("openai"))
        self.assertTrue(self.vault.has_key("groq"))
        self.assertFalse(self.vault.has_key("cohere"))

        self.assertEqual(self.vault.load_key("anthropic"), secret_anthropic)
        self.assertEqual(self.vault.load_key("openai"), secret_openai)
        self.assertEqual(self.vault.load_key("groq"), secret_groq)
        self.assertIsNone(self.vault.load_key("cohere"))

        # 2. Saved providers list
        saved = self.vault.list_saved_providers()
        self.assertCountEqual(saved, ["anthropic", "openai", "groq"])

        # 3. ZERO plaintext on disk check
        vault_file = self.vault.vault_file
        self.assertTrue(vault_file.exists())
        raw_disk_bytes = vault_file.read_bytes()

        self.assertNotIn(secret_anthropic.encode("utf-8"), raw_disk_bytes)
        self.assertNotIn(secret_openai.encode("utf-8"), raw_disk_bytes)
        self.assertNotIn(secret_groq.encode("utf-8"), raw_disk_bytes)

        # 4. Deletion
        self.assertTrue(self.vault.delete_key("openai"))
        self.assertFalse(self.vault.has_key("openai"))
        self.assertIsNone(self.vault.load_key("openai"))
        self.assertFalse(self.vault.delete_key("openai"))  # idempotent delete returns False

        # 5. Clear all
        self.vault.clear_all()
        self.assertEqual(self.vault.list_saved_providers(), [])
        self.assertFalse(self.vault.has_key("anthropic"))
        self.assertFalse(self.vault.has_key("groq"))

    # --------------------------------------------------------------------------
    # 2. CORRUPTED VAULT RESILIENCE
    # --------------------------------------------------------------------------

    def test_corrupted_vault_resilience(self) -> None:
        """Verifies graceful handling of corrupted JSON, invalid Base64, and tampered ciphertext."""
        corrupt_dir = self.temp_path / "vault_corrupt"
        vault = WindowsDPAPIVault(vault_dir=corrupt_dir)
        vault.save_key("openai", "sk-valid-key-initial")

        # Scenario A: Corrupted / invalid JSON content
        vault.vault_file.write_text("{invalid json content!@@#$", encoding="utf-8")
        self.assertIsNone(vault.load_key("openai", raise_on_corrupt=False))
        with self.assertRaises(KeyVaultError):
            vault.load_key("openai", raise_on_corrupt=True)

        # Scenario B: Valid JSON but corrupted Base64 string
        bad_payload = json.dumps({"openai": "NOT_VALID_BASE64_!@#$%"})
        vault.vault_file.write_text(bad_payload, encoding="utf-8")
        self.assertIsNone(vault.load_key("openai", raise_on_corrupt=False))
        with self.assertRaises(KeyVaultError):
            vault.load_key("openai", raise_on_corrupt=True)

        # Scenario C: Valid Base64 but tampered ciphertext (not valid DPAPI blob)
        tampered_blob = base64.b64encode(b"random tampered binary data 1234567890").decode("utf-8")
        bad_cipher_payload = json.dumps({"openai": tampered_blob})
        vault.vault_file.write_text(bad_cipher_payload, encoding="utf-8")
        self.assertIsNone(vault.load_key("openai", raise_on_corrupt=False))
        with self.assertRaises(KeyVaultError):
            vault.load_key("openai", raise_on_corrupt=True)

    # --------------------------------------------------------------------------
    # 3. SESSION LIFECYCLE & SMART AUTO-TITLING
    # --------------------------------------------------------------------------

    def test_session_lifecycle_and_smart_auto_titling(self) -> None:
        """Verifies session creation, message appending, smart auto-titling, and renaming."""
        session = self.store.create_session()
        self.assertEqual(session.title, "New Session")
        self.assertEqual(session.message_count, 0)

        query_text = "What was the total net profit across all EU subsidiaries in 2024?"
        msg1_id = self.store.append_message(
            session_id=session.session_id,
            role="user",
            natural_query=query_text,
        )
        self.assertGreater(msg1_id, 0)

        # Verify auto-titling happened
        updated_session = self.store.get_session(session.session_id)
        self.assertIsNotNone(updated_session)
        expected_title = query_text[:48]
        self.assertEqual(updated_session.title, expected_title)
        self.assertEqual(updated_session.message_count, 1)

        # Append assistant response
        msg2_id = self.store.append_message(
            session_id=session.session_id,
            role="assistant",
            natural_query=query_text,
            generated_sql="SELECT SUM(net_profit) FROM subsidiaries WHERE region = 'EU';",
            answer_markdown="Total profit was $14.2M.",
            status="SUCCESS",
            provider="ollama",
            model="qwen2.5-coder:7b",
            row_count=1,
            execution_time_ms=18.4,
            tables_used=("subsidiaries",),
        )
        self.assertGreater(msg2_id, msg1_id)

        # Verify list_sessions reflects message count 2
        sessions = self.store.list_sessions(limit=10)
        matching = [s for s in sessions if s.session_id == session.session_id]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].message_count, 2)

        # Verify renaming session
        self.assertTrue(self.store.rename_session(session.session_id, "EU Profit Analysis 2024"))
        reloaded = self.store.get_session(session.session_id)
        self.assertEqual(reloaded.title, "EU Profit Analysis 2024")

        # Verify message records inspection
        messages = self.store.get_messages(session.session_id)
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0].role, "user")
        self.assertEqual(messages[0].natural_query, query_text)
        self.assertEqual(messages[1].role, "assistant")
        self.assertEqual(messages[1].tables_used, ("subsidiaries",))
        self.assertEqual(messages[1].row_count, 1)
        self.assertAlmostEqual(messages[1].execution_time_ms, 18.4, places=1)

    # --------------------------------------------------------------------------
    # 4. FOREIGN KEY CASCADE DELETION
    # --------------------------------------------------------------------------

    def test_foreign_key_cascade_delete(self) -> None:
        """Verifies deleting a session atomically purges all messages via ON DELETE CASCADE."""
        session = self.store.create_session("Temporary Investigation")
        sid = session.session_id

        # Append 4 messages
        self.store.append_message(sid, "user", natural_query="Query 1")
        self.store.append_message(sid, "assistant", natural_query="Query 1", generated_sql="SELECT 1;", status="SUCCESS")
        self.store.append_message(sid, "user", natural_query="Query 2")
        self.store.append_message(sid, "assistant", natural_query="Query 2", generated_sql="SELECT 2;", status="SUCCESS")

        self.assertEqual(len(self.store.get_messages(sid)), 4)

        # Delete parent session
        self.assertTrue(self.store.delete_session(sid))
        self.assertIsNone(self.store.get_session(sid))

        # Directly query internal table to verify cascade
        count_res = self.db.execute_query(
            "SELECT COUNT(*) FROM _nexus_chat_messages WHERE session_id = ?;",
            (sid,),
        )
        self.assertEqual(count_res.rows[0][0], 0, "Messages must be cascade deleted")

        # Subsequent delete returns False
        self.assertFalse(self.store.delete_session(sid))

    # --------------------------------------------------------------------------
    # 5. STRICT SUCCESS-ONLY MEMORY RESTORATION
    # --------------------------------------------------------------------------

    def test_strict_success_only_memory_restoration(self) -> None:
        """Verifies memory turns load only verified SUCCESS assistant turns in chronological order."""
        session = self.store.create_session("Memory Filter Session")
        sid = session.session_id

        # Turn 1: SUCCESS
        self.store.append_message(sid, "user", natural_query="Query 1")
        self.store.append_message(
            sid, "assistant", natural_query="Query 1",
            generated_sql="SELECT 1;", answer_markdown="Answer 1",
            status="SUCCESS", tables_used=("t1",)
        )

        # Turn 2: SUCCESS
        self.store.append_message(sid, "user", natural_query="Query 2")
        self.store.append_message(
            sid, "assistant", natural_query="Query 2",
            generated_sql="SELECT 2;", answer_markdown="Answer 2",
            status="SUCCESS", tables_used=("t2",)
        )

        # Turn 3: SECURITY_BLOCKED
        self.store.append_message(sid, "user", natural_query="Drop table")
        self.store.append_message(
            sid, "assistant", natural_query="Drop table",
            generated_sql="DROP TABLE users;", answer_markdown="Blocked: Mutation detected",
            status="SECURITY_BLOCKED", tables_used=()
        )

        # Turn 4: SUCCESS
        self.store.append_message(sid, "user", natural_query="Query 4")
        self.store.append_message(
            sid, "assistant", natural_query="Query 4",
            generated_sql="SELECT 4;", answer_markdown="Answer 4",
            status="SUCCESS", tables_used=("t4",)
        )

        # Turn 5: SQL_FAILED
        self.store.append_message(sid, "user", natural_query="Invalid syntax")
        self.store.append_message(
            sid, "assistant", natural_query="Invalid syntax",
            generated_sql="SELECT * FROM missing_tbl;", answer_markdown="Table missing_tbl not found",
            status="SQL_FAILED", tables_used=()
        )

        # Turn 6: SUCCESS
        self.store.append_message(sid, "user", natural_query="Query 6")
        self.store.append_message(
            sid, "assistant", natural_query="Query 6",
            generated_sql="SELECT 6;", answer_markdown="Answer 6",
            status="SUCCESS", tables_used=("t6",)
        )

        # 1. Load with limit=4: Should retrieve all 4 SUCCESS turns (and 0 blocked/failed)
        turns = self.store.load_conversation_turns(sid, limit=4)
        self.assertEqual(len(turns), 4)

        sql_sequence = [t.generated_sql for t in turns]
        self.assertNotIn("DROP TABLE users;", sql_sequence)
        self.assertNotIn("SELECT * FROM missing_tbl;", sql_sequence)

        # Verify chronological order (oldest to newest)
        self.assertEqual(sql_sequence, ["SELECT 1;", "SELECT 2;", "SELECT 4;", "SELECT 6;"])
        self.assertEqual(turns[0].tables_used, ("t1",))
        self.assertEqual(turns[3].tables_used, ("t6",))

        # 2. Load with limit=2: Should retrieve the 2 most recent SUCCESS turns in chronological order
        turns_recent = self.store.load_conversation_turns(sid, limit=2)
        self.assertEqual(len(turns_recent), 2)
        self.assertEqual([t.generated_sql for t in turns_recent], ["SELECT 4;", "SELECT 6;"])

    # --------------------------------------------------------------------------
    # 6. SCHEMA NAMESPACE ISOLATION
    # --------------------------------------------------------------------------

    def test_namespace_isolation_verification(self) -> None:
        """Verifies internal tables are excluded from SchemaParser and protected by TableManager."""
        # Create a user table
        self.db.execute_write("CREATE TABLE active_inventory (sku TEXT PRIMARY KEY, qty INT);")

        # 1. SchemaParser must exclude _nexus_chat_* tables
        table_names = self.parser.get_table_names()
        self.assertIn("active_inventory", table_names)
        self.assertNotIn("_nexus_chat_sessions", table_names)
        self.assertNotIn("_nexus_chat_messages", table_names)
        self.assertNotIn("_nexus_metadata", table_names)
        self.assertNotIn("_nexus_query_audit", table_names)

        # 2. TableManager must block mutation of protected tables
        with self.assertRaises(TableManagerError):
            self.table_mgr.drop_table("_nexus_chat_sessions")

        with self.assertRaises(TableManagerError):
            self.table_mgr.drop_table("_nexus_chat_messages")

        with self.assertRaises(TableManagerError):
            self.table_mgr.rename_table("_nexus_chat_sessions", "tampered_sessions")

        with self.assertRaises(TableManagerError):
            self.table_mgr.rename_table("active_inventory", "_nexus_injected")


if __name__ == "__main__":
    unittest.main()
