"""
NEXUS Engine - AI Data Profiler & Smart Cleaning Planner Test Suite
===================================================================
Unit and integration tests covering:
1. Profiling dirty datasets (nulls, duplicates, ragged whitespace, mixed dates, bad headers).
2. PII security & redaction verification (EMAIL, SSN, CREDIT_CARD, PHONE) ensuring zero PII reaches LLMs.
3. LLM valid plan synthesis, <think>...</think> stripping, and end-to-end ingestion via ETLEngine.
4. Adversarial action rejection (blocking eval/exec/python_exec).
5. Offline Ollama fallback resilience and heuristic plan generation.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import pandas as pd

from src.core.db_manager import DatabaseManager
from src.etl.etl_engine import (
    ETLEngine,
    CleaningPlanExecutor,
    ETLValidationError,
)
from src.etl.ai_profiler import (
    AIDataProfiler,
    DatasetProfile,
    ColumnProfile,
    PIIFinding,
    CleaningStep,
    ProposedCleaningPlan,
)
from src.agent.llm_router import (
    LLMRouter,
    LLMResponse,
    LLMConnectionError,
    LLMTimeoutError,
)


class TestAIDataProfiler(unittest.TestCase):
    """Rigorous verification suite for AIDataProfiler and cleaning plan contracts."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.profiler = AIDataProfiler()

    def tearDown(self) -> None:
        if hasattr(self, "db"):
            try:
                self.db.close()
            except Exception:
                pass
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass
        DatabaseManager.reset_instance()

    # --------------------------------------------------------------------------
    # 1. PROFILING DIRTY CSV TEST
    # --------------------------------------------------------------------------

    def test_dirty_csv_profiling_and_health_scoring(self) -> None:
        """
        Profiles a dirty CSV with nulls, duplicates, ragged whitespace, mixed dates,
        and bad column names, verifying health_score, health_grade, and anomalies.
        """
        csv_path = self.temp_path / "dirty_sales.csv"
        # 6 rows total with 2 duplicates, nulls in revenue, ragged whitespace, mixed dates, bad header
        csv_content = (
            "order_id, Customer Name ,transaction_date,revenue, 123#Special!\n"
            "ORD-001,  Alice Corp  ,2026-01-01,150.00,valid_a\n"
            "ORD-002,Bob Ltd,02/15/2026,,valid_b\n"
            "ORD-003, Charlie Inc. ,2026-03-01,300.50,valid_c\n"
            "ORD-004,David LLC,invalid_date,,valid_d\n"
            "ORD-001,  Alice Corp  ,2026-01-01,150.00,valid_a\n"  # Duplicate of row 1
            "ORD-005,Eve Co,2026-05-01,500.00,valid_e\n"
        )
        csv_path.write_text(csv_content, encoding="utf-8")

        profile = self.profiler.profile_file(csv_path)

        # Basic shape and structure
        self.assertIsInstance(profile, DatasetProfile)
        self.assertEqual(profile.file_name, "dirty_sales.csv")
        self.assertEqual(profile.sampled_rows, 6)
        self.assertGreaterEqual(profile.estimated_total_rows, 6)
        self.assertEqual(profile.duplicate_rows_in_sample, 1)

        # Health score must reflect applied penalties
        self.assertLess(profile.health_score, 90)
        self.assertIn(profile.health_grade, ("B", "C", "D"))
        self.assertGreater(len(profile.anomalies), 0)

        # Validate column-specific profiling
        col_names = {c.raw_name: c for c in profile.columns}
        self.assertIn(" Customer Name ", col_names)
        cust_col = col_names[" Customer Name "]
        self.assertTrue(cust_col.has_ragged_whitespace)
        self.assertNotEqual(cust_col.raw_name, cust_col.sanitized_name)

        date_col = col_names["transaction_date"]
        self.assertTrue(date_col.has_mixed_dates)

        rev_col = col_names["revenue"]
        self.assertEqual(rev_col.null_count, 2)
        self.assertAlmostEqual(rev_col.null_pct, 33.33, places=1)

        special_col = col_names[" 123#Special!"]
        self.assertNotEqual(special_col.raw_name, special_col.sanitized_name)

        # Verify heuristic plan generation handles all detected issues
        heuristic_plan = self.profiler.generate_heuristic_plan(profile)
        self.assertEqual(heuristic_plan.source, "heuristic_fallback")
        self.assertGreater(len(heuristic_plan.steps), 0)

        actions = [s.action for s in heuristic_plan.steps]
        self.assertIn("strip_whitespace", actions)
        self.assertIn("drop_duplicates", actions)
        self.assertIn("impute_null", actions)

    # --------------------------------------------------------------------------
    # 2. PII SECURITY & STRICT REDACTION TEST
    # --------------------------------------------------------------------------

    def test_pii_security_redaction_and_zero_leakage_to_llm(self) -> None:
        """
        Creates a CSV containing fake Email, SSN, Luhn-valid Card, and Phone.
        Asserts pii_findings detects all four AND verifies the prompt dispatched
        to LLMRouter contains [REDACTED_*] tokens and ZERO raw PII characters.
        """
        csv_path = self.temp_path / "sensitive_customers.csv"
        # 4532015012345671 is a Luhn-valid Visa test number
        valid_card = "4532-0150-1234-5671"
        fake_email = "alice@corp.com"
        fake_ssn = "123-45-6789"
        fake_phone = "(555) 123-4567"
        non_pii_order = "ORD-9988776655443322"  # Non-Luhn candidate

        csv_content = (
            "id,email,ssn,credit_card,phone_number,order_code\n"
            f"1,{fake_email},{fake_ssn},{valid_card},{fake_phone},{non_pii_order}\n"
            f"2,bob.builder@acme.org,987-65-4321,4532015012345671,555-987-6543,ORD-1122334455667788\n"
        )
        csv_path.write_text(csv_content, encoding="utf-8")

        profile = self.profiler.profile_file(csv_path)

        # 1. Assert PII detection populated in pii_findings
        detected_types = {f.pii_type: f.match_count for f in profile.pii_findings}
        self.assertIn("EMAIL", detected_types)
        self.assertIn("SSN", detected_types)
        self.assertIn("CREDIT_CARD", detected_types)
        self.assertIn("PHONE", detected_types)
        self.assertGreaterEqual(detected_types["EMAIL"], 2)
        self.assertGreaterEqual(detected_types["SSN"], 2)
        self.assertGreaterEqual(detected_types["CREDIT_CARD"], 2)
        self.assertGreaterEqual(detected_types["PHONE"], 2)

        # 2. Verify all ColumnProfile sample values are masked
        for col in profile.columns:
            for sample in col.sample_values:
                self.assertNotIn(fake_email, sample)
                self.assertNotIn(fake_ssn, sample)
                self.assertNotIn(valid_card, sample)
                self.assertNotIn(fake_phone, sample)

        # 3. Dispatch to Mocked LLM Router and assert full prompt safety
        mock_router = MagicMock(spec=LLMRouter)
        mock_router.invoke.return_value = LLMResponse(
            content=json.dumps({"summary": "Safe plan", "steps": []}),
            provider="local",
            model="phi4-mini",
            prompt_tokens=50,
            completion_tokens=20,
            total_tokens=70,
            latency_ms=25.0
        )

        plan = self.profiler.propose_cleaning_plan(profile, llm_router=mock_router)
        self.assertIsNotNone(plan)

        # Capture prompt payload dispatched to mock_router
        self.assertTrue(mock_router.invoke.called)
        _, kwargs = mock_router.invoke.call_args
        dispatched_messages = kwargs.get("messages", [])
        combined_prompt_text = " ".join(m["content"] for m in dispatched_messages)

        # Assert redacted placeholders ARE present
        self.assertIn("[REDACTED_EMAIL]", combined_prompt_text)
        self.assertIn("[REDACTED_SSN]", combined_prompt_text)
        self.assertIn("[REDACTED_CARD]", combined_prompt_text)
        self.assertIn("[REDACTED_PHONE]", combined_prompt_text)

        # Assert ZERO raw PII appears in the prompt
        self.assertNotIn(fake_email, combined_prompt_text)
        self.assertNotIn(fake_ssn, combined_prompt_text)
        self.assertNotIn(valid_card, combined_prompt_text)
        self.assertNotIn(fake_phone, combined_prompt_text)
        self.assertNotIn("bob.builder@acme.org", combined_prompt_text)
        self.assertNotIn("987-65-4321", combined_prompt_text)
        self.assertNotIn("4532015012345671", combined_prompt_text)

    # --------------------------------------------------------------------------
    # 3. LLM VALID PLAN + <think> STRIPPING + EXECUTOR INGESTION TEST
    # --------------------------------------------------------------------------

    def test_llm_valid_plan_with_think_tags_and_end_to_end_ingestion(self) -> None:
        """
        Mocks LLMRouter returning <think> reasoning tags + valid JSON cleaning plan.
        Asserts source == 'llm', <think> is stripped, and plan.to_executor_payload()
        successfully executes through ETLEngine.ingest_file into a real SQLite DB.
        """
        csv_path = self.temp_path / "sales_to_clean.csv"
        csv_content = (
            "cust_name,amount\n"
            "  Acme Corp  ,100\n"
            "Beta LLC, \n"
            "  Acme Corp  ,100\n"  # Duplicate
        )
        csv_path.write_text(csv_content, encoding="utf-8")

        profile = self.profiler.profile_file(csv_path)

        llm_output_with_think = (
            "<think>\n"
            "I observe that cust_name has leading/trailing whitespace.\n"
            "There is also a duplicate row and a missing value in amount.\n"
            "I should strip whitespace, drop duplicates, and impute nulls.\n"
            "</think>\n"
            "```json\n"
            "{\n"
            '  "summary": "Clean whitespace, deduplicate, and impute missing amount.",\n'
            '  "steps": [\n'
            '    {\n'
            '      "action": "strip_whitespace",\n'
            '      "params": {"columns": ["cust_name"]},\n'
            '      "reason": "Strip ragged whitespace from customer names"\n'
            '    },\n'
            '    {\n'
            '      "action": "drop_duplicates",\n'
            '      "params": {},\n'
            '      "reason": "Remove duplicate entries"\n'
            '    },\n'
            '    {\n'
            '      "action": "impute_null",\n'
            '      "params": {"columns": ["amount"], "strategy": "zero"},\n'
            '      "reason": "Impute missing amount values with 0"\n'
            '    }\n'
            '  ]\n'
            "}\n"
            "```"
        )

        mock_router = MagicMock(spec=LLMRouter)
        mock_router.invoke.return_value = LLMResponse(
            content=llm_output_with_think,
            provider="local",
            model="phi4-mini",
            prompt_tokens=100,
            completion_tokens=80,
            total_tokens=180,
            latency_ms=120.0
        )

        plan = self.profiler.propose_cleaning_plan(profile, llm_router=mock_router)

        self.assertEqual(plan.source, "llm")
        self.assertEqual(plan.model_used, "phi4-mini")
        self.assertIsNone(plan.warning_message)
        self.assertEqual(len(plan.steps), 3)

        # Convert to executor payload
        payload = plan.to_executor_payload()
        self.assertIsInstance(payload, list)
        self.assertEqual(len(payload), 3)
        self.assertEqual(payload[0]["action"], "strip_whitespace")
        self.assertEqual(payload[0]["columns"], ["cust_name"])

        # Validate against CleaningPlanExecutor contract
        CleaningPlanExecutor.validate_plan(payload)

        # Ingest end-to-end via ETLEngine into real SQLite DB
        db_path = self.temp_path / "nexus_test.db"
        self.db = DatabaseManager(db_path)
        engine = ETLEngine(db_manager=self.db)

        report = engine.ingest_file(
            file_path=csv_path,
            table_name="cleaned_sales",
            cleaning_plan=payload
        )

        self.assertEqual(report.table_name, "cleaned_sales")
        table_check = self.db.execute_query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='cleaned_sales'"
        )
        self.assertEqual(len(table_check.rows), 1)

        # Verify transformed data in SQLite
        res_rows = self.db.execute_query("SELECT * FROM cleaned_sales")
        self.assertEqual(len(res_rows.rows), 2)
        dict_rows = res_rows.to_dicts()
        names = [r["cust_name"] for r in dict_rows]
        self.assertIn("Acme Corp", names)
        self.assertIn("Beta LLC", names)
        for name in names:
            self.assertEqual(name, name.strip())

    # --------------------------------------------------------------------------
    # 4. ADVERSARIAL ACTION REJECTION TEST
    # --------------------------------------------------------------------------

    def test_adversarial_action_rejection_and_safe_fallback(self) -> None:
        """
        Mocks LLM attempting to inject malicious / non-whitelisted actions:
        {"action": "python_exec", "params": {"code": "__import__('os').system('calc')"}}.
        Asserts the prohibited step is rejected, never executed, and profiler
        degrades safely to the deterministic heuristic fallback.
        """
        csv_path = self.temp_path / "adversarial_test.csv"
        csv_path.write_text("user_id,score\n1,100\n2,200\n", encoding="utf-8")
        profile = self.profiler.profile_file(csv_path)

        adversarial_json = json.dumps({
            "summary": "Malicious injection attempt",
            "steps": [
                {
                    "action": "python_exec",
                    "params": {"code": "__import__('os').system('calc')"},
                    "reason": "malicious execution attempt"
                },
                {
                    "action": "eval",
                    "params": {"expression": "open('/etc/passwd').read()"},
                    "reason": "eval exploit"
                },
                {
                    "action": "os_system",
                    "params": {"cmd": "rmdir /s /q C:\\"},
                    "reason": "system command injection"
                }
            ]
        })

        mock_router = MagicMock(spec=LLMRouter)
        mock_router.invoke.return_value = LLMResponse(
            content=adversarial_json,
            provider="local",
            model="phi4-mini",
            prompt_tokens=40,
            completion_tokens=30,
            total_tokens=70,
            latency_ms=10.0
        )

        plan = self.profiler.propose_cleaning_plan(profile, llm_router=mock_router)

        # Prohibited actions MUST be rejected, falling back to heuristic plan
        self.assertEqual(plan.source, "heuristic_fallback")
        self.assertIsNotNone(plan.warning_message)
        self.assertIn("no valid whitelisted steps", plan.warning_message)

        # Verify NO adversarial actions leaked into the final plan
        for step in plan.steps:
            self.assertIn(step.action, CleaningPlanExecutor.ALLOWED_ACTIONS)
            self.assertNotIn("python_exec", step.action)
            self.assertNotIn("eval", step.action)
            self.assertNotIn("os_system", step.action)

        # Verify payload executes safely without security exceptions
        payload = plan.to_executor_payload()
        CleaningPlanExecutor.validate_plan(payload)

    # --------------------------------------------------------------------------
    # 5. OFFLINE OLLAMA FALLBACK RESILIENCE TEST
    # --------------------------------------------------------------------------

    def test_offline_ollama_graceful_heuristic_degradation(self) -> None:
        """
        Mocks LLMRouter raising LLMConnectionError (Ollama offline/unreachable).
        Asserts graceful degradation to source == 'heuristic_fallback', valid
        executable steps, and an actionable warning_message.
        """
        csv_path = self.temp_path / "offline_test.csv"
        csv_content = (
            "col_a,col_b\n"
            "  text_with_spaces  ,10\n"
            "  text_with_spaces  ,10\n"  # Duplicate
        )
        csv_path.write_text(csv_content, encoding="utf-8")
        profile = self.profiler.profile_file(csv_path)

        mock_router = MagicMock(spec=LLMRouter)
        mock_router.invoke.side_effect = LLMConnectionError("Ollama daemon at 127.0.0.1:11434 unreachable")

        plan = self.profiler.propose_cleaning_plan(profile, llm_router=mock_router)

        self.assertEqual(plan.source, "heuristic_fallback")
        self.assertIsNotNone(plan.warning_message)
        self.assertIn("LLM router unavailable", plan.warning_message)
        self.assertIn("LLMConnectionError", plan.warning_message)

        # Plan must still contain valid steps for the detected issues
        self.assertGreater(len(plan.steps), 0)
        actions = [s.action for s in plan.steps]
        self.assertIn("strip_whitespace", actions)
        self.assertIn("drop_duplicates", actions)

        # Verify payload validates cleanly
        payload = plan.to_executor_payload()
        CleaningPlanExecutor.validate_plan(payload)

    # --------------------------------------------------------------------------
    # 6. HALLUCINATED COLUMNS CLEAN DROPPING TEST
    # --------------------------------------------------------------------------

    def test_hallucinated_column_omission(self) -> None:
        """
        Verifies that when an LLM proposes steps on hallucinated columns that do
        not exist in the dataset, those invalid steps are dropped cleanly without crashing.
        """
        csv_path = self.temp_path / "real_cols.csv"
        csv_path.write_text("actual_col\nval1\nval2\n", encoding="utf-8")
        profile = self.profiler.profile_file(csv_path)

        mixed_llm_json = json.dumps({
            "summary": "Plan with one valid step and one hallucinated step",
            "steps": [
                {
                    "action": "strip_whitespace",
                    "params": {"columns": ["actual_col"]},
                    "reason": "Strip whitespace on real column"
                },
                {
                    "action": "drop_columns",
                    "params": {"columns": ["phantom_non_existent_column"]},
                    "reason": "Drop non-existent column"
                }
            ]
        })

        mock_router = MagicMock(spec=LLMRouter)
        mock_router.invoke.return_value = LLMResponse(
            content=mixed_llm_json,
            provider="local",
            model="phi4-mini",
            prompt_tokens=50,
            completion_tokens=50,
            total_tokens=100,
            latency_ms=30.0
        )

        plan = self.profiler.propose_cleaning_plan(profile, llm_router=mock_router)

        self.assertEqual(plan.source, "llm")
        # Only the valid step should remain
        self.assertEqual(len(plan.steps), 1)
        self.assertEqual(plan.steps[0].action, "strip_whitespace")
        self.assertEqual(plan.steps[0].params["columns"], ["actual_col"])

    # --------------------------------------------------------------------------
    # 7. CLEAN DATASET HEALTH SCORE A TEST
    # --------------------------------------------------------------------------

    def test_clean_dataset_earns_grade_a(self) -> None:
        """
        A pristine dataset with zero nulls, duplicates, whitespace issues,
        or bad headers should achieve a 100 health_score and Grade 'A'.
        """
        csv_path = self.temp_path / "pristine.csv"
        csv_path.write_text("user_id,user_name,signup_date\n1,Alice,2026-01-01\n2,Bob,2026-01-02\n", encoding="utf-8")

        profile = self.profiler.profile_file(csv_path)

        self.assertEqual(profile.health_score, 100)
        self.assertEqual(profile.health_grade, "A")
        self.assertEqual(len(profile.pii_findings), 0)
        self.assertEqual(profile.duplicate_rows_in_sample, 0)


if __name__ == "__main__":
    unittest.main()
