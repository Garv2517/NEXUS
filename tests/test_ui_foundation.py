"""
NEXUS Engine - Phase 2 UI Foundation Test Suite
===============================================
Validates:
1. NexusTheme palette tokens, typography constants, and immutability.
2. apply_global_theme() headless and Windows safety.
3. mask_secret() API key masking and edge cases.
4. AsyncWorkerManager asynchronous background task submission, non-blocking execution,
   thread-safe queue dispatching, on_success / on_error / on_progress callbacks,
   exception isolation, and clean shutdown lifecycle.
"""

import sys
import time
import unittest
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.ui.theme import NexusTheme, apply_global_theme, mask_secret
from src.ui.async_worker import AsyncWorkerManager, WorkerEventType


class TestUIFoundation(unittest.TestCase):

    # --------------------------------------------------------------------------
    # 1. THEME & PALETTE SPECIFICATION TESTS
    # --------------------------------------------------------------------------

    def test_theme_palette_values(self):
        """Verify high-contrast cyber-analytics color hex codes match specs."""
        self.assertEqual(NexusTheme.BG_OBSIDIAN, "#0B0F19")
        self.assertEqual(NexusTheme.SURFACE_SLATE, "#111827")
        self.assertEqual(NexusTheme.SURFACE_ELEVATED, "#1E293B")
        self.assertEqual(NexusTheme.ACCENT_CYAN, "#06B6D4")
        self.assertEqual(NexusTheme.STATUS_EMERALD, "#10B981")
        self.assertEqual(NexusTheme.STATUS_AMBER, "#F59E0B")
        self.assertEqual(NexusTheme.STATUS_CRIMSON, "#EF4444")

    def test_theme_typography(self):
        """Verify Windows native font families and pre-configured tuples."""
        self.assertEqual(NexusTheme.FONT_FAMILY_MAIN, "Segoe UI")
        self.assertEqual(NexusTheme.FONT_FAMILY_MONO, "Consolas")
        self.assertEqual(NexusTheme.FONT_TITLE[0], "Segoe UI")
        self.assertEqual(NexusTheme.FONT_CODE[0], "Consolas")

    def test_theme_immutability(self):
        """Verify that NexusTheme attributes cannot be mutated or overridden at runtime."""
        with self.assertRaises(AttributeError):
            NexusTheme.BG_OBSIDIAN = "#FFFFFF"

        with self.assertRaises(AttributeError):
            NexusTheme.ACCENT_CYAN = "#FF0000"

    def test_apply_global_theme_headless_safety(self):
        """Verify apply_global_theme() runs without unhandled exceptions."""
        result = apply_global_theme()
        self.assertIsInstance(result, bool)

    # --------------------------------------------------------------------------
    # 2. SECRET REDACTION TESTS
    # --------------------------------------------------------------------------

    def test_mask_secret_standard_key(self):
        """Verify standard API keys expose only the last 4 characters preceded by 8 bullets."""
        key = "sk-proj-abc123xyz7890"
        masked = mask_secret(key)
        self.assertEqual(masked, "••••••••7890")
        self.assertNotIn("abc123xyz", masked)

    def test_mask_secret_edge_cases(self):
        """Verify edge cases: short keys, empty strings, None, whitespace."""
        self.assertEqual(mask_secret(None), "[EMPTY]")
        self.assertEqual(mask_secret(""), "[EMPTY]")
        self.assertEqual(mask_secret("   "), "[EMPTY]")
        self.assertEqual(mask_secret("short"), "[REDACTED]")
        self.assertEqual(mask_secret("1234567"), "[REDACTED]")

        # 8 characters: exact lower bound for masking
        self.assertEqual(mask_secret("12345678"), "••••••••5678")

    # --------------------------------------------------------------------------
    # 3. ASYNC WORKER MANAGER TESTS
    # --------------------------------------------------------------------------

    def setUp(self):
        self.worker = AsyncWorkerManager(max_workers=4)

    def tearDown(self):
        self.worker.shutdown(wait=False)

    def test_submit_task_success_callback(self):
        """Verify task runs in background and on_success callback executes via process_queue()."""
        def heavy_calc(a: int, b: int) -> int:
            time.sleep(0.05)
            return a * b

        results = []
        task_id = self.worker.submit_task(
            heavy_calc,
            6,
            7,
            on_success=lambda res: results.append(res),
            task_name="Multiply"
        )
        self.assertTrue(task_id.startswith("TASK-"))

        # Wait briefly for thread to complete
        time.sleep(0.15)

        # Main thread polls queue
        processed = self.worker.process_queue()
        self.assertEqual(processed, 1)
        self.assertEqual(results, [42])

    def test_submit_task_error_callback(self):
        """Verify task errors are captured and dispatched to on_error without crashing."""
        def failing_task():
            time.sleep(0.05)
            raise ValueError("ETL column mapping failure")

        errors = []
        self.worker.submit_task(
            failing_task,
            on_error=lambda err: errors.append(err),
            task_name="FailingJob"
        )

        time.sleep(0.15)
        processed = self.worker.process_queue()
        self.assertEqual(processed, 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ValueError)
        self.assertEqual(str(errors[0]), "ETL column mapping failure")

    def test_submit_task_progress_callback(self):
        """Verify tasks can emit progress messages to the queue."""
        def multi_step_task(progress_callback=None):
            if progress_callback:
                progress_callback("Step 1: Ingesting CSV")
                time.sleep(0.03)
                progress_callback("Step 2: Transforming DataFrame")
                time.sleep(0.03)
            return "DONE"

        progress_msgs = []
        final_results = []

        self.worker.submit_task(
            multi_step_task,
            on_progress=lambda msg: progress_msgs.append(msg),
            on_success=lambda res: final_results.append(res),
            task_name="MultiStepETL"
        )

        # Wait for all steps to finish
        time.sleep(0.2)

        processed = self.worker.process_queue()
        # Expect 2 progress events + 1 success event = 3 events
        self.assertEqual(processed, 3)
        self.assertIn("Step 1: Ingesting CSV", progress_msgs)
        self.assertIn("Step 2: Transforming DataFrame", progress_msgs)
        self.assertEqual(final_results, ["DONE"])

    def test_callback_exception_isolation(self):
        """Verify a crashing callback does not disrupt remaining queue events or caller loop."""
        def task_one():
            return "ONE"

        def task_two():
            return "TWO"

        def buggy_callback(res):
            raise ZeroDivisionError("Bug in UI callback")

        valid_results = []
        self.worker.submit_task(task_one, on_success=buggy_callback)
        self.worker.submit_task(task_two, on_success=lambda r: valid_results.append(r))

        time.sleep(0.15)
        # process_queue should execute both events, isolate the error on task_one,
        # and cleanly deliver task_two
        processed = self.worker.process_queue()
        self.assertEqual(processed, 2)
        self.assertEqual(valid_results, ["TWO"])

    def test_concurrent_tasks_execution(self):
        """Verify multiple tasks run concurrently across worker threads."""
        def sleep_task(duration: float, val: int) -> int:
            time.sleep(duration)
            return val

        collected = []
        for i in range(4):
            self.worker.submit_task(
                sleep_task,
                0.05,
                i,
                on_success=lambda r: collected.append(r)
            )

        time.sleep(0.15)
        processed = self.worker.process_queue()
        self.assertEqual(processed, 4)
        self.assertEqual(sorted(collected), [0, 1, 2, 3])

    def test_shutdown_lifecycle(self):
        """Verify shutdown terminates pool and rejects new submissions."""
        self.worker.shutdown(wait=True)
        self.assertTrue(self.worker.is_shutdown)

        with self.assertRaises(RuntimeError):
            self.worker.submit_task(lambda: 1)


if __name__ == "__main__":
    unittest.main()
