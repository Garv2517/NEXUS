"""
NEXUS Engine - AI Data Profiler & Smart Cleaning Planner
========================================================
Enterprise-grade tabular data profiler, PII redactor, and LLM-assisted / heuristic
cleaning plan synthesizer.

Architectural Guarantees:
1. Security: Zero eval()/exec(), strict action whitelist matching CleaningPlanExecutor,
   guaranteed PII masking before any sample data leaves the profiler or touches an LLM.
2. Stability & Speed: Fast sampling (first 1,000 rows max), zero redundant 100MB file reads,
   graceful deterministic heuristic fallback on offline Ollama, timeout, or malformed LLM outputs.
3. Strict Pydantic v2 Models: Fully validated schema contracts for CleaningStep and ProposedCleaningPlan.
"""

from __future__ import annotations

import csv
import dataclasses
import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Tuple, Union

import pandas as pd
from pydantic import BaseModel, Field

from src.etl.etl_engine import (
    ETLEngine,
    CleaningPlanExecutor,
    sanitize_identifier,
    ETLValidationError,
)
from src.agent.llm_router import LLMRouter, LLMRouterError, LLMConnectionError

logger = logging.getLogger("NEXUS-AIProfiler")


# ==============================================================================
# IMMUTABLE DATA PROFILE STRUCTURES
# ==============================================================================

@dataclasses.dataclass(frozen=True)
class PIIFinding:
    """Represents detected PII occurrences within a specific column."""
    column: str
    pii_type: str  # "EMAIL", "PHONE", "SSN", "CREDIT_CARD"
    match_count: int


@dataclasses.dataclass(frozen=True)
class ColumnProfile:
    """Comprehensive, immutable column-level quality profile with masked samples."""
    raw_name: str
    sanitized_name: str
    inferred_dtype: str
    null_count: int
    null_pct: float
    unique_count: int
    has_ragged_whitespace: bool
    has_mixed_dates: bool
    sample_values: List[str]  # Strictly PII-masked before ever leaving the profiler


@dataclasses.dataclass(frozen=True)
class DatasetProfile:
    """Holistic dataset health and structural audit profile."""
    file_path: str
    file_name: str
    sampled_rows: int
    estimated_total_rows: int
    duplicate_rows_in_sample: int
    health_score: int  # Clamped 0..100
    health_grade: str  # "A" >=90, "B" >=75, "C" >=60, "D" <60
    pii_findings: List[PIIFinding]
    columns: List[ColumnProfile]
    anomalies: List[str]


# ==============================================================================
# STRICT PYDANTIC V2 CLEANING PLAN MODELS
# ==============================================================================

CleaningActionType = Literal[
    "drop_columns",
    "rename_columns",
    "cast_type",
    "impute_null",
    "drop_null_rows",
    "strip_whitespace",
    "case_transform",
    "replace_value",
    "drop_duplicates",
    "clamp_range",
]


class CleaningStep(BaseModel):
    """
    Validated cleaning operation conforming to CleaningPlanExecutor whitelisted actions.
    """
    action: CleaningActionType
    params: Dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(..., max_length=160)


class ProposedCleaningPlan(BaseModel):
    """
    Validated recipe containing declarative cleaning steps, provenance, and executor export.
    """
    summary: str
    steps: List[CleaningStep] = Field(default_factory=list)
    source: Literal["llm", "heuristic_fallback"]
    model_used: Optional[str] = None
    warning_message: Optional[str] = None

    def to_executor_payload(self) -> List[Dict[str, Any]]:
        """
        Converts validated steps into the exact list-of-dicts contract
        expected by CleaningPlanExecutor.apply(df, cleaning_plan).
        """
        payload: List[Dict[str, Any]] = []
        for step in self.steps:
            # Action is guaranteed, params unpacked to top level matching CleaningPlanExecutor
            step_dict = {**step.params, "action": step.action}
            payload.append(step_dict)
        return payload


# ==============================================================================
# AI DATA PROFILER & HEURISTIC ENGINE
# ==============================================================================

class AIDataProfiler:
    """
    High-throughput dataset profiling, PII identification/redaction, and
    hybrid LLM / deterministic heuristic cleaning plan generator.
    """

    PII_PATTERNS: Dict[str, re.Pattern] = {
        "EMAIL": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
        "SSN": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "CREDIT_CARD": re.compile(r'\b(?:\d[ -]*?){13,19}\b'),
        "PHONE": re.compile(r'(?:(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\b\d{3})[-.\s]?\d{3}[-.\s]?\d{4}\b)'),
    }

    DATE_LIKE_REGEX = re.compile(r'^\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}')

    @staticmethod
    def is_luhn_valid(num_str: str) -> bool:
        """
        Validates 13-19 digit candidate string against Luhn checksum (mod 10).
        Filters out false positives such as tracking numbers, order IDs, and UUIDs.
        """
        digits = [int(c) for c in num_str if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        reverse_digits = digits[::-1]
        for idx, d in enumerate(reverse_digits):
            if idx % 2 == 1:
                doubled = d * 2
                total += doubled - 9 if doubled > 9 else doubled
            else:
                total += d
        return total % 10 == 0

    @classmethod
    def mask_pii_value(cls, value: Any) -> str:
        """
        Redacts any detected PII tokens in a value to:
        [REDACTED_EMAIL], [REDACTED_SSN], [REDACTED_CARD], or [REDACTED_PHONE].
        """
        if value is None or pd.isna(value):
            return ""
        text = str(value)

        # 1. Email Redaction
        text = cls.PII_PATTERNS["EMAIL"].sub("[REDACTED_EMAIL]", text)

        # 2. SSN Redaction (\b\d{3}-\d{2}-\d{4}\b)
        text = cls.PII_PATTERNS["SSN"].sub("[REDACTED_SSN]", text)

        # 3. Credit Card Redaction (with Luhn validation)
        def _card_sub(m: re.Match) -> str:
            val = m.group(0)
            if cls.is_luhn_valid(val):
                return "[REDACTED_CARD]"
            return val

        text = cls.PII_PATTERNS["CREDIT_CARD"].sub(_card_sub, text)

        # 4. Phone Redaction
        text = cls.PII_PATTERNS["PHONE"].sub("[REDACTED_PHONE]", text)

        return text

    @classmethod
    def detect_pii_in_texts(cls, texts: List[str]) -> Dict[str, int]:
        """
        Scans a collection of non-null strings and counts matches for each PII type,
        redacting matched tokens progressively to prevent cross-pattern overcounting.
        """
        counts = {"EMAIL": 0, "SSN": 0, "CREDIT_CARD": 0, "PHONE": 0}
        for raw in texts:
            # 1. Email
            emails = cls.PII_PATTERNS["EMAIL"].findall(raw)
            counts["EMAIL"] += len(emails)
            t = cls.PII_PATTERNS["EMAIL"].sub(" ", raw)

            # 2. SSN
            ssns = cls.PII_PATTERNS["SSN"].findall(t)
            counts["SSN"] += len(ssns)
            t = cls.PII_PATTERNS["SSN"].sub(" ", t)

            # 3. Credit Card with Luhn validation
            card_count = 0
            def _sub_card(m: re.Match) -> str:
                nonlocal card_count
                if cls.is_luhn_valid(m.group(0)):
                    card_count += 1
                    return " "
                return m.group(0)

            t = cls.PII_PATTERNS["CREDIT_CARD"].sub(_sub_card, t)
            counts["CREDIT_CARD"] += card_count

            # 4. Phone
            phones = cls.PII_PATTERNS["PHONE"].findall(t)
            counts["PHONE"] += len(phones)

        return counts

    @classmethod
    def check_mixed_dates(cls, series: pd.Series) -> bool:
        """
        Detects whether a column contains date values with mixed formatting
        (e.g., both '/' and '-' separators) or dates mixed with non-date strings.
        """
        non_nulls = series.dropna().astype(str).str.strip()
        if len(non_nulls) < 2:
            return False

        matches = non_nulls.str.contains(cls.DATE_LIKE_REGEX)
        match_count = int(matches.sum())
        if match_count == 0:
            return False

        # Some entries look like dates and some do not
        if 0 < match_count < len(non_nulls):
            return True

        # All look like dates, but use conflicting delimiters (e.g. YYYY-MM-DD vs MM/DD/YYYY)
        has_slash = bool(non_nulls.str.contains(r'/').any())
        has_dash = bool(non_nulls.str.contains(r'-').any())
        return has_slash and has_dash

    def profile_file(
        self,
        file_path: Union[str, Path],
        sample_rows: int = 1000,
        prompt_preview_rows: int = 5,
        sheet_name: Optional[Union[str, int]] = None
    ) -> DatasetProfile:
        """
        Reads at most sample_rows rows cleanly, computes ColumnProfile per column,
        populates pii_findings, masks all sample_values, detects anomalies,
        and calculates a deterministic health_score.
        """
        path = Path(file_path).resolve()
        if not path.exists() or not path.is_file():
            raise ETLValidationError(f"Source dataset does not exist or is not a file: {path}")

        ext = path.suffix.lower()
        if ext not in ETLEngine.SUPPORTED_EXTENSIONS:
            raise ETLValidationError(f"Unsupported file format '{ext}'.")

        # 1. Fast Sampling (<1,000 rows, zero redundant full reads)
        try:
            if ext in (".csv", ".tsv", ".tab", ".txt"):
                encoding, delimiter = ETLEngine.detect_encoding_and_delimiter(path)
                df = pd.read_csv(
                    path,
                    sep=delimiter,
                    encoding=encoding,
                    nrows=sample_rows,
                    low_memory=False,
                    on_bad_lines="skip"
                )
            elif ext in (".json", ".jsonl", ".ndjson"):
                try:
                    df = pd.read_json(path, lines=True, nrows=sample_rows)
                except Exception:
                    df = pd.read_json(path)
                    df = df.head(sample_rows)
            elif ext in (".xlsx", ".xls"):
                if sheet_name is not None:
                    df = pd.read_excel(path, sheet_name=sheet_name, nrows=sample_rows)
                else:
                    df = pd.read_excel(path, nrows=sample_rows)
            elif ext == ".parquet":
                df = pd.read_parquet(path)
                df = df.head(sample_rows)
            else:
                raise ETLValidationError(f"Unsupported extension: {ext}")
        except Exception as exc:
            logger.error(f"Failed to read dataset sample from {path}: {exc}")
            raise ETLValidationError(f"Failed to sample dataset {path.name}: {exc}") from exc

        sampled_rows = len(df)
        if sampled_rows == 0 or len(df.columns) == 0:
            raise ETLValidationError(f"Dataset {path.name} contains zero rows or columns.")

        # 2. Fast Binary Total Row Counting / Estimation
        estimated_total_rows = sampled_rows
        if sampled_rows >= sample_rows and ext in (".csv", ".tsv", ".tab", ".txt", ".jsonl", ".ndjson"):
            try:
                line_count = 0
                with open(path, "rb") as bf:
                    for chunk in iter(lambda: bf.read(1024 * 1024), b""):
                        line_count += chunk.count(b"\n")
                if ext in (".csv", ".tsv", ".tab", ".txt") and line_count > 0:
                    estimated_total_rows = max(sampled_rows, line_count)
                else:
                    estimated_total_rows = max(sampled_rows, line_count)
            except Exception:
                estimated_total_rows = sampled_rows

        # 3. Column Profiling & PII Identification
        column_profiles: List[ColumnProfile] = []
        pii_findings: List[PIIFinding] = []
        anomalies: List[str] = []

        # Track duplicates
        duplicate_rows_in_sample = int(df.duplicated().sum())
        if duplicate_rows_in_sample > 0:
            dup_pct = (duplicate_rows_in_sample / sampled_rows) * 100
            anomalies.append(
                f"Found {duplicate_rows_in_sample} duplicate rows in sample ({dup_pct:.1f}%)."
            )

        sanitized_col_names: Set[str] = set()

        for col in df.columns:
            raw_name = str(col)
            sanitized_name = sanitize_identifier(raw_name, is_table=False, existing_names=sanitized_col_names)
            series = df[col]

            null_count = int(series.isna().sum())
            null_pct = round(float(null_count / sampled_rows * 100), 2) if sampled_rows > 0 else 0.0
            unique_count = int(series.nunique(dropna=True))

            # Ragged whitespace check
            has_ragged_whitespace = False
            non_null_strings = series.dropna().astype(str)
            if not non_null_strings.empty:
                has_ragged_whitespace = bool((non_null_strings.str.strip() != non_null_strings).any())

            # Mixed dates check
            has_mixed_dates = self.check_mixed_dates(series)

            # Inferred data type
            if has_mixed_dates:
                inferred_dtype = "DATETIME"
            elif pd.api.types.is_bool_dtype(series):
                inferred_dtype = "BOOLEAN"
            elif pd.api.types.is_integer_dtype(series):
                inferred_dtype = "INTEGER"
            elif pd.api.types.is_float_dtype(series):
                inferred_dtype = "REAL"
            else:
                try:
                    inferred_dtype, _ = ETLEngine.profile_and_standardize_column(series)
                    if inferred_dtype == "TIMESTAMP":
                        inferred_dtype = "DATETIME"
                except Exception:
                    inferred_dtype = "TEXT"

            # Sample preview values (strictly PII-masked and length-truncated)
            sample_values: List[str] = []
            for val in series.dropna().iloc[:prompt_preview_rows]:
                # Mask PII FIRST before truncating to guarantee full token protection
                masked = self.mask_pii_value(val)[:40]
                sample_values.append(masked)

            # Detect PII across sampled series
            col_pii = self.detect_pii_in_texts(non_null_strings.tolist())
            for pii_type, count in col_pii.items():
                if count > 0:
                    pii_findings.append(
                        PIIFinding(column=raw_name, pii_type=pii_type, match_count=count)
                    )
                    anomalies.append(
                        f"Detected {pii_type} PII in column '{raw_name}' ({count} occurrences)."
                    )

            if null_count > 0:
                anomalies.append(
                    f"Column '{raw_name}' has {null_count} nulls ({null_pct:.1f}%)."
                )
            if has_ragged_whitespace:
                anomalies.append(
                    f"Column '{raw_name}' contains ragged whitespace."
                )
            if has_mixed_dates:
                anomalies.append(
                    f"Column '{raw_name}' contains mixed date formats."
                )
            if raw_name != sanitized_name:
                anomalies.append(
                    f"Column '{raw_name}' required sanitization to '{sanitized_name}'."
                )

            col_prof = ColumnProfile(
                raw_name=raw_name,
                sanitized_name=sanitized_name,
                inferred_dtype=inferred_dtype,
                null_count=null_count,
                null_pct=null_pct,
                unique_count=unique_count,
                has_ragged_whitespace=has_ragged_whitespace,
                has_mixed_dates=has_mixed_dates,
                sample_values=sample_values,
            )
            column_profiles.append(col_prof)

        # 4. Deterministic Quality Score & Grade Calculation
        total_cells = max(1, sampled_rows * len(column_profiles))
        total_nulls = int(df.isna().sum().sum())
        null_rate = total_nulls / total_cells
        null_penalty = min(30, int(round(null_rate * 50)))

        dup_rate = duplicate_rows_in_sample / max(1, sampled_rows)
        dup_penalty = min(25, int(round(dup_rate * 50)))

        ragged_count = sum(1 for c in column_profiles if c.has_ragged_whitespace)
        ragged_penalty = min(20, ragged_count * 5)

        mixed_count = sum(1 for c in column_profiles if c.has_mixed_dates)
        mixed_dates_penalty = min(15, mixed_count * 5)

        bad_headers = sum(1 for c in column_profiles if c.raw_name != c.sanitized_name)
        bad_headers_penalty = min(15, bad_headers * 5)

        raw_score = 100 - null_penalty - dup_penalty - ragged_penalty - mixed_dates_penalty - bad_headers_penalty
        health_score = max(0, min(100, raw_score))

        if health_score >= 90:
            health_grade = "A"
        elif health_score >= 75:
            health_grade = "B"
        elif health_score >= 60:
            health_grade = "C"
        else:
            health_grade = "D"

        return DatasetProfile(
            file_path=str(path),
            file_name=path.name,
            sampled_rows=sampled_rows,
            estimated_total_rows=estimated_total_rows,
            duplicate_rows_in_sample=duplicate_rows_in_sample,
            health_score=health_score,
            health_grade=health_grade,
            pii_findings=pii_findings,
            columns=column_profiles,
            anomalies=anomalies,
        )

    def generate_heuristic_plan(
        self,
        profile: DatasetProfile,
        warning_message: Optional[str] = None
    ) -> ProposedCleaningPlan:
        """
        Pure deterministic fallback (0 LLM calls) emitting valid CleaningStep items
        for detected duplicates, ragged whitespace, null imputation, and mixed dates.
        """
        steps: List[CleaningStep] = []

        # 1. Strip whitespace on ragged columns
        ragged_cols = [c.raw_name for c in profile.columns if c.has_ragged_whitespace]
        if ragged_cols:
            steps.append(
                CleaningStep(
                    action="strip_whitespace",
                    params={"columns": ragged_cols},
                    reason=f"Strip ragged whitespace from {len(ragged_cols)} text columns."[:160]
                )
            )

        # 2. Deduplication
        if profile.duplicate_rows_in_sample > 0:
            steps.append(
                CleaningStep(
                    action="drop_duplicates",
                    params={},
                    reason=f"Drop duplicate rows ({profile.duplicate_rows_in_sample} detected in sample)."[:160]
                )
            )

        # 3. Numeric Null Imputation
        numeric_null_cols = [
            c.raw_name for c in profile.columns
            if c.null_count > 0 and c.inferred_dtype in ("INTEGER", "REAL", "NUMERIC")
        ]
        if numeric_null_cols:
            steps.append(
                CleaningStep(
                    action="impute_null",
                    params={"columns": numeric_null_cols, "strategy": "zero"},
                    reason=f"Impute numeric nulls with 0 across {len(numeric_null_cols)} columns."[:160]
                )
            )

        # 4. Text Null Imputation
        text_null_cols = [
            c.raw_name for c in profile.columns
            if c.null_count > 0 and c.inferred_dtype in ("TEXT", "STRING")
        ]
        if text_null_cols:
            steps.append(
                CleaningStep(
                    action="impute_null",
                    params={"columns": text_null_cols, "strategy": "constant", "value": "Unknown"},
                    reason=f"Impute text nulls with 'Unknown' across {len(text_null_cols)} columns."[:160]
                )
            )

        # 5. Mixed Dates Casting
        for c in profile.columns:
            if c.has_mixed_dates:
                steps.append(
                    CleaningStep(
                        action="cast_type",
                        params={"column": c.raw_name, "target_type": "datetime"},
                        reason=f"Cast mixed date column '{c.raw_name}' to standardized datetime."[:160]
                    )
                )

        # 6. Bad Column Header Renaming
        rename_map = {c.raw_name: c.sanitized_name for c in profile.columns if c.raw_name != c.sanitized_name}
        if rename_map:
            steps.append(
                CleaningStep(
                    action="rename_columns",
                    params={"mapping": rename_map},
                    reason=f"Sanitize {len(rename_map)} non-standard column headers."[:160]
                )
            )

        summary = (
            f"Deterministic heuristic cleaning plan with {len(steps)} steps "
            f"addressing data quality anomalies in {profile.file_name}."
        )

        return ProposedCleaningPlan(
            summary=summary,
            steps=steps,
            source="heuristic_fallback",
            model_used=None,
            warning_message=warning_message,
        )

    def propose_cleaning_plan(
        self,
        profile: DatasetProfile,
        llm_router: Optional[LLMRouter] = None
    ) -> ProposedCleaningPlan:
        """
        Builds a compact, 4 GB VRAM-friendly JSON-only prompt with PII-masked sample values,
        invokes the LLM router, validates every step against CleaningPlanExecutor contracts,
        and degrades gracefully to the deterministic heuristic plan on any failure.
        """
        if llm_router is None:
            return self.generate_heuristic_plan(profile)

        # Prepare compact schema payload (STRICTLY PII-masked)
        profile_metadata = {
            "file_name": profile.file_name,
            "sampled_rows": profile.sampled_rows,
            "estimated_total_rows": profile.estimated_total_rows,
            "duplicate_rows_in_sample": profile.duplicate_rows_in_sample,
            "health_score": profile.health_score,
            "health_grade": profile.health_grade,
            "anomalies": profile.anomalies,
            "columns": [
                {
                    "name": col.raw_name,
                    "inferred_dtype": col.inferred_dtype,
                    "null_count": col.null_count,
                    "null_pct": col.null_pct,
                    "unique_count": col.unique_count,
                    "has_ragged_whitespace": col.has_ragged_whitespace,
                    "has_mixed_dates": col.has_mixed_dates,
                    "sample_values_masked": col.sample_values,  # Guaranteed PII-masked
                }
                for col in profile.columns
            ]
        }

        system_prompt = (
            "You are the NEXUS Autonomous Data Cleaning Planner.\n"
            "Analyze the dataset profile and output ONLY a raw valid JSON object specifying data cleaning steps.\n\n"
            "STRICT ACTION WHITELIST (ONLY THESE 10 ACTIONS ARE ALLOWED):\n"
            "1. drop_columns: {\"columns\": [str]}\n"
            "2. rename_columns: {\"mapping\": {str: str}}\n"
            "3. cast_type: {\"column\": str, \"target_type\": \"integer\"|\"float\"|\"string\"|\"datetime\"|\"boolean\"}\n"
            "4. impute_null: {\"columns\": [str], \"strategy\": \"zero\"|\"constant\"|\"mean\"|\"median\"|\"mode\", \"value\": optional}\n"
            "5. drop_null_rows: {\"columns\": optional [str], \"how\": \"any\"|\"all\"}\n"
            "6. strip_whitespace: {\"columns\": [str]}\n"
            "7. case_transform: {\"columns\": [str], \"mode\": \"lower\"|\"upper\"|\"title\"}\n"
            "8. replace_value: {\"column\": str, \"to_replace\": any, \"value\": any}\n"
            "9. drop_duplicates: {\"subset\": optional [str]}\n"
            "10. clamp_range: {\"column\": str, \"min\": optional num, \"max\": optional num}\n\n"
            "RULES:\n"
            "- ZERO code execution (no python, eval, exec, calc, shell).\n"
            "- ONLY reference column names that exist in the profile.\n"
            "- Every step must include 'action', 'params', and 'reason' (max 160 chars).\n"
            "- Format output strictly as:\n"
            "{\n"
            '  "summary": "1-2 sentence overview",\n'
            '  "steps": [{"action": "...", "params": {...}, "reason": "..."}]\n'
            "}"
        )

        user_prompt = f"Dataset Profile:\n{json.dumps(profile_metadata, indent=2)}\n\nOutput JSON Cleaning Plan:"

        try:
            response = llm_router.invoke(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.0,
                json_mode=True
            )
            raw_content = response.content
        except (LLMRouterError, Exception) as exc:
            logger.warning(f"LLM invocation failed during cleaning plan synthesis: {exc}")
            return self.generate_heuristic_plan(
                profile,
                warning_message=f"LLM router unavailable ({type(exc).__name__}: {exc}). Deployed deterministic heuristic fallback."
            )

        # 1. Strip reasoning tags (<think>...</think>) from DeepSeek-R1 / Phi-4
        raw_content = re.sub(r'<think>.*?</think>', '', raw_content, flags=re.DOTALL).strip()

        # 2. Strip code fences
        raw_content = re.sub(r'^```(?:json)?\s*', '', raw_content)
        raw_content = re.sub(r'\s*```$', '', raw_content).strip()

        # 3. Extract JSON object
        json_match = re.search(r'\{.*\}', raw_content, re.DOTALL)
        if json_match:
            raw_content = json_match.group(0)

        # 4. Parse JSON
        try:
            parsed = json.loads(raw_content)
            if not isinstance(parsed, dict):
                raise ValueError("Parsed JSON root is not an object.")
        except Exception as exc:
            logger.warning(f"Failed to parse LLM JSON: {exc}. Content: {raw_content[:200]}")
            return self.generate_heuristic_plan(
                profile,
                warning_message=f"LLM returned malformed JSON: {exc}. Deployed deterministic heuristic fallback."
            )

        # 5. Security & Column Existence Validation
        existing_cols = {c.raw_name for c in profile.columns}
        raw_steps = parsed.get("steps", [])
        if not isinstance(raw_steps, list):
            raw_steps = []

        valid_steps: List[CleaningStep] = []
        for step_data in raw_steps:
            if not isinstance(step_data, dict):
                continue

            action = step_data.get("action")
            # Strict Action Whitelist Check
            if not action or action not in CleaningPlanExecutor.ALLOWED_ACTIONS:
                logger.warning(f"Adversarial or unknown action rejected: {action}")
                continue

            params = step_data.get("params", {})
            if not isinstance(params, dict):
                params = {}

            # Filter hallucinated column names
            clean_params = self._filter_params_columns(action, params, existing_cols)
            if clean_params is None:
                logger.warning(f"Step with action '{action}' omitted due to invalid/missing columns.")
                continue

            reason = str(step_data.get("reason", f"Automated {action} step."))[:160]
            try:
                valid_steps.append(
                    CleaningStep(action=action, params=clean_params, reason=reason)
                )
            except Exception as exc:
                logger.warning(f"Failed to instantiate CleaningStep: {exc}")
                continue

        if not valid_steps:
            logger.warning("No valid cleaning steps remained after validation. Reverting to heuristic plan.")
            return self.generate_heuristic_plan(
                profile,
                warning_message="LLM proposed no valid whitelisted steps. Deployed deterministic heuristic fallback."
            )

        model_name = getattr(response, "model", None) or getattr(response, "model_name", None)
        return ProposedCleaningPlan(
            summary=str(parsed.get("summary", "LLM-synthesized data cleaning plan.")),
            steps=valid_steps,
            source="llm",
            model_used=model_name,
            warning_message=None
        )

    @staticmethod
    def _filter_params_columns(
        action: str,
        params: Dict[str, Any],
        existing_cols: Set[str]
    ) -> Optional[Dict[str, Any]]:
        """
        Validates that any column names referenced in params actually exist
        in the profiled dataset, dropping invalid/hallucinated columns or returning None
        if the step is irrecoverable.
        """
        clean_params = dict(params)

        if action == "drop_columns":
            cols = [c for c in clean_params.get("columns", []) if c in existing_cols]
            if not cols:
                return None
            clean_params["columns"] = cols

        elif action == "rename_columns":
            mapping = clean_params.get("mapping", {})
            valid_mapping = {k: v for k, v in mapping.items() if k in existing_cols}
            if not valid_mapping:
                return None
            clean_params["mapping"] = valid_mapping

        elif action == "cast_type":
            col = clean_params.get("column")
            if col not in existing_cols:
                return None
            target = str(clean_params.get("target_type", "")).lower()
            if target not in (
                "integer", "int", "float", "real", "numeric",
                "string", "text", "str", "datetime", "timestamp", "boolean", "bool"
            ):
                clean_params["target_type"] = "string"

        elif action == "impute_null":
            cols = [c for c in clean_params.get("columns", []) if c in existing_cols]
            if not cols:
                return None
            clean_params["columns"] = cols
            strategy = str(clean_params.get("strategy", "constant")).lower()
            if strategy not in ("zero", "mean", "median", "mode", "constant"):
                clean_params["strategy"] = "constant"

        elif action == "drop_null_rows":
            if "columns" in clean_params and clean_params["columns"]:
                cols = [c for c in clean_params["columns"] if c in existing_cols]
                clean_params["columns"] = cols

        elif action == "strip_whitespace":
            if "columns" in clean_params and clean_params["columns"]:
                cols = [c for c in clean_params["columns"] if c in existing_cols]
                if not cols:
                    return None
                clean_params["columns"] = cols

        elif action == "case_transform":
            cols = [c for c in clean_params.get("columns", []) if c in existing_cols]
            if not cols:
                return None
            clean_params["columns"] = cols
            mode = str(clean_params.get("mode", "lower")).lower()
            if mode not in ("lower", "upper", "title"):
                clean_params["mode"] = "lower"

        elif action == "replace_value":
            col = clean_params.get("column")
            if col not in existing_cols:
                return None

        elif action == "drop_duplicates":
            if "subset" in clean_params and clean_params["subset"]:
                cols = [c for c in clean_params["subset"] if c in existing_cols]
                clean_params["subset"] = cols

        elif action == "clamp_range":
            col = clean_params.get("column")
            if col not in existing_cols:
                return None

        return clean_params
