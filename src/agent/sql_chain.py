"""
NEXUS Engine - Autonomous Text-to-SQL Agent Pipeline
===================================================
Architecture Role: Schema-injected, self-healing Text-to-SQL reasoning chain
coordinating prompt assembly, 8-layer QueryGuard validation, execution,
bounded error repair, natural-language synthesis, and declarative visualization.

Security & Execution Invariants:
1. QueryGuard 8-Layer Security Gate: Zero-retry immediate abort on any detected
   mutation (INSERT, UPDATE, DELETE, DROP, ALTER, PRAGMA, ATTACH).
2. Engine-Enforced Read-Only: All queries execute with PRAGMA query_only = ON.
3. Bounded Self-Healing: Non-security syntax or column errors are retried up to
   max_repair_attempts (default: 2) with SQLite error diagnostics fed back to the LLM.
4. Empty DB Short-Circuit: Zero LLM calls when database has 0 tables.
5. Context Budget Protection: Result sets are clamped to 25 rows with string-length
   capping prior to synthesis to prevent local LLM context overflow.
6. Declarative Visualizations: Detects chart intent and emits safe ChartSpecs.

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import dataclasses
import json
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Union

from langchain_core.messages import HumanMessage, SystemMessage

# Core NEXUS dependencies
from src.agent.chart_engine import ChartEngine, ChartSpec, ChartValidationError
from src.agent.llm_router import LLMResponse, LLMRouter, LLMRouterError
from src.core.db_manager import (
    DatabaseError,
    DatabaseManager,
    QueryExecutionError,
    QueryResult,
    ReadOnlyViolationError,
)
from src.core.query_guard import QueryGuard, SecurityException, guard_query
from src.core.schema_parser import SchemaParser

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger("NEXUS-SQLAgent")  # type: ignore


# ==============================================================================
# SQL EXTRACTION UTILITIES
# ==============================================================================

def extract_sql_from_response(raw_text: str) -> str:
    """
    Extracts a clean, single SQL query string from heterogeneous LLM outputs.
    Handles ```sql fences, generic fences, JSON dicts, and raw SQL blocks.
    """
    if not raw_text or not raw_text.strip():
        return ""
    text = raw_text.strip()

    # 0. Strip reasoning-model <think>...</think> blocks
    text = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()
    if not text:
        return ""

    # 1. Match ```sql ... ```
    sql_fence = re.search(r"```sql\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if sql_fence:
        return sql_fence.group(1).strip()

    # 2. Match generic ``` ... ```
    generic_fence = re.search(r"```\s*([\s\S]*?)\s*```", text)
    if generic_fence:
        fenced_content = generic_fence.group(1).strip()
        if any(fenced_content.upper().startswith(kw) for kw in ("SELECT", "WITH")):
            return fenced_content

    # 3. Match JSON payload {"sql": "..."}
    try:
        json_match = re.search(r"\{[\s\S]*?\}", text)
        if json_match:
            parsed = json.loads(json_match.group(0))
            if isinstance(parsed, dict) and "sql" in parsed:
                return str(parsed["sql"]).strip()
    except Exception:
        pass

    # 4. Search for SELECT or WITH keyword in raw text
    sql_keyword_match = re.search(r"\b(SELECT|WITH)\b[\s\S]*", text, re.IGNORECASE)
    if sql_keyword_match:
        cand = sql_keyword_match.group(0).strip()
        cand = re.sub(r"```.*$", "", cand, flags=re.DOTALL).strip()
        return cand

    return text


# ==============================================================================
# AGENT RESULT CONTAINER
# ==============================================================================

@dataclasses.dataclass(frozen=True)
class AgentRunResult:
    """Immutable record capturing the complete lifecycle of an Agent execution run."""
    natural_query: str
    generated_sql: str
    query_result: Optional[QueryResult]
    answer_markdown: str
    chart_spec: Optional[ChartSpec] = None
    status: str = "SUCCESS"  # "SUCCESS", "SECURITY_BLOCKED", "SQL_FAILED", "LLM_ERROR", "EMPTY_DB"
    repair_attempts: int = 0
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    provider: str = ""
    model: str = ""
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert agent result to a dictionary for telemetry and UI display."""
        return {
            "natural_query": self.natural_query,
            "generated_sql": self.generated_sql,
            "row_count": self.query_result.row_count if self.query_result else 0,
            "answer_markdown": self.answer_markdown,
            "chart_spec": self.chart_spec.model_dump() if self.chart_spec else None,
            "status": self.status,
            "repair_attempts": self.repair_attempts,
            "total_tokens": self.total_tokens,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "provider": self.provider,
            "model": self.model,
            "error_message": self.error_message,
        }


# ==============================================================================
# AUTONOMOUS SQL AGENT CHAIN
# ==============================================================================

class SQLAgentChain:
    """
    End-to-end Autonomous Text-to-SQL Agent.
    Transforms natural language into guarded SQLite queries with self-healing
    repair loops and automated insight synthesis.
    """

    CHART_INTENT_KEYWORDS: Set[str] = {
        "chart", "plot", "graph", "visualiz", "visualization",
        "bar", "line", "pie", "scatter", "hist", "histogram", "trend"
    }

    def __init__(
        self,
        db_manager: DatabaseManager,
        schema_parser: SchemaParser,
        llm_router: LLMRouter,
        max_repair_attempts: int = 2
    ) -> None:
        self.db = db_manager
        self.parser = schema_parser
        self.router = llm_router
        self.max_repair_attempts = max_repair_attempts

    def run(
        self,
        natural_query: str,
        include_samples: bool = False,
        request_chart: Optional[bool] = None,
        progress_callback: Optional[Callable[[str], None]] = None
    ) -> AgentRunResult:
        """
        Executes the autonomous analytical loop for a natural language inquiry.

        Stages:
        1. Empty Database Check (short-circuit).
        2. Schema Context Assembly.
        3. Initial SQL Generation via LLM.
        4. QueryGuard 8-Layer Security Filter (0 retries on violation).
        5. Execution & Bounded Self-Healing Repair Loop.
        6. Executive Insight Generation.
        7. Declarative ChartSpec Synthesis (if requested).
        """
        t0 = time.perf_counter()
        total_tokens = 0
        total_latency_ms = 0.0
        provider = self.router.config.provider
        model = self.router.config.model

        clean_query = natural_query.strip()
        if not clean_query:
            return AgentRunResult(
                natural_query="",
                generated_sql="",
                query_result=None,
                answer_markdown="Please provide a valid question or analytical prompt.",
                status="SQL_FAILED",
                provider=provider,
                model=model,
                error_message="Empty prompt provided"
            )

        # ----------------------------------------------------------------------
        # Stage 1: Empty Database Short-Circuit (0 LLM calls)
        # ----------------------------------------------------------------------
        stats = self.parser.get_summary_stats()
        if stats.get("table_count", 0) == 0:
            if progress_callback:
                progress_callback("Database empty. Aborting with zero LLM calls.")
            return AgentRunResult(
                natural_query=clean_query,
                generated_sql="",
                query_result=None,
                answer_markdown=(
                    "⚠️ **Workspace Database Empty**\n\n"
                    "No tables found in the active workspace. Please ingest a dataset "
                    "(CSV, TSV, or XLSX) via the Sidebar before asking questions."
                ),
                status="EMPTY_DB",
                provider=provider,
                model=model
            )

        # ----------------------------------------------------------------------
        # Stage 2: Schema Context Assembly
        # ----------------------------------------------------------------------
        if progress_callback:
            progress_callback("Assembling relational schema context...")
        schema_markdown = self.parser.generate_markdown(
            include_samples=include_samples,
            use_cache=not include_samples
        )

        # ----------------------------------------------------------------------
        # Stage 3: Initial SQL Synthesis
        # ----------------------------------------------------------------------
        if progress_callback:
            progress_callback(f"Synthesizing SQLite query via {model}...")

        system_instruction = (
            "You are an expert SQLite data analyst and read-only Text-to-SQL engineer.\n"
            "Given the relational database schema below, generate a single valid, optimized SQLite3 query "
            "that answers the user's natural language question.\n\n"
            "STRICT RULES:\n"
            "1. Output SQLite3 SELECT statements or read-only CTEs (WITH ... SELECT) ONLY.\n"
            "2. NEVER output mutating queries (INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, ATTACH, DETACH, PRAGMA, VACUUM, TRUNCATE).\n"
            "3. Always wrap the SQL query inside ```sql ... ``` code fences.\n"
            "4. Return ONLY the SQL query with zero conversational preamble.\n\n"
            f"DATABASE RELATIONAL SCHEMA:\n{schema_markdown}\n"
        )

        messages = [
            SystemMessage(content=system_instruction),
            HumanMessage(content=clean_query)
        ]

        try:
            llm_resp = self.router.invoke(messages, temperature=0.0)
            total_tokens += llm_resp.total_tokens
            total_latency_ms += llm_resp.latency_ms
        except Exception as llm_err:
            logger.error(f"LLM invocation failed: {llm_err}")
            return AgentRunResult(
                natural_query=clean_query,
                generated_sql="",
                query_result=None,
                answer_markdown=f"❌ **AI Provider Error**: {llm_err}",
                status="LLM_ERROR",
                total_tokens=total_tokens,
                total_latency_ms=total_latency_ms,
                provider=provider,
                model=model,
                error_message=str(llm_err)
            )

        raw_sql = extract_sql_from_response(llm_resp.content)

        # ----------------------------------------------------------------------
        # Stage 4: QueryGuard Security Filter (Zero Retries on Violation)
        # ----------------------------------------------------------------------
        if progress_callback:
            progress_callback("Running QueryGuard 8-layer security inspection...")

        try:
            safe_sql = guard_query(raw_sql)
        except SecurityException as sec_exc:
            logger.warning(
                f"[SECURITY BLOCKED] QueryGuard intercepted adversarial query: {sec_exc}. "
                f"Aborting immediately with zero retries."
            )
            self.db.log_audit_event(
                natural_query=clean_query,
                generated_sql=raw_sql,
                status="REJECTED",
                error_message=str(sec_exc)
            )
            return AgentRunResult(
                natural_query=clean_query,
                generated_sql=raw_sql,
                query_result=None,
                answer_markdown=(
                    f"🛡️ **Security Policy Enforcement**\n\n"
                    f"The synthesized SQL query was blocked by QueryGuard: **{sec_exc}**.\n\n"
                    f"Blocked SQL:\n```sql\n{raw_sql}\n```"
                ),
                status="SECURITY_BLOCKED",
                repair_attempts=0,
                total_tokens=total_tokens,
                total_latency_ms=total_latency_ms,
                provider=provider,
                model=model,
                error_message=str(sec_exc)
            )

        # ----------------------------------------------------------------------
        # Stage 5: Execution & Bounded Self-Healing Repair Loop
        # ----------------------------------------------------------------------
        current_sql = safe_sql
        repair_attempts = 0
        query_result: Optional[QueryResult] = None

        while True:
            try:
                if progress_callback:
                    progress_callback("Executing verified read-only SQL...")
                query_result = self.db.execute_query(current_sql, read_only=True)
                break  # Execution successful

            except ReadOnlyViolationError as ro_exc:
                # Engine-level mutation violation -> ABORT (0 retries)
                logger.error(f"Read-only engine violation: {ro_exc}")
                self.db.log_audit_event(
                    natural_query=clean_query,
                    generated_sql=current_sql,
                    status="REJECTED",
                    error_message=str(ro_exc)
                )
                return AgentRunResult(
                    natural_query=clean_query,
                    generated_sql=current_sql,
                    query_result=None,
                    answer_markdown=f"🛡️ **Engine Security Violation**: Attempted write operation on read-only database.",
                    status="SECURITY_BLOCKED",
                    repair_attempts=repair_attempts,
                    total_tokens=total_tokens,
                    total_latency_ms=total_latency_ms,
                    provider=provider,
                    model=model,
                    error_message=str(ro_exc)
                )

            except QueryExecutionError as qe_exc:
                if repair_attempts < self.max_repair_attempts:
                    repair_attempts += 1
                    if progress_callback:
                        progress_callback(
                            f"Repairing SQL syntax/column error (Attempt {repair_attempts}/{self.max_repair_attempts})..."
                        )

                    repair_system = (
                        "You are an expert SQLite engineer repairing an erroneous SQL query.\n"
                        f"Database Schema:\n{schema_markdown}\n\n"
                        f"Failed SQL Query:\n{current_sql}\n\n"
                        f"SQLite Error Message:\n{qe_exc}\n\n"
                        "Rules:\n"
                        "1. Return ONLY the corrected SQLite SELECT statement wrapped in ```sql ... ```.\n"
                        "2. Ensure all referenced table and column names exactly match the schema above."
                    )
                    repair_messages = [
                        SystemMessage(content=repair_system),
                        HumanMessage(content=f"Fix this query to answer: '{clean_query}'")
                    ]

                    try:
                        repair_resp = self.router.invoke(repair_messages, temperature=0.0)
                        total_tokens += repair_resp.total_tokens
                        total_latency_ms += repair_resp.latency_ms
                    except Exception as err:
                        logger.error(f"Repair LLM invocation failed: {err}")
                        break

                    repaired_raw = extract_sql_from_response(repair_resp.content)

                    # Validate repaired query through QueryGuard
                    try:
                        current_sql = guard_query(repaired_raw)
                    except SecurityException as sec_exc:
                        self.db.log_audit_event(clean_query, repaired_raw, status="REJECTED", error_message=str(sec_exc))
                        return AgentRunResult(
                            natural_query=clean_query,
                            generated_sql=repaired_raw,
                            query_result=None,
                            answer_markdown=f"🛡️ **Security Block**: Repaired query violates security rules: {sec_exc}",
                            status="SECURITY_BLOCKED",
                            repair_attempts=repair_attempts,
                            total_tokens=total_tokens,
                            total_latency_ms=total_latency_ms,
                            provider=provider,
                            model=model,
                            error_message=str(sec_exc)
                        )
                    continue

                # Repair attempts exhausted
                logger.error(f"SQL execution failed after {repair_attempts} repairs: {qe_exc}")
                self.db.log_audit_event(clean_query, current_sql, status="FAILED", error_message=str(qe_exc))
                return AgentRunResult(
                    natural_query=clean_query,
                    generated_sql=current_sql,
                    query_result=None,
                    answer_markdown=f"❌ **SQL Execution Failed** after {repair_attempts} self-healing attempt(s): {qe_exc}",
                    status="SQL_FAILED",
                    repair_attempts=repair_attempts,
                    total_tokens=total_tokens,
                    total_latency_ms=total_latency_ms,
                    provider=provider,
                    model=model,
                    error_message=str(qe_exc)
                )

        # Log audit event for successful execution
        self.db.log_audit_event(clean_query, current_sql, status="SUCCESS")

        # ----------------------------------------------------------------------
        # Stage 6: Executive Insight Synthesis
        # ----------------------------------------------------------------------
        if progress_callback:
            progress_callback("Synthesizing executive insight from query results...")

        # Construct compact preview (max 25 rows with truncated strings)
        preview_rows = query_result.rows[:25]
        cleaned_preview = [
            [str(v)[:40] if isinstance(v, str) and len(v) > 40 else v for v in row]
            for row in preview_rows
        ]

        summary_prompt = (
            f"User Question: {clean_query}\n"
            f"Executed SQL: {current_sql}\n"
            f"Columns: {query_result.columns}\n"
            f"Total Matching Rows: {query_result.row_count}\n"
            f"Sample Data (up to 25 rows): {cleaned_preview}\n\n"
            "Provide a concise, direct analytical answer answering the user's question "
            "based on the query results. Use clean markdown formatting."
        )

        try:
            insight_resp = self.router.generate(
                prompt=summary_prompt,
                system_prompt="You are a senior data analyst. Synthesize a direct, factual markdown explanation of data findings."
            )
            total_tokens += insight_resp.total_tokens
            total_latency_ms += insight_resp.latency_ms
            answer_markdown = insight_resp.content.strip()
        except Exception as exc:
            logger.warning(f"Executive insight generation failed: {exc}")
            answer_markdown = (
                f"Query executed successfully with **{query_result.row_count}** row(s) returned.\n\n"
                f"SQL: `{current_sql}`"
            )

        # ----------------------------------------------------------------------
        # Stage 7: Declarative ChartSpec Generation
        # ----------------------------------------------------------------------
        chart_spec: Optional[ChartSpec] = None
        has_chart_keyword = any(kw in clean_query.lower() for kw in self.CHART_INTENT_KEYWORDS)
        wants_chart = request_chart if request_chart is not None else has_chart_keyword

        if wants_chart and query_result.row_count > 0 and len(query_result.columns) >= 1:
            if progress_callback:
                progress_callback("Synthesizing declarative analytical ChartSpec...")

            chart_prompt = (
                f"User Question: {clean_query}\n"
                f"Available Columns: {query_result.columns}\n"
                f"Sample Records: {cleaned_preview[:5]}\n\n"
                "Return a JSON ChartSpec choosing the best chart_type ('bar', 'line', 'scatter', 'pie', 'hist'), "
                "setting 'x_column', 'y_column', 'title', and optional 'x_label', 'y_label'. "
                "Columns must exist in Available Columns."
            )

            try:
                chart_resp = self.router.generate(
                    prompt=chart_prompt,
                    system_prompt=(
                        "Return ONLY a single valid JSON object matching the ChartSpec schema: "
                        "{\"chart_type\": ..., \"x_column\": ..., \"y_column\": ..., \"title\": ...}."
                    ),
                    json_mode=True
                )
                total_tokens += chart_resp.total_tokens
                total_latency_ms += chart_resp.latency_ms
                chart_spec = ChartEngine.parse_chart_spec(chart_resp.content, query_result.columns)
            except Exception as chart_err:
                logger.warning(f"Chart specification synthesis degraded gracefully: {chart_err}")
                chart_spec = None

        if progress_callback:
            progress_callback("Execution pipeline completed.")

        return AgentRunResult(
            natural_query=clean_query,
            generated_sql=current_sql,
            query_result=query_result,
            answer_markdown=answer_markdown,
            chart_spec=chart_spec,
            status="SUCCESS",
            repair_attempts=repair_attempts,
            total_tokens=total_tokens,
            total_latency_ms=total_latency_ms,
            provider=provider,
            model=model
        )
