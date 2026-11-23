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
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

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
# CONVERSATION MEMORY & AGENT CONTAINERS
# ==============================================================================

@dataclasses.dataclass(frozen=True)
class ConversationTurn:
    """Represents a single verified turn in an ongoing analytical conversation."""
    natural_query: str
    generated_sql: str
    answer_summary: str  # compact summary truncated to <= 240 chars
    tables_used: Tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class AgentRunResult:
    """Immutable record capturing the complete lifecycle of an Agent execution run."""
    natural_query: str
    generated_sql: str
    query_result: Optional[QueryResult] = None
    answer_markdown: str = ""
    chart_spec: Optional[ChartSpec] = None
    status: str = "SUCCESS"  # "SUCCESS", "SECURITY_BLOCKED", "SQL_FAILED", "LLM_ERROR", "EMPTY_DB"
    repair_attempts: int = 0
    total_tokens: int = 0
    total_latency_ms: float = 0.0
    provider: str = ""
    model: str = ""
    error_message: Optional[str] = None
    tables_in_context: Tuple[str, ...] = ()
    was_pruned: bool = False

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
            "tables_in_context": list(self.tables_in_context),
            "was_pruned": self.was_pruned,
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
        max_repair_attempts: int = 2,
        max_schema_tables: int = 8,
        max_history_turns: int = 4
    ) -> None:
        self.db = db_manager
        self.parser = schema_parser
        self.schema_parser = schema_parser
        self.router = llm_router
        self.max_repair_attempts = max_repair_attempts
        self.max_schema_tables = max_schema_tables
        self.max_history_turns = max_history_turns

    def run(
        self,
        natural_query: str,
        include_samples: bool = False,
        request_chart: Optional[bool] = None,
        progress_callback: Optional[Callable[[str], None]] = None,
        conversation_history: Optional[List[ConversationTurn]] = None
    ) -> AgentRunResult:
        """
        Executes the autonomous analytical loop for a natural language inquiry.

        Stages:
        1. Empty Database Check (short-circuit).
        2. Schema Context Assembly & Pruning.
        3. Initial SQL Generation via LLM (with bounded conversation memory).
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
                error_message="Empty prompt provided",
                tables_in_context=(),
                was_pruned=False
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
                model=model,
                tables_in_context=(),
                was_pruned=False
            )

        # ----------------------------------------------------------------------
        # Stage 2: Schema Context Assembly & Smart Pruning
        # ----------------------------------------------------------------------
        if progress_callback:
            progress_callback("Assembling relational schema context...")

        all_tables = self.parser.get_table_names()
        was_pruned = False
        if len(all_tables) > self.max_schema_tables:
            was_pruned = True
            pruning_query = clean_query
            if conversation_history:
                last_turn = conversation_history[-1]
                pruning_query = f"{clean_query} {last_turn.natural_query} {last_turn.generated_sql}"

            selected_tables = self.parser.select_relevant_tables(
                pruning_query,
                max_tables=self.max_schema_tables
            )
            tables_in_context = tuple(selected_tables)
            schema_markdown = self.parser.generate_markdown(
                tables=selected_tables,
                include_samples=include_samples,
                use_cache=False
            )
        else:
            tables_in_context = tuple(all_tables)
            schema_markdown = self.parser.generate_markdown(
                include_samples=include_samples,
                use_cache=not include_samples
            )

        # ----------------------------------------------------------------------
        # Stage 3: Initial SQL Synthesis
        # ----------------------------------------------------------------------
        if progress_callback:
            progress_callback(f"Synthesizing SQLite query via {model}...")

        recent_history = (conversation_history or [])[-self.max_history_turns:]
        history_context = ""
        if recent_history:
            history_lines = []
            start_num = len(conversation_history or []) - len(recent_history) + 1
            for i, turn in enumerate(recent_history, start=start_num):
                summary_snip = (turn.answer_summary or "").replace("\n", " ").strip()
                if len(summary_snip) > 240:
                    summary_snip = summary_snip[:237] + "..."
                history_lines.append(
                    f'Turn {i}: User asked: "{turn.natural_query}" | SQL: "{turn.generated_sql}" | Summary: "{summary_snip}"'
                )
            history_context = (
                "\n\nPREVIOUS CONVERSATION CONTEXT (Most Recent Turns):\n"
                + "\n".join(history_lines)
                + "\nUse this history to resolve pronouns, filter refinements, and follow-up aggregations."
            )

        system_instruction = (
            "You are an expert SQLite data analyst and read-only Text-to-SQL engineer.\n"
            "Given the relational database schema below, generate a single valid, optimized SQLite3 query "
            "that answers the user's natural language question.\n\n"
            "STRICT RULES:\n"
            "1. Output SQLite3 SELECT statements or read-only CTEs (WITH ... SELECT) ONLY.\n"
            "2. NEVER output mutating queries (INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, ATTACH, DETACH, PRAGMA, VACUUM, TRUNCATE).\n"
            "3. Always wrap the SQL query inside ```sql ... ``` code fences.\n"
            "4. Return ONLY the SQL query with zero conversational preamble.\n\n"
            f"DATABASE RELATIONAL SCHEMA:\n{schema_markdown}"
            f"{history_context}\n"
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
                error_message=str(llm_err),
                tables_in_context=tables_in_context,
                was_pruned=was_pruned
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
                error_message=str(sec_exc),
                tables_in_context=tables_in_context,
                was_pruned=was_pruned
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
                    error_message=str(ro_exc),
                    tables_in_context=tables_in_context,
                    was_pruned=was_pruned
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
                            error_message=str(sec_exc),
                            tables_in_context=tables_in_context,
                            was_pruned=was_pruned
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
                    error_message=str(qe_exc),
                    tables_in_context=tables_in_context,
                    was_pruned=was_pruned
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
            model=model,
            tables_in_context=tables_in_context,
            was_pruned=was_pruned
        )


# ==============================================================================
# ZERO-LLM STARTER QUESTION GENERATION
# ==============================================================================

def generate_starter_questions(schema_parser: SchemaParser, max_questions: int = 3) -> List[str]:
    """
    Deterministically generates up to `max_questions` natural, table-specific analytical
    questions using pure Python heuristics with zero LLM calls.

    Inspects up to the top 3 tables (prioritizing largest row count).
    Identifies numeric (INTEGER/REAL non-ID), categorical (TEXT), and date/timestamp columns.
    Emits up to max_questions natural prompts (aggregation + bar chart prompt,
    time-trend line chart or distribution, top-N ranking).
    Returns [] cleanly if the database has 0 tables.
    """
    table_names = schema_parser.get_table_names()
    if not table_names:
        return []

    tables_info = schema_parser.get_schema_info()
    if not tables_info:
        return []

    # Sort tables prioritizing largest estimated_rows descending, then name ascending
    sorted_tables = sorted(tables_info, key=lambda t: (t.estimated_rows, -len(t.name)), reverse=True)
    top_tables = sorted_tables[:3]

    questions: List[str] = []

    ID_PATTERN = re.compile(r"(^id$|_id$|uuid|guid|key$|^pk_)", re.IGNORECASE)
    DATE_PATTERN = re.compile(r"(date|time|created|timestamp|updated|period|year|month|day)", re.IGNORECASE)

    for table in top_tables:
        if len(questions) >= max_questions:
            break

        numeric_cols: List[str] = []
        categorical_cols: List[str] = []
        date_cols: List[str] = []

        for col in table.columns:
            c_name = col.name
            c_type = (col.data_type or "").upper()

            # Skip primary keys / ID columns for metrics
            if col.is_primary_key or ID_PATTERN.search(c_name):
                continue

            if DATE_PATTERN.search(c_name) or any(t in c_type for t in ("DATE", "TIME", "TIMESTAMP")):
                date_cols.append(c_name)
            elif any(t in c_type for t in ("INT", "REAL", "FLOAT", "DOUBLE", "NUMERIC", "DECIMAL")):
                numeric_cols.append(c_name)
            elif any(t in c_type for t in ("TEXT", "CHAR", "VARCHAR", "CLOB")):
                categorical_cols.append(c_name)

        t_name = table.name

        # 1. Aggregation + bar chart prompt
        if numeric_cols and categorical_cols:
            num = numeric_cols[0]
            cat = categorical_cols[0]
            q1 = f"Show a bar chart of total {num} by {cat}"
            if q1 not in questions:
                questions.append(q1)

        # 2. Time-trend line chart or distribution prompt
        if len(questions) < max_questions:
            if numeric_cols and date_cols:
                num = numeric_cols[0]
                dt = date_cols[0]
                q2 = f"Show monthly trend of {num} over {dt} as a line chart"
                if q2 not in questions:
                    questions.append(q2)
            elif date_cols:
                dt = date_cols[0]
                q2 = f"How many records were created per {dt}?"
                if q2 not in questions:
                    questions.append(q2)

        # 3. Top-N ranking prompt
        if len(questions) < max_questions:
            if numeric_cols and categorical_cols:
                num = numeric_cols[-1]
                cat = categorical_cols[-1]
                q3 = f"What are the top 5 {cat} by {num}?"
                if q3 not in questions:
                    questions.append(q3)
            elif categorical_cols:
                cat = categorical_cols[0]
                q3 = f"What are the most frequent {cat} in {t_name}?"
                if q3 not in questions:
                    questions.append(q3)
            elif numeric_cols:
                num = numeric_cols[0]
                q3 = f"What is the average {num} across all {t_name}?"
                if q3 not in questions:
                    questions.append(q3)

    # Fallback to general table queries if questions still needed
    if len(questions) < max_questions:
        for table in top_tables:
            if len(questions) >= max_questions:
                break
            q_fallback = f"Show the first 10 records from {table.name}"
            if q_fallback not in questions:
                questions.append(q_fallback)

    return questions[:max_questions]
