"""
NEXUS Engine - Real-Time Telemetry & Security HUD Tab
=====================================================
Architecture Role: Operational command center displaying live system telemetry,
p95/avg latency metrics, security deflection statistics, an interactive
SQL injection attack simulation harness, and the persistent query audit ledger.

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / CustomTkinter
"""

from __future__ import annotations

import io
import random
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import customtkinter

# Resilient logging initialization
try:
    from loguru import logger
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("NEXUS-TelemetryHUD")  # type: ignore

from src.core.db_manager import DatabaseManager
from src.core.query_guard import QueryGuard, SecurityException, guard_query
from src.ui.async_worker import AsyncWorkerManager
from src.ui.theme import NexusTheme


class TelemetryHudTab(customtkinter.CTkFrame):
    """
    Futurized telemetry dashboard and security monitoring cockpit.

    Key Features:
    1. 4 Futuristic Cyber KPI Metric Cards (Total Queries, P95 Latency, Avg Latency, Security Blocks).
    2. Interactive 'Simulate SQLi Attack' live demonstration suite.
    3. Live audit ledger viewer reflecting disk-persisted _nexus_query_audit records.
    4. Zero-thread-blocking asynchronous telemetry polling.
    """

    ADVERSARIAL_PAYLOADS: List[Tuple[str, str]] = [
        ("Multi-Statement Drop", "SELECT 1; DROP TABLE _nexus_metadata;"),
        ("Destructive CTE Mutation", "WITH d AS (DELETE FROM _nexus_query_audit) SELECT * FROM d;"),
        ("Engine Pragma Exploit", "PRAGMA writable_schema = 1;"),
        ("Database File Attachment", "ATTACH DATABASE 'malicious.db' AS evil;"),
        ("Stacked Truncate", "SELECT * FROM users; TRUNCATE TABLE logs;"),
        ("Nested Subquery Injection", "SELECT * FROM (INSERT INTO logs VALUES ('probe'));"),
        ("System Table Poisoning", "UPDATE sqlite_master SET sql = 'DROP';"),
        ("Admin Vacuum Exploit", "VACUUM INTO 'exfil.db';"),
    ]

    def __init__(
        self,
        master: Any,
        db_manager: Optional[DatabaseManager] = None,
        async_worker: Optional[AsyncWorkerManager] = None,
        **kwargs: Any
    ) -> None:
        worker = async_worker or kwargs.pop("worker_manager", None)
        super().__init__(
            master,
            fg_color=NexusTheme.BG_OBSIDIAN,
            corner_radius=0,
            **kwargs
        )

        self.db = db_manager or DatabaseManager()
        self.worker = worker

        self._build_ui()

        # Property aliases for full cross-module compatibility
        self.total_q_lbl = self.val_total_queries
        self.p95_lbl = self.val_p95_latency
        self.avg_lbl = self.val_avg_latency
        self.blocks_lbl = self.val_security_blocks
        self.refresh_metrics = self.refresh_hud
        self.refresh_audit_ledger = self.refresh_hud
        self.audit_textbox = self.ledger_textbox

        self.refresh_hud()

    # --------------------------------------------------------------------------
    # UI CONSTRUCTION
    # --------------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Assembles the HUD layout: header bar, KPI cards, attack harness, and ledger."""
        self.grid_rowconfigure(3, weight=1)  # Ledger viewer expands
        self.grid_columnconfigure(0, weight=1)

        # 1. Header & Controls Bar
        self._build_header_bar()

        # 2. KPI Metrics Grid (4 Cards)
        self._build_kpi_cards()

        # 3. Interactive Attack Simulator Harness
        self._build_attack_simulator()

        # 4. Live Audit Ledger View
        self._build_ledger_viewer()

    def _build_header_bar(self) -> None:
        header_frame = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        header_frame.grid(row=0, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(NexusTheme.PADDING_MD, 8))
        header_frame.grid_columnconfigure(0, weight=1)

        title_lbl = customtkinter.CTkLabel(
            header_frame,
            text="TELEMETRY & SECURITY MONITORING COCKPIT",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.TEXT_SECONDARY
        )
        title_lbl.grid(row=0, column=0, sticky="w", padx=NexusTheme.PADDING_MD, pady=NexusTheme.PADDING_SM)

        self.refresh_btn = customtkinter.CTkButton(
            header_frame,
            text="↻ Refresh HUD",
            width=100,
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.ACCENT_CYAN_MUTED,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self.refresh_hud
        )
        self.refresh_btn.grid(row=0, column=1, sticky="e", padx=NexusTheme.PADDING_MD, pady=NexusTheme.PADDING_SM)

    def _build_kpi_cards(self) -> None:
        cards_grid = customtkinter.CTkFrame(self, fg_color="transparent")
        cards_grid.grid(row=1, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=8)

        # Configure 4 equal-width columns
        for col in range(4):
            cards_grid.grid_columnconfigure(col, weight=1)

        # Card 1: Total Queries
        self.val_total_queries, card_1 = self._create_metric_card(
            cards_grid,
            title="TOTAL QUERIES",
            initial_value="0",
            accent_color=NexusTheme.ACCENT_CYAN
        )
        card_1.grid(row=0, column=0, sticky="ew", padx=(0, 6), pady=0)

        # Card 2: P95 Latency
        self.val_p95_latency, card_2 = self._create_metric_card(
            cards_grid,
            title="P95 LATENCY",
            initial_value="0.00 ms",
            accent_color=NexusTheme.STATUS_EMERALD
        )
        card_2.grid(row=0, column=1, sticky="ew", padx=3, pady=0)

        # Card 3: Avg Latency
        self.val_avg_latency, card_3 = self._create_metric_card(
            cards_grid,
            title="AVG LATENCY",
            initial_value="0.00 ms",
            accent_color=NexusTheme.STATUS_AMBER
        )
        card_3.grid(row=0, column=2, sticky="ew", padx=3, pady=0)

        # Card 4: Security Blocks & Errors
        self.val_security_blocks, card_4 = self._create_metric_card(
            cards_grid,
            title="SECURITY BLOCKS / ERRORS",
            initial_value="0",
            accent_color=NexusTheme.STATUS_CRIMSON
        )
        card_4.grid(row=0, column=3, sticky="ew", padx=(6, 0), pady=0)

    def _create_metric_card(
        self,
        parent: Any,
        title: str,
        initial_value: str,
        accent_color: str
    ) -> Tuple[customtkinter.CTkLabel, customtkinter.CTkFrame]:
        card = customtkinter.CTkFrame(
            parent,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )

        title_lbl = customtkinter.CTkLabel(
            card,
            text=title,
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_MUTED,
            anchor="w"
        )
        title_lbl.pack(anchor="w", padx=NexusTheme.PADDING_SM, pady=(NexusTheme.PADDING_SM, 2))

        val_lbl = customtkinter.CTkLabel(
            card,
            text=initial_value,
            font=("Segoe UI", 20, "bold"),
            text_color=accent_color,
            anchor="w"
        )
        val_lbl.pack(anchor="w", padx=NexusTheme.PADDING_SM, pady=(0, NexusTheme.PADDING_SM))

        return val_lbl, card

    def _build_attack_simulator(self) -> None:
        harness_frame = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        harness_frame.grid(row=2, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=8)
        harness_frame.grid_columnconfigure(2, weight=1)

        payload_names = [p[0] for p in self.ADVERSARIAL_PAYLOADS]
        self.payload_dropdown = customtkinter.CTkOptionMenu(
            harness_frame,
            values=payload_names,
            font=NexusTheme.FONT_SMALL,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            button_color=NexusTheme.ACCENT_CYAN_MUTED,
            button_hover_color=NexusTheme.ACCENT_CYAN,
            text_color=NexusTheme.TEXT_PRIMARY,
            command=self._on_payload_selected
        )
        self.payload_dropdown.set(payload_names[0])
        self.payload_dropdown.grid(row=0, column=0, padx=(NexusTheme.PADDING_MD, 6), pady=NexusTheme.PADDING_SM)

        # Attack Button
        self.simulate_attack_btn = customtkinter.CTkButton(
            harness_frame,
            text="⚡ Simulate SQLi Attack",
            font=NexusTheme.FONT_BODY_BOLD,
            fg_color=NexusTheme.STATUS_CRIMSON,
            hover_color="#DC2626",
            text_color="#FFFFFF",
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self._handle_simulate_attack
        )
        self.simulate_attack_btn.grid(row=0, column=1, padx=6, pady=NexusTheme.PADDING_SM)
        self.launch_attack_btn = self.simulate_attack_btn

        # Feedback Status Banner
        self.attack_status_label = customtkinter.CTkLabel(
            harness_frame,
            text="Adversarial Harness Ready. Click above to inject DDL/DML exploit payload.",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_SECONDARY,
            anchor="w"
        )
        self.attack_status_label.grid(row=0, column=2, sticky="ew", padx=(8, NexusTheme.PADDING_MD), pady=NexusTheme.PADDING_SM)
        self.payload_preview_lbl = self.attack_status_label

    def _build_ledger_viewer(self) -> None:
        ledger_frame = customtkinter.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER
        )
        ledger_frame.grid(row=3, column=0, sticky="nsew", padx=NexusTheme.PADDING_MD, pady=(8, NexusTheme.PADDING_MD))
        ledger_frame.grid_rowconfigure(1, weight=1)
        ledger_frame.grid_columnconfigure(0, weight=1)

        # Ledger Header
        header_row = customtkinter.CTkFrame(ledger_frame, fg_color="transparent")
        header_row.grid(row=0, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(NexusTheme.PADDING_SM, 4))
        header_row.grid_columnconfigure(0, weight=1)

        lbl = customtkinter.CTkLabel(
            header_row,
            text="PERSISTENT AUDIT LEDGER & RECENT QUERY LOGS",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.TEXT_SECONDARY,
            anchor="w"
        )
        lbl.grid(row=0, column=0, sticky="w")

        self.ledger_summary_badge = customtkinter.CTkLabel(
            header_row,
            text="Ledger: Active",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.STATUS_EMERALD,
            anchor="e"
        )
        self.ledger_summary_badge.grid(row=0, column=1, sticky="e")

        # Monospace Text Viewer
        self.ledger_textbox = customtkinter.CTkTextbox(
            ledger_frame,
            font=NexusTheme.FONT_CODE,
            fg_color=NexusTheme.BG_OBSIDIAN,
            text_color=NexusTheme.TEXT_PRIMARY,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            wrap="none"
        )
        self.ledger_textbox.grid(row=1, column=0, sticky="nsew", padx=NexusTheme.PADDING_MD, pady=(4, NexusTheme.PADDING_MD))
        self.ledger_textbox.insert("1.0", "(Loading audit records...)")
        self.ledger_textbox.configure(state="disabled")

    def _on_payload_selected(self, chosen_name: str) -> None:
        """Updates preview status when an attack payload is selected in dropdown."""
        for name, sql in self.ADVERSARIAL_PAYLOADS:
            if name == chosen_name:
                self.attack_status_label.configure(
                    text=f"Selected: [{name}] {sql[:50]}...",
                    text_color=NexusTheme.TEXT_SECONDARY
                )
                break

    def _handle_simulate_attack(self) -> None:
        """Triggered from UI button using currently selected payload."""
        chosen_name = self.payload_dropdown.get()
        chosen_payload = None
        for name, sql in self.ADVERSARIAL_PAYLOADS:
            if name == chosen_name:
                chosen_payload = (name, sql)
                break
        self.simulate_sqli_attack(chosen_payload)

    # --------------------------------------------------------------------------
    # TELEMETRY DATA REFRESH (ASYNC)
    # --------------------------------------------------------------------------

    def refresh_hud(self) -> None:
        """Fetches telemetry metrics and recent audit rows asynchronously."""
        def _fetch_data() -> Dict[str, Any]:
            # 1. In-memory Telemetry Metrics & History
            mem_metrics = self.db.telemetry.get_metrics()
            telemetry_history = self.db.telemetry.get_history(limit=30)

            # 2. Disk-persisted Audit Ledger Metrics via db.readonly() cursor
            disk_total = 0
            disk_rejected = 0
            disk_failed = 0
            audit_records: List[Dict[str, Any]] = []

            try:
                with self.db.readonly() as cursor:
                    cursor.execute("""
                        SELECT 
                            COUNT(*) as total,
                            SUM(CASE WHEN UPPER(status) = 'REJECTED' THEN 1 ELSE 0 END) as rejected_cnt,
                            SUM(CASE WHEN UPPER(status) = 'FAILED' THEN 1 ELSE 0 END) as failed_cnt
                        FROM _nexus_query_audit;
                    """)
                    row = cursor.fetchone()
                    if row:
                        disk_total = row[0] or 0
                        disk_rejected = row[1] or 0
                        disk_failed = row[2] or 0

                    cursor.execute("""
                        SELECT query_id, natural_query, generated_sql, status, error_message, executed_at
                        FROM _nexus_query_audit
                        ORDER BY query_id DESC
                        LIMIT 30;
                    """)
                    for r in cursor.fetchall():
                        audit_records.append({
                            "query_id": r[0],
                            "natural_query": r[1],
                            "sql": r[2],
                            "status": r[3],
                            "error": r[4],
                            "timestamp": r[5],
                        })
            except Exception as exc:
                logger.warning(f"Failed to query _nexus_query_audit for HUD: {exc}")

            return {
                "mem_metrics": mem_metrics,
                "telemetry_history": telemetry_history,
                "disk_total": disk_total,
                "disk_rejected": disk_rejected,
                "disk_failed": disk_failed,
                "audit_records": audit_records,
            }

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _fetch_data,
                on_success=self._on_hud_data_loaded,
                on_error=self._on_hud_refresh_error,
                task_name="RefreshHUD"
            )
        else:
            try:
                data = _fetch_data()
                self._on_hud_data_loaded(data)
            except Exception as exc:
                self._on_hud_refresh_error(exc)

    def _on_hud_data_loaded(self, data: Dict[str, Any]) -> None:
        if not self.winfo_exists():
            return
        mem_metrics = data.get("mem_metrics", {})
        disk_rejected = data.get("disk_rejected", 0)
        disk_failed = data.get("disk_failed", 0)

        total_queries = mem_metrics.get("total_queries", 0)
        p95_lat = mem_metrics.get("p95_execution_ms", 0.0)
        avg_lat = mem_metrics.get("avg_execution_ms", 0.0)
        mem_errors = mem_metrics.get("error_count", 0)

        # Combined security blocks / errors (telemetry + audit ledger without double-counting)
        total_security_blocks = disk_rejected + max(mem_errors, disk_failed)

        # Update Card Values
        self.val_total_queries.configure(text=f"{total_queries:,}")
        self.val_p95_latency.configure(text=f"{p95_lat:.2f} ms")
        self.val_avg_latency.configure(text=f"{avg_lat:.2f} ms")
        self.val_security_blocks.configure(text=f"{total_security_blocks:,}")

        # Render Ledger Text with both audit ledger and in-memory telemetry
        self._render_ledger_records(data.get("audit_records", []), data.get("telemetry_history", []))

    def _on_hud_refresh_error(self, exc: Exception) -> None:
        if not self.winfo_exists():
            return
        logger.error(f"Synchronous HUD refresh failed: {exc}")

    def _render_ledger_records(
        self,
        audit_records: List[Dict[str, Any]],
        telemetry_history: List[Dict[str, Any]]
    ) -> None:
        buffer = io.StringIO()

        # Section 1: Persistent Audit Ledger
        buffer.write("=== PERSISTENT SECURITY AUDIT LEDGER (_nexus_query_audit) ===\n")
        if not audit_records:
            buffer.write("(Audit ledger is empty. Execute queries in Data Explorer or click 'Simulate SQLi Attack'.)\n")
        else:
            buffer.write(f"  {'ID':<8} | {'STATUS':<10} | {'TIMESTAMP':<20} | {'QUERY / SQL STATEMENT'}\n")
            buffer.write("  " + "-" * 8 + "-+-" + "-" * 10 + "-+-" + "-" * 20 + "-+-" + "-" * 50 + "\n")

            for r in audit_records:
                q_id = f"#{r['query_id']}"
                status = str(r["status"]).upper()
                timestamp = str(r["timestamp"])[:19]
                sql = str(r["sql"]).replace("\n", " ").strip()
                if len(sql) > 60:
                    sql = sql[:57] + "..."

                status_tag = f"[{status}]"
                buffer.write(f"  {q_id:<8} | {status_tag:<10} | {timestamp:<20} | {sql}\n")
                if r.get("error"):
                    err = str(r["error"]).replace("\n", " ")[:70]
                    buffer.write(f"           | -> Error: {err}\n")

        # Section 2: In-Memory Telemetry Stream
        buffer.write("\n=== IN-MEMORY TELEMETRY STREAM (Last 30 Queries via TelemetryLogger) ===\n")
        if not telemetry_history:
            buffer.write("(In-memory telemetry buffer is empty. Run queries via Data Explorer or API.)\n")
        else:
            buffer.write(f"  {'QUERY ID':<10} | {'STATUS':<10} | {'LATENCY':<10} | {'ROWS':<8} | {'SQL'}\n")
            buffer.write("  " + "-" * 10 + "-+-" + "-" * 10 + "-+-" + "-" * 10 + "-+-" + "-" * 8 + "-+-" + "-" * 40 + "\n")
            for t in telemetry_history:
                qid = str(t.get("query_id", "Q-XXXX"))
                stat = str(t.get("status", "SUCCESS")).upper()
                lat = f"{t.get('execution_time_ms', 0.0):.2f}ms"
                rc = str(t.get("row_count", 0))
                sql_preview = str(t.get("sql", "")).replace("\n", " ").strip()
                if len(sql_preview) > 50:
                    sql_preview = sql_preview[:47] + "..."
                buffer.write(f"  {qid:<10} | [{stat:<8}] | {lat:<10} | {rc:<8} | {sql_preview}\n")

        self.ledger_textbox.configure(state="normal")
        self.ledger_textbox.delete("1.0", "end")
        self.ledger_textbox.insert("1.0", buffer.getvalue())
        self.ledger_textbox.configure(state="disabled")

    # --------------------------------------------------------------------------
    # ADVERSARIAL ATTACK SIMULATOR (ASYNC WORKER)
    # --------------------------------------------------------------------------

    def simulate_sqli_attack(self, payload_choice: Optional[Tuple[str, str]] = None) -> None:
        """
        Fires a destructive SQL exploit payload against QueryGuard inside AsyncWorkerManager.
        Demonstrates zero-percent execution rate for non-SELECT queries live without UI thread lockup.
        """
        if payload_choice is not None:
            attack_name, payload = payload_choice
        else:
            attack_name, payload = random.choice(self.ADVERSARIAL_PAYLOADS)

        self.simulate_attack_btn.configure(state="disabled")
        self.attack_status_label.configure(
            text=f"Simulating attack '{attack_name}' in background worker...",
            text_color=NexusTheme.ACCENT_CYAN
        )

        def _bg_attack_task() -> Dict[str, Any]:
            # Step 1: QueryGuard verification in worker thread
            try:
                guard_query(payload)
                # If QueryGuard failed to block, this is a vulnerability
                return {
                    "deflected": False,
                    "attack_name": attack_name,
                    "payload": payload,
                    "error": "Query passed guard unexpectedly",
                    "violation_type": "NONE"
                }
            except SecurityException as sec_exc:
                # Expected security deflection
                logger.info(f"NEXUS-TelemetryHUD: [DEFENSE DEMO] Deflected attack '{attack_name}': {sec_exc}")
                # Record REJECTED event into SQLite audit ledger in background thread
                self.db.log_audit_event(
                    natural_query=f"SQLi Attack Simulation: {attack_name}",
                    generated_sql=payload,
                    status="REJECTED",
                    error_message=str(sec_exc)
                )
                return {
                    "deflected": True,
                    "attack_name": attack_name,
                    "payload": payload,
                    "error": str(sec_exc),
                    "violation_type": getattr(sec_exc, "violation_type", "SECURITY_VIOLATION")
                }
            except Exception as exc:
                # Other unexpected runtime failure (do NOT mask as security deflection)
                logger.error(f"Unexpected error in attack simulation: {exc}")
                return {
                    "deflected": False,
                    "attack_name": attack_name,
                    "payload": payload,
                    "error": str(exc),
                    "violation_type": "UNEXPECTED_ERROR"
                }

        if self.worker and not self.worker.is_shutdown:
            self.worker.submit_task(
                _bg_attack_task,
                on_success=self._on_attack_sim_complete,
                on_error=self._on_attack_sim_error,
                task_name="SimulateSQLiAttack"
            )
        else:
            try:
                res = _bg_attack_task()
                self._on_attack_sim_complete(res)
            except Exception as exc:
                self._on_attack_sim_error(exc)

    def _on_attack_sim_complete(self, result: Dict[str, Any]) -> None:
        if not self.winfo_exists():
            return
        self.simulate_attack_btn.configure(state="normal")
        attack_name = result.get("attack_name", "Unknown")
        payload = result.get("payload", "")
        deflected = result.get("deflected", False)

        if deflected:
            viol_type = result.get("violation_type", "SECURITY_VIOLATION")
            self.attack_status_label.configure(
                text=f"🛡️ Deflected [{attack_name}]: {viol_type} caught. (Payload: {payload[:45]}...)",
                text_color=NexusTheme.STATUS_EMERALD
            )
        else:
            err = result.get("error", "Unknown")
            self.attack_status_label.configure(
                text=f"❌ Simulation Alert [{attack_name}]: {err}",
                text_color=NexusTheme.STATUS_CRIMSON
            )

        # Refresh HUD to update metric cards and audit ledger
        self.refresh_hud()

    def _on_attack_sim_error(self, exc: Exception) -> None:
        if not self.winfo_exists():
            return
        self.simulate_attack_btn.configure(state="normal")
        logger.error(f"Attack simulation worker task failed: {exc}")
        self.attack_status_label.configure(
            text=f"Simulation worker error: {exc}",
            text_color=NexusTheme.STATUS_CRIMSON
        )
