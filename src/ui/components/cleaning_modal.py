"""
NEXUS Engine - AI Smart Clean Plan Approval Modal
=================================================
Modeless-safe, high-contrast cyber-analytics modal dialog for reviewing,
customizing, and confirming AI-generated or heuristic data cleaning plans.

Architectural Invariants:
1. Security: Prominent PII Shield indicator displaying pre-LLM redaction metrics.
   Zero automatic execution—explicit user confirmation is required before any
   cleaning step touches the database.
2. Stability & Headless Safety: Wrapped transient/grab_set protocols preventing
   test harness failures on headless Windows environments.
3. Futurized Styling: NexusTheme compliant obsidian/slate surfaces with
   color-coded health scoring and monospace action badges.
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Dict, List, Optional

import customtkinter as ctk

from src.etl.ai_profiler import (
    DatasetProfile,
    ProposedCleaningPlan,
    CleaningStep,
)
from src.ui.theme import NexusTheme


class CleaningPlanModal(ctk.CTkToplevel):
    """
    Cyber-Analytics Modal Dialog for approving or skipping proposed cleaning steps.
    """

    def __init__(
        self,
        master: Any,
        profile: DatasetProfile,
        plan: ProposedCleaningPlan,
        on_apply: Callable[[List[Dict[str, Any]]], None],
        on_skip: Callable[[], None],
        on_cancel: Optional[Callable[[], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(master, fg_color=NexusTheme.BG_OBSIDIAN, **kwargs)

        self.profile = profile
        self.plan = plan
        self.on_apply = on_apply
        self.on_skip = on_skip
        self.on_cancel = on_cancel

        # Checkbox state tracking
        self._step_vars: Dict[int, tk.BooleanVar] = {}
        self._step_checkboxes: List[ctk.CTkCheckBox] = []

        # Modeless-safe window configuration
        self.title("NEXUS — AI Smart Clean Plan Approval")
        self.geometry("780x660")
        self.minsize(680, 480)

        try:
            if master and hasattr(master, "winfo_exists") and master.winfo_exists():
                self.transient(master)
        except Exception:
            pass

        try:
            self.grab_set()
        except Exception:
            pass

        self.protocol("WM_DELETE_WINDOW", self.cancel)

        # Build UI layout
        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_rowconfigure(2, weight=1)  # Step checklist expands
        self.grid_columnconfigure(0, weight=1)

        # 1. Header Bar with Dataset Metadata, Health Score, and Plan Source Pill
        self._build_header_card()

        # 2. Security Alerts (PII Shield & Anomalies)
        self._build_alerts_section()

        # 3. Scrollable Step Approval Checklist
        self._build_checklist_section()

        # 4. Footer Action Row
        self._build_footer_actions()

    def _build_header_card(self) -> None:
        header_card = ctk.CTkFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER,
        )
        header_card.grid(row=0, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(NexusTheme.PADDING_MD, 8))
        header_card.grid_columnconfigure(0, weight=1)

        # File & Ingestion Metadata
        title_label = ctk.CTkLabel(
            header_card,
            text=f"📊 DATASET: {self.profile.file_name}",
            font=NexusTheme.FONT_SUBTITLE,
            text_color=NexusTheme.ACCENT_CYAN,
            anchor="w",
        )
        title_label.pack(fill="x", padx=NexusTheme.PADDING_MD, pady=(NexusTheme.PADDING_SM, 2))

        meta_label = ctk.CTkLabel(
            header_card,
            text=f"Sampled: {self.profile.sampled_rows:,} rows  •  Estimated Total: ~{self.profile.estimated_total_rows:,} rows  •  Columns: {len(self.profile.columns)}",
            font=NexusTheme.FONT_SMALL,
            text_color=NexusTheme.TEXT_MUTED,
            anchor="w",
        )
        meta_label.pack(fill="x", padx=NexusTheme.PADDING_MD, pady=(0, NexusTheme.PADDING_SM))

        # Badges Row (Health Score + Plan Source Pill)
        badges_frame = ctk.CTkFrame(header_card, fg_color="transparent")
        badges_frame.pack(fill="x", padx=NexusTheme.PADDING_MD, pady=(0, NexusTheme.PADDING_SM))

        # Health Grade Color Coding
        grade = self.profile.health_grade
        if grade in ("A", "B"):
            health_color = NexusTheme.STATUS_EMERALD
            health_bg = "#064E3B"
        elif grade == "C":
            health_color = NexusTheme.STATUS_AMBER
            health_bg = "#78350F"
        else:
            health_color = NexusTheme.STATUS_CRIMSON
            health_bg = "#7F1D1D"

        self.health_badge = ctk.CTkLabel(
            badges_frame,
            text=f"Health: {self.profile.health_score}/100 • Grade {grade}",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=health_color,
            fg_color=health_bg,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            padx=10,
            pady=4,
        )
        self.health_badge.pack(side="left", padx=(0, 10))

        # Plan Source Pill
        if self.plan.source == "llm":
            pill_text = f"🤖 AI Plan ({self.plan.model_used or 'active-llm'})"
            pill_color = NexusTheme.ACCENT_CYAN
            pill_bg = NexusTheme.ACCENT_CYAN_MUTED
        else:
            pill_text = "⚡ Heuristic Fallback"
            pill_color = NexusTheme.STATUS_AMBER
            pill_bg = "#78350F"

        self.plan_source_pill = ctk.CTkLabel(
            badges_frame,
            text=pill_text,
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=pill_color,
            fg_color=pill_bg,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            padx=10,
            pady=4,
        )
        self.plan_source_pill.pack(side="left")

        # Optional Warning Message (e.g. from fallback)
        if self.plan.warning_message:
            warn_lbl = ctk.CTkLabel(
                badges_frame,
                text=f"⚠️ {self.plan.warning_message}",
                font=NexusTheme.FONT_SMALL,
                text_color=NexusTheme.STATUS_AMBER,
            )
            warn_lbl.pack(side="left", padx=10)

    def _build_alerts_section(self) -> None:
        alerts_container = ctk.CTkFrame(self, fg_color="transparent")
        alerts_container.grid(row=1, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=(0, 8))
        alerts_container.grid_columnconfigure(0, weight=1)

        # 1. PII Shield Banner (only if profile.pii_findings is non-empty)
        if self.profile.pii_findings:
            pii_counts: Dict[str, int] = {}
            pii_cols = set()
            for finding in self.profile.pii_findings:
                pii_counts[finding.pii_type] = pii_counts.get(finding.pii_type, 0) + finding.match_count
                pii_cols.add(finding.column)

            counts_str = ", ".join(f"{cnt} {ptype}" for ptype, cnt in sorted(pii_counts.items()))
            cols_count = len(pii_cols)

            banner_frame = ctk.CTkFrame(
                alerts_container,
                fg_color="#3B1219",
                corner_radius=NexusTheme.CORNER_RADIUS_SM,
                border_width=NexusTheme.BORDER_WIDTH,
                border_color=NexusTheme.STATUS_CRIMSON,
            )
            banner_frame.pack(fill="x", pady=2)

            self.pii_banner = ctk.CTkLabel(
                banner_frame,
                text=f"🛡️ PII Shield Active: Masked {counts_str} across {cols_count} column(s) before LLM profiling",
                font=NexusTheme.FONT_SMALL_BOLD,
                text_color="#FCA5A5",
                anchor="w",
                padx=10,
                pady=6,
            )
            self.pii_banner.pack(fill="x")
        else:
            self.pii_banner = None

        # 2. Detected Anomalies Strip (if any)
        if self.profile.anomalies:
            anom_frame = ctk.CTkFrame(
                alerts_container,
                fg_color=NexusTheme.SURFACE_ELEVATED,
                corner_radius=NexusTheme.CORNER_RADIUS_SM,
                border_width=NexusTheme.BORDER_WIDTH,
                border_color=NexusTheme.SURFACE_BORDER,
            )
            anom_frame.pack(fill="x", pady=2)

            anom_text = " • ".join(self.profile.anomalies)
            self.anomalies_banner = ctk.CTkLabel(
                anom_frame,
                text=f"⚠️ Anomalies Detected: {anom_text}",
                font=NexusTheme.FONT_SMALL,
                text_color=NexusTheme.STATUS_AMBER,
                anchor="w",
                padx=10,
                pady=4,
                wraplength=720,
            )
            self.anomalies_banner.pack(fill="x")
        else:
            self.anomalies_banner = None

    def _build_checklist_section(self) -> None:
        self.scroll_frame = ctk.CTkScrollableFrame(
            self,
            fg_color=NexusTheme.SURFACE_SLATE,
            corner_radius=NexusTheme.CORNER_RADIUS_MD,
            border_width=NexusTheme.BORDER_WIDTH,
            border_color=NexusTheme.SURFACE_BORDER,
        )
        self.scroll_frame.grid(row=2, column=0, sticky="nsew", padx=NexusTheme.PADDING_MD, pady=4)
        self.scroll_frame.grid_columnconfigure(0, weight=1)

        checklist_title = ctk.CTkLabel(
            self.scroll_frame,
            text=f"PROPOSED CLEANING STEPS ({len(self.plan.steps)})",
            font=NexusTheme.FONT_BODY_BOLD,
            text_color=NexusTheme.TEXT_SECONDARY,
            anchor="w",
        )
        checklist_title.pack(fill="x", padx=8, pady=(4, 8))

        if not self.plan.steps:
            clean_card = ctk.CTkFrame(
                self.scroll_frame,
                fg_color=NexusTheme.SURFACE_ELEVATED,
                corner_radius=NexusTheme.CORNER_RADIUS_SM,
                border_width=NexusTheme.BORDER_WIDTH,
                border_color=NexusTheme.STATUS_EMERALD,
            )
            clean_card.pack(fill="x", padx=4, pady=8)

            clean_lbl = ctk.CTkLabel(
                clean_card,
                text="✨ Dataset looks clean! No corrective steps needed.",
                font=NexusTheme.FONT_BODY_BOLD,
                text_color=NexusTheme.STATUS_EMERALD,
                pady=16,
            )
            clean_lbl.pack()
            return

        for idx, step in enumerate(self.plan.steps):
            step_var = tk.BooleanVar(value=True)
            self._step_vars[idx] = step_var

            card = ctk.CTkFrame(
                self.scroll_frame,
                fg_color=NexusTheme.SURFACE_ELEVATED,
                corner_radius=NexusTheme.CORNER_RADIUS_SM,
                border_width=NexusTheme.BORDER_WIDTH,
                border_color=NexusTheme.SURFACE_BORDER,
            )
            card.pack(fill="x", padx=4, pady=4)
            card.grid_columnconfigure(1, weight=1)

            # Checkbox
            cb = ctk.CTkCheckBox(
                card,
                text="",
                variable=step_var,
                width=24,
                checkbox_width=20,
                checkbox_height=20,
                corner_radius=4,
                fg_color=NexusTheme.ACCENT_CYAN,
                hover_color=NexusTheme.ACCENT_CYAN_HOVER,
                border_color=NexusTheme.TEXT_MUTED,
            )
            cb.grid(row=0, column=0, rowspan=2, padx=(10, 8), pady=8, sticky="n")
            self._step_checkboxes.append(cb)

            # Header line: [action_name] + compact params
            badge_text = f"[{step.action}]"
            params_str = ", ".join(f"{k}={v}" for k, v in step.params.items())
            if len(params_str) > 70:
                params_str = params_str[:67] + "..."

            header_text = f"{badge_text}  {params_str}" if params_str else badge_text

            step_hdr = ctk.CTkLabel(
                card,
                text=header_text,
                font=NexusTheme.FONT_CODE_BOLD,
                text_color=NexusTheme.ACCENT_CYAN,
                anchor="w",
            )
            step_hdr.grid(row=0, column=1, sticky="w", padx=(0, 10), pady=(6, 2))

            # Reason description
            reason_lbl = ctk.CTkLabel(
                card,
                text=step.reason,
                font=NexusTheme.FONT_SMALL,
                text_color=NexusTheme.TEXT_SECONDARY,
                anchor="w",
                justify="left",
                wraplength=620,
            )
            reason_lbl.grid(row=1, column=1, sticky="w", padx=(0, 10), pady=(0, 8))

    def _build_footer_actions(self) -> None:
        footer_frame = ctk.CTkFrame(self, fg_color="transparent")
        footer_frame.grid(row=3, column=0, sticky="ew", padx=NexusTheme.PADDING_MD, pady=NexusTheme.PADDING_MD)

        # Primary Apply Button
        self.apply_btn = ctk.CTkButton(
            footer_frame,
            text="⚡ Apply Selected Steps & Ingest",
            font=NexusTheme.FONT_BODY_BOLD,
            fg_color=NexusTheme.ACCENT_CYAN,
            hover_color=NexusTheme.ACCENT_CYAN_HOVER,
            text_color="#000000",
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self.confirm_apply,
            height=36,
        )
        self.apply_btn.pack(side="left", padx=(0, 10))

        # Secondary Fast Skip Button
        self.skip_btn = ctk.CTkButton(
            footer_frame,
            text="⏩ Skip Plan (Fast Raw Ingest)",
            font=NexusTheme.FONT_BODY,
            fg_color=NexusTheme.SURFACE_ELEVATED,
            hover_color=NexusTheme.SURFACE_BORDER,
            text_color=NexusTheme.TEXT_PRIMARY,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self.confirm_skip,
            height=36,
        )
        self.skip_btn.pack(side="left", padx=(0, 10))

        # Muted Cancel Button
        self.cancel_btn = ctk.CTkButton(
            footer_frame,
            text="Cancel",
            font=NexusTheme.FONT_BODY,
            fg_color="transparent",
            hover_color=NexusTheme.SURFACE_ELEVATED,
            text_color=NexusTheme.TEXT_MUTED,
            corner_radius=NexusTheme.CORNER_RADIUS_SM,
            command=self.cancel,
            height=36,
        )
        self.cancel_btn.pack(side="right")

    # --------------------------------------------------------------------------
    # PUBLIC PROGRAMMATIC HELPERS
    # --------------------------------------------------------------------------

    def get_selected_steps(self) -> List[CleaningStep]:
        """Returns the list of CleaningStep instances selected by the operator."""
        selected: List[CleaningStep] = []
        for idx, step in enumerate(self.plan.steps):
            var = self._step_vars.get(idx)
            if var is not None and var.get():
                selected.append(step)
        return selected

    def get_selected_executor_payload(self) -> List[Dict[str, Any]]:
        """
        Builds a filtered ProposedCleaningPlan from operator-approved steps
        and converts it into the exact list-of-dicts contract expected by
        CleaningPlanExecutor.apply().
        """
        selected_steps = self.get_selected_steps()
        filtered_plan = ProposedCleaningPlan(
            summary=self.plan.summary,
            steps=selected_steps,
            source=self.plan.source,
            model_used=self.plan.model_used,
            warning_message=self.plan.warning_message,
        )
        return filtered_plan.to_executor_payload()

    def confirm_apply(self) -> None:
        """Applies approved steps via on_apply callback and closes the modal."""
        payload = self.get_selected_executor_payload()
        try:
            self.on_apply(payload)
        finally:
            self.destroy()

    def confirm_skip(self) -> None:
        """Bypasses cleaning steps via on_skip callback and closes the modal."""
        try:
            self.on_skip()
        finally:
            self.destroy()

    def cancel(self) -> None:
        """Cancels the ingestion workflow and closes the modal."""
        try:
            if callable(self.on_cancel):
                self.on_cancel()
        finally:
            self.destroy()
