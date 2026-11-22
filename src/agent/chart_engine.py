"""
NEXUS Engine - Safe Declarative Analytical Chart Engine
======================================================
Architecture Role: Deterministic, zero-eval/exec declarative visualization engine.
Parses structured ChartSpec payloads, applies NexusTheme styling, and renders
thread-safe Matplotlib Figure objects (OO API) for headless execution and
CustomTkinter GUI integration.

Design Invariants:
1. Zero Code Execution: Completely immune to arbitrary Python code execution;
   never parses, executes, or evaluates LLM-generated Python or matplotlib scripts.
2. Thread-Safe Object-Oriented Matplotlib API: Uses `matplotlib.figure.Figure` directly.
   NEVER calls `matplotlib.pyplot.figure()`, preventing global state corruption and
   Tkinter / Tcl thread conflicts when invoked from AsyncWorkerManager worker threads.
3. Strict Clamping & Resource Caps: Clamps `top_n` to [1, 50] to prevent huge datasets
   from freezing UI rendering on local Windows hardware.
4. NexusTheme Dark Cyber-Analytics Styling: High-contrast palette (BG_OBSIDIAN,
   SURFACE_SLATE, ACCENT_CYAN, STATUS_EMERALD, STATUS_AMBER, TEXT_PRIMARY, TEXT_SECONDARY).

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple, Union

import pandas as pd
from matplotlib.figure import Figure
from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.core.db_manager import QueryResult
from src.ui.theme import NexusTheme


# ==============================================================================
# EXCEPTIONS & SPECIFICATION SCHEMAS
# ==============================================================================

class ChartValidationError(Exception):
    """Raised when a chart specification or data payload violates schema constraints."""
    pass


class ChartSpec(BaseModel):
    """
    Strict declarative specification for analytical chart generation.
    Completely isolated from executable code.
    """
    model_config = ConfigDict(extra="ignore", frozen=True)

    chart_type: Literal["bar", "line", "scatter", "pie", "hist"] = Field(
        description="The geometry type of analytical chart to render."
    )
    x_column: Optional[str] = Field(
        default=None,
        description="Name of column to map to the X-axis (or category for pie/bar)."
    )
    y_column: Optional[str] = Field(
        default=None,
        description="Name of column to map to the Y-axis (or value metric)."
    )
    title: str = Field(
        default="Analytical Chart",
        description="Sanitized chart title."
    )
    x_label: Optional[str] = Field(
        default=None,
        description="Optional custom label for the X-axis."
    )
    y_label: Optional[str] = Field(
        default=None,
        description="Optional custom label for the Y-axis."
    )
    top_n: int = Field(
        default=20,
        description="Maximum number of rows to plot (clamped between 1 and 50)."
    )

    @field_validator("title")
    @classmethod
    def sanitize_title(cls, v: str) -> str:
        """Sanitizes control characters and caps title length at 100 characters."""
        if not v or not str(v).strip():
            return "Analytical Chart"
        cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", str(v).strip())
        return cleaned[:100] if cleaned else "Analytical Chart"

    @field_validator("top_n", mode="before")
    @classmethod
    def clamp_top_n(cls, v: Any) -> int:
        """Clamps top_n between 1 and 50 to prevent UI canvas memory bloat."""
        try:
            val = int(v) if v is not None else 20
        except (ValueError, TypeError):
            val = 20
        return max(1, min(50, val))


# ==============================================================================
# CHART ENGINE
# ==============================================================================

class ChartEngine:
    """
    Stateless, thread-safe renderer translating declarative ChartSpecs into
    dark-mode Matplotlib Figure instances.
    """

    PALETTE_COLORS = [
        NexusTheme.ACCENT_CYAN,
        NexusTheme.STATUS_EMERALD,
        NexusTheme.STATUS_AMBER,
        "#8B5CF6",  # Purple accent
        "#EC4899",  # Pink accent
        "#3B82F6",  # Blue accent
        NexusTheme.STATUS_CRIMSON,
    ]

    # --------------------------------------------------------------------------
    # SPECIFICATION PARSER & VALIDATOR
    # --------------------------------------------------------------------------

    @classmethod
    def parse_chart_spec(
        cls,
        raw_payload: Union[str, Dict[str, Any]],
        available_columns: List[str]
    ) -> ChartSpec:
        """
        Parses raw text or dictionary payloads into a validated ChartSpec.
        Safely strips markdown fences and verifies that specified columns exist.

        Parameters:
            raw_payload: Raw JSON string (optionally fenced in ```json) or dict.
            available_columns: List of column names present in QueryResult.

        Returns:
            Validated, typed ChartSpec instance.

        Raises:
            ChartValidationError if parsing fails or required columns are missing.
        """
        payload_dict: Dict[str, Any] = {}

        if isinstance(raw_payload, str):
            text = raw_payload.strip()
            # Strip reasoning-model <think>...</think> blocks
            text = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()

            # Strip markdown code fences if present
            fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
            if fence_match:
                text = fence_match.group(1).strip()

            try:
                payload_dict = json.loads(text)
            except Exception as exc:
                raise ChartValidationError(f"Invalid JSON payload for ChartSpec: {exc}") from exc

        elif isinstance(raw_payload, dict):
            payload_dict = raw_payload
        else:
            raise ChartValidationError(
                f"Expected str or dict for ChartSpec, got {type(raw_payload).__name__}"
            )

        # Validate basic schema with Pydantic
        try:
            spec = ChartSpec.model_validate(payload_dict)
        except Exception as exc:
            raise ChartValidationError(f"ChartSpec schema validation failed: {exc}") from exc

        # Column existence verification (case-insensitive mapping to exact casing)
        col_lookup = {col.lower(): col for col in available_columns}

        resolved_x = None
        if spec.x_column:
            x_lower = spec.x_column.lower()
            if x_lower in col_lookup:
                resolved_x = col_lookup[x_lower]
            else:
                raise ChartValidationError(
                    f"Specified x_column '{spec.x_column}' does not exist in available columns: {available_columns}"
                )

        resolved_y = None
        if spec.y_column:
            y_lower = spec.y_column.lower()
            if y_lower in col_lookup:
                resolved_y = col_lookup[y_lower]
            else:
                raise ChartValidationError(
                    f"Specified y_column '{spec.y_column}' does not exist in available columns: {available_columns}"
                )

        # Validate axis presence per chart type
        chart_type = spec.chart_type
        if chart_type in ("bar", "line", "scatter", "pie"):
            if not resolved_x or not resolved_y:
                raise ChartValidationError(
                    f"Chart type '{chart_type}' requires both 'x_column' and 'y_column'. "
                    f"Provided x_column={resolved_x!r}, y_column={resolved_y!r}."
                )

        elif chart_type == "hist":
            if not resolved_x and not resolved_y:
                raise ChartValidationError(
                    "Histogram chart requires at least 'x_column' or 'y_column'."
                )

        return spec.model_copy(update={"x_column": resolved_x, "y_column": resolved_y})

    # --------------------------------------------------------------------------
    # THREAD-SAFE OBJECT-ORIENTED FIGURE RENDERER
    # --------------------------------------------------------------------------

    @classmethod
    def render_figure(
        cls,
        query_result: QueryResult,
        spec: ChartSpec,
        figsize: Tuple[float, float] = (6.8, 3.8),
        dpi: int = 100
    ) -> Figure:
        """
        Renders a thread-safe, dark-mode Matplotlib Figure matching the ChartSpec.

        CRITICAL THREAD-SAFETY GUARANTEE:
        Uses `matplotlib.figure.Figure()` directly without importing or invoking
        `matplotlib.pyplot`. Zero global state, zero GUI thread lockups.

        Parameters:
            query_result: The executed QueryResult containing columns and rows.
            spec: The validated ChartSpec.
            figsize: Tuple of (width, height) in inches.
            dpi: Dots per inch resolution.

        Returns:
            Configured `matplotlib.figure.Figure` ready for FigureCanvasTkAgg embedding.
        """
        # 1. Instantiate pure OO Figure
        fig = Figure(figsize=figsize, dpi=dpi, facecolor=NexusTheme.BG_OBSIDIAN)
        ax = fig.add_subplot(111, facecolor=NexusTheme.SURFACE_SLATE)

        # 2. Extract DataFrame and clamp top_n rows
        df = pd.DataFrame(query_result.rows, columns=query_result.columns)
        if df.empty:
            ax.text(
                0.5, 0.5, "No query results to display.",
                ha="center", va="center", color=NexusTheme.TEXT_SECONDARY,
                fontsize=11, transform=ax.transAxes
            )
            ax.set_xticks([])
            ax.set_yticks([])
            fig.tight_layout()
            return fig

        top_limit = min(len(df), spec.top_n)
        plot_df = df.iloc[:top_limit].copy()

        # 3. Apply Base Cyber-Analytics Styling (Spines, Ticks, Grid)
        for spine in ax.spines.values():
            spine.set_color(NexusTheme.SURFACE_BORDER)
            spine.set_linewidth(1.0)

        ax.tick_params(colors=NexusTheme.TEXT_SECONDARY, labelsize=8.5)
        ax.grid(True, linestyle="--", alpha=0.20, color=NexusTheme.SURFACE_BORDER)
        ax.set_axisbelow(True)

        chart_type = spec.chart_type

        # 4. Geometry-Specific Rendering
        if chart_type == "bar":
            x_vals = plot_df[spec.x_column].astype(str)
            y_vals = pd.to_numeric(plot_df[spec.y_column], errors="coerce").fillna(0)
            ax.bar(
                x_vals,
                y_vals,
                color=NexusTheme.ACCENT_CYAN,
                edgecolor=NexusTheme.SURFACE_BORDER,
                linewidth=0.8,
                width=0.6,
                zorder=3
            )

        elif chart_type == "line":
            x_vals = plot_df[spec.x_column].astype(str)
            y_vals = pd.to_numeric(plot_df[spec.y_column], errors="coerce").fillna(0)
            ax.plot(
                x_vals,
                y_vals,
                color=NexusTheme.ACCENT_CYAN,
                marker="o",
                markersize=5,
                linewidth=2.0,
                markerfacecolor=NexusTheme.STATUS_EMERALD,
                markeredgecolor=NexusTheme.BG_OBSIDIAN,
                zorder=3
            )

        elif chart_type == "scatter":
            x_vals = pd.to_numeric(plot_df[spec.x_column], errors="coerce").fillna(0)
            y_vals = pd.to_numeric(plot_df[spec.y_column], errors="coerce").fillna(0)
            ax.scatter(
                x_vals,
                y_vals,
                color=NexusTheme.ACCENT_CYAN,
                edgecolors=NexusTheme.STATUS_EMERALD,
                s=60,
                alpha=0.85,
                zorder=3
            )

        elif chart_type == "pie":
            labels = plot_df[spec.x_column].astype(str).tolist()
            raw_vals = pd.to_numeric(plot_df[spec.y_column], errors="coerce").fillna(0)
            # Pie slices require non-negative values
            values = [max(0.0, float(v)) for v in raw_vals]
            if sum(values) <= 0:
                values = [1.0] * len(values)

            pie_colors = [cls.PALETTE_COLORS[i % len(cls.PALETTE_COLORS)] for i in range(len(values))]
            wedges, texts, autotexts = ax.pie(
                values,
                labels=labels,
                colors=pie_colors,
                autopct="%1.1f%%",
                startangle=140,
                textprops={"color": NexusTheme.TEXT_SECONDARY, "fontsize": 8}
            )
            for autotext in autotexts:
                autotext.set_color("#000000")
                autotext.set_fontweight("bold")
                autotext.set_fontsize(7.5)

        elif chart_type == "hist":
            metric_col = spec.y_column or spec.x_column
            data = pd.to_numeric(plot_df[metric_col], errors="coerce").dropna()
            bin_count = min(15, max(5, len(data) // 2)) if len(data) > 0 else 5
            ax.hist(
                data,
                bins=bin_count,
                color=NexusTheme.ACCENT_CYAN,
                edgecolor=NexusTheme.BG_OBSIDIAN,
                linewidth=0.8,
                alpha=0.85,
                zorder=3
            )

        # 5. Labels & Title Configuration
        ax.set_title(
            spec.title,
            color=NexusTheme.TEXT_PRIMARY,
            fontsize=10.5,
            fontweight="bold",
            pad=10
        )

        if chart_type != "pie":
            x_title = spec.x_label or spec.x_column or ""
            y_title = spec.y_label or spec.y_column or ""
            if x_title:
                ax.set_xlabel(x_title, color=NexusTheme.TEXT_SECONDARY, fontsize=8.5, labelpad=6)
            if y_title:
                ax.set_ylabel(y_title, color=NexusTheme.TEXT_SECONDARY, fontsize=8.5, labelpad=6)

            # Rotate crowded X tick labels
            tick_labels = ax.get_xticklabels()
            if len(tick_labels) > 4 or any(len(t.get_text()) > 6 for t in tick_labels):
                for lbl in tick_labels:
                    lbl.set_rotation(28)
                    lbl.set_ha("right")

        fig.tight_layout()
        return fig

    # --------------------------------------------------------------------------
    # FIGURE EXPORT
    # --------------------------------------------------------------------------

    @classmethod
    def save_figure(cls, figure: Figure, output_path: Union[str, Path]) -> Path:
        """
        Persists a Matplotlib Figure cleanly to disk with dark theme styling.
        """
        path = Path(output_path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        figure.savefig(
            path,
            format="png",
            facecolor=NexusTheme.BG_OBSIDIAN,
            edgecolor="none",
            dpi=figure.dpi,
            bbox_inches="tight"
        )
        return path
