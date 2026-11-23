"""
NEXUS Engine - High-Performance Data & Executive Brief Export Subsystem
========================================================================
Architecture Role: Production-grade export pipelines supporting:
1. OWASP CSV/Excel Formula Injection sanitized tabular exports (CSV, XLSX).
2. Standalone Executive Brief generation (Markdown, XSS-hardened self-contained HTML).
3. Base64 dark-mode chart embedding for offline-ready standalone briefs.

Security Invariants:
- OWASP Formula Injection Defense: Prepends single quote (') to string cells starting
  with dangerous triggers (=, +, -, @, \\t, \\r) while preserving true numeric values.
- Strict XSS Defense: All dynamic inputs in HTML generation are escaped via
  html.escape(..., quote=True). Zero unescaped string injection.
- UTF-8 with BOM (utf-8-sig) default for CSV to ensure clean rendering in Windows Excel.
- Zero GUI thread blocking: Pure-core logic callable from background workers.

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import base64
import csv
import datetime
import html
import io
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Sequence, Union

from src.ui.formatters import format_ascii_table, format_cell_value

if TYPE_CHECKING:
    from src.agent.sql_chain import AgentRunResult

try:
    import openpyxl
    import openpyxl.styles
    HAS_OPENPYXL = True
except ImportError:
    openpyxl = None  # type: ignore
    HAS_OPENPYXL = False


# ==============================================================================
# OWASP FORMULA INJECTION SANITIZATION
# ==============================================================================

DANGEROUS_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def sanitize_spreadsheet_cell(value: Any) -> Any:
    """
    Sanitizes an individual cell value against OWASP CSV/Excel Formula Injection.

    Rules:
    - None -> None
    - bool -> preserved as bool (True/False are not formula triggers)
    - int, float -> preserved as-is so genuine numeric math works in Excel (e.g. -42.5)
    - str -> if the string (after optional leading whitespace) starts with any
      formula trigger (=, +, -, @, \\t, \\r), neutralize it by prepending a single quote (').
      e.g., "=CMD|' /C calc'!A0" -> "'=CMD|' /C calc'!A0"
    - Other objects -> converted to string and checked against formula triggers.
    """
    if value is None:
        return None

    # In Python, bool is a subclass of int; check bool first
    if isinstance(value, bool):
        return value

    if isinstance(value, (int, float)):
        return value

    if isinstance(value, str):
        if not value:
            return value
        if value[0] in DANGEROUS_FORMULA_TRIGGERS:
            return "'" + value
        space_stripped = value.lstrip(" ")
        if space_stripped and space_stripped[0] in DANGEROUS_FORMULA_TRIGGERS:
            return "'" + value
        return value

    # Fallback for complex types (dates, decimals, etc.)
    val_str = str(value)
    if val_str and (val_str[0] in DANGEROUS_FORMULA_TRIGGERS or val_str.lstrip(" ")[:1] in DANGEROUS_FORMULA_TRIGGERS):
        return "'" + val_str
    return value


def _extract_row_values(row: Any, columns: Sequence[str]) -> List[Any]:
    """Extracts ordered cell values from heterogeneous row representations."""
    if isinstance(row, dict):
        return [row.get(col) for col in columns]
    elif isinstance(row, (list, tuple, sqlite3.Row)) or (hasattr(row, "__getitem__") and not isinstance(row, (str, bytes))):
        try:
            return [row[i] if i < len(row) else None for i in range(len(columns))]
        except Exception:
            return [row] + [None] * (len(columns) - 1)
    else:
        return [row] + [None] * (len(columns) - 1)


# ==============================================================================
# TABULAR DATA EXPORT ENGINE (CSV & XLSX)
# ==============================================================================

class DataExportEngine:
    """
    High-throughput, memory-safe tabular export engine.
    Produces Excel-compatible CSVs and styled OpenPyXL workbooks.
    """

    @staticmethod
    def export_csv(
        columns: List[str],
        rows: List[Any],
        output_path: Union[str, Path],
        neutralize_formulas: bool = True
    ) -> Path:
        """
        Exports tabular data to a CSV file.

        - Uses UTF-8 with BOM (utf-8-sig) so Excel on Windows auto-detects Unicode.
        - Sanitizes headers and cell strings against formula injection when neutralize_formulas=True.
        - Creates parent directories automatically if they do not exist.
        """
        out_file = Path(output_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)

        header_row = [
            sanitize_spreadsheet_cell(col) if neutralize_formulas else col
            for col in columns
        ]

        with open(out_file, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(header_row)

            for row in rows:
                raw_vals = _extract_row_values(row, columns)
                if neutralize_formulas:
                    processed_vals = [sanitize_spreadsheet_cell(v) for v in raw_vals]
                else:
                    processed_vals = raw_vals
                writer.writerow(processed_vals)

        return out_file

    @staticmethod
    def export_excel(
        columns: List[str],
        rows: List[Any],
        output_path: Union[str, Path],
        sheet_name: str = "NEXUS_Export",
        neutralize_formulas: bool = True
    ) -> Path:
        """
        Exports tabular data to a styled OpenPyXL (.xlsx) workbook.

        - Requires openpyxl; raises a clear ImportError with installation instructions if missing.
        - Styles header row with bold font and slate background.
        - Auto-fits column widths clamped between [10, 48].
        - Freezes top header pane (freeze_panes = "A2").
        - Neutralizes formula cells when neutralize_formulas=True.
        """
        if not HAS_OPENPYXL or openpyxl is None:
            raise ImportError(
                "openpyxl is required for Excel export. "
                "Install it in your environment using: pip install openpyxl"
            )

        out_file = Path(output_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)

        wb = openpyxl.Workbook()
        ws = wb.active
        # Excel sheet title cannot exceed 31 chars
        clean_title = (sheet_name or "NEXUS_Export").strip()[:31]
        ws.title = clean_title or "NEXUS_Export"
        ws.freeze_panes = "A2"

        # 1. Write Header Row
        header_vals = [
            sanitize_spreadsheet_cell(col) if neutralize_formulas else col
            for col in columns
        ]
        ws.append(header_vals)

        # Style Header Row
        header_font = openpyxl.styles.Font(name="Segoe UI", size=11, bold=True, color="FFFFFF")
        header_fill = openpyxl.styles.PatternFill(
            start_color="1E293B", end_color="1E293B", fill_type="solid"
        )
        header_align = openpyxl.styles.Alignment(horizontal="left", vertical="center")

        for cell in ws[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_align

        # 2. Write Data Rows
        for row in rows:
            raw_vals = _extract_row_values(row, columns)
            if neutralize_formulas:
                processed_vals = [sanitize_spreadsheet_cell(v) for v in raw_vals]
            else:
                processed_vals = raw_vals
            ws.append(processed_vals)

        # 3. Auto-fit column widths (clamped to [10, 48])
        for col in ws.columns:
            max_len = 0
            col_letter = col[0].column_letter
            for cell in col:
                val_str = str(cell.value) if cell.value is not None else ""
                max_len = max(max_len, len(val_str))
            ws.column_dimensions[col_letter].width = min(max(max_len + 3, 10), 48)

        wb.save(out_file)
        return out_file


# ==============================================================================
# EXECUTIVE BRIEF EXPORTER (UPGRADE U3.5)
# ==============================================================================

class ExecutiveBriefExporter:
    """
    Generates standalone, executive-ready analytical briefs in Markdown and HTML.
    Features:
    - Strict HTML XSS defense via quote-escaping on every dynamic token.
    - Self-contained dark cyber-analytics styling matching NexusTheme.
    - In-memory Base64-encoded Matplotlib chart embedding for zero-dependency offline sharing.
    """

    @staticmethod
    def export_markdown(
        result: AgentRunResult,
        output_path: Union[str, Path],
        max_table_rows: int = 100
    ) -> Path:
        """
        Produces a structured Markdown analytical brief from an AgentRunResult.
        """
        out_file = Path(output_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        row_count = result.query_result.row_count if result.query_result else 0
        tables_str = ", ".join(result.tables_in_context) if result.tables_in_context else "None"
        pruned_str = f"Yes ({len(result.tables_in_context)} tables in context)" if result.was_pruned else "No"
        truncated_str = "Yes (RAM safety cap applied)" if (result.query_result and getattr(result.query_result, "truncated", False)) else "No"

        # Render ASCII / Markdown preview table
        table_section = ""
        if result.query_result and result.query_result.columns:
            ascii_table = format_ascii_table(
                columns=result.query_result.columns,
                rows=result.query_result.rows,
                max_rows=max_table_rows,
                truncated=getattr(result.query_result, "truncated", False)
            )
            table_section = f"```text\n{ascii_table}\n```"
        else:
            table_section = "_No tabular records returned._"

        chart_note = ""
        if result.chart_spec:
            chart_note = f"\n**Chart Spec:** `{result.chart_spec.chart_type}` (X: `{result.chart_spec.x_column}`, Y: `{result.chart_spec.y_columns}`)\n"

        content = f"""# NEXUS Analytical Executive Brief
**Generated:** {now_str}  
**Status:** {result.status}

---

## 1. Query Metadata
| Parameter | Value |
|:---|:---|
| **Natural Query** | {result.natural_query} |
| **Active Model** | {result.model} ({result.provider.upper() if result.provider else 'N/A'}) |
| **Pipeline Latency** | {result.total_latency_ms:.2f} ms |
| **Token Usage** | {result.total_tokens:,} tokens |
| **Records Returned** | {row_count:,} |
| **Pruned Context** | {pruned_str} |
| **Results Truncated** | {truncated_str} |
| **Tables Used** | {tables_str} |

---

## 2. Executive Summary
{result.answer_markdown}

{chart_note}

---

## 3. Verified SQLite Query
```sql
{result.generated_sql or '-- No SQL executed'}
```

---

## 4. Tabular Results Preview
{table_section}

---
*Report autonomously compiled by NEXUS Enterprise AI Core v1.1.*
"""
        with open(out_file, mode="w", encoding="utf-8") as f:
            f.write(content)

        return out_file

    @staticmethod
    def export_html(
        result: AgentRunResult,
        output_path: Union[str, Path],
        figure: Optional[Any] = None,
        max_table_rows: int = 100
    ) -> Path:
        """
        Produces a 100% self-contained, XSS-hardened dark cyber HTML brief.
        Embeds Matplotlib charts as inline Base64 data URIs.
        """
        out_file = Path(output_path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)

        def esc(val: Any) -> str:
            """Strict XSS escape helper."""
            return html.escape(str(val) if val is not None else "", quote=True)

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        row_count = result.query_result.row_count if result.query_result else 0
        tables_str = ", ".join(result.tables_in_context) if result.tables_in_context else "None"
        pruned_badge = f'<span class="badge badge-cyan">⚡ Context Pruned ({len(result.tables_in_context)} tables)</span>' if result.was_pruned else ""
        truncated_badge = '<span class="badge badge-amber">⚠️ Results Capped for RAM Safety</span>' if (result.query_result and getattr(result.query_result, "truncated", False)) else ""
        status_color = "badge-emerald" if result.status == "SUCCESS" else "badge-crimson"

        # 1. Base64 Chart Embedding
        chart_html = ""
        if figure is not None:
            try:
                buf = io.BytesIO()
                figure.savefig(
                    buf,
                    format="png",
                    dpi=140,
                    facecolor="#0A0E17",
                    edgecolor="none",
                    bbox_inches="tight"
                )
                buf.seek(0)
                b64_data = base64.b64encode(buf.read()).decode("ascii")
                chart_html = f"""
                <div class="card chart-card">
                    <div class="card-header">📊 Visual Analytics Chart</div>
                    <div class="chart-container">
                        <img src="data:image/png;base64,{b64_data}" alt="Visual Analytics Chart" class="chart-img"/>
                    </div>
                </div>
                """
            except Exception as chart_err:
                chart_html = f"""
                <div class="card">
                    <div class="card-header">📊 Visual Analytics Chart</div>
                    <div class="text-muted">Chart rendering failed: {esc(str(chart_err))}</div>
                </div>
                """

        # 2. Formatted Table HTML
        table_html = ""
        if result.query_result and result.query_result.columns:
            qr = result.query_result
            display_rows = qr.rows[:max_table_rows]
            headers_html = "".join(f"<th>{esc(col)}</th>" for col in qr.columns)

            rows_html_list: List[str] = []
            for r in display_rows:
                raw_vals = _extract_row_values(r, qr.columns)
                cells = "".join(f"<td>{esc(format_cell_value(v))}</td>" for v in raw_vals)
                rows_html_list.append(f"<tr>{cells}</tr>")
            rows_html = "\n".join(rows_html_list)

            truncation_notice = ""
            if getattr(qr, "truncated", False) or len(qr.rows) > max_table_rows:
                truncation_notice = f"""
                <div class="table-footer-notice">
                    Showing first {len(display_rows):,} of {qr.row_count:,} records (preview capped).
                </div>
                """

            table_html = f"""
            <div class="table-container">
                <table class="data-table">
                    <thead>
                        <tr>{headers_html}</tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
                {truncation_notice}
            </div>
            """
        else:
            table_html = '<div class="text-muted">No tabular data records returned.</div>'

        # 3. Assemble Self-Contained HTML Document
        document_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEXUS Executive Brief — {esc(result.natural_query[:50])}</title>
    <style>
        :root {{
            --bg-obsidian: #0A0E17;
            --bg-surface: #141B2D;
            --bg-surface-elevated: #1E293B;
            --border-color: #2A3548;
            --text-primary: #F8FAFC;
            --text-secondary: #94A3B8;
            --accent-cyan: #00F0FF;
            --accent-emerald: #10B981;
            --accent-amber: #F59E0B;
            --accent-crimson: #EF4444;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-obsidian);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            font-size: 14px;
            line-height: 1.6;
            padding: 32px 20px;
        }}
        .container {{
            max-width: 1040px;
            margin: 0 auto;
        }}
        .header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 28px;
        }}
        .brand-title {{
            font-size: 22px;
            font-weight: 700;
            color: var(--accent-cyan);
            letter-spacing: 0.5px;
        }}
        .brand-sub {{
            font-size: 12px;
            color: var(--text-secondary);
        }}
        .card {{
            background-color: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .card-header {{
            font-size: 15px;
            font-weight: 600;
            color: var(--accent-cyan);
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }}
        .meta-item {{
            background-color: var(--bg-surface-elevated);
            padding: 10px 14px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }}
        .meta-label {{
            font-size: 11px;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        .meta-value {{
            font-size: 13px;
            font-weight: 600;
            color: var(--text-primary);
            word-break: break-all;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: 600;
            border-radius: 4px;
        }}
        .badge-emerald {{ background-color: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); border: 1px solid var(--accent-emerald); }}
        .badge-cyan {{ background-color: rgba(0, 240, 255, 0.15); color: var(--accent-cyan); border: 1px solid var(--accent-cyan); }}
        .badge-amber {{ background-color: rgba(245, 158, 11, 0.15); color: var(--accent-amber); border: 1px solid var(--accent-amber); }}
        .badge-crimson {{ background-color: rgba(239, 68, 68, 0.15); color: var(--accent-crimson); border: 1px solid var(--accent-crimson); }}
        .query-box {{
            background-color: var(--bg-surface-elevated);
            border-left: 3px solid var(--accent-cyan);
            padding: 12px 16px;
            margin-bottom: 20px;
            border-radius: 0 6px 6px 0;
            font-size: 15px;
            font-weight: 500;
        }}
        .summary-content {{
            white-space: pre-wrap;
            font-size: 14px;
            color: var(--text-primary);
        }}
        pre.sql-block {{
            background-color: #070A10;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 14px;
            font-family: "Cascadia Code", "Consolas", monospace;
            font-size: 13px;
            color: #38BDF8;
            overflow-x: auto;
            white-space: pre-wrap;
        }}
        .table-container {{
            overflow-x: auto;
            border: 1px solid var(--border-color);
            border-radius: 6px;
        }}
        table.data-table {{
            width: 100%;
            border-collapse: collapse;
            font-family: "Cascadia Code", "Consolas", monospace;
            font-size: 12px;
            text-align: left;
        }}
        table.data-table th {{
            background-color: var(--bg-surface-elevated);
            color: var(--accent-cyan);
            font-weight: 600;
            padding: 10px 14px;
            border-bottom: 1px solid var(--border-color);
            white-space: nowrap;
        }}
        table.data-table td {{
            padding: 8px 14px;
            border-bottom: 1px solid rgba(42, 53, 72, 0.5);
            color: var(--text-primary);
            white-space: nowrap;
        }}
        table.data-table tr:nth-child(even) {{
            background-color: rgba(30, 41, 59, 0.35);
        }}
        table.data-table tr:hover {{
            background-color: rgba(0, 240, 255, 0.05);
        }}
        .table-footer-notice {{
            padding: 8px 14px;
            font-size: 11px;
            color: var(--accent-amber);
            background-color: rgba(245, 158, 11, 0.08);
            border-top: 1px solid var(--border-color);
        }}
        .chart-container {{
            text-align: center;
            padding: 8px 0;
        }}
        .chart-img {{
            max-width: 100%;
            height: auto;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }}
        .footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 36px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }}
        .text-muted {{ color: var(--text-secondary); }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <div class="brand-title">⚡ NEXUS ANALYTICS</div>
                <div class="brand-sub">Autonomous Text-to-SQL Executive Brief</div>
            </div>
            <div>
                <span class="badge {status_color}">{esc(result.status)}</span>
                {pruned_badge}
                {truncated_badge}
            </div>
        </header>

        <div class="query-box">
            💬 {esc(result.natural_query)}
        </div>

        <div class="card">
            <div class="card-header">📊 Execution Metadata</div>
            <div class="metadata-grid">
                <div class="meta-item">
                    <div class="meta-label">Timestamp</div>
                    <div class="meta-value">{esc(now_str)}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">AI Engine</div>
                    <div class="meta-value">{esc(result.model)} ({esc(result.provider.upper() if result.provider else 'N/A')})</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Latency / Tokens</div>
                    <div class="meta-value">{result.total_latency_ms:.2f}ms • {result.total_tokens:,} tok</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Rows Returned</div>
                    <div class="meta-value">{row_count:,} rows</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Active Tables</div>
                    <div class="meta-value">{esc(tables_str)}</div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">💡 Executive Analysis</div>
            <div class="summary-content">{esc(result.answer_markdown)}</div>
        </div>

        {chart_html}

        <div class="card">
            <div class="card-header">⚡ Verified SQLite Query</div>
            <pre class="sql-block"><code>{esc(result.generated_sql or '-- No SQL executed')}</code></pre>
        </div>

        <div class="card">
            <div class="card-header">📋 Result Data Preview</div>
            {table_html}
        </div>

        <footer class="footer">
            Compiled autonomously by <strong>NEXUS Enterprise AI Platform v1.1</strong> • All queries guarded by PRAGMA query_only=ON & QueryGuard Layer 7.
        </footer>
    </div>
</body>
</html>
"""
        with open(out_file, mode="w", encoding="utf-8") as f:
            f.write(document_html)

        return out_file
