"""
NEXUS Engine - High-Performance Pure-Python Data Formatters
===========================================================
Architecture Role: Clean numerical and tabular data formatting for UI
grids, ASCII console previews, and export channels.

Invariants:
- Zero Tkinter / CustomTkinter dependencies (pure Python stdlib).
- Eliminates IEEE-754 binary floating point precision artifacts.
- Preserves raw integer formatting for IDs/years (avoids e.g. 1,001 for order IDs).
- Renders deterministic, aligned monospace ASCII tables with truncation notices.

Author: Senior Systems & Security Engineer
Target Platform: Windows 11 / Python 3.13 / Desktop Executable
"""

from __future__ import annotations

import math
import sqlite3
from typing import Any, List, Optional, Sequence


def format_cell_value(val: Any, float_precision: int = 2) -> str:
    """
    Formats an individual cell value into a display-ready string.

    Rules:
    - None -> "NULL"
    - bool -> "True" / "False" (checked prior to int)
    - int -> unformatted string without thousands commas (e.g. 2026, 1001)
    - float: cleanly eliminates IEEE-754 precision artifacts:
        - NaN -> "NaN"
        - Inf -> "Infinity" / "-Infinity"
        - 239365.96000000002 -> "239,365.96"
        - 1160577.8800000001 -> "1,160,577.88"
        - Whole number floats like 0.0 -> "0.00"
        - Small ratios/rates in (-10, 10) like 0.4089 -> "0.4089" (up to 4 decimals without noise zeros)
    - str -> collapses linebreaks for clean tabular grid display
    - other -> standard string representation
    """
    if val is None:
        return "NULL"

    # In Python, bool is a subclass of int; check bool first
    if isinstance(val, bool):
        return "True" if val else "False"

    if isinstance(val, int):
        return str(val)

    if isinstance(val, float):
        if math.isnan(val):
            return "NaN"
        if math.isinf(val):
            return "Infinity" if val > 0 else "-Infinity"

        # Round to 8 decimal places to strip IEEE-754 representation noise
        cleaned = round(val, 8)

        # For small numbers/rates in (-10, 10)
        if -10 < cleaned < 10:
            if cleaned == 0.0 or cleaned.is_integer():
                return f"{cleaned:.{float_precision}f}"
            s = f"{cleaned:.4f}".rstrip("0").rstrip(".")
            parts = s.split(".")
            if len(parts) == 1:
                return f"{parts[0]}.{'0' * float_precision}"
            elif len(parts[1]) < float_precision:
                return f"{parts[0]}.{parts[1]:<0{float_precision}}"
            return s
        else:
            # For larger numbers: format with commas and requested precision
            return f"{cleaned:,.{float_precision}f}"

    s = str(val)
    return " ".join(s.splitlines())


def format_ascii_table(
    columns: Sequence[str],
    rows: Sequence[Any],
    max_rows: int = 100,
    truncated: bool = False
) -> str:
    """
    Renders an aligned monospace ASCII table using format_cell_value(),
    appending a clear truncation footer note if truncated=True or len(rows) > max_rows.

    Parameters:
        columns: Header column names.
        rows: Sequence of records (each record can be a dict, tuple, list, or scalar).
        max_rows: Maximum data rows to render before truncation (default 100).
        truncated: Flag indicating if source query was truncated by safety cap.

    Returns:
        Monospace ASCII table string suitable for text widgets or console output.
    """
    if not columns:
        return ""

    display_rows = rows[:max_rows]
    is_truncated = truncated or (len(rows) > max_rows)

    # Format cells across all display rows
    formatted_data: List[List[str]] = []
    for r in display_rows:
        if isinstance(r, dict):
            row_vals = [format_cell_value(r.get(c)) for c in columns]
        elif isinstance(r, (list, tuple, sqlite3.Row)):
            row_vals = [
                format_cell_value(r[i]) if i < len(r) else "NULL"
                for i in range(len(columns))
            ]
        elif hasattr(r, "__getitem__") and not isinstance(r, (str, bytes)):
            try:
                row_vals = [
                    format_cell_value(r[i]) if i < len(r) else "NULL"
                    for i in range(len(columns))
                ]
            except Exception:
                row_vals = [format_cell_value(r)] + ["NULL"] * (len(columns) - 1)
        else:
            row_vals = [format_cell_value(r)] + ["NULL"] * (len(columns) - 1)
        formatted_data.append(row_vals)

    # Compute column widths ensuring header and all cells fit
    col_widths = [len(str(col)) for col in columns]
    for row_vals in formatted_data:
        for idx, val in enumerate(row_vals):
            col_widths[idx] = max(col_widths[idx], len(val))

    # Construct boundary and header lines
    sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    header = "| " + " | ".join(str(col).ljust(col_widths[i]) for i, col in enumerate(columns)) + " |"

    lines = [sep, header, sep]
    for row_vals in formatted_data:
        row_str = "| " + " | ".join(val.ljust(col_widths[i]) for i, val in enumerate(row_vals)) + " |"
        lines.append(row_str)
    lines.append(sep)

    if is_truncated:
        lines.append(f"\n[Showing first {len(display_rows)} row(s) (results truncated)]")

    return "\n".join(lines)
