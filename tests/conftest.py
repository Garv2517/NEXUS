"""
NEXUS Test Configuration & Environment Bootstrap
================================================
Ensures deterministic Tcl/Tk 8.6 forward-slashed library resolution across
headless test executions on Windows 11 with Python 3.13.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Configure forward-slashed Tcl/Tk paths on Windows 11 before any UI modules load
if sys.platform == "win32":
    tcl_path = Path(sys.prefix) / "tcl" / "tcl8.6"
    tk_path = Path(sys.prefix) / "tcl" / "tk8.6"
    if tcl_path.exists():
        os.environ["TCL_LIBRARY"] = tcl_path.as_posix()
    if tk_path.exists():
        os.environ["TK_LIBRARY"] = tk_path.as_posix()

# Force headless Matplotlib Agg backend during test suite to prevent Tkinter state conflicts
import matplotlib
matplotlib.use("Agg")
