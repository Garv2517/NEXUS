# -*- mode: python ; coding: utf-8 -*-
"""
NEXUS Engine - Hardened PyInstaller Packaging Specification
===========================================================
Produces an enterprise-grade standalone Windows executable for the
NEXUS Autonomous Data Pipeline & Analytics Engine.

Key Architectural Guarantees:
1. Bloat Exclusion: Explicitly strips multi-gigabyte scientific and deep learning
   frameworks (torch, ultralytics, cv2, scipy, etc.) present in host site-packages.
2. Asset Bundling: Automatically bundles CustomTkinter themes/json, Matplotlib
   mpl-data, and Python 3.13 Tcl/Tk 8.6 runtime libraries for zero-dependency portability.
3. Dual Build Strategy:
   - 'onedir' (Default): Ultra-fast startup, instantaneous compilation (<60s). Output: dist/NEXUS/NEXUS.exe
   - 'onefile': Single self-contained distributable binary. Output: dist/NEXUS.exe
   Selected via environment variable NEXUS_BUILD_MODE='onedir'|'onefile'.
4. GUI Subsystem with CLI Console Attachment: Runs with console=False (no flickering
   DOS window for desktop users) while supporting --smoke-test via AttachConsole(-1).
"""

import os
import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

PROJECT_ROOT = Path(os.path.abspath(".")).resolve()

# ------------------------------------------------------------------------------
# 1. DATA FILES & ASSET COLLECTION
# ------------------------------------------------------------------------------
datas = []

# Collect CustomTkinter assets, themes, and font files
datas += collect_data_files("customtkinter")

# Collect Matplotlib baseline styles and configurations
datas += collect_data_files("matplotlib")

# Bundle sample dataset for out-of-the-box demonstration
sample_csv = PROJECT_ROOT / "data" / "raw_uploads" / "nexus_manual_test_sales.csv"
if sample_csv.exists():
    datas.append((str(sample_csv), "data/raw_uploads"))

# Bundle Python 3.13 Tcl/Tk libraries for zero-dependency offline execution
tcl_dir = Path(sys.prefix) / "tcl" / "tcl8.6"
tk_dir = Path(sys.prefix) / "tcl" / "tk8.6"
if tcl_dir.exists():
    datas.append((str(tcl_dir), "tcl/tcl8.6"))
if tk_dir.exists():
    datas.append((str(tk_dir), "tcl/tk8.6"))

# ------------------------------------------------------------------------------
# 2. HIDDEN IMPORTS & DYNAMIC REFLECTION
# ------------------------------------------------------------------------------
hiddenimports = [
    # UI Framework & Imaging
    "customtkinter",
    "PIL",
    "PIL.Image",
    "PIL.ImageTk",
    "PIL._tkinter_finder",
    # Data Visualization
    "matplotlib",
    "matplotlib.pyplot",
    "matplotlib.figure",
    "matplotlib.backends.backend_tkagg",
    "matplotlib.backends._backend_tk",
    # Data Engineering & Serialization
    "pandas",
    "openpyxl",
    "openpyxl.styles",
    "openpyxl.utils",
    "openpyxl.cell._writer",
    "et_xmlfile",
    "pydantic",
    "pydantic_core",
    "sqlparse",
    "sqlparse.engine",
    "sqlparse.filters",
    "sqlalchemy",
    "sqlalchemy.dialects.sqlite",
    "sqlite3",
    # LLM & Agent Frameworks
    "langchain",
    "langchain_core",
    "langchain_core.messages",
    "langchain_core.prompts",
    "langchain_core.output_parsers",
    "langchain_community",
    "loguru",
    "urllib.request",
    "urllib.error",
    # Internal NEXUS Packages
    "src",
    "src.main",
    "src.core",
    "src.core.runtime_paths",
    "src.core.db_manager",
    "src.core.query_guard",
    "src.core.schema_parser",
    "src.core.export_engine",
    "src.core.table_manager",
    "src.core.key_vault",
    "src.core.session_store",
    "src.etl",
    "src.etl.etl_engine",
    "src.etl.ai_profiler",
    "src.agent",
    "src.agent.llm_router",
    "src.agent.chart_engine",
    "src.agent.sql_chain",
    "src.ui",
    "src.ui.theme",
    "src.ui.formatters",
    "src.ui.async_worker",
    "src.ui.app",
    "src.ui.components",
    "src.ui.components.sidebar",
    "src.ui.components.data_explorer_tab",
    "src.ui.components.chat_tab",
    "src.ui.components.telemetry_hud_tab",
    "src.ui.components.cleaning_modal",
    "src.ui.components.sheet_picker_modal",
]

# ------------------------------------------------------------------------------
# 3. BLOAT EXCLUSIONS (CRITICAL FOR LEAN DESKTOP ARTIFACTS)
# ------------------------------------------------------------------------------
excludes = [
    # Machine Learning / Computer Vision / Heavy Scientific Runtimes
    "torch",
    "torchvision",
    "torchaudio",
    "ultralytics",
    "cv2",
    "scipy",
    "tensorboard",
    "onnx",
    "onnxruntime",
    "numba",
    "llvmlite",
    # Testing & Developer Harnesses
    "pytest",
    "_pytest",
    "IPython",
    "ipykernel",
    "jupyter",
    "jupyter_client",
    "jupyter_core",
    "notebook",
    "nbformat",
    "nbconvert",
    "tkinter.test",
    "unittest.test",
    "test",
]

# ------------------------------------------------------------------------------
# 4. ANALYSIS & COMPILATION
# ------------------------------------------------------------------------------
a = Analysis(
    [os.path.join("src", "main.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

build_mode = os.environ.get("NEXUS_BUILD_MODE", "onedir").strip().lower()

if build_mode == "onefile":
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.zipfiles,
        a.datas,
        [],
        name="NEXUS",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name="NEXUS",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name="NEXUS",
    )
