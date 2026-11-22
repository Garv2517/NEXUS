"""
NEXUS Engine - PyInstaller-Safe Application Launcher
====================================================
Architecture Role: Production entry point and bootstrap manager for the
NEXUS Autonomous Data Pipeline & Analytics Engine.

Features:
1. Dynamic Path Resolution: Resolves repository root across normal python
   module invocations (python -m src.main / python src/main.py) and frozen
   standalone binary executions (PyInstaller sys._MEIPASS).
2. Automated Headless Smoke Testing: Supports --smoke-test CLI flag for CI/CD
   and PowerShell startup validation without hanging on mainloop().
3. Defense-in-Depth Logging: Structured error logging with zero secret leakage.

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / CustomTkinter / PyInstaller
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

# Attach standard streams to console / calling pipe if launched from terminal on Windows
if sys.platform == "win32":
    try:
        import ctypes
        import msvcrt

        # Attempt to bind existing pipe handles first (e.g. CI / PowerShell redirected pipeline)
        h_out = ctypes.windll.kernel32.GetStdHandle(-11)
        if h_out and h_out != -1:
            try:
                fd_out = msvcrt.open_osfhandle(h_out, os.O_WRONLY)
                sys.stdout = open(fd_out, "w", encoding="utf-8", buffering=1, closefd=False)
            except Exception:
                pass

        h_err = ctypes.windll.kernel32.GetStdHandle(-12)
        if h_err and h_err != -1:
            try:
                fd_err = msvcrt.open_osfhandle(h_err, os.O_WRONLY)
                sys.stderr = open(fd_err, "w", encoding="utf-8", buffering=1, closefd=False)
            except Exception:
                pass

        # If not attached to a pipe, attempt attaching to parent console
        try:
            if ctypes.windll.kernel32.AttachConsole(0xFFFFFFFF):
                sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
                sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
        except Exception:
            pass
    except Exception:
        pass

# Resolve base project directory across normal execution and PyInstaller bundles
if getattr(sys, "frozen", False):
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        PROJECT_ROOT = Path(meipass).resolve()
    else:
        PROJECT_ROOT = Path(sys.executable).resolve().parent

    # Configure bundled Tcl/Tk environments for zero-dependency execution
    for c in [PROJECT_ROOT / "tcl" / "tcl8.6", PROJECT_ROOT / "_internal" / "tcl" / "tcl8.6"]:
        if c.exists():
            os.environ["TCL_LIBRARY"] = c.as_posix()
            break

    for c in [PROJECT_ROOT / "tcl" / "tk8.6", PROJECT_ROOT / "_internal" / "tcl" / "tk8.6"]:
        if c.exists():
            os.environ["TK_LIBRARY"] = c.as_posix()
            break
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Resilient structured logging initialization
try:
    from loguru import logger
    logger.remove()
    logger.add(
        sys.stderr,
        level="INFO",
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>"
    )
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("NEXUS-Launcher")  # type: ignore

from src.ui.theme import apply_global_theme
from src.ui.app import NexusApp
from src.core.runtime_paths import ensure_runtime_directories, set_portable_mode


def emit_output(msg: str) -> None:
    """
    Emit console / CLI output reliably across GUI subsystem, PyInstaller,
    pipes, and Windows consoles.
    """
    try:
        print(msg, flush=True)
    except Exception:
        pass

    if sys.platform == "win32":
        try:
            import ctypes
            h_out = ctypes.windll.kernel32.GetStdHandle(-11)
            if not h_out or h_out == -1:
                ctypes.windll.kernel32.AttachConsole(0xFFFFFFFF)
                h_out = ctypes.windll.kernel32.GetStdHandle(-11)

            if h_out and h_out != -1:
                raw_bytes = (msg + "\r\n").encode("utf-8")
                written = ctypes.c_ulong(0)
                ctypes.windll.kernel32.WriteFile(
                    h_out, raw_bytes, len(raw_bytes), ctypes.byref(written), None
                )
        except Exception:
            pass


def run_smoke_test() -> int:
    """
    Automated non-interactive startup verification.
    Boots NexusApp, immediately withdraws the window, executes 2 event-loop ticks,
    verifies component instantiation, closes cleanly, and exits 0.
    """
    logger.info("Initiating NEXUS non-interactive startup smoke test...")
    apply_global_theme()

    app = NexusApp()
    app.withdraw()

    try:
        # Tick 1: Process initial window layout and idle tasks
        app.update_idletasks()
        app.update()
        if hasattr(app, "_poll_worker_events"):
            app._poll_worker_events()

        # Tick 2: Process background worker queues
        app.update_idletasks()
        app.update()
        if hasattr(app, "_poll_worker_events"):
            app._poll_worker_events()

        # Verify core modular components initialized cleanly
        assert app.sidebar is not None, "SidebarPanel failed to initialize."
        assert app.data_explorer_tab is not None, "DataExplorerTab failed to initialize."
        assert app.chat_tab is not None, "ChatAnalystTab failed to initialize."
        assert app.telemetry_hud_tab is not None, "TelemetryHudTab failed to initialize."
        assert app.tabview is not None, "CTkTabview failed to initialize."
        assert (
            app.tabview.get() == "Data Explorer"
        ), f"Expected default tab 'Data Explorer', got '{app.tabview.get()}'"

        logger.info("NEXUS smoke test assertions passed successfully.")
    finally:
        app.on_closing()

    # Exact token required for automated PowerShell / CI verification
    emit_output("NEXUS_SMOKE_TEST_OK")
    return 0


def main() -> int:
    """Application CLI entry point."""
    parser = argparse.ArgumentParser(
        description="NEXUS Autonomous Data Pipeline & Analytics Engine"
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Perform automated non-interactive startup verification and exit with code 0"
    )
    parser.add_argument(
        "--portable",
        action="store_true",
        help="Store persistent data in the application directory next to the executable instead of %LOCALAPPDATA%"
    )
    args = parser.parse_args()

    if args.portable:
        set_portable_mode(True)

    ensure_runtime_directories()

    if args.smoke_test:
        return run_smoke_test()

    # Normal interactive GUI execution
    logger.info("Launching NEXUS Autonomous Data Pipeline & Analytics Engine...")
    apply_global_theme()

    try:
        app = NexusApp()
        app.mainloop()
        return 0
    except KeyboardInterrupt:
        logger.info("NEXUS desktop process terminated via keyboard interrupt.")
        return 0
    except Exception as exc:
        logger.exception(f"Unhandled fatal exception in NEXUS application: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
