"""
NEXUS Engine - Runtime Path Resolution
======================================
Architecture Role: Dynamic and persistent path manager ensuring zero data loss
across normal Python interpreter sessions and frozen PyInstaller executables.

Invariants & Guarantees:
1. Resource Root: In frozen mode (PyInstaller), resolves to sys._MEIPASS (assets,
   themes, bundled data). In dev mode, resolves to the repository root.
2. Persistent Data Root: In frozen mode, persistent databases and user uploads are
   stored in %LOCALAPPDATA%\\NEXUS\\data (or application directory in --portable mode
   or NEXUS_DATA_DIR env override). This prevents the critical PyInstaller bug where
   data written to %TEMP%\\_MEIxxxxx is permanently deleted upon process exit.
3. Dev Mode Parity: In standard development, data paths continue to default to
   <repo_root>/data, preserving 100% backward compatibility for all test suites.

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / PyInstaller
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional, Union

# Global programmatic override for portable mode
_PORTABLE_OVERRIDE: Optional[bool] = None


def is_frozen() -> bool:
    """Return True if running inside a PyInstaller frozen binary."""
    return getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS")


def set_portable_mode(enabled: Optional[bool]) -> None:
    """
    Programmatically toggle portable mode.
    Pass True to force portable, False to force standard, or None to reset to CLI/env detection.
    """
    global _PORTABLE_OVERRIDE
    _PORTABLE_OVERRIDE = enabled


def is_portable() -> bool:
    """
    Check if portable mode is enabled.
    Portable mode stores data in a 'data' directory adjacent to the executable.
    Triggered by:
    1. Programmatic set_portable_mode(True)
    2. CLI argument '--portable' in sys.argv
    3. Environment variable NEXUS_PORTABLE=1/true
    """
    if _PORTABLE_OVERRIDE is not None:
        return _PORTABLE_OVERRIDE

    if "--portable" in sys.argv:
        return True

    env_val = os.environ.get("NEXUS_PORTABLE", "").strip().lower()
    return env_val in ("1", "true", "yes", "on")


def get_resource_root() -> Path:
    """
    Return the root directory for read-only bundled assets, icons, and themes.
    - Frozen: sys._MEIPASS (temporary extraction directory created by PyInstaller)
    - Dev: Repository root directory containing 'src', 'data', etc.
    """
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass).resolve()
        return Path(sys.executable).resolve().parent

    # Dev mode: src/core/runtime_paths.py -> parent(core) -> parent(src) -> parent(repo)
    return Path(__file__).resolve().parent.parent.parent


def get_resource_path(relative_path: Union[str, Path]) -> Path:
    """Resolve a path relative to the resource root."""
    return (get_resource_root() / relative_path).resolve()


def get_data_root() -> Path:
    """
    Return the persistent writable root directory for databases and uploads.
    Resolution Priority:
    1. NEXUS_DATA_DIR environment variable (explicit override).
    2. Portable mode:
       - Frozen: <executable_dir>/data
       - Dev: <repo_root>/data
    3. Standard mode:
       - Frozen: %LOCALAPPDATA%\\NEXUS\\data (Windows) or ~/.nexus/data (POSIX)
       - Dev: <repo_root>/data
    """
    # 1. Environment variable override
    env_dir = os.environ.get("NEXUS_DATA_DIR")
    if env_dir:
        return Path(env_dir).resolve()

    # 2. Portable mode
    if is_portable():
        if is_frozen():
            return (Path(sys.executable).resolve().parent / "data").resolve()
        return (get_resource_root() / "data").resolve()

    # 3. Standard execution
    if is_frozen():
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return (Path(local_app_data) / "NEXUS" / "data").resolve()
        # Fallback for non-Windows or environments without LOCALAPPDATA
        return (Path.home() / ".nexus" / "data").resolve()

    # Dev mode default
    return (get_resource_root() / "data").resolve()


def get_database_dir() -> Path:
    """Return the persistent directory housing the SQLite database."""
    return get_data_root() / "database"


def get_database_path() -> Path:
    """Return the full persistent path to nexus_workspace.db."""
    return get_database_dir() / "nexus_workspace.db"


def get_raw_uploads_dir() -> Path:
    """Return the persistent directory housing raw uploaded files."""
    return get_data_root() / "raw_uploads"


def ensure_runtime_directories() -> None:
    """Ensure persistent directories for database and raw uploads exist on disk."""
    get_database_dir().mkdir(parents=True, exist_ok=True)
    get_raw_uploads_dir().mkdir(parents=True, exist_ok=True)
