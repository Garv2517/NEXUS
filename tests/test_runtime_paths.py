"""
NEXUS Engine - Runtime Path Resolution Unit Tests
=================================================
Validates persistent and resource path resolutions across standard development
environments, PyInstaller frozen bundles, portable modes, and environment overrides.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from src.core.db_manager import DatabaseConfig, DatabaseManager
from src.core.runtime_paths import (
    ensure_runtime_directories,
    get_data_root,
    get_database_dir,
    get_database_path,
    get_raw_uploads_dir,
    get_resource_path,
    get_resource_root,
    is_frozen,
    is_portable,
    set_portable_mode,
)


class TestRuntimePathsDevMode:
    """Tests path resolution in normal Python development mode."""

    def setup_method(self) -> None:
        set_portable_mode(None)

    def test_dev_mode_is_not_frozen(self) -> None:
        assert not is_frozen()

    def test_dev_mode_resource_root(self) -> None:
        expected_root = Path(__file__).resolve().parent.parent
        assert get_resource_root() == expected_root

    def test_dev_mode_data_root(self) -> None:
        expected_root = Path(__file__).resolve().parent.parent
        assert get_data_root() == expected_root / "data"

    def test_dev_mode_database_path(self) -> None:
        expected_root = Path(__file__).resolve().parent.parent
        expected_db = expected_root / "data" / "database" / "nexus_workspace.db"
        assert get_database_path() == expected_db

    def test_database_config_reflects_dev_paths(self) -> None:
        expected_root = Path(__file__).resolve().parent.parent
        assert DatabaseConfig.PROJECT_ROOT == expected_root
        assert DatabaseConfig.DEFAULT_DB_DIR == expected_root / "data" / "database"
        assert DatabaseConfig.DEFAULT_DB_PATH == expected_root / "data" / "database" / "nexus_workspace.db"

    def test_database_config_instance_reflects_dev_paths(self) -> None:
        cfg = DatabaseConfig()
        expected_root = Path(__file__).resolve().parent.parent
        assert cfg.PROJECT_ROOT == expected_root
        assert cfg.DEFAULT_DB_PATH == expected_root / "data" / "database" / "nexus_workspace.db"


class TestRuntimePathsFrozenMode:
    """Tests path resolution when executing inside a PyInstaller frozen binary."""

    def setup_method(self) -> None:
        set_portable_mode(None)

    def test_frozen_mode_detection_and_resource_root(self, tmp_path: Path) -> None:
        fake_meipass = tmp_path / "_MEI12345"
        fake_meipass.mkdir()

        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "_MEIPASS", str(fake_meipass), create=True):
            assert is_frozen()
            assert get_resource_root() == fake_meipass.resolve()
            assert get_resource_path("assets/icon.ico") == (fake_meipass / "assets" / "icon.ico").resolve()

    def test_frozen_standard_mode_uses_localappdata(self, tmp_path: Path) -> None:
        fake_meipass = tmp_path / "_MEI12345"
        fake_meipass.mkdir()
        fake_localappdata = tmp_path / "AppData" / "Local"
        fake_localappdata.mkdir(parents=True)

        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "_MEIPASS", str(fake_meipass), create=True), \
             patch.dict(os.environ, {"LOCALAPPDATA": str(fake_localappdata)}, clear=False):
            
            # Ensure data root is strictly outside the ephemeral _MEIPASS folder!
            data_root = get_data_root()
            assert data_root == (fake_localappdata / "NEXUS" / "data").resolve()
            assert not str(data_root).startswith(str(fake_meipass))

            db_path = get_database_path()
            assert db_path == (fake_localappdata / "NEXUS" / "data" / "database" / "nexus_workspace.db").resolve()
            assert DatabaseConfig.DEFAULT_DB_PATH == db_path

    def test_frozen_portable_mode_stores_next_to_executable(self, tmp_path: Path) -> None:
        fake_dist_dir = tmp_path / "dist" / "NEXUS"
        fake_dist_dir.mkdir(parents=True)
        fake_exe = fake_dist_dir / "NEXUS.exe"
        fake_exe.touch()

        fake_meipass = tmp_path / "_MEI12345"
        fake_meipass.mkdir()

        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "_MEIPASS", str(fake_meipass), create=True), \
             patch.object(sys, "executable", str(fake_exe)), \
             patch.object(sys, "argv", ["NEXUS.exe", "--portable"]):
            
            assert is_portable()
            data_root = get_data_root()
            assert data_root == (fake_dist_dir / "data").resolve()
            assert get_database_path() == (fake_dist_dir / "data" / "database" / "nexus_workspace.db").resolve()
            assert not str(data_root).startswith(str(fake_meipass))

    def test_programmatic_portable_mode_toggle(self, tmp_path: Path) -> None:
        fake_dist_dir = tmp_path / "bin"
        fake_dist_dir.mkdir()
        fake_exe = fake_dist_dir / "app.exe"
        fake_exe.touch()

        fake_meipass = tmp_path / "_MEI99999"
        fake_meipass.mkdir()

        try:
            set_portable_mode(True)
            with patch.object(sys, "frozen", True, create=True), \
                 patch.object(sys, "_MEIPASS", str(fake_meipass), create=True), \
                 patch.object(sys, "executable", str(fake_exe)):
                assert is_portable()
                assert get_data_root() == (fake_dist_dir / "data").resolve()
        finally:
            set_portable_mode(None)


class TestRuntimePathsOverridesAndDirectoryCreation:
    """Tests environment variable overrides and directory auto-creation."""

    def setup_method(self) -> None:
        set_portable_mode(None)

    def test_nexus_data_dir_env_override(self, tmp_path: Path) -> None:
        custom_data = tmp_path / "custom_nexus_storage"
        custom_data.mkdir()

        with patch.dict(os.environ, {"NEXUS_DATA_DIR": str(custom_data)}):
            assert get_data_root() == custom_data.resolve()
            assert get_database_dir() == (custom_data / "database").resolve()
            assert get_database_path() == (custom_data / "database" / "nexus_workspace.db").resolve()
            assert get_raw_uploads_dir() == (custom_data / "raw_uploads").resolve()

    def test_ensure_runtime_directories_creates_all_subfolders(self, tmp_path: Path) -> None:
        sandbox_data = tmp_path / "sandbox_data"
        with patch.dict(os.environ, {"NEXUS_DATA_DIR": str(sandbox_data)}):
            assert not (sandbox_data / "database").exists()
            assert not (sandbox_data / "raw_uploads").exists()

            ensure_runtime_directories()

            assert (sandbox_data / "database").is_dir()
            assert (sandbox_data / "raw_uploads").is_dir()
