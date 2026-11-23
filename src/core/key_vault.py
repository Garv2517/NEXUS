"""
NEXUS Engine - Windows DPAPI Key Vault
======================================
Architecture Role: OS-level user-bound encrypted persistence for cloud AI API
credentials using native Win32 Data Protection API (DPAPI).

Security & Architectural Invariants:
1. OS-Level User-Bound Encryption:
   Ciphertext is strongly encrypted via crypt32.CryptProtectData with
   fixed application entropy ("NEXUS-DPAPI-VAULT-V1.1"). It is cryptographically
   bound to the active Windows user account login credentials.
2. Zero External Dependencies:
   Implemented strictly using Python standard library ctypes and ctypes.wintypes.
3. Memory & Native Heap Hygiene:
   LocalFree is invoked deterministically inside finally blocks on all native
   heap buffers allocated by CryptProtectData and CryptUnprotectData.
4. Zero Plaintext Leakage:
   Plaintext secrets are never logged, formatted into error messages, or written
   to disk in unencrypted form.
5. Atomic Persistence:
   Vault updates are serialized atomically to disk using staging files and os.replace
   to eliminate corrupt writes during power loss or abrupt termination.
6. Freeze-Safe Pathing:
   Resolves path via src/core/runtime_paths.py, working cleanly across dev mode,
   %LOCALAPPDATA%\\NEXUS\\data, and --portable mode.

Author: Senior Systems & Security Engineer
Platform: Windows 11 (Python 3.13) / PyInstaller
"""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Resilient logging initialization
try:
    from loguru import logger
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("NEXUS-KeyVault")  # type: ignore

from src.core.runtime_paths import get_vault_dir, get_writable_data_dir


class KeyVaultError(Exception):
    """Raised when encryption, decryption, or vault storage operations fail."""
    pass


# ==============================================================================
# WIN32 DPAPI CTYPES DEFINITIONS
# ==============================================================================

CRYPTPROTECT_UI_FORBIDDEN: int = 0x01
VAULT_ENTROPY: bytes = b"NEXUS-DPAPI-VAULT-V1.1"

_IS_WINDOWS = sys.platform == "win32"
_CRYPT32 = None
_KERNEL32 = None

if _IS_WINDOWS:
    import ctypes
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        """Win32 DATA_BLOB structure used by CryptoAPI / DPAPI."""
        _fields_ = [
            ("cbData", wt.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    try:
        _CRYPT32 = ctypes.windll.crypt32
        _KERNEL32 = ctypes.windll.kernel32

        _CRYPT32.CryptProtectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            wt.LPCWSTR,
            ctypes.POINTER(DATA_BLOB),
            wt.LPVOID,
            wt.LPVOID,
            wt.DWORD,
            ctypes.POINTER(DATA_BLOB),
        ]
        _CRYPT32.CryptProtectData.restype = wt.BOOL

        _CRYPT32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),
            wt.LPVOID,
            ctypes.POINTER(DATA_BLOB),
            wt.LPVOID,
            wt.LPVOID,
            wt.DWORD,
            ctypes.POINTER(DATA_BLOB),
        ]
        _CRYPT32.CryptUnprotectData.restype = wt.BOOL

        _KERNEL32.LocalFree.argtypes = [wt.HLOCAL]
        _KERNEL32.LocalFree.restype = wt.HLOCAL

    except Exception as exc:
        logger.warning(f"Failed to load Win32 crypt32/kernel32 libraries: {exc}")
        _CRYPT32 = None
        _KERNEL32 = None


def _dpapi_protect(plaintext: bytes, entropy: bytes = VAULT_ENTROPY) -> bytes:
    """
    Encrypts bytes using Windows DPAPI CryptProtectData with application-scoped entropy.
    Guarantees deterministic LocalFree buffer deallocation.
    """
    if not _IS_WINDOWS or _CRYPT32 is None or _KERNEL32 is None:
        raise KeyVaultError("Windows DPAPI is only supported on Windows platforms.")

    in_blob = DATA_BLOB(
        len(plaintext),
        ctypes.cast(ctypes.create_string_buffer(plaintext), ctypes.POINTER(ctypes.c_char)),
    )
    ent_blob = DATA_BLOB(
        len(entropy),
        ctypes.cast(ctypes.create_string_buffer(entropy), ctypes.POINTER(ctypes.c_char)),
    )
    out_blob = DATA_BLOB()

    success = _CRYPT32.CryptProtectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )

    if not success:
        err_code = ctypes.GetLastError()
        raise KeyVaultError(f"CryptProtectData failed with Windows error code: {err_code}")

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _KERNEL32.LocalFree(out_blob.pbData)


def _dpapi_unprotect(ciphertext: bytes, entropy: bytes = VAULT_ENTROPY) -> bytes:
    """
    Decrypts bytes using Windows DPAPI CryptUnprotectData with application-scoped entropy.
    Guarantees deterministic LocalFree buffer deallocation.
    """
    if not _IS_WINDOWS or _CRYPT32 is None or _KERNEL32 is None:
        raise KeyVaultError("Windows DPAPI is only supported on Windows platforms.")

    in_blob = DATA_BLOB(
        len(ciphertext),
        ctypes.cast(ctypes.create_string_buffer(ciphertext), ctypes.POINTER(ctypes.c_char)),
    )
    ent_blob = DATA_BLOB(
        len(entropy),
        ctypes.cast(ctypes.create_string_buffer(entropy), ctypes.POINTER(ctypes.c_char)),
    )
    out_blob = DATA_BLOB()

    success = _CRYPT32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )

    if not success:
        err_code = ctypes.GetLastError()
        raise KeyVaultError(f"CryptUnprotectData failed with Windows error code: {err_code}")

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        _KERNEL32.LocalFree(out_blob.pbData)


# ==============================================================================
# WINDOWS DPAPI VAULT
# ==============================================================================

class WindowsDPAPIVault:
    """
    Secure persistent vault managing AI provider credentials encrypted via Windows DPAPI.
    Stores ciphertext base64 blobs in JSON with atomic updates.
    """

    VAULT_VERSION: int = 1

    def __init__(
        self,
        vault_path: Optional[Union[str, Path]] = None,
        vault_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        if vault_path is not None:
            self._vault_path = Path(vault_path).resolve()
            self._vault_dir = self._vault_path.parent
        elif vault_dir is not None:
            self._vault_dir = Path(vault_dir).resolve()
            self._vault_path = (self._vault_dir / "nexus_keys.vault.json").resolve()
        else:
            self._vault_dir = get_vault_dir().resolve()
            self._vault_path = (self._vault_dir / "nexus_keys.vault.json").resolve()

    @property
    def vault_path(self) -> Path:
        """Returns the absolute path to the vault file."""
        return self._vault_path

    @property
    def vault_file(self) -> Path:
        """Alias for vault_path."""
        return self._vault_path

    @staticmethod
    def is_supported() -> bool:
        """Returns True if running on Windows and CryptoAPI is functional."""
        return _IS_WINDOWS and (_CRYPT32 is not None) and (_KERNEL32 is not None)

    # --------------------------------------------------------------------------
    # INTERNAL FILE OPERATIONS
    # --------------------------------------------------------------------------

    def _read_vault_dict(self, raise_on_corrupt: bool = False) -> Dict[str, Any]:
        """Reads and parses the vault JSON file safely."""
        if not self._vault_path.exists():
            return {"version": self.VAULT_VERSION, "keys": {}}

        try:
            content = self._vault_path.read_text(encoding="utf-8")
            if not content.strip():
                return {"version": self.VAULT_VERSION, "keys": {}}
            parsed = json.loads(content)
            if not isinstance(parsed, dict) or "keys" not in parsed:
                raise ValueError("Vault JSON schema is invalid or malformed.")
            return parsed
        except Exception as exc:
            logger.warning("Corrupted or unreadable vault JSON file detected.")
            if raise_on_corrupt:
                raise KeyVaultError(f"Failed to read vault file: {exc}") from exc
            return {"version": self.VAULT_VERSION, "keys": {}}

    def _write_vault_dict(self, data: Dict[str, Any]) -> None:
        """Atomically writes vault data to disk via a temporary file and os.replace."""
        self._vault_dir.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(data, indent=2, sort_keys=True)

        temp_file = None
        try:
            # Create temporary file in the same directory to guarantee atomic rename on the same filesystem
            fd, temp_path = tempfile.mkstemp(
                prefix="nexus_vault_",
                suffix=".tmp",
                dir=str(self._vault_dir)
            )
            temp_file = Path(temp_path)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(serialized)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_path, self._vault_path)
        except Exception as exc:
            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass
            raise KeyVaultError(f"Atomic vault write failed: {exc}") from exc

    # --------------------------------------------------------------------------
    # PUBLIC API
    # --------------------------------------------------------------------------

    def save_key(self, provider: str, api_key: str) -> None:
        """
        Encrypts and stores an API key for the given provider.
        Normalizes provider name to uppercase and rejects empty keys.
        """
        if not self.is_supported():
            raise KeyVaultError("Windows DPAPI vault is not supported on this platform.")

        norm_provider = str(provider).strip().lower()
        if not norm_provider:
            raise KeyVaultError("Provider name cannot be empty.")

        cleaned_key = str(api_key).strip() if api_key else ""
        if not cleaned_key:
            raise KeyVaultError(f"Cannot save empty API key for provider '{norm_provider}'.")

        # 1. Encrypt key bytes via DPAPI
        try:
            encrypted_bytes = _dpapi_protect(cleaned_key.encode("utf-8"))
            b64_blob = base64.b64encode(encrypted_bytes).decode("ascii")
        except Exception as exc:
            raise KeyVaultError(f"DPAPI encryption failed for provider '{norm_provider}': {exc}") from exc

        # 2. Update vault JSON dictionary atomically
        vault_data = self._read_vault_dict(raise_on_corrupt=False)
        if "keys" not in vault_data or not isinstance(vault_data["keys"], dict):
            vault_data["keys"] = {}
        vault_data["version"] = self.VAULT_VERSION
        vault_data["keys"][norm_provider] = b64_blob

        self._write_vault_dict(vault_data)
        logger.info(f"Credential securely saved in DPAPI vault for provider: {norm_provider}")

    def load_key(self, provider: str, raise_on_corrupt: bool = False) -> Optional[str]:
        """
        Loads and decrypts the stored API key for the specified provider.
        Returns None if not stored. If corruption or decryption error occurs,
        raises KeyVaultError if raise_on_corrupt=True, else returns None.
        """
        if not self.is_supported():
            if raise_on_corrupt:
                raise KeyVaultError("Windows DPAPI vault is not supported on this platform.")
            return None

        norm_provider = str(provider).strip().lower()
        if not norm_provider:
            return None

        vault_data = self._read_vault_dict(raise_on_corrupt=raise_on_corrupt)
        b64_blob = vault_data.get("keys", {}).get(norm_provider)
        if not b64_blob:
            return None

        try:
            encrypted_bytes = base64.b64decode(b64_blob)
            decrypted_bytes = _dpapi_unprotect(encrypted_bytes)
            return decrypted_bytes.decode("utf-8")
        except Exception as exc:
            logger.warning(f"Failed to decrypt stored credential for provider '{norm_provider}'.")
            if raise_on_corrupt:
                raise KeyVaultError(f"Failed to decrypt key for '{norm_provider}': {exc}") from exc
            return None

    def has_key(self, provider: str) -> bool:
        """Checks if a ciphertext entry exists for the given provider."""
        norm_provider = str(provider).strip().lower()
        if not norm_provider:
            return False
        vault_data = self._read_vault_dict(raise_on_corrupt=False)
        return bool(vault_data.get("keys", {}).get(norm_provider))

    def delete_key(self, provider: str) -> bool:
        """
        Removes the stored credential for the specified provider.
        Returns True if an entry was removed, False if not present.
        """
        norm_provider = str(provider).strip().lower()
        if not norm_provider:
            return False

        vault_data = self._read_vault_dict(raise_on_corrupt=False)
        keys_dict = vault_data.get("keys", {})
        if norm_provider not in keys_dict:
            return False

        del keys_dict[norm_provider]
        self._write_vault_dict(vault_data)
        logger.info(f"Credential removed from DPAPI vault for provider: {norm_provider}")
        return True

    def clear_all(self) -> None:
        """Clears all stored credentials and cleans the vault file."""
        if self._vault_path.exists():
            try:
                self._vault_path.unlink()
                logger.info("DPAPI vault file cleared.")
            except Exception as exc:
                logger.warning(f"Failed to remove vault file: {exc}")
                # Overwrite with empty keys if unlink fails
                self._write_vault_dict({"version": self.VAULT_VERSION, "keys": {}})

    def list_saved_providers(self) -> List[str]:
        """Returns a sorted list of provider names that have stored credentials."""
        vault_data = self._read_vault_dict(raise_on_corrupt=False)
        keys_dict = vault_data.get("keys", {})
        if isinstance(keys_dict, dict):
            return sorted(keys_dict.keys())
        return []
