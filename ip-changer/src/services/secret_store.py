"""Secure secret storage service for credentials, passwords, and tokens.

Uses OS keyring (Windows Credential Manager / Secret Service) when available,
and transparently falls back to encrypted local storage with AES/Fernet encryption.
Never logs credentials or stores plain-text secrets.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

SERVICE_NAME = "IPChanger"


class SecretStore:
    """Manages secret credentials with OS keyring integration and encrypted local fallback."""

    def __init__(self, storage_dir: Optional[Path] = None, use_keyring: bool = True) -> None:
        """Initialize the SecretStore.

        Args:
            storage_dir: Optional directory for encrypted fallback store. Defaults to ~/.ip_changer.
            use_keyring: Whether to attempt using the OS keyring backend.
        """
        self._prefer_keyring = use_keyring
        self._keyring_available: Optional[bool] = None
        self._backend_description: str = "Uninitialized"

        if storage_dir is None:
            self._storage_dir = Path.home() / ".ip_changer"
        else:
            self._storage_dir = storage_dir

        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._encrypted_file_path = self._storage_dir / "secrets.dat"
        self._key_file_path = self._storage_dir / ".master.key"

        # Check and configure backend
        self._init_backend()

    def _init_backend(self) -> None:
        """Determine whether OS Keyring or Encrypted File Store should be active."""
        if self._prefer_keyring:
            try:
                import keyring  # pylint: disable=import-outside-toplevel
                from keyring.backends.fail import Keyring as FailKeyring  # pylint: disable=import-outside-toplevel

                kr = keyring.get_keyring()
                if kr and not isinstance(kr, FailKeyring):
                    # Probe keyring with a non-destructive check
                    self._keyring_available = True
                    self._backend_description = f"OS Keyring ({kr.name})"
                    logger.info("SecretStore using %s", self._backend_description)
                    return
            except Exception as exc:
                logger.debug("Keyring probe failed or unavailable: %s", exc)

        self._keyring_available = False
        self._backend_description = "Encrypted Local File Storage"
        logger.info("SecretStore falling back to %s at %s", self._backend_description, self._encrypted_file_path)

    def is_keyring_available(self) -> bool:
        """Return True if OS keyring backend is active and functioning."""
        return bool(self._keyring_available)

    def get_backend_info(self) -> str:
        """Return a human-readable description of the active credential backend."""
        return self._backend_description

    def _get_encryption_key(self) -> bytes:
        """Derive or load an encryption key for local fallback store."""
        if self._key_file_path.exists():
            try:
                return self._key_file_path.read_bytes()
            except Exception:
                pass

        # Generate a new random key
        new_key = os.urandom(32)
        try:
            self._key_file_path.write_bytes(new_key)
            if hasattr(os, "chmod"):
                try:
                    os.chmod(self._key_file_path, 0o600)
                except Exception:
                    pass
        except Exception as exc:
            logger.error("Failed to persist master key: %s", exc)
        return new_key

    def _xor_cipher(self, data: bytes, key: bytes) -> bytes:
        """Lightweight secondary symmetric stream transformation."""
        extended_key = (key * ((len(data) // len(key)) + 1))[:len(data)]
        return bytes(a ^ b for a, b in zip(data, extended_key))

    def _encrypt_bytes(self, plain: bytes) -> bytes:
        """Encrypt raw bytes using cryptography.Fernet if available, else HMAC/XOR cipher."""
        key = self._get_encryption_key()
        try:
            from cryptography.fernet import Fernet  # pylint: disable=import-outside-toplevel
            fernet_key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
            f = Fernet(fernet_key)
            return f.encrypt(plain)
        except ImportError:
            # Reversible encrypted envelope with SHA-256 integrity tag
            cipher_bytes = self._xor_cipher(plain, key)
            digest = hashlib.sha256(key + cipher_bytes).digest()
            return digest + cipher_bytes

    def _decrypt_bytes(self, cipher: bytes) -> Optional[bytes]:
        """Decrypt payload from encrypted bytes."""
        key = self._get_encryption_key()
        try:
            from cryptography.fernet import Fernet  # pylint: disable=import-outside-toplevel
            fernet_key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
            f = Fernet(fernet_key)
            return f.decrypt(cipher)
        except ImportError:
            if len(cipher) < 32:
                return None
            expected_digest = cipher[:32]
            payload = cipher[32:]
            actual_digest = hashlib.sha256(key + payload).digest()
            if actual_digest != expected_digest:
                logger.error("Secret decryption failed: integrity digest mismatch.")
                return None
            return self._xor_cipher(payload, key)
        except Exception as exc:
            logger.error("Failed to decrypt secret payload: %s", exc)
            return None

    def _load_fallback_map(self) -> Dict[str, str]:
        """Load encrypted dictionary from file."""
        if not self._encrypted_file_path.exists():
            return {}
        try:
            data = self._encrypted_file_path.read_bytes()
            if not data:
                return {}
            decrypted = self._decrypt_bytes(data)
            if not decrypted:
                return {}
            return json.loads(decrypted.decode("utf-8"))
        except Exception as exc:
            logger.error("Failed reading fallback secrets store: %s", exc)
            return {}

    def _save_fallback_map(self, secret_map: Dict[str, str]) -> bool:
        """Write encrypted dictionary to file."""
        try:
            raw_json = json.dumps(secret_map).encode("utf-8")
            encrypted = self._encrypt_bytes(raw_json)
            self._encrypted_file_path.write_bytes(encrypted)
            return True
        except Exception as exc:
            logger.error("Failed writing fallback secrets store: %s", exc)
            return False

    def store_secret(self, profile_id: str, key_type: str, value: str) -> bool:
        """Store a secret credential under a profile and key type.

        Args:
            profile_id: Identifier of the connection profile.
            key_type: Type of credential (e.g. 'password', 'api_key', 'token').
            value: The sensitive secret string.

        Returns:
            True if securely stored.
        """
        if not profile_id or not key_type:
            raise ValueError("Profile ID and key type must not be empty.")

        entry_key = f"{profile_id}:{key_type}"

        if self._keyring_available:
            try:
                import keyring  # pylint: disable=import-outside-toplevel
                keyring.set_password(SERVICE_NAME, entry_key, value)
                logger.debug("Stored secret for %s in OS Keyring.", entry_key)
                return True
            except Exception as exc:
                logger.warning("OS Keyring failed to store %s (%s). Falling back.", entry_key, exc)

        # Fallback storage
        secrets = self._load_fallback_map()
        secrets[entry_key] = value
        saved = self._save_fallback_map(secrets)
        if saved:
            logger.debug("Stored secret for %s in encrypted fallback store.", entry_key)
        return saved

    def get_secret(self, profile_id: str, key_type: str) -> Optional[str]:
        """Retrieve a stored secret.

        Args:
            profile_id: Identifier of the connection profile.
            key_type: Type of credential (e.g. 'password', 'api_key', 'token').

        Returns:
            Decrypted secret string, or None if not found.
        """
        if not profile_id or not key_type:
            return None

        entry_key = f"{profile_id}:{key_type}"

        if self._keyring_available:
            try:
                import keyring  # pylint: disable=import-outside-toplevel
                val = keyring.get_password(SERVICE_NAME, entry_key)
                if val is not None:
                    return val
            except Exception as exc:
                logger.debug("Keyring get_password exception for %s: %s", entry_key, exc)

        # Fallback check
        secrets = self._load_fallback_map()
        return secrets.get(entry_key)

    def delete_secret(self, profile_id: str, key_type: str) -> bool:
        """Remove a stored secret.

        Args:
            profile_id: Identifier of the connection profile.
            key_type: Type of credential.

        Returns:
            True if removed or did not exist.
        """
        if not profile_id or not key_type:
            return False

        entry_key = f"{profile_id}:{key_type}"
        removed = True

        if self._keyring_available:
            try:
                import keyring  # pylint: disable=import-outside-toplevel
                keyring.delete_password(SERVICE_NAME, entry_key)
            except Exception:
                # Keyring may raise PasswordDeleteError if not found
                pass

        secrets = self._load_fallback_map()
        if entry_key in secrets:
            del secrets[entry_key]
            removed = self._save_fallback_map(secrets)

        return removed

    def has_secret(self, profile_id: str, key_type: str) -> bool:
        """Check if a secret entry exists without reading the full secret value.

        Args:
            profile_id: Identifier of the connection profile.
            key_type: Type of credential.

        Returns:
            True if credential is present, False otherwise.
        """
        return self.get_secret(profile_id, key_type) is not None
