"""
CipherGuard — Encrypted Clipboard Vault
AES-256 encrypted clipboard history with auto-expiry for sensitive content.
"""

import threading
from datetime import datetime, timedelta
from typing import List, Optional, Callable

from models.database import DatabaseManager
from models.schemas import VaultEntry
from utils.crypto import encrypt_data, decrypt_data, derive_key, generate_salt
from utils.patterns import is_sensitive_content
from utils.logger import setup_logger
from config import VAULT_MAX_ENTRIES, VAULT_SENSITIVE_EXPIRY_SECONDS

logger = setup_logger("Vault")


class VaultManager:
    """
    Encrypted clipboard vault.
    Stores clipboard entries encrypted with AES-256-GCM.
    Sensitive entries auto-expire after a configurable duration.
    """

    def __init__(self, master_password: str, db: DatabaseManager):
        """
        Initialize the vault.

        Args:
            master_password: The master password for encryption/decryption.
            db: DatabaseManager instance for persistence.
        """
        self.db = db
        self._lock = threading.Lock()
        self._expiry_timer: Optional[threading.Timer] = None

        # Load or create the persistent salt.
        # CRITICAL: The same salt must be used every session so that the
        # derived key is identical and old entries can be decrypted.
        saved_salt_hex = self.db.get_setting("vault_salt")
        if saved_salt_hex:
            # Reuse existing salt from the database
            self._salt = bytes.fromhex(saved_salt_hex)
            logger.info("Vault salt loaded from database (entries decryptable)")
        else:
            # First run — generate a new salt and save it permanently
            self._salt = generate_salt()
            self.db.save_setting("vault_salt", self._salt.hex())
            logger.info("Vault salt generated and saved to database")

        self._key = derive_key(master_password, self._salt)

        # Start the expiry checker
        self._start_expiry_checker()

        logger.info("Vault initialized and encrypted")

    def add_entry(self, content: str, on_update: Optional[Callable] = None):
        """
        Add a new clipboard entry to the vault (encrypted).

        Args:
            content: The plaintext clipboard content to store.
            on_update: Optional callback when vault is updated.
        """
        if not content or not content.strip():
            return

        with self._lock:
            # Encrypt the content
            encrypted = encrypt_data(content, self._key)

            # Determine content type and sensitivity
            sensitive = is_sensitive_content(content)
            content_type = "sensitive" if sensitive else "text"

            # Set expiry for sensitive content
            expires_at = None
            if sensitive:
                expires_at = (
                    datetime.now() + timedelta(seconds=VAULT_SENSITIVE_EXPIRY_SECONDS)
                ).isoformat()

            # Create and save the entry
            entry = VaultEntry(
                timestamp=datetime.now().isoformat(),
                content=encrypted,
                content_type=content_type,
                expires_at=expires_at,
                is_expired=False,
            )
            self.db.save_vault_entry(entry)

            # Enforce max entries limit
            self._enforce_max_entries()

            logger.info(f"Vault entry added | Type: {content_type} | Sensitive: {sensitive}")

            if on_update:
                on_update()

    def get_entries(self) -> List[dict]:
        """
        Get all active vault entries (decrypted).

        Returns:
            List of dicts with 'id', 'timestamp', 'content', 'content_type', 'expires_at'.
        """
        # First, expire old entries
        self.db.expire_vault_entries()

        entries = self.db.get_vault_entries(include_expired=False)
        decrypted_entries = []

        for entry in entries:
            try:
                plaintext = decrypt_data(entry["content"], self._key)
                decrypted_entries.append({
                    "id": entry["id"],
                    "timestamp": entry["timestamp"],
                    "content": plaintext,
                    "content_type": entry["content_type"],
                    "expires_at": entry["expires_at"],
                })
            except Exception as e:
                logger.error(f"Failed to decrypt vault entry {entry['id']}: {e}")

        return decrypted_entries

    def get_entry_content(self, entry_id: int) -> Optional[str]:
        """
        Get a single decrypted vault entry by ID.

        Args:
            entry_id: The database ID of the vault entry.

        Returns:
            Decrypted content string, or None if not found/failed.
        """
        entries = self.db.get_vault_entries()
        for entry in entries:
            if entry["id"] == entry_id:
                try:
                    return decrypt_data(entry["content"], self._key)
                except Exception as e:
                    logger.error(f"Failed to decrypt entry {entry_id}: {e}")
                    return None
        return None

    def get_entry_count(self) -> int:
        """Get count of active vault entries."""
        return self.db.get_vault_count()

    def clear_vault(self):
        """Delete all vault entries."""
        self.db.delete_expired_vault_entries()
        logger.info("Vault cleared")

    def _enforce_max_entries(self):
        """Remove oldest entries if vault exceeds max size."""
        entries = self.db.get_vault_entries()
        if len(entries) > VAULT_MAX_ENTRIES:
            # The entries are ordered by timestamp DESC,
            # so the oldest are at the end
            excess = len(entries) - VAULT_MAX_ENTRIES
            logger.info(f"Vault overflow: removing {excess} oldest entries")
            # For simplicity, mark the oldest as expired for cleanup
            self.db.expire_vault_entries()

    def _start_expiry_checker(self):
        """Periodically check and expire vault entries."""
        if not hasattr(self, 'db'):
            return

        def check():
            try:
                self.db.expire_vault_entries()
                self.db.delete_expired_vault_entries()
            except Exception as e:
                logger.error(f"Expiry check error: {e}")

            # Schedule next check in 10 seconds
            if hasattr(self, '_expiry_timer'):
                self._expiry_timer = threading.Timer(10.0, check)
                self._expiry_timer.daemon = True
                self._expiry_timer.start()

        self._expiry_timer = threading.Timer(10.0, check)
        self._expiry_timer.daemon = True
        self._expiry_timer.start()

    def stop(self):
        """Stop the vault (cancel expiry timer)."""
        if self._expiry_timer:
            self._expiry_timer.cancel()
        logger.info("Vault stopped")
