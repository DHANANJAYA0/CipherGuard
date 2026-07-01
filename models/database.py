"""
CipherGuard — Database Manager
SQLite database for logging KeyShield events, ClipGuard events, and vault entries.
"""

import sqlite3
import threading
from datetime import datetime
from typing import List, Optional, Tuple

from config import DB_PATH
from models.schemas import KeyShieldEvent, ClipGuardEvent, VaultEntry, ThreatStats


class DatabaseManager:
    """Thread-safe SQLite database manager for CipherGuard."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Create a new connection (SQLite connections are not thread-safe)."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")  # Better concurrent read performance
        return conn

    def _init_database(self):
        """Create tables if they don't exist."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()

                # Table 1: KeyShield events
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS keyshield_events (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp   TEXT NOT NULL,
                        session_id  TEXT NOT NULL,
                        original    TEXT,
                        scrambled   TEXT,
                        app_name    TEXT,
                        algorithm   TEXT
                    )
                """)

                # Table 2: ClipGuard events
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS clipguard_events (
                        id               INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp        TEXT NOT NULL,
                        event_type       TEXT NOT NULL,
                        original_content TEXT,
                        hijacked_content TEXT,
                        content_hash     TEXT,
                        pattern_type     TEXT DEFAULT 'unknown',
                        attacker_pid     INTEGER,
                        attacker_process TEXT,
                        action_taken     TEXT
                    )
                """)

                # Table 3: Encrypted vault entries
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS vault_entries (
                        id           INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp    TEXT NOT NULL,
                        content      BLOB NOT NULL,
                        content_type TEXT DEFAULT 'text',
                        expires_at   TEXT,
                        is_expired   INTEGER DEFAULT 0
                    )
                """)

                # Table 4: Persistent settings (e.g. vault salt)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS settings (
                        key   TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                """)

                conn.commit()
            finally:
                conn.close()

    # ─── KeyShield Operations ─────────────────────────────────────

    def log_keyshield_event(self, event: KeyShieldEvent):
        """Log a single keystroke event from KeyShield."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    """INSERT INTO keyshield_events
                       (timestamp, session_id, original, scrambled, app_name, algorithm)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (event.timestamp, event.session_id, event.original,
                     event.scrambled, event.app_name, event.algorithm)
                )
                conn.commit()
            finally:
                conn.close()

    def get_keyshield_count(self, session_id: Optional[str] = None) -> int:
        """Get total number of keystrokes protected."""
        with self._lock:
            conn = self._get_connection()
            try:
                if session_id:
                    row = conn.execute(
                        "SELECT COUNT(*) as cnt FROM keyshield_events WHERE session_id = ?",
                        (session_id,)
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT COUNT(*) as cnt FROM keyshield_events"
                    ).fetchone()
                return row["cnt"] if row else 0
            finally:
                conn.close()

    # ─── ClipGuard Operations ─────────────────────────────────────

    def log_clipguard_event(self, event: ClipGuardEvent):
        """Log a clipboard event or hijack attempt."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    """INSERT INTO clipguard_events
                       (timestamp, event_type, original_content, hijacked_content,
                        content_hash, pattern_type, attacker_pid, attacker_process, action_taken)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (event.timestamp, event.event_type, event.original_content,
                     event.hijacked_content, event.content_hash, event.pattern_type,
                     event.attacker_pid, event.attacker_process, event.action_taken)
                )
                conn.commit()
            finally:
                conn.close()

    def get_hijack_events(self, limit: int = 50) -> List[dict]:
        """Get recent clipboard hijack events."""
        with self._lock:
            conn = self._get_connection()
            try:
                rows = conn.execute(
                    """SELECT * FROM clipguard_events
                       WHERE event_type = 'hijack_detected'
                       ORDER BY timestamp DESC LIMIT ?""",
                    (limit,)
                ).fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()

    def get_clipguard_count(self, event_type: Optional[str] = None) -> int:
        """Get count of clipboard events by type."""
        with self._lock:
            conn = self._get_connection()
            try:
                if event_type:
                    row = conn.execute(
                        "SELECT COUNT(*) as cnt FROM clipguard_events WHERE event_type = ?",
                        (event_type,)
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT COUNT(*) as cnt FROM clipguard_events"
                    ).fetchone()
                return row["cnt"] if row else 0
            finally:
                conn.close()

    def get_unique_attacker_count(self) -> int:
        """Get count of unique attacker processes detected."""
        with self._lock:
            conn = self._get_connection()
            try:
                row = conn.execute(
                    """SELECT COUNT(DISTINCT attacker_process) as cnt
                       FROM clipguard_events
                       WHERE event_type = 'hijack_detected'
                         AND attacker_process IS NOT NULL
                         AND attacker_process != ''"""
                ).fetchone()
                return row["cnt"] if row else 0
            finally:
                conn.close()

    # ─── Vault Operations ─────────────────────────────────────────

    def save_vault_entry(self, entry: VaultEntry) -> int:
        """Save an encrypted entry to the vault. Returns the entry ID."""
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.execute(
                    """INSERT INTO vault_entries
                       (timestamp, content, content_type, expires_at, is_expired)
                       VALUES (?, ?, ?, ?, ?)""",
                    (entry.timestamp, entry.content, entry.content_type,
                     entry.expires_at, int(entry.is_expired))
                )
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def get_vault_entries(self, include_expired: bool = False) -> List[dict]:
        """Get all vault entries (optionally including expired ones)."""
        with self._lock:
            conn = self._get_connection()
            try:
                if include_expired:
                    rows = conn.execute(
                        "SELECT * FROM vault_entries ORDER BY timestamp DESC"
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM vault_entries WHERE is_expired = 0 ORDER BY timestamp DESC"
                    ).fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()

    def expire_vault_entries(self):
        """Mark expired vault entries based on expires_at timestamp."""
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    """UPDATE vault_entries SET is_expired = 1
                       WHERE expires_at IS NOT NULL AND expires_at <= ? AND is_expired = 0""",
                    (now,)
                )
                conn.commit()
            finally:
                conn.close()

    def delete_expired_vault_entries(self):
        """Permanently delete expired vault entries."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("DELETE FROM vault_entries WHERE is_expired = 1")
                conn.commit()
            finally:
                conn.close()

    def get_vault_count(self) -> int:
        """Get count of active vault entries."""
        with self._lock:
            conn = self._get_connection()
            try:
                row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM vault_entries WHERE is_expired = 0"
                ).fetchone()
                return row["cnt"] if row else 0
            finally:
                conn.close()

    def delete_vault_entry(self, entry_id: int):
        """Permanently delete a single vault entry by ID."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
                conn.commit()
            finally:
                conn.close()

    def get_setting(self, key: str) -> str:
        """Get a persistent setting value by key. Returns None if not found."""
        with self._lock:
            conn = self._get_connection()
            try:
                row = conn.execute(
                    "SELECT value FROM settings WHERE key = ?", (key,)
                ).fetchone()
                return row["value"] if row else None
            finally:
                conn.close()

    def save_setting(self, key: str, value: str):
        """Save a persistent setting (insert or update)."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (key, value)
                )
                conn.commit()
            finally:
                conn.close()

    # ─── Dashboard Aggregation ────────────────────────────────────

    def get_threat_stats(self) -> ThreatStats:
        """Get aggregated threat statistics for the dashboard."""
        return ThreatStats(
            total_keystrokes_protected=self.get_keyshield_count(),
            total_clipboard_hijacks_blocked=self.get_clipguard_count("hijack_detected"),
            total_clipboard_copies_monitored=self.get_clipguard_count("copy"),
            unique_attacker_processes=self.get_unique_attacker_count(),
            vault_entries_count=self.get_vault_count(),
        )

    def get_recent_events(self, limit: int = 50) -> List[dict]:
        """Get recent events from all tables for the live activity feed."""
        with self._lock:
            conn = self._get_connection()
            try:
                # Combine ClipGuard events into a unified feed
                rows = conn.execute(
                    """SELECT timestamp, event_type, original_content,
                              hijacked_content, pattern_type, attacker_process, action_taken
                       FROM clipguard_events
                       ORDER BY timestamp DESC LIMIT ?""",
                    (limit,)
                ).fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()

    def get_events_by_hour(self, hours: int = 24) -> List[Tuple[str, int]]:
        """Get event counts grouped by hour for the timeline chart."""
        with self._lock:
            conn = self._get_connection()
            try:
                rows = conn.execute(
                    """SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
                              COUNT(*) as cnt
                       FROM clipguard_events
                       WHERE event_type = 'hijack_detected'
                       GROUP BY hour
                       ORDER BY hour DESC
                       LIMIT ?""",
                    (hours,)
                ).fetchall()
                return [(row["hour"], row["cnt"]) for row in rows]
            finally:
                conn.close()

    def clear_all_data(self):
        """Clear all data from all tables (for testing/reset)."""
        with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("DELETE FROM keyshield_events")
                conn.execute("DELETE FROM clipguard_events")
                conn.execute("DELETE FROM vault_entries")
                conn.commit()
            finally:
                conn.close()
