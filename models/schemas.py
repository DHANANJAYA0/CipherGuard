"""
CipherGuard — Data Schemas
Dataclass definitions for all event types used across the application.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class KeyShieldEvent:
    """Represents a single keystroke event captured by KeyShield."""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    session_id: str = ""
    original: str = ""        # The real key pressed
    scrambled: str = ""       # What the keylogger would see
    app_name: str = ""        # Target application name
    algorithm: str = ""       # Scrambling algorithm used


@dataclass
class ClipGuardEvent:
    """Represents a clipboard event or hijack attempt."""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    event_type: str = ""          # 'copy', 'hijack_detected', 'restored'
    original_content: str = ""    # What user originally copied
    hijacked_content: str = ""    # What attacker replaced it with
    content_hash: str = ""        # SHA-256 hash of original
    pattern_type: str = "unknown" # 'bitcoin', 'ethereum', 'upi', 'iban', 'phone', 'unknown'
    attacker_pid: Optional[int] = None
    attacker_process: str = ""
    action_taken: str = ""        # 'restored', 'blocked', 'vault_saved'


@dataclass
class VaultEntry:
    """Represents an encrypted clipboard vault entry."""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    content: bytes = b""          # AES-256 encrypted content
    content_type: str = "text"    # 'text', 'address', 'password', 'key'
    expires_at: Optional[str] = None
    is_expired: bool = False


@dataclass
class ThreatStats:
    """Aggregated threat statistics for the dashboard."""
    total_keystrokes_protected: int = 0
    total_clipboard_hijacks_blocked: int = 0
    total_clipboard_copies_monitored: int = 0
    unique_attacker_processes: int = 0
    vault_entries_count: int = 0
    session_start_time: str = field(default_factory=lambda: datetime.now().isoformat())
