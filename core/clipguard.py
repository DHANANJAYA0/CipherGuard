"""
CipherGuard — ClipGuard Engine
Clipboard hijack detection module that monitors the Windows clipboard
for unauthorized modifications and alerts the user in real-time.
"""

import threading
import ctypes
import ctypes.wintypes
import hashlib
from datetime import datetime
from typing import Optional, Callable

import win32clipboard
import win32process
import win32api
import win32con

from pynput import keyboard as kb

from models.schemas import ClipGuardEvent
from utils.patterns import detect_pattern, is_same_pattern_type, is_sensitive_content
from utils.crypto import hash_content
from utils.logger import setup_logger

logger = setup_logger("ClipGuard")

# Windows constants
WM_CLIPBOARDUPDATE = 0x031D


class ClipGuardEngine:
    """
    Clipboard hijack detection engine.

    Monitors the Windows clipboard for unauthorized modifications.
    When the user presses Ctrl+C, the engine snapshots the clipboard content.
    If the content changes without user action, a hijack is detected.
    """

    def __init__(self,
                 on_hijack_callback: Optional[Callable] = None,
                 on_copy_callback: Optional[Callable] = None,
                 on_stats_callback: Optional[Callable] = None):
        """
        Initialize ClipGuard.

        Args:
            on_hijack_callback: Called with ClipGuardEvent when hijack detected.
            on_copy_callback: Called with content when user copies something.
            on_stats_callback: Called with updated stats dict.
        """
        self.on_hijack_callback = on_hijack_callback
        self.on_copy_callback = on_copy_callback
        self.on_stats_callback = on_stats_callback

        self._active = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._key_listener: Optional[kb.Listener] = None

        # Clipboard state tracking
        self._last_content: str = ""
        self._last_hash: str = ""
        self._user_just_copied: bool = False
        self._copy_timestamp: Optional[str] = None
        self._lock = threading.Lock()

        # Stats
        self._copies_monitored: int = 0
        self._hijacks_blocked: int = 0

        # Ctrl+C detection state
        self._ctrl_pressed: bool = False

        logger.info("ClipGuard initialized")

    @property
    def active(self) -> bool:
        return self._active

    @property
    def copies_monitored(self) -> int:
        return self._copies_monitored

    @property
    def hijacks_blocked(self) -> int:
        return self._hijacks_blocked

    def start(self):
        """Start clipboard monitoring."""
        if self._active:
            logger.warning("ClipGuard is already active")
            return

        self._active = True
        self._copies_monitored = 0
        self._hijacks_blocked = 0

        # Start keyboard listener for Ctrl+C detection
        self._key_listener = kb.Listener(
            on_press=self._on_key_press,
            on_release=self._on_key_release,
        )
        self._key_listener.start()

        # Start clipboard monitoring thread
        self._monitor_thread = threading.Thread(
            target=self._clipboard_monitor_loop,
            daemon=True,
            name="ClipGuardMonitor"
        )
        self._monitor_thread.start()

        logger.info("ClipGuard STARTED")

    def stop(self):
        """Stop clipboard monitoring."""
        if not self._active:
            return

        self._active = False

        if self._key_listener:
            self._key_listener.stop()
            self._key_listener = None

        logger.info(f"ClipGuard STOPPED | Copies: {self._copies_monitored} | Hijacks blocked: {self._hijacks_blocked}")

    def get_clipboard_content(self) -> str:
        """Safely read the current clipboard text content."""
        try:
            win32clipboard.OpenClipboard()
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                    data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                    return data if data else ""
                return ""
            finally:
                win32clipboard.CloseClipboard()
        except Exception as e:
            logger.debug(f"Could not read clipboard: {e}")
            return ""

    def set_clipboard_content(self, content: str):
        """Safely write content to the clipboard."""
        try:
            win32clipboard.OpenClipboard()
            try:
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardText(content, win32clipboard.CF_UNICODETEXT)
            finally:
                win32clipboard.CloseClipboard()
        except Exception as e:
            logger.error(f"Could not write to clipboard: {e}")

    def restore_clipboard(self, original_content: str):
        """Restore the clipboard to the original safe content."""
        self.set_clipboard_content(original_content)
        logger.info("Clipboard restored to original content")

    def _on_key_press(self, key):
        """Detect Ctrl+C press to mark user-initiated copies."""
        try:
            if key == kb.Key.ctrl_l or key == kb.Key.ctrl_r:
                self._ctrl_pressed = True
            elif self._ctrl_pressed and isinstance(key, kb.KeyCode) and key.char == '\x03':
                # Ctrl+C detected (char code 0x03)
                self._on_user_copy()
        except Exception:
            pass

    def _on_key_release(self, key):
        """Track Ctrl key release."""
        if key == kb.Key.ctrl_l or key == kb.Key.ctrl_r:
            self._ctrl_pressed = False

    def _on_user_copy(self):
        """Handle user-initiated Ctrl+C copy action."""
        with self._lock:
            self._user_just_copied = True
            self._copy_timestamp = datetime.now().isoformat()

        # Small delay to let the clipboard update
        import time
        time.sleep(0.1)

        content = self.get_clipboard_content()
        if content:
            with self._lock:
                self._last_content = content
                self._last_hash = hash_content(content)
                self._copies_monitored += 1

            pattern_key, pattern_label = detect_pattern(content)

            logger.info(f"User copied: {content[:50]}... | Pattern: {pattern_label}")

            if self.on_copy_callback:
                self.on_copy_callback(content)

    def _clipboard_monitor_loop(self):
        """
        Main clipboard monitoring loop using polling with sequence number.
        Checks if clipboard content changed without user pressing Ctrl+C.
        """
        import time

        last_seq = self._get_clipboard_sequence()

        while self._active:
            try:
                current_seq = self._get_clipboard_sequence()

                if current_seq != last_seq:
                    last_seq = current_seq

                    # Check if this change was user-initiated
                    with self._lock:
                        user_copied = self._user_just_copied
                        self._user_just_copied = False

                    if user_copied:
                        # User pressed Ctrl+C — this is a legitimate copy
                        continue

                    # Clipboard changed WITHOUT user pressing Ctrl+C
                    current_content = self.get_clipboard_content()

                    if not current_content or not self._last_content:
                        continue

                    if current_content == self._last_content:
                        continue

                    # HIJACK DETECTED!
                    self._handle_hijack_detected(current_content)

                time.sleep(0.2)  # Check every 200ms

            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                time.sleep(0.5)

    def _get_clipboard_sequence(self) -> int:
        """Get the clipboard sequence number from Windows API."""
        try:
            return ctypes.windll.user32.GetClipboardSequenceNumber()
        except Exception:
            return 0

    def _handle_hijack_detected(self, hijacked_content: str):
        """Handle a detected clipboard hijack attempt."""
        with self._lock:
            original = self._last_content
            original_hash = self._last_hash
            self._hijacks_blocked += 1

        # Detect pattern types
        orig_pattern, orig_label = detect_pattern(original)
        hijack_pattern, hijack_label = detect_pattern(hijacked_content)

        # Check if it's a same-type address substitution (most dangerous)
        same_type = is_same_pattern_type(original, hijacked_content)

        # Try to identify the attacker process
        attacker_pid, attacker_name = self._get_clipboard_owner()

        # Create event
        event = ClipGuardEvent(
            timestamp=datetime.now().isoformat(),
            event_type="hijack_detected",
            original_content=original,
            hijacked_content=hijacked_content,
            content_hash=original_hash,
            pattern_type=orig_label if orig_pattern else hijack_label,
            attacker_pid=attacker_pid,
            attacker_process=attacker_name,
            action_taken="pending",
        )

        severity = "CRITICAL" if same_type else "HIGH"
        logger.warning(
            f"CLIPBOARD HIJACK DETECTED [{severity}]!\n"
            f"  Original: {original[:60]}...\n"
            f"  Hijacked: {hijacked_content[:60]}...\n"
            f"  Pattern: {orig_label} → {hijack_label}\n"
            f"  Attacker PID: {attacker_pid} ({attacker_name})"
        )

        # Restore clipboard to original
        self.restore_clipboard(original)
        event.action_taken = "restored"

        # Notify UI
        if self.on_hijack_callback:
            self.on_hijack_callback(event)

        if self.on_stats_callback:
            self.on_stats_callback({
                "copies_monitored": self._copies_monitored,
                "hijacks_blocked": self._hijacks_blocked,
            })

    def _get_clipboard_owner(self):
        """
        Try to identify the process that last modified the clipboard.
        Returns (pid, process_name) or (None, 'Unknown').
        """
        try:
            hwnd = ctypes.windll.user32.GetClipboardOwner()
            if hwnd:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                try:
                    handle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, False, pid)
                    exe_name = win32process.GetModuleFileNameEx(handle, 0)
                    win32api.CloseHandle(handle)
                    return pid, exe_name
                except Exception:
                    return pid, f"PID:{pid}"
            return None, "Unknown"
        except Exception as e:
            logger.debug(f"Could not get clipboard owner: {e}")
            return None, "Unknown"
