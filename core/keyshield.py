"""
CipherGuard — KeyShield Engine
Anti-keylogger module that monitors keyboard input and demonstrates
how keystroke scrambling defeats keyloggers.

Architecture:
- Monitors all keystrokes in real-time (non-blocking)
- For each keystroke, computes the scrambled equivalent
- Logs both original and scrambled versions to the dashboard
- The demo_keylogger.py captures real keys (proving it works)
- The dashboard shows what a protected system would feed to a keylogger

This monitor-based approach is used because Windows low-level keyboard
hooks (WH_KEYBOARD_LL) with pynput's suppress=True block ALL events
including our own re-injected keys, making it impossible to type.
Production anti-keyloggers use kernel-level drivers (e.g., KMDF filter
drivers) which operate below the hook layer — that requires driver signing
certificates and is beyond the scope of a Python application.
"""

import threading
import uuid
from datetime import datetime
from typing import Optional, Callable

from pynput import keyboard

from core.scrambler import get_algorithm_map, scramble_char
from models.schemas import KeyShieldEvent
from utils.logger import setup_logger

logger = setup_logger("KeyShield")


class KeyShieldEngine:
    """
    Anti-keylogger demonstration engine.

    Monitors keystrokes and computes scrambled equivalents to show
    how key scrambling defeats keylogger malware. The dashboard
    displays a real-time side-by-side comparison:
      Original (what you typed) → Scrambled (what a keylogger would see)
    """

    def __init__(self, algorithm: str = "random_map",
                 on_event_callback: Optional[Callable] = None,
                 on_stats_callback: Optional[Callable] = None):
        """
        Initialize KeyShield.

        Args:
            algorithm: Scrambling algorithm ('random_map', 'caesar', 'phonetic').
            on_event_callback: Called with KeyShieldEvent for each keystroke.
            on_stats_callback: Called with updated keystroke count.
        """
        self.algorithm = algorithm
        self.session_id = str(uuid.uuid4())[:8]
        self.scramble_map = get_algorithm_map(algorithm, seed=self.session_id)
        self.on_event_callback = on_event_callback
        self.on_stats_callback = on_stats_callback

        self._active = False
        self._protection_active = False  # True = scrambling ON, False = monitor-only
        self._listener: Optional[keyboard.Listener] = None
        self._keystroke_count = 0
        self._lock = threading.Lock()

        # Track what user typed vs what scrambled version would be
        self._original_buffer = []
        self._scrambled_buffer = []

        # Safety hotkey state tracking
        self._ctrl_pressed = False
        self._shift_pressed = False

        logger.info(f"KeyShield initialized | Algorithm: {algorithm} | Session: {self.session_id}")

    @property
    def active(self) -> bool:
        """True if the listener is running (monitoring keystrokes)."""
        return self._active

    @property
    def protection_active(self) -> bool:
        """True if scrambling/protection is ON. False = monitor only (real text)."""
        return self._protection_active

    @property
    def keystroke_count(self) -> int:
        return self._keystroke_count

    def get_original_text(self) -> str:
        """Get the original text the user typed."""
        return "".join(self._original_buffer)

    def get_scrambled_text(self) -> str:
        """Get what a keylogger would have captured (scrambled)."""
        return "".join(self._scrambled_buffer)

    def clear_buffers(self):
        """Clear the text comparison buffers."""
        self._original_buffer.clear()
        self._scrambled_buffer.clear()

    def start(self):
        """Start the KeyShield keyboard monitor WITH scrambling protection."""
        self._protection_active = True
        self.session_id = str(uuid.uuid4())[:8]
        self.scramble_map = get_algorithm_map(self.algorithm, seed=self.session_id)
        self.clear_buffers()

        if not self._active:
            self._active = True
            self._keystroke_count = 0
            # Non-blocking listener — keys pass through to applications normally
            self._listener = keyboard.Listener(
                on_press=self._on_press,
                on_release=self._on_release,
                suppress=False
            )
            self._listener.start()
            logger.info(f"KeyShield STARTED (protected) | Session: {self.session_id}")
        else:
            logger.info(f"KeyShield protection ENABLED | Session: {self.session_id}")

    def stop(self):
        """Disable protection but KEEP listener running (monitor-only mode).
        Shows real text in keylogger to demonstrate vulnerability without protection.
        Call shutdown() to fully stop the listener.
        """
        if not self._active:
            return

        self._protection_active = False
        self.clear_buffers()
        logger.info("KeyShield protection DISABLED (monitor-only mode — real text visible)")

    def shutdown(self):
        """Fully stop the KeyShield listener (call on app exit)."""
        self._active = False
        self._protection_active = False
        if self._listener:
            self._listener.stop()
            self._listener = None
        logger.info(f"KeyShield SHUTDOWN | Keystrokes monitored: {self._keystroke_count}")

    def start_monitor_only(self):
        """Start listener in monitor-only mode (no scrambling). Used on app launch."""
        if self._active:
            return
        self._active = True
        self._protection_active = False
        self._listener = keyboard.Listener(
            on_press=self._on_press,
            on_release=self._on_release,
            suppress=False
        )
        self._listener.start()
        logger.info("KeyShield STARTED (monitor-only mode)")

    def set_algorithm(self, algorithm: str):
        """Change the scrambling algorithm."""
        self.algorithm = algorithm
        self.scramble_map = get_algorithm_map(algorithm, seed=self.session_id)
        logger.info(f"Algorithm changed to: {algorithm}")

    def _on_press(self, key):
        """Handle key press events (monitor only, no blocking)."""
        # Track modifier keys for safety hotkey
        if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
            self._ctrl_pressed = True
            return
        if key == keyboard.Key.shift_l or key == keyboard.Key.shift_r:
            self._shift_pressed = True
            return

        # Safety hotkey: Ctrl+Shift+F12 → disable protection
        if key == keyboard.Key.f12 and self._ctrl_pressed and self._shift_pressed:
            logger.warning("SAFETY HOTKEY TRIGGERED — KeyShield protection disabled!")
            self.stop()
            return

        # Skip keyboard shortcuts (Ctrl+C, Ctrl+V, etc.)
        if self._ctrl_pressed:
            return

        # Handle printable characters
        if isinstance(key, keyboard.KeyCode) and key.char:
            original_char = key.char

            # If protection is ON → scramble. If OFF → use real char (vulnerable mode).
            if self._protection_active:
                scrambled_char = scramble_char(original_char, self.scramble_map)
            else:
                scrambled_char = original_char  # No protection — real text exposed!

            with self._lock:
                self._keystroke_count += 1
                self._original_buffer.append(original_char)
                self._scrambled_buffer.append(scrambled_char)

            # Create event for the dashboard
            event = KeyShieldEvent(
                timestamp=datetime.now().isoformat(),
                session_id=self.session_id,
                original=original_char,
                scrambled=scrambled_char,
                app_name="",
                algorithm=self.algorithm if self._protection_active else "UNPROTECTED",
            )

            if self.on_event_callback:
                self.on_event_callback(event)

            if self.on_stats_callback:
                self.on_stats_callback(self._keystroke_count)

        # Handle special keys for buffer tracking
        elif key == keyboard.Key.space:
            with self._lock:
                self._original_buffer.append(" ")
                self._scrambled_buffer.append(" ")
        elif key == keyboard.Key.backspace:
            with self._lock:
                if self._original_buffer:
                    self._original_buffer.pop()
                if self._scrambled_buffer:
                    self._scrambled_buffer.pop()
        elif key == keyboard.Key.enter:
            with self._lock:
                self._original_buffer.append("\n")
                self._scrambled_buffer.append("\n")

    def _on_release(self, key):
        """Handle key release events."""
        if key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
            self._ctrl_pressed = False
        if key == keyboard.Key.shift_l or key == keyboard.Key.shift_r:
            self._shift_pressed = False
