"""
CipherGuard — Main Entry Point
Initializes all modules, connects them to the UI, and launches the application.
"""

import sys
import os
import winsound

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication, QInputDialog, QLineEdit, QMessageBox
from PyQt5.QtCore import QTimer

from config import APP_NAME
from models.database import DatabaseManager
from core.keyshield import KeyShieldEngine
from core.clipguard import ClipGuardEngine
from core.vault import VaultManager
from ui.main_window import MainWindow
from ui.tray_icon import TrayIcon
from ui.alert_dialog import AlertDialog
from ui.styles import DARK_THEME
from utils.pdf_report import generate_report
from utils.logger import setup_logger

logger = setup_logger("Main")


class CipherGuardApp:
    """
    Main application controller.
    Connects all modules (KeyShield, ClipGuard, Vault) to the UI.
    """

    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setQuitOnLastWindowClosed(False)
        self.app.setStyleSheet(DARK_THEME)

        # ─── Master Password ─────────────────────────────
        self.master_password = self._prompt_password()
        if not self.master_password:
            sys.exit(0)

        # ─── Initialize Components ───────────────────────
        logger.info(f"{APP_NAME} starting...")

        # Database
        self.db = DatabaseManager()

        # Core engines
        self.keyshield = KeyShieldEngine(
            algorithm="random_map",
            on_event_callback=self._on_keyshield_event,
            on_stats_callback=self._on_keyshield_stats,
        )

        self.clipguard = ClipGuardEngine(
            on_hijack_callback=self._on_hijack_detected,
            on_copy_callback=self._on_clipboard_copy,
            on_stats_callback=self._on_clipguard_stats,
        )

        self.vault = VaultManager(self.master_password, self.db)

        # ─── UI Components ───────────────────────────────
        self.window = MainWindow()
        self._connect_window_callbacks()

        self.tray = TrayIcon(self.app)
        self._connect_tray_signals()

        # ─── Vault refresh timer ─────────────────────────
        self.vault_timer = QTimer()
        self.vault_timer.timeout.connect(self._refresh_vault)
        self.vault_timer.start(10000)  # Refresh every 10 seconds

        # ─── Chart refresh timer ─────────────────────────
        self.chart_timer = QTimer()
        self.chart_timer.timeout.connect(self._refresh_chart)
        self.chart_timer.start(60000)  # Refresh every 60 seconds

        logger.info(f"{APP_NAME} initialized successfully")

        # Start KeyShield in monitor-only mode immediately (listener always running).
        # This means the keylogger shows REAL text when protection is OFF,
        # and SCRAMBLED text when protection is ON — perfect for demo.
        self.keyshield.start_monitor_only()

    def _prompt_password(self) -> str:
        """Show a password dialog on startup."""
        password, ok = QInputDialog.getText(
            None,
            f"🔐 {APP_NAME} — Master Password",
            "Enter your master password to unlock the Vault:\n"
            "(This encrypts your clipboard history with AES-256)",
            QLineEdit.Password
        )
        if ok and password:
            return password
        return ""

    def _connect_window_callbacks(self):
        """Connect UI callbacks to engine methods."""
        self.window.on_keyshield_toggle = self._toggle_keyshield
        self.window.on_clipguard_toggle = self._toggle_clipguard
        self.window.on_algorithm_change = self._change_algorithm
        self.window.on_vault_paste = self._vault_action
        self.window.on_generate_report = self._generate_report
        self.window.on_clear_buffers = self._clear_keyshield_buffers
        self.window.on_protected_input = self._on_protected_input
        self.window.on_save_to_vault = self._save_generated_password

        # DIRECT signal connection — bypasses the callback chain entirely.
        # This fires for BOTH typing and Ctrl+V paste in the Protected Input field.
        self.window.protected_input.textChanged.connect(self._on_protected_input_direct)

        # Backup timer for buffer updates every 300ms
        self.buffer_timer = QTimer()
        self.buffer_timer.timeout.connect(self._update_keyshield_buffers)
        self.buffer_timer.start(300)

    def _connect_tray_signals(self):
        """Connect tray icon signals."""
        self.tray.show_dashboard_signal.connect(self._show_dashboard)
        self.tray.toggle_keyshield_signal.connect(self._toggle_keyshield)
        self.tray.toggle_clipguard_signal.connect(self._toggle_clipguard)
        self.tray.quit_signal.connect(self._quit)

    # ─── KeyShield Controls ──────────────────────────────

    def _toggle_keyshield(self, enabled: bool):
        """Toggle KeyShield on/off."""
        if enabled:
            self.keyshield.start()
            logger.info("KeyShield enabled by user")
        else:
            self.keyshield.stop()
            logger.info("KeyShield disabled by user")

        self.window.update_keyshield_status(enabled)
        self.tray.update_keyshield_status(enabled)

        if enabled:
            self.tray.show_notification(
                "KeyShield Active ⌨️",
                "Anti-keylogger protection is now ON.\n"
                "Safety hotkey: Ctrl+Shift+F12"
            )

    def _change_algorithm(self, algorithm: str):
        """Change the KeyShield scrambling algorithm."""
        self.keyshield.set_algorithm(algorithm)
        self.keyshield.clear_buffers()
        logger.info(f"Algorithm changed to: {algorithm}")

    def _on_keyshield_event(self, event):
        """Handle KeyShield keystroke events (from background thread)."""
        self.db.log_keyshield_event(event)
        # Use signal for thread-safe UI update
        self.window.keyshield_event_signal.emit(event)

        # Write to keylogger file on EVERY keystroke from ANY app.
        # This makes the demo work with Notepad too.
        # Shows what a keylogger captures vs what it WOULD capture with full protection.
        self._write_keylogger_file_from_monitor()

    def _write_keylogger_file_from_monitor(self):
        """
        Write the keylogger output file.
        - KeyShield OFF: shows REAL text (proves vulnerability without protection)
        - KeyShield ON:  shows SCRAMBLED text (proves CipherGuard works)
        """
        from config import BASE_DIR
        import datetime

        original = self.keyshield.get_original_text()
        scrambled = self.keyshield.get_scrambled_text()

        if not original:
            return

        protected = self.keyshield.protection_active

        # Update green/red comparison boxes in real-time (thread-safe Qt signal)
        self.window.buffer_update_signal.emit(original, scrambled)

        keylogger_file = os.path.join(BASE_DIR, "demo", "keylogger_output.txt")
        now = datetime.datetime.now().strftime("%H:%M:%S")
        try:
            with open(keylogger_file, "w", encoding="utf-8") as f:
                if protected:
                    # KeyShield ON — attacker gets garbage
                    f.write("=== KEYLOGGER CAPTURED DATA [CIPHERGUARD ACTIVE] ===\n")
                    f.write(f"Time: {now} | Algorithm: {self.keyshield.algorithm}\n")
                    f.write("-" * 48 + "\n\n")
                    f.write("Keystroke-by-keystroke (attacker's view):\n")
                    for i, (orig, scr) in enumerate(zip(original, scrambled)):
                        f.write(f"  Key #{i+1:03d}: Attacker sees [ {scr} ]\n")
                    f.write("\n" + "-" * 48 + "\n")
                    f.write(f"FULL STOLEN TEXT (useless to attacker): {scrambled}\n")
                    f.write("-" * 48 + "\n")
                    f.write("[ATTACKER FAILED - cannot decode without CipherGuard key]\n")
                    f.write(f"[What was actually typed: {original}]\n")
                else:
                    # KeyShield OFF — attacker gets real text!
                    f.write("=== KEYLOGGER CAPTURED DATA [NO PROTECTION] ===\n")
                    f.write(f"Time: {now} | Status: VULNERABLE\n")
                    f.write("-" * 48 + "\n\n")
                    f.write("Keystroke-by-keystroke (attacker's view):\n")
                    for i, ch in enumerate(original):
                        f.write(f"  Key #{i+1:03d}: Attacker sees [ {ch} ]  <-- REAL KEY!\n")
                    f.write("\n" + "-" * 48 + "\n")
                    f.write(f"FULL STOLEN TEXT (attacker gets everything): {original}\n")
                    f.write("-" * 48 + "\n")
                    f.write("[ATTACKER SUCCEEDED - Enable CipherGuard KeyShield to protect!]\n")
        except Exception as e:
            logger.error(f"Failed to write keylogger file: {e}")


    def _on_keyshield_stats(self, count: int):
        """Handle KeyShield stats updates."""
        self.window.stats_update_signal.emit({"keystrokes": count})

    def _update_keyshield_buffers(self):
        """
        Backup timer — DISABLED for comparison boxes.
        The direct textChanged signal on protected_input handles all updates.
        The backup timer used keyshield monitor buffers which miss paste events,
        causing it to overwrite correct paste data with incomplete typed data.
        """
        pass  # No-op: direct signal from _on_protected_input_direct handles this

    def _clear_keyshield_buffers(self):
        """Clear the KeyShield text comparison buffers."""
        self.keyshield.clear_buffers()

    def _on_protected_input(self, text: str):
        """
        Handle text typed OR pasted in the Protected Input Field.
        Works for both typing and Ctrl+V paste.
        Computes scrambled version and writes to keylogger_output.txt.
        """
        from core.scrambler import scramble_char, get_algorithm_map
        from config import BASE_DIR
        import datetime

        # Use active KeyShield map, or fallback demo map
        if self.keyshield.active:
            scramble_map = self.keyshield.scramble_map
            algorithm = self.keyshield.algorithm
        else:
            scramble_map = get_algorithm_map("random_map", seed="demo_default")
            algorithm = "random_map (demo)"

        # Build scrambled version of entire text
        scrambled = ""
        for ch in text:
            scrambled += scramble_char(ch, scramble_map)

        # Update comparison boxes via thread-safe signal
        self.window.buffer_update_signal.emit(text, scrambled)

        # Write scrambled output to keylogger_output.txt
        # demo_keylogger.py reads this file and displays it as "attacker's capture"
        keylogger_file = os.path.join(BASE_DIR, "demo", "keylogger_output.txt")
        now = datetime.datetime.now().strftime("%H:%M:%S")
        try:
            with open(keylogger_file, "w", encoding="utf-8") as f:
                f.write("=== KEYLOGGER CAPTURED DATA ===\n")
                f.write(f"Time: {now} | Algorithm: {algorithm}\n")
                f.write("-" * 42 + "\n\n")
                f.write("Character-by-character capture:\n")
                for i, (orig, scr) in enumerate(zip(text, scrambled)):
                    f.write(f"  Keystroke #{i+1:03d}: [ {scr} ]\n")
                f.write("\n" + "-" * 42 + "\n")
                f.write(f"FULL STOLEN TEXT:  {scrambled}\n")
                f.write("-" * 42 + "\n")
                f.write("[ATTACKER FAILED - cannot decode without CipherGuard key]\n")
                f.write(f"\n[Real text was: {text}]\n")
            logger.debug(f"Keylogger file updated: {len(text)} chars, scrambled: {scrambled}")
        except Exception as e:
            logger.error(f"Failed to write keylogger file: {e}")

    def _on_protected_input_direct(self):
        """
        DIRECT slot connected to protected_input.textChanged signal.
        This is guaranteed to fire on every change (type or paste).
        Reads current text from the widget and calls _on_protected_input.
        """
        text = self.window.protected_input.toPlainText().strip()
        if not text:  # Skip empty text (from initialization or clear button)
            return
        self._on_protected_input(text)

    # ─── ClipGuard Controls ──────────────────────────────

    def _toggle_clipguard(self, enabled: bool):
        """Toggle ClipGuard on/off."""
        if enabled:
            self.clipguard.start()
            logger.info("ClipGuard enabled by user")
        else:
            self.clipguard.stop()
            logger.info("ClipGuard disabled by user")

        self.window.update_clipguard_status(enabled)
        self.tray.update_clipguard_status(enabled)

        if enabled:
            self.tray.show_notification(
                "ClipGuard Active 📋",
                "Clipboard hijack protection is now ON."
            )

    def _on_hijack_detected(self, event):
        """Handle clipboard hijack detection (from background thread)."""
        # Log to database
        self.db.log_clipguard_event(event)

        # Update UI (thread-safe)
        self.window.clipguard_event_signal.emit(event)

        # Show alert dialog (must be on main thread)
        QTimer.singleShot(0, lambda: self._show_alert(event))

        # Show tray notification
        self.tray.show_notification(
            "⚠️ CLIPBOARD HIJACK DETECTED!",
            f"Original: {event.original_content[:40]}...\n"
            f"Replaced with: {event.hijacked_content[:40]}...\n"
            f"Attacker: {event.attacker_process}"
        )

        # Play alert sound (non-blocking)
        try:
            winsound.PlaySound("SystemExclamation", winsound.SND_ALIAS | winsound.SND_ASYNC)
        except Exception:
            pass  # Silently ignore if sound playback fails

    def _on_clipboard_copy(self, content: str):
        """Handle user clipboard copy (store in vault)."""
        from models.schemas import ClipGuardEvent
        event = ClipGuardEvent(event_type="copy", original_content=content[:100])
        self.db.log_clipguard_event(event)
        self.window.clipguard_event_signal.emit(event)

        # Store in vault
        self.vault.add_entry(content)

    def _on_clipguard_stats(self, stats: dict):
        """Handle ClipGuard stats updates."""
        self.window.stats_update_signal.emit({
            "copies": stats.get("copies_monitored", 0),
            "hijacks": stats.get("hijacks_blocked", 0),
        })

    def _show_alert(self, event):
        """Show the hijack alert dialog."""
        dialog = AlertDialog(event, self.window)
        dialog.exec_()

        if dialog.result_action == "vault":
            self.vault.add_entry(event.original_content)
            self.window.status_bar.showMessage("Original content saved to Vault", 3000)

    # ─── Vault Controls ──────────────────────────────────

    def _vault_action(self, index):
        """Handle vault paste, refresh, manual add, or delete."""
        # Handle tuple signals from new buttons
        if isinstance(index, tuple):
            signal_type, data = index
            if signal_type == -2:
                # Manual add entry — vault.add_entry only accepts (content, on_update)
                try:
                    self.vault.add_entry(data)
                    self._refresh_vault()
                    logger.info(f"Manual vault entry added: {data[:20]}...")
                except Exception as e:
                    logger.error(f"Failed to add vault entry: {e}")
                return
            elif signal_type == -3:
                # Delete entry by row index
                try:
                    entries = self.vault.get_entries()
                    if 0 <= data < len(entries):
                        entry_id = entries[data].get("id")
                        if entry_id:
                            self.db.delete_vault_entry(entry_id)
                    self._refresh_vault()
                except Exception as e:
                    logger.error(f"Failed to delete vault entry: {e}")
                return

        if index == -1:
            # Refresh request
            self._refresh_vault()
            return

        entries = self.vault.get_entries()
        if 0 <= index < len(entries):
            content = entries[index]["content"]
            self.clipguard.set_clipboard_content(content)
            self.window.status_bar.showMessage("📋  Pasted from Vault to clipboard", 3000)

    def _refresh_vault(self):
        """Refresh the vault table in the UI."""
        entries = self.vault.get_entries()
        self.window.update_vault_table(entries)

    def _save_generated_password(self, password: str):
        """Save a generated password to the vault (from Password Generator tab)."""
        try:
            self.vault.add_entry(f"[Generated] {password}")
            self._refresh_vault()
            logger.info("Generated password saved to vault")
        except Exception as e:
            logger.error(f"Failed to save generated password: {e}")

    def _refresh_chart(self):
        """Refresh the threat timeline chart with latest data."""
        try:
            data = self.db.get_events_by_hour(24)
            self.window.chart_update_signal.emit(data)
        except Exception as e:
            logger.error(f"Chart refresh failed: {e}")

    # ─── Report Generation ───────────────────────────────

    def _generate_report(self):
        """Generate a PDF forensic report."""
        try:
            stats = self.db.get_threat_stats()
            hijack_events = self.db.get_hijack_events(limit=50)
            report_path = generate_report(stats, hijack_events)

            QMessageBox.information(
                self.window,
                "Report Generated ✅",
                f"PDF forensic report saved to:\n{report_path}"
            )

            # Open the PDF
            os.startfile(report_path)

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            QMessageBox.critical(
                self.window,
                "Report Error",
                f"Failed to generate report:\n{str(e)}"
            )

    # ─── Application Controls ────────────────────────────

    def _show_dashboard(self):
        """Show/raise the main dashboard window."""
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def _quit(self):
        """Clean shutdown of all modules."""
        logger.info("Shutting down CipherGuard...")
        self.keyshield.stop()
        self.clipguard.stop()
        self.vault.stop()
        self.vault_timer.stop()
        self.chart_timer.stop()
        self.buffer_timer.stop()
        self.app.quit()

    def run(self):
        """Launch the application."""
        self._show_dashboard()
        self._refresh_vault()

        # Update dashboard with any existing stats
        stats = self.db.get_threat_stats()
        self.window.stats_update_signal.emit({
            "keystrokes": stats.total_keystrokes_protected,
            "hijacks": stats.total_clipboard_hijacks_blocked,
            "copies": stats.total_clipboard_copies_monitored,
            "attackers": stats.unique_attacker_processes,
        })

        logger.info(f"{APP_NAME} is running!")

        # Initial chart refresh
        self._refresh_chart()

        return self.app.exec_()


def main():
    """Entry point."""
    try:
        app = CipherGuardApp()
        sys.exit(app.run())
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        print(f"\n[FATAL ERROR] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
