"""
CipherGuard — System Tray Icon
Manages the system tray icon with context menu for quick access.
"""

from PyQt5.QtWidgets import QSystemTrayIcon, QMenu, QAction, QApplication, QStyle
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSignal, QObject

from config import APP_NAME


class TrayIcon(QObject):
    """
    System tray icon for CipherGuard.
    Provides quick access to show/hide dashboard and toggle modules.
    """

    show_dashboard_signal = pyqtSignal()
    toggle_keyshield_signal = pyqtSignal(bool)
    toggle_clipguard_signal = pyqtSignal(bool)
    quit_signal = pyqtSignal()

    def __init__(self, app: QApplication, parent=None):
        super().__init__(parent)
        self.app = app
        self._keyshield_active = False
        self._clipguard_active = False

        self.tray = QSystemTrayIcon()
        # Use a built-in icon (shield-like)
        self.tray.setIcon(app.style().standardIcon(QStyle.SP_VistaShield))
        self.tray.setToolTip(f"{APP_NAME} — Real-Time I/O Protection")
        self.tray.activated.connect(self._on_activated)

        self._setup_menu()
        self.tray.setVisible(True)

    def _setup_menu(self):
        """Create the right-click context menu."""
        menu = QMenu()

        # Dashboard action
        self.action_dashboard = QAction(f"📊  Open {APP_NAME} Dashboard")
        self.action_dashboard.triggered.connect(self.show_dashboard_signal.emit)
        menu.addAction(self.action_dashboard)

        menu.addSeparator()

        # KeyShield toggle
        self.action_keyshield = QAction("⌨️  KeyShield: OFF")
        self.action_keyshield.triggered.connect(self._toggle_keyshield)
        menu.addAction(self.action_keyshield)

        # ClipGuard toggle
        self.action_clipguard = QAction("📋  ClipGuard: OFF")
        self.action_clipguard.triggered.connect(self._toggle_clipguard)
        menu.addAction(self.action_clipguard)

        menu.addSeparator()

        # Quit
        action_quit = QAction("❌  Quit CipherGuard")
        action_quit.triggered.connect(self.quit_signal.emit)
        menu.addAction(action_quit)

        self.tray.setContextMenu(menu)

    def _on_activated(self, reason):
        """Handle tray icon double-click to show dashboard."""
        if reason == QSystemTrayIcon.DoubleClick:
            self.show_dashboard_signal.emit()

    def _toggle_keyshield(self):
        self._keyshield_active = not self._keyshield_active
        self.toggle_keyshield_signal.emit(self._keyshield_active)

    def _toggle_clipguard(self):
        self._clipguard_active = not self._clipguard_active
        self.toggle_clipguard_signal.emit(self._clipguard_active)

    def update_keyshield_status(self, active: bool):
        """Update the tray menu text for KeyShield."""
        self._keyshield_active = active
        status = "ON ✅" if active else "OFF"
        self.action_keyshield.setText(f"⌨️  KeyShield: {status}")

    def update_clipguard_status(self, active: bool):
        """Update the tray menu text for ClipGuard."""
        self._clipguard_active = active
        status = "ON ✅" if active else "OFF"
        self.action_clipguard.setText(f"📋  ClipGuard: {status}")

    def show_notification(self, title: str, message: str,
                          icon: QSystemTrayIcon.MessageIcon = QSystemTrayIcon.Warning):
        """Show a system tray notification balloon."""
        self.tray.showMessage(title, message, icon, 5000)
