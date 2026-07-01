"""
CipherGuard — Alert Dialog
Red alert popup that appears when a clipboard hijack is detected.
Shows side-by-side comparison of original vs hijacked content.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QSizePolicy
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from models.schemas import ClipGuardEvent


class AlertDialog(QDialog):
    """
    Critical alert dialog for clipboard hijack detection.
    Displays original vs hijacked content with action buttons.
    """

    def __init__(self, event: ClipGuardEvent, parent=None):
        super().__init__(parent)
        self.event = event
        self.result_action = "restore"  # Default action
        self._setup_ui()

    def _setup_ui(self):
        self.setWindowTitle("⚠️ CLIPBOARD HIJACK DETECTED — CipherGuard")
        self.setMinimumSize(600, 400)
        self.setMaximumSize(800, 600)
        self.setWindowFlags(
            Qt.WindowStaysOnTopHint | Qt.Dialog | Qt.CustomizeWindowHint | Qt.WindowTitleHint
        )

        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(24, 24, 24, 24)

        # ─── Alert Header ────────────────────────────────
        header = QLabel("⚠️  CLIPBOARD HIJACK DETECTED")
        header.setObjectName("alert_title")
        header.setFont(QFont("Segoe UI", 18, QFont.Bold))
        header.setStyleSheet("color: #ff4444; padding: 8px;")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background-color: #ff4444;")
        sep.setFixedHeight(2)
        layout.addWidget(sep)

        # ─── Original Content ─────────────────────────────
        orig_header = QLabel("✅  You copied:")
        orig_header.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 14px;")
        layout.addWidget(orig_header)

        orig_content = QLabel(self._truncate(self.event.original_content, 120))
        orig_content.setStyleSheet(
            "background-color: #0a3d2a; color: #00ff88; padding: 12px; "
            "border: 1px solid #00ff88; border-radius: 6px; font-family: 'Consolas';"
        )
        orig_content.setWordWrap(True)
        orig_content.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(orig_content)

        # ─── Hijacked Content ─────────────────────────────
        hijack_header = QLabel("❌  Something changed it to:")
        hijack_header.setStyleSheet("color: #ff4444; font-weight: bold; font-size: 14px;")
        layout.addWidget(hijack_header)

        hijack_content = QLabel(self._truncate(self.event.hijacked_content, 120))
        hijack_content.setStyleSheet(
            "background-color: #3d0a0a; color: #ff4444; padding: 12px; "
            "border: 1px solid #ff4444; border-radius: 6px; font-family: 'Consolas';"
        )
        hijack_content.setWordWrap(True)
        hijack_content.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(hijack_content)

        # ─── Attacker Info ────────────────────────────────
        attacker_frame = QFrame()
        attacker_frame.setStyleSheet(
            "background-color: #1a1a2e; border: 1px solid #2d2d4a; "
            "border-radius: 6px; padding: 8px;"
        )
        attacker_layout = QVBoxLayout(attacker_frame)

        attacker_info = QLabel(
            f"🔍  Attacker Process: {self.event.attacker_process}\n"
            f"🔢  Process ID (PID): {self.event.attacker_pid or 'Unknown'}\n"
            f"📋  Pattern Type: {self.event.pattern_type}\n"
            f"🕐  Timestamp: {self.event.timestamp}"
        )
        attacker_info.setStyleSheet("color: #cccccc; font-size: 12px;")
        attacker_layout.addWidget(attacker_info)

        layout.addWidget(attacker_frame)

        # ─── Action Buttons ───────────────────────────────
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        btn_restore = QPushButton("✅  Restore Original")
        btn_restore.setObjectName("btn_safe")
        btn_restore.setMinimumHeight(40)
        btn_restore.clicked.connect(self._on_restore)
        btn_layout.addWidget(btn_restore)

        btn_vault = QPushButton("📋  Copy to Vault")
        btn_vault.setObjectName("btn_primary")
        btn_vault.setMinimumHeight(40)
        btn_vault.clicked.connect(self._on_vault)
        btn_layout.addWidget(btn_vault)

        btn_block = QPushButton("🚫  Block")
        btn_block.setObjectName("btn_danger")
        btn_block.setMinimumHeight(40)
        btn_block.clicked.connect(self._on_block)
        btn_layout.addWidget(btn_block)

        layout.addLayout(btn_layout)

    def _truncate(self, text: str, max_length: int) -> str:
        """Truncate text with ellipsis if too long."""
        if len(text) > max_length:
            return text[:max_length] + "..."
        return text

    def _on_restore(self):
        self.result_action = "restore"
        self.accept()

    def _on_vault(self):
        self.result_action = "vault"
        self.accept()

    def _on_block(self):
        self.result_action = "block"
        self.accept()
