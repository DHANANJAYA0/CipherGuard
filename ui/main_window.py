"""
CipherGuard — Main Window
Tabbed dashboard with KeyShield, ClipGuard, Dashboard, Vault, and Password Generator tabs.
"""

from PyQt5.QtWidgets import (
    QMainWindow, QTabWidget, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QCheckBox, QComboBox, QGroupBox,
    QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QFrame, QStatusBar, QSizePolicy, QLineEdit, QMessageBox,
    QProgressBar, QSlider, QSpinBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QColor

import pyqtgraph as pg

from models.schemas import ThreatStats, ClipGuardEvent, KeyShieldEvent
from utils.password_strength import calculate_strength
from utils.password_generator import generate_password, generate_passphrase
from config import APP_NAME, APP_VERSION


class MainWindow(QMainWindow):
    """
    CipherGuard main dashboard window with 4 tabs.
    """

    # Signals for thread-safe UI updates
    keyshield_event_signal = pyqtSignal(object)
    clipguard_event_signal = pyqtSignal(object)
    stats_update_signal = pyqtSignal(object)
    buffer_update_signal = pyqtSignal(str, str)  # (original_text, scrambled_text)
    chart_update_signal = pyqtSignal(object)  # list of (hour_str, count) tuples

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION} — Real-Time I/O Protection")
        self.setMinimumSize(1000, 700)

        # State
        self._keyshield_active = False
        self._clipguard_active = False
        self._keystroke_count = 0
        self._hijack_count = 0
        self._copies_count = 0

        # Callbacks (set by main.py)
        self.on_keyshield_toggle = None
        self.on_clipguard_toggle = None
        self.on_algorithm_change = None
        self.on_vault_paste = None
        self.on_generate_report = None
        self.on_protected_input = None
        self.on_clear_buffers = None
        self.on_save_to_vault = None  # For password generator → vault

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        """Build the main UI layout."""
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # ─── Header ──────────────────────────────────────
        header_frame = QFrame()
        header_frame.setStyleSheet("background-color: #0d1117; padding: 12px;")
        header_layout = QHBoxLayout(header_frame)

        title = QLabel(f"🛡️  {APP_NAME}")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color: #ffffff;")
        header_layout.addWidget(title)

        subtitle = QLabel("Real-Time Input & Output Protection Agent")
        subtitle.setStyleSheet("color: #8888aa; font-size: 13px;")
        header_layout.addWidget(subtitle)

        header_layout.addStretch()

        # Status indicators
        self.keyshield_status = QLabel("● KeyShield: OFF")
        self.keyshield_status.setStyleSheet("color: #ff4444; font-weight: bold;")
        header_layout.addWidget(self.keyshield_status)

        self.clipguard_status = QLabel("● ClipGuard: OFF")
        self.clipguard_status.setStyleSheet("color: #ff4444; font-weight: bold;")
        header_layout.addWidget(self.clipguard_status)

        main_layout.addWidget(header_frame)

        # ─── Tab Widget ──────────────────────────────────
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_dashboard_tab(), "📊  Dashboard")
        self.tabs.addTab(self._create_keyshield_tab(), "⌨️  KeyShield")
        self.tabs.addTab(self._create_clipguard_tab(), "📋  ClipGuard")
        self.tabs.addTab(self._create_vault_tab(), "🔒  Vault")
        self.tabs.addTab(self._create_password_generator_tab(), "🔑  Password Generator")
        main_layout.addWidget(self.tabs)

        # ─── Status Bar ──────────────────────────────────
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"{APP_NAME} v{APP_VERSION} — Ready")

    # ─── Dashboard Tab ────────────────────────────────────

    def _create_dashboard_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Stats cards row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(16)

        self.stat_keystrokes = self._create_stat_card("0", "KEYSTROKES PROTECTED", "#00ff88")
        self.stat_hijacks = self._create_stat_card("0", "HIJACKS BLOCKED", "#ff4444")
        self.stat_copies = self._create_stat_card("0", "COPIES MONITORED", "#4488ff")
        self.stat_attackers = self._create_stat_card("0", "ATTACKER PROCESSES", "#ffaa00")

        cards_layout.addWidget(self.stat_keystrokes)
        cards_layout.addWidget(self.stat_hijacks)
        cards_layout.addWidget(self.stat_copies)
        cards_layout.addWidget(self.stat_attackers)

        layout.addLayout(cards_layout)

        # ─── Threat Timeline Chart ────────────────────────
        chart_group = QGroupBox("📈  Threat Timeline (Hijack Attempts per Hour)")
        chart_layout = QVBoxLayout(chart_group)

        # Configure pyqtgraph global settings for dark theme
        pg.setConfigOptions(antialias=True)

        self.timeline_chart = pg.PlotWidget()
        self.timeline_chart.setBackground('#0d1117')
        self.timeline_chart.setMinimumHeight(180)
        self.timeline_chart.setMaximumHeight(220)
        self.timeline_chart.showGrid(x=False, y=True, alpha=0.15)
        self.timeline_chart.setLabel('left', 'Hijacks', color='#8888aa', **{'font-size': '11px'})
        self.timeline_chart.setLabel('bottom', 'Hour', color='#8888aa', **{'font-size': '11px'})
        self.timeline_chart.getAxis('left').setTextPen('#8888aa')
        self.timeline_chart.getAxis('bottom').setTextPen('#8888aa')
        self.timeline_chart.getAxis('left').setPen('#2d2d4a')
        self.timeline_chart.getAxis('bottom').setPen('#2d2d4a')

        # Placeholder text when no data
        self.chart_placeholder = pg.TextItem(
            "No hijack data yet — enable ClipGuard to start monitoring",
            color='#555577', anchor=(0.5, 0.5)
        )
        self.timeline_chart.addItem(self.chart_placeholder)
        self.chart_placeholder.setPos(12, 0.5)

        chart_layout.addWidget(self.timeline_chart)
        layout.addWidget(chart_group)

        # Live activity log
        log_group = QGroupBox("📡  Live Activity Feed")
        log_layout = QVBoxLayout(log_group)

        self.activity_log = QTextEdit()
        self.activity_log.setReadOnly(True)
        self.activity_log.setMinimumHeight(180)
        self.activity_log.setPlaceholderText("Waiting for events...")
        log_layout.addWidget(self.activity_log)

        layout.addWidget(log_group)

        # Report button
        btn_report = QPushButton("📄  Generate PDF Forensic Report")
        btn_report.setObjectName("btn_primary")
        btn_report.setMinimumHeight(40)
        btn_report.clicked.connect(self._on_generate_report)
        layout.addWidget(btn_report)

        return tab

    def _create_stat_card(self, value: str, label: str, color: str) -> QFrame:
        """Create a single statistics card widget."""
        card = QFrame()
        card.setStyleSheet(
            f"background-color: #16213e; border: 1px solid #2d2d4a; "
            f"border-radius: 10px; padding: 16px;"
        )
        card_layout = QVBoxLayout(card)
        card_layout.setAlignment(Qt.AlignCenter)

        val_label = QLabel(value)
        val_label.setFont(QFont("Segoe UI", 32, QFont.Bold))
        val_label.setStyleSheet(f"color: {color};")
        val_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(val_label)

        desc_label = QLabel(label)
        desc_label.setFont(QFont("Segoe UI", 10, QFont.Bold))
        desc_label.setStyleSheet("color: #8888aa;")
        desc_label.setAlignment(Qt.AlignCenter)
        card_layout.addWidget(desc_label)

        # Store reference to value label for updates
        card.value_label = val_label
        return card

    # ─── KeyShield Tab ────────────────────────────────────

    def _create_keyshield_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Enable toggle
        toggle_group = QGroupBox("⚡  KeyShield Control")
        toggle_layout = QVBoxLayout(toggle_group)

        self.keyshield_toggle = QCheckBox("  Enable KeyShield Anti-Keylogger Protection")
        self.keyshield_toggle.setFont(QFont("Segoe UI", 13, QFont.Bold))
        self.keyshield_toggle.toggled.connect(self._on_keyshield_toggle)
        toggle_layout.addWidget(self.keyshield_toggle)

        # Algorithm selector
        algo_layout = QHBoxLayout()
        algo_label = QLabel("Scrambling Algorithm:")
        algo_label.setStyleSheet("font-weight: bold;")
        algo_layout.addWidget(algo_label)

        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["Random Map", "Caesar Shift", "Phonetic Swap"])
        self.algo_combo.currentTextChanged.connect(self._on_algorithm_change)
        algo_layout.addWidget(self.algo_combo)
        algo_layout.addStretch()

        toggle_layout.addLayout(algo_layout)

        # Safety hotkey info
        safety_label = QLabel("⚠️  Safety Hotkey: Ctrl+Shift+F12 (Emergency Disable)")
        safety_label.setStyleSheet("color: #ffaa00; font-style: italic;")
        toggle_layout.addWidget(safety_label)

        layout.addWidget(toggle_group)

        # ─── Protected Input Demo Field ───────────────────────────────
        demo_group = QGroupBox("🛡️  Protected Input Field — Type here for live demo")
        demo_layout = QVBoxLayout(demo_group)

        demo_info = QLabel(
            "Type your password/text below. CipherGuard intercepts each keystroke "
            "inside this field and shows BOTH versions in real-time.\n"
            "The keylogger output file will receive only the scrambled version."
        )
        demo_info.setStyleSheet("color: #aaaacc; font-size: 12px; padding: 4px;")
        demo_info.setWordWrap(True)
        demo_layout.addWidget(demo_info)

        # The actual protected input field (QTextEdit supports Ctrl+V paste fully)
        self.protected_input = QTextEdit()
        self.protected_input.setPlaceholderText("🔐  Type here or paste (Ctrl+V) — e.g. MyBankPassword@123")
        self.protected_input.setStyleSheet(
            "background-color: #0f2a1a; color: #00ff88; border: 2px solid #00ff88; "
            "border-radius: 8px; padding: 10px; font-size: 18px; font-family: 'Consolas';"
        )
        self.protected_input.setMinimumHeight(60)
        self.protected_input.setMaximumHeight(80)
        self.protected_input.textChanged.connect(self._on_protected_input_changed)
        demo_layout.addWidget(self.protected_input)

        # ─── Password Strength Meter ──────────────────────
        strength_layout = QHBoxLayout()

        self.ks_strength_bar = QProgressBar()
        self.ks_strength_bar.setRange(0, 100)
        self.ks_strength_bar.setValue(0)
        self.ks_strength_bar.setTextVisible(False)
        self.ks_strength_bar.setFixedHeight(8)
        self.ks_strength_bar.setStyleSheet(
            "QProgressBar { background-color: #2d2d4a; border: none; border-radius: 4px; }"
            "QProgressBar::chunk { background-color: #ff4444; border-radius: 4px; }"
        )
        strength_layout.addWidget(self.ks_strength_bar)

        self.ks_strength_label = QLabel("")
        self.ks_strength_label.setStyleSheet("color: #8888aa; font-size: 11px; font-weight: bold;")
        self.ks_strength_label.setMinimumWidth(200)
        strength_layout.addWidget(self.ks_strength_label)

        demo_layout.addLayout(strength_layout)

        # Connect strength meter updates
        self.protected_input.textChanged.connect(self._update_ks_strength_meter)

        # Clear protected input button
        btn_clear_input = QPushButton("🗑️  Clear Input")
        btn_clear_input.setObjectName("btn_primary")
        btn_clear_input.setMaximumWidth(150)
        btn_clear_input.clicked.connect(self._clear_protected_input)
        demo_layout.addWidget(btn_clear_input)

        layout.addWidget(demo_group)

        # ─── Side-by-Side Text Comparison ─────────────────────────────
        compare_group = QGroupBox("🔍  Live Comparison — What you typed  vs  What a keylogger sees")
        compare_layout = QVBoxLayout(compare_group)

        boxes_layout = QHBoxLayout()
        boxes_layout.setSpacing(16)

        # Left: Real text (green)
        left_frame = QFrame()
        left_frame.setStyleSheet(
            "background-color: #0a3d2a; border: 2px solid #00ff88; border-radius: 8px;"
        )
        left_layout = QVBoxLayout(left_frame)
        left_header = QLabel("✅  What you typed  (your actual text)")
        left_header.setStyleSheet("color: #00ff88; font-weight: bold; font-size: 13px;")
        left_layout.addWidget(left_header)
        self.ks_original_text = QTextEdit()
        self.ks_original_text.setReadOnly(True)
        self.ks_original_text.setStyleSheet(
            "background-color: #0a3d2a; color: #00ff88; border: none; "
            "font-family: 'Consolas'; font-size: 18px;"
        )
        self.ks_original_text.setMinimumHeight(80)
        left_layout.addWidget(self.ks_original_text)
        boxes_layout.addWidget(left_frame)

        # Right: Scrambled text (red)
        right_frame = QFrame()
        right_frame.setStyleSheet(
            "background-color: #3d0a0a; border: 2px solid #ff4444; border-radius: 8px;"
        )
        right_layout = QVBoxLayout(right_frame)
        right_header = QLabel("❌  What a keylogger captures  (scrambled garbage)")
        right_header.setStyleSheet("color: #ff4444; font-weight: bold; font-size: 13px;")
        right_layout.addWidget(right_header)
        self.ks_scrambled_text = QTextEdit()
        self.ks_scrambled_text.setReadOnly(True)
        self.ks_scrambled_text.setStyleSheet(
            "background-color: #3d0a0a; color: #ff4444; border: none; "
            "font-family: 'Consolas'; font-size: 18px;"
        )
        self.ks_scrambled_text.setMinimumHeight(80)
        right_layout.addWidget(self.ks_scrambled_text)
        boxes_layout.addWidget(right_frame)

        compare_layout.addLayout(boxes_layout)
        layout.addWidget(compare_group)

        # KeyShield event log
        ks_log_group = QGroupBox("📝  KeyShield Event Log (Original → Scrambled per keystroke)")
        ks_log_layout = QVBoxLayout(ks_log_group)

        self.keyshield_log = QTextEdit()
        self.keyshield_log.setReadOnly(True)
        self.keyshield_log.setMaximumHeight(130)
        self.keyshield_log.setPlaceholderText("Keystroke-level events appear here...")
        ks_log_layout.addWidget(self.keyshield_log)

        layout.addWidget(ks_log_group)

        return tab

    def _on_protected_input_changed(self):
        """Called when user types or pastes in the protected input field."""
        # QTextEdit.textChanged has no argument — get text manually
        text = self.protected_input.toPlainText()
        if self.on_protected_input:
            self.on_protected_input(text)

    def _update_ks_strength_meter(self):
        """Update the password strength meter below the protected input field."""
        text = self.protected_input.toPlainText().strip()
        if not text:
            self.ks_strength_bar.setValue(0)
            self.ks_strength_bar.setStyleSheet(
                "QProgressBar { background-color: #2d2d4a; border: none; border-radius: 4px; }"
                "QProgressBar::chunk { background-color: #ff4444; border-radius: 4px; }"
            )
            self.ks_strength_label.setText("")
            return

        result = calculate_strength(text)
        self.ks_strength_bar.setValue(result.score)
        self.ks_strength_bar.setStyleSheet(
            f"QProgressBar {{ background-color: #2d2d4a; border: none; border-radius: 4px; }}"
            f"QProgressBar::chunk {{ background-color: {result.color}; border-radius: 4px; }}"
        )
        self.ks_strength_label.setText(
            f"{result.label}  •  {result.score}/100  •  Crack time: {result.crack_time}"
        )
        self.ks_strength_label.setStyleSheet(
            f"color: {result.color}; font-size: 11px; font-weight: bold;"
        )

    def _clear_protected_input(self):
        """Clear the protected input field and reset strength meter."""
        self.protected_input.clear()
        self.ks_strength_bar.setValue(0)
        self.ks_strength_label.setText("")

    def _on_clear_keyshield_buffers(self):
        """Clear the text comparison buffers."""
        self.ks_original_text.clear()
        self.ks_scrambled_text.clear()
        if hasattr(self, 'on_clear_buffers') and self.on_clear_buffers:
            self.on_clear_buffers()

    # ─── ClipGuard Tab ────────────────────────────────────

    def _create_clipguard_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Enable toggle
        toggle_group = QGroupBox("🔍  ClipGuard Control")
        toggle_layout = QVBoxLayout(toggle_group)

        self.clipguard_toggle = QCheckBox("  Enable ClipGuard Clipboard Protection")
        self.clipguard_toggle.setFont(QFont("Segoe UI", 13, QFont.Bold))
        self.clipguard_toggle.toggled.connect(self._on_clipguard_toggle)
        toggle_layout.addWidget(self.clipguard_toggle)

        layout.addWidget(toggle_group)

        # Hijack events table
        events_group = QGroupBox("🚨  Detected Hijack Attempts")
        events_layout = QVBoxLayout(events_group)

        self.hijack_table = QTableWidget()
        self.hijack_table.setColumnCount(5)
        self.hijack_table.setHorizontalHeaderLabels([
            "Timestamp", "Original", "Hijacked", "Pattern", "Attacker"
        ])
        self.hijack_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.hijack_table.setAlternatingRowColors(True)
        self.hijack_table.setSelectionBehavior(QTableWidget.SelectRows)
        events_layout.addWidget(self.hijack_table)

        layout.addWidget(events_group)

        # ClipGuard log
        cg_log_group = QGroupBox("📝  ClipGuard Activity")
        cg_log_layout = QVBoxLayout(cg_log_group)

        self.clipguard_log = QTextEdit()
        self.clipguard_log.setReadOnly(True)
        self.clipguard_log.setPlaceholderText("ClipGuard events will appear here...")
        cg_log_layout.addWidget(self.clipguard_log)

        layout.addWidget(cg_log_group)

        return tab

    # ─── Vault Tab ────────────────────────────────────────

    def _create_vault_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # Vault info
        info_group = QGroupBox("🔐  Encrypted Clipboard Vault")
        info_layout = QVBoxLayout(info_group)

        info_label = QLabel(
            "📌  HOW IT WORKS: The Vault automatically saves everything you copy (Ctrl+C) "
            "while ClipGuard is running.\n"
            "You can also manually add passwords/secrets below.\n"
            "All entries are encrypted with AES-256-GCM using your master password."
        )
        info_label.setStyleSheet("color: #aaaacc; font-size: 12px; padding: 4px;")
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)

        layout.addWidget(info_group)

        # ─── Vault Search Bar ─────────────────────────────
        search_layout = QHBoxLayout()
        self.vault_search = QLineEdit()
        self.vault_search.setPlaceholderText("🔍  Search vault entries...")
        self.vault_search.setStyleSheet(
            "background-color: #0d1117; color: #e0e0e0; border: 1px solid #2d2d4a; "
            "border-radius: 6px; padding: 8px 12px; font-size: 13px;"
        )
        self.vault_search.setClearButtonEnabled(True)
        self.vault_search.textChanged.connect(self._on_vault_search)
        search_layout.addWidget(self.vault_search)
        layout.addLayout(search_layout)

        # Vault entries table
        self.vault_table = QTableWidget()
        self.vault_table.setColumnCount(4)
        self.vault_table.setHorizontalHeaderLabels([
            "Timestamp", "Content (Preview)", "Type", "Expires"
        ])
        self.vault_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.vault_table.setAlternatingRowColors(True)
        self.vault_table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.vault_table)

        # Vault actions - row 1: Add and Delete
        vault_btn_layout1 = QHBoxLayout()

        btn_add = QPushButton("➕  Add Entry Manually")
        btn_add.setObjectName("btn_primary")
        btn_add.setMinimumHeight(40)
        btn_add.setStyleSheet(
            "background-color: #1a4a2a; color: #00ff88; border: 2px solid #00ff88; "
            "border-radius: 6px; font-size: 13px; font-weight: bold;"
        )
        btn_add.clicked.connect(self._on_vault_add_entry)
        vault_btn_layout1.addWidget(btn_add)

        btn_delete = QPushButton("🗑️  Delete Selected")
        btn_delete.setObjectName("btn_primary")
        btn_delete.setMinimumHeight(40)
        btn_delete.setStyleSheet(
            "background-color: #4a1a1a; color: #ff4444; border: 2px solid #ff4444; "
            "border-radius: 6px; font-size: 13px; font-weight: bold;"
        )
        btn_delete.clicked.connect(self._on_vault_delete_entry)
        vault_btn_layout1.addWidget(btn_delete)

        layout.addLayout(vault_btn_layout1)

        # Row 2: Paste and Refresh
        vault_btn_layout2 = QHBoxLayout()

        btn_paste = QPushButton("📋  Paste from Vault (copy to clipboard)")
        btn_paste.setObjectName("btn_safe")
        btn_paste.setMinimumHeight(36)
        btn_paste.clicked.connect(self._on_vault_paste)
        vault_btn_layout2.addWidget(btn_paste)

        btn_refresh = QPushButton("🔄  Refresh")
        btn_refresh.setObjectName("btn_primary")
        btn_refresh.setMinimumHeight(36)
        btn_refresh.clicked.connect(self._on_vault_refresh)
        vault_btn_layout2.addWidget(btn_refresh)

        layout.addLayout(vault_btn_layout2)

        return tab

    def _on_vault_add_entry(self):
        """Show dialog to manually add a vault entry."""
        from PyQt5.QtWidgets import QDialog, QFormLayout, QDialogButtonBox
        dialog = QDialog(self)
        dialog.setWindowTitle("🔐  Add Vault Entry")
        dialog.setMinimumWidth(450)
        dialog.setStyleSheet("background-color: #0d1117; color: #ffffff;")

        form = QFormLayout(dialog)
        form.setSpacing(12)
        form.setContentsMargins(20, 20, 20, 20)

        label_input = QLineEdit()
        label_input.setPlaceholderText("e.g. Gmail Password, Bank PIN...")
        label_input.setStyleSheet(
            "background: #1a1a2e; color: #fff; border: 1px solid #444; "
            "border-radius: 4px; padding: 8px;"
        )
        form.addRow("Label:", label_input)

        secret_input = QLineEdit()
        secret_input.setPlaceholderText("Enter the password or secret...")
        secret_input.setEchoMode(QLineEdit.Password)
        secret_input.setStyleSheet(
            "background: #1a1a2e; color: #00ff88; border: 1px solid #00ff88; "
            "border-radius: 4px; padding: 8px; font-size: 14px;"
        )
        form.addRow("Secret:", secret_input)

        show_cb = QCheckBox("Show secret while typing")
        show_cb.setStyleSheet("color: #aaaacc;")
        show_cb.toggled.connect(
            lambda checked: secret_input.setEchoMode(
                QLineEdit.Normal if checked else QLineEdit.Password
            )
        )
        form.addRow("", show_cb)

        # Password Strength Meter in the Add Entry dialog
        vault_strength_bar = QProgressBar()
        vault_strength_bar.setRange(0, 100)
        vault_strength_bar.setValue(0)
        vault_strength_bar.setTextVisible(False)
        vault_strength_bar.setFixedHeight(8)
        vault_strength_bar.setStyleSheet(
            "QProgressBar { background-color: #2d2d4a; border: none; border-radius: 4px; }"
            "QProgressBar::chunk { background-color: #ff4444; border-radius: 4px; }"
        )
        form.addRow("", vault_strength_bar)

        vault_strength_label = QLabel("")
        vault_strength_label.setStyleSheet("color: #8888aa; font-size: 11px; font-weight: bold;")
        form.addRow("", vault_strength_label)

        # Connect strength meter updates for the dialog
        def update_vault_dialog_strength(text):
            if not text:
                vault_strength_bar.setValue(0)
                vault_strength_label.setText("")
                return
            result = calculate_strength(text)
            vault_strength_bar.setValue(result.score)
            vault_strength_bar.setStyleSheet(
                f"QProgressBar {{ background-color: #2d2d4a; border: none; border-radius: 4px; }}"
                f"QProgressBar::chunk {{ background-color: {result.color}; border-radius: 4px; }}"
            )
            vault_strength_label.setText(
                f"{result.label}  •  {result.score}/100  •  Crack time: {result.crack_time}"
            )
            vault_strength_label.setStyleSheet(
                f"color: {result.color}; font-size: 11px; font-weight: bold;"
            )

        secret_input.textChanged.connect(update_vault_dialog_strength)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.setStyleSheet("color: #ffffff;")
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)

        if dialog.exec_() == QDialog.Accepted:
            label = label_input.text().strip()
            secret = secret_input.text()
            if secret:
                content = f"[{label}] {secret}" if label else secret
                if self.on_vault_paste:
                    self.on_vault_paste((-2, content))  # -2 = manual add signal
                self.status_bar.showMessage(
                    f"✅ Entry '{label or 'Secret'}' saved to vault (AES-256 encrypted)", 4000
                )

    def _on_vault_delete_entry(self):
        """Delete the selected vault entry."""
        selected = self.vault_table.currentRow()
        if selected >= 0:
            if self.on_vault_paste:
                self.on_vault_paste((-3, selected))  # -3 = delete signal
            self.vault_table.removeRow(selected)
            self.status_bar.showMessage("🗑️  Entry deleted from vault", 3000)
        else:
            self.status_bar.showMessage("⚠️  Select an entry to delete first", 3000)

    def _on_vault_search(self, text: str):
        """Filter vault table rows based on search text."""
        search_lower = text.lower().strip()
        for row in range(self.vault_table.rowCount()):
            match = False
            if not search_lower:
                match = True
            else:
                for col in range(self.vault_table.columnCount()):
                    item = self.vault_table.item(row, col)
                    if item and search_lower in item.text().lower():
                        match = True
                        break
            self.vault_table.setRowHidden(row, not match)


    # ─── Signal Connections ───────────────────────────────

    def _connect_signals(self):
        """Connect thread-safe signals to UI update slots."""
        self.keyshield_event_signal.connect(self._update_keyshield_log)
        self.clipguard_event_signal.connect(self._update_clipguard_log)
        self.stats_update_signal.connect(self._update_stats)
        self.buffer_update_signal.connect(self._update_buffer_boxes)
        self.chart_update_signal.connect(self._update_timeline_chart)

    # ─── UI Update Methods (called from signals) ─────────

    def _update_keyshield_log(self, event: KeyShieldEvent):
        """Add a KeyShield event to the log (thread-safe via signal)."""
        self.keyshield_log.append(
            f'<span style="color:#8888aa;">[{event.timestamp[11:19]}]</span> '
            f'<span style="color:#00ff88;">Original: {event.original}</span> → '
            f'<span style="color:#ff4444;">Scrambled: {event.scrambled}</span> '
            f'<span style="color:#8888aa;">({event.algorithm})</span>'
        )
        self._keystroke_count += 1
        self.stat_keystrokes.value_label.setText(str(self._keystroke_count))

        # Also add to main activity log
        self.activity_log.append(
            f'<span style="color:#8888aa;">[{event.timestamp[11:19]}]</span> '
            f'<span style="color:#00ff88;">⌨️ KeyShield:</span> Keystroke protected '
            f'({event.algorithm})'
        )

    def _update_buffer_boxes(self, original: str, scrambled: str):
        """Update the side-by-side text comparison boxes (thread-safe via signal)."""
        self.ks_original_text.setPlainText(original)
        self.ks_scrambled_text.setPlainText(scrambled)

    def update_keyshield_buffers(self, original: str, scrambled: str):
        """Update the side-by-side text comparison boxes (called from timer)."""
        self.ks_original_text.setPlainText(original)
        self.ks_scrambled_text.setPlainText(scrambled)

    def _update_clipguard_log(self, event: ClipGuardEvent):
        """Add a ClipGuard event to the log (thread-safe via signal)."""
        if event.event_type == "hijack_detected":
            self.clipguard_log.append(
                f'<span style="color:#ff4444;font-weight:bold;">'
                f'[{event.timestamp[11:19]}] 🚨 HIJACK DETECTED!</span><br>'
                f'  Original: <span style="color:#00ff88;">{event.original_content[:60]}</span><br>'
                f'  Hijacked: <span style="color:#ff4444;">{event.hijacked_content[:60]}</span><br>'
                f'  Attacker: {event.attacker_process} (PID: {event.attacker_pid})<br>'
                f'  Action: {event.action_taken}'
            )
            # Add to hijack table
            row = self.hijack_table.rowCount()
            self.hijack_table.insertRow(row)
            self.hijack_table.setItem(row, 0, QTableWidgetItem(event.timestamp[11:19]))
            self.hijack_table.setItem(row, 1, QTableWidgetItem(event.original_content[:40]))
            self.hijack_table.setItem(row, 2, QTableWidgetItem(event.hijacked_content[:40]))
            self.hijack_table.setItem(row, 3, QTableWidgetItem(event.pattern_type))
            self.hijack_table.setItem(row, 4, QTableWidgetItem(event.attacker_process))

            self._hijack_count += 1
            self.stat_hijacks.value_label.setText(str(self._hijack_count))

            # Activity log
            self.activity_log.append(
                f'<span style="color:#ff4444;font-weight:bold;">'
                f'[{event.timestamp[11:19]}] 🚨 CLIPBOARD HIJACK BLOCKED!</span> '
                f'Attacker: {event.attacker_process}'
            )
        elif event.event_type == "copy":
            self._copies_count += 1
            self.stat_copies.value_label.setText(str(self._copies_count))

    def _update_stats(self, stats: dict):
        """Update dashboard statistics."""
        if "keystrokes" in stats:
            self.stat_keystrokes.value_label.setText(str(stats["keystrokes"]))
        if "hijacks" in stats:
            self.stat_hijacks.value_label.setText(str(stats["hijacks"]))
        if "copies" in stats:
            self.stat_copies.value_label.setText(str(stats["copies"]))
        if "attackers" in stats:
            self.stat_attackers.value_label.setText(str(stats["attackers"]))

    def update_keyshield_status(self, active: bool):
        """Update the KeyShield status indicator in the header."""
        self._keyshield_active = active
        if active:
            self.keyshield_status.setText("● KeyShield: ON")
            self.keyshield_status.setStyleSheet("color: #00ff88; font-weight: bold;")
        else:
            self.keyshield_status.setText("● KeyShield: OFF")
            self.keyshield_status.setStyleSheet("color: #ff4444; font-weight: bold;")

    def update_clipguard_status(self, active: bool):
        """Update the ClipGuard status indicator in the header."""
        self._clipguard_active = active
        if active:
            self.clipguard_status.setText("● ClipGuard: ON")
            self.clipguard_status.setStyleSheet("color: #00ff88; font-weight: bold;")
        else:
            self.clipguard_status.setText("● ClipGuard: OFF")
            self.clipguard_status.setStyleSheet("color: #ff4444; font-weight: bold;")

    def update_vault_table(self, entries: list):
        """Refresh the vault entries table."""
        self.vault_table.setRowCount(0)
        for entry in entries:
            row = self.vault_table.rowCount()
            self.vault_table.insertRow(row)
            self.vault_table.setItem(row, 0, QTableWidgetItem(entry.get("timestamp", "")[:19]))
            content_preview = entry.get("content", "")[:50] + ("..." if len(entry.get("content", "")) > 50 else "")
            self.vault_table.setItem(row, 1, QTableWidgetItem(content_preview))
            self.vault_table.setItem(row, 2, QTableWidgetItem(entry.get("content_type", "text")))
            expires = entry.get("expires_at", "Never")
            self.vault_table.setItem(row, 3, QTableWidgetItem(expires[:19] if expires else "Never"))

    # ─── Event Handlers ───────────────────────────────────

    def _on_keyshield_toggle(self, checked: bool):
        if self.on_keyshield_toggle:
            self.on_keyshield_toggle(checked)

    def _on_clipguard_toggle(self, checked: bool):
        if self.on_clipguard_toggle:
            self.on_clipguard_toggle(checked)

    def _on_algorithm_change(self, text: str):
        algo_map = {
            "Random Map": "random_map",
            "Caesar Shift": "caesar",
            "Phonetic Swap": "phonetic",
        }
        algo = algo_map.get(text, "random_map")
        if self.on_algorithm_change:
            self.on_algorithm_change(algo)

    def _on_vault_paste(self):
        if self.on_vault_paste:
            selected = self.vault_table.currentRow()
            if selected >= 0:
                self.on_vault_paste(selected)
            else:
                self.status_bar.showMessage("Select a vault entry first", 3000)

    def _on_vault_refresh(self):
        """Emit signal to refresh vault from main.py."""
        if self.on_vault_paste:
            self.on_vault_paste(-1)  # -1 signals a refresh request

    def _on_generate_report(self):
        if self.on_generate_report:
            self.on_generate_report()

    # ─── Threat Timeline Chart ─────────────────────────────

    def _update_timeline_chart(self, data):
        """
        Update the threat timeline bar chart with hourly data.
        data: list of (hour_string, count) tuples from db.get_events_by_hour()
        """
        self.timeline_chart.clear()

        if not data:
            # Show placeholder when no data
            placeholder = pg.TextItem(
                "No hijack data yet — enable ClipGuard to start monitoring",
                color='#555577', anchor=(0.5, 0.5)
            )
            self.timeline_chart.addItem(placeholder)
            placeholder.setPos(12, 0.5)
            return

        # Prepare bar chart data
        hours = [item[0] for item in data]  # hour strings
        counts = [item[1] for item in data]  # event counts

        # Reverse to show oldest first (left to right)
        hours.reverse()
        counts.reverse()

        x = list(range(len(counts)))

        # Create bar chart items
        bar_item = pg.BarGraphItem(
            x=x, height=counts, width=0.6,
            brush=pg.mkBrush('#ff4444'),
            pen=pg.mkPen('#ff6666', width=1)
        )
        self.timeline_chart.addItem(bar_item)

        # Set x-axis tick labels (show hour only, e.g., "14:00")
        tick_labels = []
        for i, h in enumerate(hours):
            # h format: "2026-07-02 14:00" → show "14:00"
            short = h.split(' ')[-1] if ' ' in h else h
            tick_labels.append((i, short))

        ax = self.timeline_chart.getAxis('bottom')
        ax.setTicks([tick_labels])

    # ─── Password Generator Tab ────────────────────────────

    def _create_password_generator_tab(self) -> QWidget:
        """Create the Password Generator tab with controls and output."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # ─── Controls Group ───────────────────────────────
        controls_group = QGroupBox("⚙️  Password Settings")
        controls_layout = QVBoxLayout(controls_group)

        # Length control
        length_layout = QHBoxLayout()
        length_label = QLabel("Password Length:")
        length_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        length_layout.addWidget(length_label)

        self.pw_length_slider = QSlider(Qt.Horizontal)
        self.pw_length_slider.setRange(8, 128)
        self.pw_length_slider.setValue(16)
        self.pw_length_slider.setTickPosition(QSlider.TicksBelow)
        self.pw_length_slider.setTickInterval(8)
        length_layout.addWidget(self.pw_length_slider)

        self.pw_length_spin = QSpinBox()
        self.pw_length_spin.setRange(8, 128)
        self.pw_length_spin.setValue(16)
        self.pw_length_spin.setStyleSheet(
            "background: #0d1117; color: #00ff88; border: 1px solid #2d2d4a; "
            "border-radius: 4px; padding: 4px; font-size: 14px; font-weight: bold;"
        )
        length_layout.addWidget(self.pw_length_spin)

        # Sync slider and spinbox
        self.pw_length_slider.valueChanged.connect(self.pw_length_spin.setValue)
        self.pw_length_spin.valueChanged.connect(self.pw_length_slider.setValue)

        controls_layout.addLayout(length_layout)

        # Character set checkboxes
        charset_layout = QHBoxLayout()
        charset_layout.setSpacing(24)

        self.pw_uppercase = QCheckBox("  A-Z Uppercase")
        self.pw_uppercase.setChecked(True)
        charset_layout.addWidget(self.pw_uppercase)

        self.pw_lowercase = QCheckBox("  a-z Lowercase")
        self.pw_lowercase.setChecked(True)
        charset_layout.addWidget(self.pw_lowercase)

        self.pw_digits = QCheckBox("  0-9 Digits")
        self.pw_digits.setChecked(True)
        charset_layout.addWidget(self.pw_digits)

        self.pw_symbols = QCheckBox("  !@#$ Symbols")
        self.pw_symbols.setChecked(True)
        charset_layout.addWidget(self.pw_symbols)

        controls_layout.addLayout(charset_layout)

        # Exclude ambiguous option
        self.pw_exclude_ambiguous = QCheckBox("  Exclude ambiguous characters (0, O, l, 1, I)")
        self.pw_exclude_ambiguous.setStyleSheet("color: #aaaacc; font-size: 12px;")
        controls_layout.addWidget(self.pw_exclude_ambiguous)

        layout.addWidget(controls_group)

        # ─── Generated Password Output ────────────────────
        output_group = QGroupBox("🔑  Generated Password")
        output_layout = QVBoxLayout(output_group)

        self.pw_output = QTextEdit()
        self.pw_output.setReadOnly(True)
        self.pw_output.setMinimumHeight(60)
        self.pw_output.setMaximumHeight(80)
        self.pw_output.setPlaceholderText("Click 'Generate Password' to create a secure password...")
        self.pw_output.setStyleSheet(
            "background-color: #0a2a1a; color: #00ff88; border: 2px solid #00ff88; "
            "border-radius: 8px; padding: 12px; font-size: 20px; "
            "font-family: 'Consolas', 'Cascadia Code', monospace; font-weight: bold;"
        )
        output_layout.addWidget(self.pw_output)

        # Strength meter for generated password
        pw_strength_layout = QHBoxLayout()

        self.pw_strength_bar = QProgressBar()
        self.pw_strength_bar.setRange(0, 100)
        self.pw_strength_bar.setValue(0)
        self.pw_strength_bar.setTextVisible(False)
        self.pw_strength_bar.setFixedHeight(8)
        self.pw_strength_bar.setStyleSheet(
            "QProgressBar { background-color: #2d2d4a; border: none; border-radius: 4px; }"
            "QProgressBar::chunk { background-color: #ff4444; border-radius: 4px; }"
        )
        pw_strength_layout.addWidget(self.pw_strength_bar)

        self.pw_strength_label = QLabel("")
        self.pw_strength_label.setStyleSheet(
            "color: #8888aa; font-size: 11px; font-weight: bold;"
        )
        self.pw_strength_label.setMinimumWidth(250)
        pw_strength_layout.addWidget(self.pw_strength_label)

        output_layout.addLayout(pw_strength_layout)

        layout.addWidget(output_group)

        # ─── Action Buttons ───────────────────────────────
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        btn_generate = QPushButton("🔄  Generate Password")
        btn_generate.setObjectName("btn_safe")
        btn_generate.setMinimumHeight(44)
        btn_generate.setStyleSheet(
            "background-color: #0a3d2a; color: #00ff88; border: 2px solid #00ff88; "
            "border-radius: 6px; font-size: 14px; font-weight: bold;"
        )
        btn_generate.clicked.connect(self._on_generate_password)
        btn_layout.addWidget(btn_generate)

        btn_copy = QPushButton("📋  Copy to Clipboard")
        btn_copy.setObjectName("btn_primary")
        btn_copy.setMinimumHeight(44)
        btn_copy.clicked.connect(self._on_copy_password)
        btn_layout.addWidget(btn_copy)

        btn_save_vault = QPushButton("🔒  Save to Vault")
        btn_save_vault.setObjectName("btn_primary")
        btn_save_vault.setMinimumHeight(44)
        btn_save_vault.clicked.connect(self._on_save_password_to_vault)
        btn_layout.addWidget(btn_save_vault)

        layout.addLayout(btn_layout)

        # ─── Passphrase Section ───────────────────────────
        passphrase_group = QGroupBox("📝  Passphrase Generator")
        passphrase_layout = QVBoxLayout(passphrase_group)

        pp_info = QLabel(
            "Generate a memorable passphrase from random words. "
            "Easier to remember, often stronger than short complex passwords."
        )
        pp_info.setStyleSheet("color: #aaaacc; font-size: 12px;")
        pp_info.setWordWrap(True)
        passphrase_layout.addWidget(pp_info)

        pp_controls = QHBoxLayout()

        pp_words_label = QLabel("Words:")
        pp_words_label.setStyleSheet("font-weight: bold;")
        pp_controls.addWidget(pp_words_label)

        self.pp_word_count = QSpinBox()
        self.pp_word_count.setRange(3, 8)
        self.pp_word_count.setValue(4)
        self.pp_word_count.setStyleSheet(
            "background: #0d1117; color: #00ff88; border: 1px solid #2d2d4a; "
            "border-radius: 4px; padding: 4px;"
        )
        pp_controls.addWidget(self.pp_word_count)

        pp_sep_label = QLabel("Separator:")
        pp_sep_label.setStyleSheet("font-weight: bold;")
        pp_controls.addWidget(pp_sep_label)

        self.pp_separator = QComboBox()
        self.pp_separator.addItems(["-", "_", ".", " ", "/"])
        pp_controls.addWidget(self.pp_separator)

        pp_controls.addStretch()

        btn_pp_generate = QPushButton("🔄  Generate Passphrase")
        btn_pp_generate.setObjectName("btn_safe")
        btn_pp_generate.setMinimumHeight(36)
        btn_pp_generate.clicked.connect(self._on_generate_passphrase)
        pp_controls.addWidget(btn_pp_generate)

        passphrase_layout.addLayout(pp_controls)

        self.pp_output = QLineEdit()
        self.pp_output.setReadOnly(True)
        self.pp_output.setPlaceholderText("Generated passphrase will appear here...")
        self.pp_output.setStyleSheet(
            "background-color: #0a2a1a; color: #00ff88; border: 2px solid #00ff88; "
            "border-radius: 8px; padding: 10px; font-size: 16px; "
            "font-family: 'Consolas', monospace; font-weight: bold;"
        )
        passphrase_layout.addWidget(self.pp_output)

        layout.addWidget(passphrase_group)

        layout.addStretch()
        return tab

    def _on_generate_password(self):
        """Generate a new random password based on current settings."""
        try:
            password = generate_password(
                length=self.pw_length_spin.value(),
                uppercase=self.pw_uppercase.isChecked(),
                lowercase=self.pw_lowercase.isChecked(),
                digits=self.pw_digits.isChecked(),
                symbols=self.pw_symbols.isChecked(),
                exclude_ambiguous=self.pw_exclude_ambiguous.isChecked(),
            )
            self.pw_output.setPlainText(password)

            # Update strength meter
            result = calculate_strength(password)
            self.pw_strength_bar.setValue(result.score)
            self.pw_strength_bar.setStyleSheet(
                f"QProgressBar {{ background-color: #2d2d4a; border: none; border-radius: 4px; }}"
                f"QProgressBar::chunk {{ background-color: {result.color}; border-radius: 4px; }}"
            )
            self.pw_strength_label.setText(
                f"{result.label}  •  {result.score}/100  •  "
                f"Entropy: {result.entropy_bits} bits  •  Crack time: {result.crack_time}"
            )
            self.pw_strength_label.setStyleSheet(
                f"color: {result.color}; font-size: 11px; font-weight: bold;"
            )

            self.status_bar.showMessage(
                f"🔑 Password generated ({self.pw_length_spin.value()} chars, "
                f"{result.label})", 3000
            )
        except ValueError as e:
            QMessageBox.warning(self, "Generation Error", str(e))

    def _on_copy_password(self):
        """Copy the generated password to clipboard."""
        password = self.pw_output.toPlainText().strip()
        if password:
            from PyQt5.QtWidgets import QApplication
            QApplication.clipboard().setText(password)
            self.status_bar.showMessage("📋  Password copied to clipboard!", 3000)
        else:
            self.status_bar.showMessage("⚠️  Generate a password first", 3000)

    def _on_save_password_to_vault(self):
        """Save the generated password to the encrypted vault."""
        password = self.pw_output.toPlainText().strip()
        if not password:
            self.status_bar.showMessage("⚠️  Generate a password first", 3000)
            return

        if self.on_save_to_vault:
            self.on_save_to_vault(password)
            self.status_bar.showMessage(
                "🔒  Password saved to Vault (AES-256 encrypted)", 4000
            )
        elif self.on_vault_paste:
            # Fallback: use vault_paste with manual add signal
            self.on_vault_paste((-2, f"[Generated] {password}"))
            self.status_bar.showMessage(
                "🔒  Password saved to Vault (AES-256 encrypted)", 4000
            )

    def _on_generate_passphrase(self):
        """Generate a new random passphrase."""
        try:
            passphrase = generate_passphrase(
                word_count=self.pp_word_count.value(),
                separator=self.pp_separator.currentText(),
            )
            self.pp_output.setText(passphrase)
            self.status_bar.showMessage(
                f"📝  Passphrase generated ({self.pp_word_count.value()} words)", 3000
            )
        except ValueError as e:
            QMessageBox.warning(self, "Generation Error", str(e))
