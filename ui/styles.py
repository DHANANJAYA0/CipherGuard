"""
CipherGuard — Dark Theme Stylesheet
Premium dark UI theme with green/red accent colors.
"""

DARK_THEME = """
/* ─── Global ──────────────────────────────────────────── */
QWidget {
    background-color: #1a1a2e;
    color: #e0e0e0;
    font-family: 'Segoe UI', 'Arial', sans-serif;
    font-size: 13px;
}

QMainWindow {
    background-color: #1a1a2e;
}

/* ─── Tab Widget ──────────────────────────────────────── */
QTabWidget::pane {
    border: 1px solid #2d2d4a;
    border-radius: 8px;
    background-color: #16213e;
    margin-top: -1px;
}

QTabBar::tab {
    background-color: #1a1a2e;
    color: #8888aa;
    padding: 10px 20px;
    margin-right: 2px;
    border: 1px solid #2d2d4a;
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    font-weight: bold;
    min-width: 120px;
}

QTabBar::tab:selected {
    background-color: #16213e;
    color: #00ff88;
    border-bottom: 2px solid #00ff88;
}

QTabBar::tab:hover {
    background-color: #1f2b47;
    color: #ffffff;
}

/* ─── Labels ──────────────────────────────────────────── */
QLabel {
    color: #e0e0e0;
    padding: 2px;
}

QLabel#title {
    font-size: 22px;
    font-weight: bold;
    color: #ffffff;
}

QLabel#subtitle {
    font-size: 14px;
    color: #8888aa;
}

QLabel#stat_value {
    font-size: 36px;
    font-weight: bold;
    color: #00ff88;
}

QLabel#stat_label {
    font-size: 12px;
    color: #8888aa;
    font-weight: bold;
    text-transform: uppercase;
}

QLabel#alert_title {
    font-size: 18px;
    font-weight: bold;
    color: #ff4444;
}

QLabel#safe_text {
    color: #00ff88;
}

QLabel#danger_text {
    color: #ff4444;
}

/* ─── Buttons ─────────────────────────────────────────── */
QPushButton {
    background-color: #2d2d4a;
    color: #e0e0e0;
    border: 1px solid #3d3d5c;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: bold;
    min-height: 32px;
}

QPushButton:hover {
    background-color: #3d3d5c;
    border: 1px solid #00ff88;
    color: #ffffff;
}

QPushButton:pressed {
    background-color: #00ff88;
    color: #1a1a2e;
}

QPushButton#btn_safe {
    background-color: #0a3d2a;
    border: 1px solid #00ff88;
    color: #00ff88;
}

QPushButton#btn_safe:hover {
    background-color: #00ff88;
    color: #1a1a2e;
}

QPushButton#btn_danger {
    background-color: #3d0a0a;
    border: 1px solid #ff4444;
    color: #ff4444;
}

QPushButton#btn_danger:hover {
    background-color: #ff4444;
    color: #ffffff;
}

QPushButton#btn_primary {
    background-color: #0f3460;
    border: 1px solid #4488ff;
    color: #4488ff;
}

QPushButton#btn_primary:hover {
    background-color: #4488ff;
    color: #ffffff;
}

/* ─── Toggle Switch (Checkbox styled) ─────────────────── */
QCheckBox {
    spacing: 10px;
    color: #e0e0e0;
    font-weight: bold;
}

QCheckBox::indicator {
    width: 44px;
    height: 22px;
    border-radius: 11px;
    border: 2px solid #3d3d5c;
    background-color: #2d2d4a;
}

QCheckBox::indicator:checked {
    background-color: #00ff88;
    border-color: #00cc6a;
}

/* ─── Group Box ───────────────────────────────────────── */
QGroupBox {
    border: 1px solid #2d2d4a;
    border-radius: 8px;
    margin-top: 16px;
    padding: 16px;
    padding-top: 24px;
    font-weight: bold;
    color: #ffffff;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 16px;
    padding: 0px 8px;
    color: #00ff88;
}

/* ─── Text Edit / Log Area ────────────────────────────── */
QTextEdit, QPlainTextEdit {
    background-color: #0d1117;
    color: #c9d1d9;
    border: 1px solid #2d2d4a;
    border-radius: 6px;
    padding: 8px;
    font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    selection-background-color: #264f78;
}

/* ─── Line Edit / Input ───────────────────────────────── */
QLineEdit {
    background-color: #0d1117;
    color: #e0e0e0;
    border: 1px solid #2d2d4a;
    border-radius: 6px;
    padding: 8px 12px;
    font-size: 14px;
    selection-background-color: #264f78;
}

QLineEdit:focus {
    border: 1px solid #00ff88;
}

/* ─── Combo Box ───────────────────────────────────────── */
QComboBox {
    background-color: #2d2d4a;
    color: #e0e0e0;
    border: 1px solid #3d3d5c;
    border-radius: 6px;
    padding: 6px 12px;
    min-height: 28px;
}

QComboBox:hover {
    border: 1px solid #00ff88;
}

QComboBox::drop-down {
    border: none;
    width: 24px;
}

QComboBox QAbstractItemView {
    background-color: #1a1a2e;
    color: #e0e0e0;
    border: 1px solid #2d2d4a;
    selection-background-color: #0f3460;
}

/* ─── Table Widget ────────────────────────────────────── */
QTableWidget {
    background-color: #0d1117;
    color: #c9d1d9;
    border: 1px solid #2d2d4a;
    border-radius: 6px;
    gridline-color: #2d2d4a;
    selection-background-color: #0f3460;
}

QTableWidget::item {
    padding: 6px;
}

QHeaderView::section {
    background-color: #1a1a2e;
    color: #00ff88;
    padding: 8px;
    border: 1px solid #2d2d4a;
    font-weight: bold;
}

/* ─── Scroll Bar ──────────────────────────────────────── */
QScrollBar:vertical {
    background-color: #1a1a2e;
    width: 10px;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background-color: #3d3d5c;
    border-radius: 5px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background-color: #00ff88;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background-color: #1a1a2e;
    height: 10px;
    border-radius: 5px;
}

QScrollBar::handle:horizontal {
    background-color: #3d3d5c;
    border-radius: 5px;
    min-width: 30px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #00ff88;
}

/* ─── Progress Bar ────────────────────────────────────── */
QProgressBar {
    background-color: #2d2d4a;
    border: 1px solid #3d3d5c;
    border-radius: 6px;
    text-align: center;
    color: #ffffff;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: #00ff88;
    border-radius: 5px;
}

/* ─── Status Bar ──────────────────────────────────────── */
QStatusBar {
    background-color: #0d1117;
    color: #8888aa;
    border-top: 1px solid #2d2d4a;
}

/* ─── Menu ────────────────────────────────────────────── */
QMenu {
    background-color: #1a1a2e;
    color: #e0e0e0;
    border: 1px solid #2d2d4a;
    border-radius: 6px;
    padding: 4px;
}

QMenu::item {
    padding: 8px 24px;
    border-radius: 4px;
}

QMenu::item:selected {
    background-color: #0f3460;
    color: #ffffff;
}

QMenu::separator {
    height: 1px;
    background-color: #2d2d4a;
    margin: 4px 8px;
}

/* ─── Tool Tip ────────────────────────────────────────── */
QToolTip {
    background-color: #0d1117;
    color: #e0e0e0;
    border: 1px solid #00ff88;
    border-radius: 4px;
    padding: 6px;
}
"""
