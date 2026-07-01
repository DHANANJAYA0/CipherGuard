"""
CipherGuard — Configuration & Constants
"""

import os

# ─── Application Info ─────────────────────────────────────────────
APP_NAME = "CipherGuard"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Real-Time Input & Output Protection Agent"

# ─── Paths ────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
DB_PATH = os.path.join(BASE_DIR, "cipherguard.db")
LOG_PATH = os.path.join(BASE_DIR, "cipherguard.log")

# ─── KeyShield Settings ──────────────────────────────────────────
KEYSHIELD_SAFETY_HOTKEY = "ctrl+shift+f12"  # Emergency disable hotkey
KEYSHIELD_DEFAULT_ALGORITHM = "random_map"  # Options: random_map, caesar, phonetic

# Characters that KeyShield will scramble (printable ASCII)
SCRAMBLE_CHARS = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "!@#$%^&*()-_=+[]{}|;:',.<>?/`~"
)

# ─── ClipGuard Settings ──────────────────────────────────────────
CLIPGUARD_POLL_INTERVAL_MS = 200  # Fallback polling interval in milliseconds
CLIPGUARD_HASH_ALGORITHM = "sha256"

# ─── Vault Settings ──────────────────────────────────────────────
VAULT_MAX_ENTRIES = 50
VAULT_SENSITIVE_EXPIRY_SECONDS = 60  # Auto-delete sensitive entries after 60s
VAULT_PBKDF2_ITERATIONS = 600_000

# ─── Dashboard Settings ──────────────────────────────────────────
DASHBOARD_MAX_LOG_ENTRIES = 200  # Max events shown in the live feed
DASHBOARD_CHART_WINDOW_HOURS = 24  # Show last 24 hours in timeline

# ─── PDF Report Settings ─────────────────────────────────────────
PDF_REPORT_FILENAME = "CipherGuard_Forensic_Report.pdf"
