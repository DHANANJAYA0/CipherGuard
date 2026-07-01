"""
CipherGuard — Demo Keylogger Viewer
Shows what a keylogger would capture when CipherGuard KeyShield is active.

HOW TO DEMO:
  Terminal 1: python demo/demo_keylogger.py    ← start this first
  Terminal 2: python main.py                    ← start CipherGuard

  In CipherGuard:
    1. KeyShield tab -> Enable KeyShield
    2. Click the green Protected Input Field
    3. Type: MyBankPassword@123
       OR paste with Ctrl+V

  Watch THIS terminal — only scrambled garbage appears here!
"""

import os
import sys
import time
import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "keylogger_output.txt")

SEPARATOR = "=" * 55


def print_header():
    print(SEPARATOR)
    print("  DEMO KEYLOGGER  |  CipherGuard Anti-Keylogger Demo")
    print(SEPARATOR)
    print(f"  Watching: ...\\demo\\keylogger_output.txt")
    print()
    print("  HOW TO USE:")
    print("  1. In CipherGuard -> KeyShield tab -> Enable KeyShield")
    print("  2. Click the GREEN Protected Input Field")
    print("  3. Type or paste any text (e.g. MyBankPassword@123)")
    print()
    print("  This window shows only SCRAMBLED garbage.")
    print("  CipherGuard shows the real text side-by-side.")
    print()
    print("  Press Ctrl+C to stop.")
    print(SEPARATOR)
    print()


def read_file():
    """Read keylogger file, return content or None on error."""
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return None


def main():
    print_header()

    capture_count = 0
    last_content = None

    # Always show current file content on startup (if it exists and is non-empty)
    existing = read_file()
    if existing:
        capture_count += 1
        now = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"  [{now}] ====== PREVIOUS CAPTURE (startup) ======")
        for line in existing.splitlines():
            print(f"  {line}")
        print()
        last_content = existing
    else:
        print("  [Waiting for CipherGuard typing...]")
        print("  (Type in the green Protected Input Field in CipherGuard)")
        print()

    try:
        while True:
            content = read_file()

            if content and content != last_content:
                last_content = content
                capture_count += 1
                now = datetime.datetime.now().strftime("%H:%M:%S")
                print(f"  [{now}] ====== CAPTURE #{capture_count} ======")
                for line in content.splitlines():
                    print(f"  {line}")
                print()

            time.sleep(0.3)  # Check 3x per second

    except KeyboardInterrupt:
        print()
        print(SEPARATOR)
        print(f"  Demo stopped. Total captures: {capture_count}")
        print(SEPARATOR)


if __name__ == "__main__":
    main()
