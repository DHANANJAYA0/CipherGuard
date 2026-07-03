"""
CipherGuard — Standalone Executable Builder
Uses PyInstaller to bundle CipherGuard into a single one-file executable.
"""
import os
import sys
import subprocess

def install_pyinstaller():
    print("Checking for PyInstaller...")
    try:
        import PyInstaller
        print("PyInstaller is already installed.")
    except ImportError:
        print("PyInstaller not found. Installing now...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

def build():
    install_pyinstaller()
    
    # Define entrypoint and parameters
    entrypoint = "main.py"
    app_name = "CipherGuard"
    
    # Gather hidden imports that are dynamically loaded or might be missed by PyInstaller
    hidden_imports = [
        "pynput.keyboard._win32",
        "pynput.mouse._win32",
        "pyqtgraph.graphicsItems.PlotDataItem",
        "reportlab.pdfgen.canvas",
        "cryptography.hazmat.backends.openssl",
        "win32clipboard",
        "win32process",
        "win32gui",
        "win32con",
    ]
    
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--onefile",
        "--windowed",
        f"--name={app_name}",
    ]
    
    for imp in hidden_imports:
        cmd.append(f"--hidden-import={imp}")
        
    cmd.append(entrypoint)
    
    print("\nRunning PyInstaller build command:")
    print(" ".join(cmd))
    print("\nPlease wait, compiling executable...")
    
    try:
        subprocess.check_call(cmd)
        print("\n" + "=" * 50)
        print("[SUCCESS] CipherGuard standalone executable built successfully!")
        print(f"Location: {os.path.abspath(os.path.join('dist', f'{app_name}.exe'))}")
        print("=" * 50)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Build failed with exit code: {e.returncode}")
        sys.exit(e.returncode)

if __name__ == "__main__":
    build()
