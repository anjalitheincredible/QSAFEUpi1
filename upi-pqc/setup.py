"""
setup.py — Run this ONCE to install everything needed for the UPI PQC server.
Usage:   python3 setup.py
"""

import subprocess, sys, platform, os

OS = platform.system()  # 'Windows', 'Darwin', 'Linux'
PY = sys.executable

def run(cmd, **kwargs):
    print(f"\n>>> {cmd}")
    result = subprocess.run(cmd, shell=True, **kwargs)
    return result.returncode == 0

def pip(*packages):
    pkgs = " ".join(packages)
    ok = run(f'"{PY}" -m pip install --upgrade {pkgs}')
    if not ok:
        # Debian/Ubuntu systems need --break-system-packages
        run(f'"{PY}" -m pip install --break-system-packages --upgrade {pkgs}')

print("=" * 60)
print("  UPI PQC SERVER — SETUP")
print(f"  OS: {OS}  |  Python: {sys.version.split()[0]}")
print("=" * 60)

# ── 1. Core Python deps ──────────────────────────────────────
print("\n[1/4] Installing Python dependencies...")
pip(
    "flask",
    "cryptography",
    "pyopenssl",
    "qiskit",
    "qiskit-aer",
    "matplotlib",
    "pylatexenc",
    "qrcode",
    "pillow",
)

# ── 2. liboqs (real PQC) ──────────────────────────────────────
print("\n[2/4] Attempting to install liboqs-python (real Kyber/Dilithium)...")
print("      This may take a minute and requires cmake + a C compiler.")
ok = run(f'"{PY}" -m pip install liboqs-python')
if not ok:
    ok = run(f'"{PY}" -m pip install --break-system-packages liboqs-python')
if not ok:
    print("\n  ⚠  liboqs-python failed — server will run in X25519 fallback mode.")
    print("     To get REAL Kyber/Dilithium, install cmake first:")
    if OS == "Windows":
        print("       winget install cmake  OR  choco install cmake")
    elif OS == "Darwin":
        print("       brew install cmake")
    else:
        print("       sudo apt install cmake build-essential  OR  sudo dnf install cmake gcc")
    print("     Then re-run:  pip install liboqs-python")
else:
    print("  ✓  liboqs-python installed — REAL PQC mode active!")

# ── 3. ngrok ─────────────────────────────────────────────────
print("\n[3/4] Installing ngrok via pip wrapper (optional)...")
run(f'"{PY}" -m pip install pyngrok')

# ── 4. Verify ────────────────────────────────────────────────
print("\n[4/4] Verifying imports...")
imports = ["flask", "cryptography", "qiskit", "qiskit_aer", "matplotlib", "qrcode", "PIL"]
all_ok = True
for mod in imports:
    try:
        __import__(mod)
        print(f"  ✓  {mod}")
    except ImportError:
        print(f"  ✗  {mod}  ← MISSING")
        all_ok = False

try:
    import oqs
    print("  ✓  oqs (liboqs) — REAL PQC mode")
except ImportError:
    print("  ⚠  oqs (liboqs) — fallback mode (X25519)")

print("\n" + "=" * 60)
if all_ok:
    print("  ✓  Setup complete!")
    print("  Run the server:  python3 run_server.py")
else:
    print("  ⚠  Some packages missing — check errors above.")
print("=" * 60)