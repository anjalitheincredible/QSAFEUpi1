"""
run_server.py — Starts the UPI PQC Flask server + ngrok tunnel together.
Usage:   python3 run_server.py

If you have an ngrok auth token, set it here or as env var NGROK_TOKEN.
Get a free token at: https://dashboard.ngrok.com/get-started/your-authtoken
"""

import os, sys, time, threading, subprocess, signal, platform

# ── CONFIG ────────────────────────────────────────────────────
PORT         = int(os.environ.get("PORT", 5000))
NGROK_TOKEN  = os.environ.get("32VMwv32zWPo9ol4Rdtc2utO6wY_2Hmja2F9NGZf6xoWeN2jF")   # paste your token here if you have one
SERVER_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "2_server.py")
PY           = sys.executable
# ─────────────────────────────────────────────────────────────

def check_server_file():
    if not os.path.exists(SERVER_FILE):
        print(f"[ERROR] Cannot find {SERVER_FILE}")
        print(f"        Make sure run_server.py is in the same folder as 2_server.py")
        sys.exit(1)

def start_flask():
    """Start the Flask server as a subprocess."""
    print(f"[FLASK] Starting server on port {PORT}...")
    env = os.environ.copy()
    env["PORT"] = str(PORT)
    proc = subprocess.Popen(
        [PY, SERVER_FILE],
        env=env,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
    return proc

def start_ngrok_pyngrok():
    """Try to start ngrok using the pyngrok library."""
    try:
        from pyngrok import ngrok, conf
        if NGROK_TOKEN:
            ngrok.set_auth_token(NGROK_TOKEN)
        print("[NGROK] Opening tunnel...")
        tunnel = ngrok.connect(PORT, "http")
        url = tunnel.public_url
        # ngrok gives http:// — upgrade to https://
        url = url.replace("http://", "https://")
        return url, tunnel
    except ImportError:
        return None, None
    except Exception as e:
        print(f"[NGROK] pyngrok error: {e}")
        return None, None

def start_ngrok_binary():
    """Try to start the ngrok binary directly if pyngrok isn't available."""
    import shutil
    ngrok_path = shutil.which("ngrok")
    if not ngrok_path:
        return None, None
    print("[NGROK] Starting ngrok binary...")
    cmd = [ngrok_path, "http", str(PORT)]
    if NGROK_TOKEN:
        cmd += ["--authtoken", NGROK_TOKEN]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)  # give ngrok a moment to start
    # Fetch the public URL from ngrok's local API
    try:
        import urllib.request, json
        resp = urllib.request.urlopen("http://localhost:4040/api/tunnels", timeout=5)
        data = json.loads(resp.read())
        for t in data.get("tunnels", []):
            if t.get("proto") == "https":
                return t["public_url"], proc
        # fallback: grab first tunnel
        url = data["tunnels"][0]["public_url"]
        return url, proc
    except Exception as e:
        print(f"[NGROK] Could not read tunnel URL: {e}")
        return None, proc

def print_banner(url=None):
    print("\n" + "=" * 60)
    print("  UPI PQC SERVER — RUNNING")
    print("=" * 60)
    print(f"  Local:   http://localhost:{PORT}")
    if url:
        print(f"  Public:  {url}  ← share this!")
        print(f"\n  ✓ QR camera scanning works on the public HTTPS URL")
    else:
        print("\n  ⚠  No ngrok tunnel — to get a public URL:")
        print(f"     Option A:  Set NGROK_TOKEN env var and re-run")
        print(f"     Option B:  In another terminal:  ngrok http {PORT}")
        print(f"     Get a free token: https://dashboard.ngrok.com/get-started/your-authtoken")
    print("\n  Demo accounts (password: demo1234):")
    print("    alice@ybl  ₹50,000")
    print("    bob@upi    ₹25,000")
    print("    carol@okaxis ₹75,000")
    print("\n  Press Ctrl+C to stop.")
    print("=" * 60 + "\n")

def main():
    check_server_file()

    # Start Flask
    flask_proc = start_flask()
    print("[FLASK] Waiting for server to initialise...")
    time.sleep(2)

    if flask_proc.poll() is not None:
        print("[ERROR] Flask server crashed on startup. Check 2_server.py for errors.")
        sys.exit(1)

    # Start ngrok
    ngrok_url    = None
    ngrok_handle = None

    ngrok_url, ngrok_handle = start_ngrok_pyngrok()
    if not ngrok_url:
        ngrok_url, ngrok_handle = start_ngrok_binary()
    if not ngrok_url:
        print("[NGROK] Could not start ngrok automatically.")

    print_banner(ngrok_url)

    # Keep running until Ctrl+C
    def shutdown(sig, frame):
        print("\n[SHUTDOWN] Stopping...")
        flask_proc.terminate()
        if ngrok_handle:
            try:
                from pyngrok import ngrok as ng
                ng.kill()
            except Exception:
                if hasattr(ngrok_handle, 'terminate'):
                    ngrok_handle.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    flask_proc.wait()

if __name__ == "__main__":
    main()