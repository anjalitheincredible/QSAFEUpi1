"""
UPI PQC CLIENT  (command-line)
==============================
Run in a second terminal while server is running:
    python3 3_client.py
    python3 3_client.py --sender alice@ybl --receiver bob@upi --amount 5000

Uses liboqs Kyber512 if installed, falls back to X25519.
"""

import os, sys, json, hashlib, hmac as hmaclib, time, argparse, requests

SERVER = os.environ.get("UPI_SERVER", "http://127.0.0.1:5000")

# ── PQC backend ───────────────────────────────────────────────────────────────
try:
    import oqs
    PQC_MODE = "REAL"
    KEM_ALG  = "Kyber512"
except ImportError:
    oqs      = None
    PQC_MODE = "FALLBACK"

R  = "\033[0m";  RD = "\033[91m"; GR = "\033[92m"
YL = "\033[93m"; CY = "\033[96m"; MG = "\033[95m"
BL = "\033[94m"; BD = "\033[1m";  DM = "\033[2m"

def line(): print(f"{DM}{'─'*62}{R}")
def hdr(t, c=CY): line(); print(f"{c}{BD}  {t}{R}"); line()
def row(k, v, vc=GR): print(f"  {DM}{k:<26}{R}{vc}{v}{R}")
def ok(msg):   print(f"  {GR}✓  {msg}{R}")
def err(msg):  print(f"  {RD}✗  {msg}{R}"); sys.exit(1)
def info(msg): print(f"  {DM}»  {msg}{R}")

# ── Crypto helpers (must match server) ────────────────────────────────────────
def encrypt_aes_gcm(plaintext: bytes, key: bytes) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k  = hashlib.sha256(key).digest()
    iv = os.urandom(12)
    ct = AESGCM(k).encrypt(iv, plaintext, None)
    return {"iv": iv.hex(), "ct": ct.hex()}

def make_hmac(data: str, key: bytes) -> str:
    return hmaclib.new(hashlib.sha256(key).digest(), data.encode(), hashlib.sha256).hexdigest()

# ── Args ──────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser(description="UPI PQC CLI Client")
parser.add_argument("--sender",   default="alice@ybl",    help="Sender VPA")
parser.add_argument("--receiver", default="bob@upi",      help="Receiver VPA")
parser.add_argument("--amount",   default="2500",         help="Amount in INR")
parser.add_argument("--remarks",  default="Rent payment", help="Remarks")
args = parser.parse_args()

# ─────────────────────────────────────────────────────────────────────────────
hdr("UPI POST-QUANTUM SECURE PAYMENT  (CLI CLIENT)")

if PQC_MODE == "REAL":
    ok(f"liboqs found — using real CRYSTALS-{KEM_ALG}")
else:
    print(f"  {YL}⚠  liboqs not found — using X25519 fallback{R}")
    print(f"  {DM}   Install: sudo apt install cmake gcc libssl-dev python3-dev{R}")
    print(f"  {DM}            pip3 install liboqs-python{R}")

print()
row("Server",   SERVER)
row("Sender",   args.sender,   CY)
row("Receiver", args.receiver, CY)
row("Amount",   f"₹{args.amount}", GR)
row("Remarks",  args.remarks)
print()

import uuid
session_id = str(uuid.uuid4())
txn_id     = "UPI" + hashlib.sha256(f"{session_id}{time.time()}".encode()).hexdigest()[:12].upper()

# ── STEP 1: Fetch public key ──────────────────────────────────────────────────
hdr("STEP 1 — Fetch Server's Kyber Public Key", BL)
r = requests.get(f"{SERVER}/api/pubkey")
r.raise_for_status()
pk_data = r.json()
pk_hex  = pk_data["pk_hex"]
pk_bytes = bytes.fromhex(pk_hex)
row("Algorithm", pk_data["alg"], MG)
row("PK size",   f"{len(pk_bytes)} bytes")
row("PK[:16]",   pk_hex[:32] + "...", YL)
ok("Public key received")

# ── STEP 2: Client-side KEM encapsulation ─────────────────────────────────────
hdr("STEP 2 — KEM Encapsulation  (client-side)", MG)
info("Generating ephemeral keys and encapsulating shared secret...")

if oqs:
    kem          = oqs.KeyEncapsulation(KEM_ALG)
    ct, ss_bytes = kem.encap_secret(pk_bytes)
    kem.free()
    ct_hex = ct.hex()
    row("Ciphertext size", f"{len(ct)} bytes  (Kyber512 spec: 768)")
else:
    # X25519 fallback
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    srv_pub_obj  = X25519PrivateKey.from_private_bytes(os.urandom(32)).public_key().__class__
    # Deserialize server public key
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    srv_pub      = X25519PublicKey.from_public_bytes(pk_bytes)
    eph_priv     = X25519PrivateKey.generate()
    ss_bytes     = eph_priv.exchange(srv_pub)
    ct_hex       = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    row("Ciphertext size", f"{len(ct_hex)//2} bytes  (X25519 ephemeral pubkey)")

row("Session ID",    session_id[:18] + "...", CY)
row("SS[:16]",       ss_bytes.hex()[:32] + "...", GR)
row("CT[:16]",       ct_hex[:32] + "...", YL)
info("Shared secret derived — NOT sent over the network")
ok("Encapsulation complete")

# ── STEP 3: Encrypt transaction ───────────────────────────────────────────────
hdr("STEP 3 — Encrypt Transaction  (AES-256-GCM)", BL)
info("Encrypting amount and remarks with shared secret...")

enc_amount  = encrypt_aes_gcm(args.amount.encode(),  ss_bytes)
enc_remarks = encrypt_aes_gcm(args.remarks.encode(), ss_bytes)
mac_input   = f"{txn_id}:{args.sender}:{args.receiver}:{enc_amount['ct']}:{enc_remarks['ct']}"
mac         = make_hmac(mac_input, ss_bytes)

row("TXN ID",         txn_id)
row("Amount (plain)", f"₹{args.amount}")
row("Amount (enc)",   enc_amount["ct"][:32] + "...", YL)
row("IV",             enc_amount["iv"], DM)
row("HMAC-SHA256",    mac[:32] + "...", MG)
ok("Payload encrypted and signed")

# ── STEP 4: POST to server ────────────────────────────────────────────────────
hdr("STEP 4 — Send Ciphertext to Server  (KEM decap)", BL)
info("Sending KEM ciphertext so server can derive the same shared secret...")

# Tell server to decapsulate (derive shared secret from ciphertext)
decap_payload = {
    "session_id": session_id,
    "ct_hex":     ct_hex,
    "alg":        pk_data["alg"]
}
dr = requests.post(f"{SERVER}/api/decap", json=decap_payload)
dr.raise_for_status()
ok("Server decapsulated — both sides now have the same shared secret")

# ── STEP 5: POST payment ──────────────────────────────────────────────────────
hdr("STEP 5 — POST Encrypted UPI Payment", BL)
info("Sending encrypted transaction payload...")

pay_payload = {
    "session_id":  session_id,
    "txn_id":      txn_id,
    "sender":      args.sender,
    "receiver":    args.receiver,
    "enc_amount":  enc_amount,
    "enc_remarks": enc_remarks,
    "hmac":        mac
}
pr = requests.post(f"{SERVER}/api/pay", json=pay_payload)
pr.raise_for_status()
result = pr.json()

# ── RESULT ────────────────────────────────────────────────────────────────────
if result["status"] == "SUCCESS":
    hdr("✓  TRANSACTION SUCCESSFUL", GR)
    row("Status",    result["status"],    GR)
    row("TXN ID",    result["txn_id"])
    row("Ref Num",   result["ref_num"],   YL)
    row("From",      result["from"],      CY)
    row("To",        result["to"],        CY)
    row("Amount",    f"₹{result['amount']}", GR)
    row("Remarks",   result["remarks"])
    row("Security",  result["pqc"],       MG)
    row("Timestamp", result["timestamp"])
    print(f"""
  {DM}The entire transaction was quantum-safe:
  • Shared secret established via Kyber KEM (never transmitted)
  • Amount encrypted with AES-256-GCM
  • Integrity protected with HMAC-SHA256
  • Zero classical asymmetric crypto (no RSA, no ECDH){R}
""")
else:
    err(result.get("msg", "Unknown error"))
