"""
RSA ENCRYPTION + SHOR'S ALGORITHM ATTACK SIMULATION
=====================================================
Run:  python3 1_rsa_attack.py
Deps: pip3 install cryptography
"""

import math, random, time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

R  = "\033[0m";  RD = "\033[91m"; GR = "\033[92m"
YL = "\033[93m"; CY = "\033[96m"; BD = "\033[1m";  DM = "\033[2m"

def line(): print(f"{DM}{'─'*62}{R}")
def hdr(t, c=CY): line(); print(f"{c}{BD}  {t}{R}"); line()
def row(k, v, vc=GR): print(f"  {DM}{k:<26}{R}{vc}{v}{R}")

# ── PART 1: RSA-2048 ──────────────────────────────────────────────
hdr("PART 1 — RSA-2048 KEY GENERATION & ENCRYPTION")

priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub  = priv.public_key()
nums = priv.private_numbers()
pn   = nums.public_numbers

row("Algorithm",  "RSA-2048  (OAEP + SHA-256)")
row("Public e",   str(pn.e))
row("Modulus n",  str(pn.n)[:70] + "...", YL)
row("Private d",  str(nums.d)[:70] + "...", RD)
print()

msg = b"UPI:PAY:alice@ybl->bob@upi:INR2500:TXN20240315"
row("Plaintext", msg.decode())

ct = pub.encrypt(msg, padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(), label=None))
row("Ciphertext", ct.hex()[:70] + "...", YL)

pt = priv.decrypt(ct, padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(), label=None))
row("Decrypted",  pt.decode())
print(f"\n  {GR}✓  RSA works fine against classical computers.{R}\n")

# ── PART 2: SHOR'S ATTACK ─────────────────────────────────────────
hdr("PART 2 — SHOR'S ALGORITHM ATTACK ON TOY RSA", RD)
print(f"""  {YL}Why toy RSA?{R}
  RSA-2048 has a 617-digit modulus — takes 300 trillion years
  classically to factor. A quantum computer using Shor's algorithm
  factors RSA-2048 in ~8 hours with ~4000 logical qubits. We use
  small primes here so every step is fully visible.
""")

p_r, q_r = 167, 173
n = p_r * q_r
phi = (p_r-1)*(q_r-1)
e = 17

def modinv(a, m):
    def egcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = egcd(b % a, a)
        return g, y-(b//a)*x, x
    _, x, _ = egcd(a % m, m)
    return x % m

d     = modinv(e, phi)
m_int = 1337
c_int = pow(m_int, e, n)

row("Primes",      f"p={p_r}, q={q_r}")
row("Modulus n",   str(n))
row("phi(n)",      str(phi))
row("Public key",  f"e={e}, n={n}")
row("Private key", f"d={d}  ← attacker wants this", RD)
row("Plaintext",   str(m_int))
row("Ciphertext",  f"{c_int}  (= {m_int}^{e} mod {n})", YL)
print()

print(f"  {RD}{BD}--- Simulating Shor's Algorithm ---{R}")
print(f"""
  On a quantum computer:
    1. Pick random a < n
    2. Quantum circuit finds period r of f(x)=aˣ mod n   ← quantum speedup here
    3. gcd(a^(r/2) ± 1, n) gives factors
    4. Recover φ(n) → recover private key d → decrypt everything
""")

def find_period(a, n):
    x, r = a, 1
    while x != 1:
        x = (x * a) % n
        r += 1
        if r > n: return None
    return r

print(f"  {RD}[QUANTUM]  Initialising superposition over {n*n} basis states...{R}"); time.sleep(0.4)
print(f"  {RD}[QUANTUM]  Applying controlled-U quantum gates...{R}"); time.sleep(0.4)
print(f"  {RD}[QUANTUM]  Running Quantum Fourier Transform...{R}"); time.sleep(0.5)

fp = fq = a_used = period = None
for _ in range(50):
    a = random.randint(2, n-2)
    g = math.gcd(a, n)
    if 1 < g < n:
        fp, fq, a_used = g, n//g, a; break
    r = find_period(a, n)
    if not r or r % 2: continue
    p1 = math.gcd(pow(a, r//2)-1, n)
    p2 = math.gcd(pow(a, r//2)+1, n)
    if 1 < p1 < n and 1 < p2 < n and p1*p2 == n:
        fp, fq, a_used, period = p1, p2, a, r; break

if fp and fp * fq == n:
    rec_phi = (fp-1)*(fq-1)
    rec_d   = modinv(e, rec_phi)
    cracked = pow(c_int, rec_d, n)
    print(f"\n  {RD}{BD}✗  RSA BROKEN{R}\n")
    row("Base a",         str(a_used),                         RD)
    if period: row("Period r", f"{period}  (a^r ≡ 1 mod n)",  RD)
    row("Factor p",       str(fp),                             RD)
    row("Factor q",       str(fq),                             RD)
    row("Recovered d",    f"{rec_d}  (matches: {rec_d==d})",   RD)
    row("Cracked m",      f"{cracked}  ← decrypted {m_int}",   RD)
    print(f"""
  {RD}Conclusion:{R}
  RSA, ECDH, DSA are all broken by Shor's algorithm on quantum hardware.
  NIST 2024 replacements  (used in the UPI app below):
    ML-KEM   (CRYSTALS-Kyber)     → replaces RSA/ECDH  key exchange
    ML-DSA   (CRYSTALS-Dilithium) → replaces RSA/ECDSA signatures
""")
