# CTF Crypto - RSA Oracle Attacks

Padding/OAEP/blinding/LSB oracle attacks on RSA. For factoring attacks (Wiener, Fermat, Pollard, common-modulus, Coppersmith), see [rsa-attacks.md](rsa-attacks.md).

## Table of Contents
- [Manger's RSA Padding Oracle Attack (Nullcon 2026)](#mangers-rsa-padding-oracle-attack-nullcon-2026)
- [Manger's Attack on RSA-OAEP via Timing Oracle (HTB Early Bird)](#mangers-attack-on-rsa-oaep-via-timing-oracle-htb-early-bird)
- [RSA Blinding Defeat via TLS Renegeration (PlaidCTF 2025)](#rsa-blinding-defeat-via-tls-renegeration-plaidctf-2025)
- [Manger's Attack — RSA-OAEP First-Byte Padding Oracle (HTB Business 2025 Early Bird)](#mangers-attack--rsa-oaep-first-byte-padding-oracle-source-htb-business-2025-early-bird)

---

## Manger's RSA Padding Oracle Attack (Nullcon 2026)

**Pattern (TLS, Nullcon 2026):** RSA-encrypted key with threshold oracle. Phase 1: double f until `k*f >= threshold`. Phase 2: binary search. ~128 total queries for 64-bit key.

See [advanced-math.md](advanced-math.md) for full implementation.

---

## Manger's Attack on RSA-OAEP via Timing Oracle (HTB Early Bird)

**Pattern:** Flask app implements RSA-OAEP with custom hash (PBKDF2, 2M iterations). Python's short-circuit `or` evaluation creates a timing oracle: if the first byte Y != 0, PBKDF2 is never called (~0.6s). If Y == 0, PBKDF2 runs (~2s).

**Vulnerable code pattern:**
```python
if Y != 0 or not self.H_verify(self.L, DB[:self.hLen]) or self.os2ip(PS) != 0:
    return {"ok": False, "error": "decryption error"}
```

**Oracle mapping:** Fast response → Y != 0 (decrypted message >= B). Slow response → Y == 0 (decrypted message < B = 2^(8*(k-1))).

**Calibration for network reliability:**
```python
def calibrate(n, e, k):
    B = pow(2, 8 * (k - 1))
    slow_times, fast_times = [], []
    for i in range(5):
        # Known-slow: encrypt values < B
        enc = pow(B - 1 - i*100, e, n).to_bytes(k, 'big')
        slow_times.append(measure(enc))
        # Known-fast: encrypt values > B
        enc = pow(B + 1 + i*100, e, n).to_bytes(k, 'big')
        fast_times.append(measure(enc))
    FAST_UPPER = max(fast_times) * 1.5
    SLOW_LOWER = min(slow_times) * 0.9
```

**Oracle with retry for ambiguous results:**
```python
def padding_oracle(c_int):
    while True:
        total = measure_response_time(c_int)
        if SLOW_LOWER < total < SLOW_UPPER:
            return True   # Y == 0 (below B)
        elif total < FAST_UPPER:
            return False  # Y != 0 (above B)
        # Ambiguous: retry
```

**Full 3-step Manger's attack (~1024 iterations for 1024-bit RSA):**
```python
# Step 1: Find f1 where f1 * m >= B
f1 = 2
while oracle((pow(f1, e, n) * c) % n):
    f1 *= 2

# Step 2: Find f2 where n <= f2 * m < n + B
f2 = (n + B) // B * f1 // 2
while not oracle((pow(f2, e, n) * c) % n):
    f2 += f1 // 2

# Step 3: Binary search narrowing m to exact value
mmin, mmax = ceil_div(n, f2), floor_div(n + B, f2)
while mmin < mmax:
    f = floor_div(2 * B, mmax - mmin)
    i = floor_div(f * mmin, n)
    f3 = ceil_div(i * n, mmin)
    if oracle((pow(f3, e, n) * c) % n):
        mmax = floor_div(i * n + B, f3)
    else:
        mmin = ceil_div(i * n + B, f3)
m = mmin
```

**Post-recovery OAEP decode:**
```python
from Crypto.Signature.pss import MGF1
maskedSeed = EM[1:hLen+1]
maskedDB = EM[hLen+1:]
seed = bytes(a ^ b for a, b in zip(maskedSeed, MGF1(maskedDB, hLen, HF)))
DB = bytes(a ^ b for a, b in zip(maskedDB, MGF1(seed, k - hLen - 1, HF)))
# DB[:hLen] should match lHash; rest is 0x00...0x01 || message
```

**Key insight:** Python's `or` short-circuits left-to-right. When expensive operations (PBKDF2, bcrypt, argon2) appear in chained conditions, the first condition becomes a timing oracle. RFC 8017 explicitly warns implementations must not let attackers distinguish error conditions — timing differences violate this.

**Detection:** RSA-OAEP with custom hash or slow KDF. Flask/Python backend. `/verify-token` or similar decryption endpoint returning generic errors. Timing differences between responses.

---

## RSA Blinding Defeat via TLS Renegeration (PlaidCTF 2025)

**Pattern ("Tales from the Crypt"):** OpenSSL RSA-CRT fault-attack mitigation uses blinding: per-session, signature is computed as `S = blind * (m * blind^(-e))^d mod n`, where `blind = A` is a fresh random. Bug: on **TLS renegotiation**, the implementation updates the blinder as `A -> A^2` instead of regenerating. Two faulted signatures under *related* blinders let you eliminate `A` algebraically and recover the corrupted bit of `d`.

**Core math:** If session 1 uses blinder `A` and leaks a faulty signature `S1 = m^(d + eps1) * A (mod n)`, and session 2 (after reneg) uses `A^2` leaking `S2 = m^(d + eps2) * A^2 (mod n)`, then:
```
S1^2 / S2 = m^(2*eps1 - eps2) (mod n)
```
The unknown blinder cancels. Comparing the resulting value against expected bit-flip deltas recovers `d` bit-by-bit.

**Why it's a new class:** not a pure math attack and not a pure implementation bug — a **protocol-crypto crossover**. The weakness lives in the TLS state-machine assumption that a renegotiated session is independent.

**Exploitation checklist:**
1. Inject a fault (e.g. Rowhammer, clock glitch, or server already leaks faulty signatures) during sign.
2. Force TLS renegotiation before grabbing a second signature.
3. Compute `S1^2 * S2^(-1) mod n` — the blinder cancels.
4. Iterate bit-by-bit: each bit of `d` gives two possible eps values; one matches, the other doesn't.

**Takeaway for CTFs:** when you see RSA + TLS renegotiation + "weird" signatures, assume blinder is related across sessions and look for `S1^2 / S2` style algebraic cancellation.

Source: [jsur.in/posts/2025-04-07-plaid-ctf-2025-tales-from-the-crypt](https://jsur.in/posts/2025-04-07-plaid-ctf-2025-tales-from-the-crypt/).

---

## Manger's Attack — RSA-OAEP First-Byte Padding Oracle (source: HTB Business 2025 Early Bird)

**Trigger:** OAEP-decrypting service whose response distinguishes `m ≥ B` vs `m < B` (where `B = 2^(8·(k-1))`), typically via "invalid padding" vs "invalid message" error differentiation.
**Signals:** `RSAES-OAEP` / `OAEP` in code, two distinguishable error branches, ability to submit ciphertexts adaptively.
**Mechanic:** binary search via multiplicative blinding `c' = c · s^e mod n`. Each oracle query halves the interval. Recovers `m` in ~`log2(n)` queries — ~2048 for 2048-bit RSA. Reference: Manger "A chosen ciphertext attack on RSA optimal asymmetric encryption padding" (2001).
Template:
```python
def manger(c, e, n, oracle, k):
    B = 1 << (8*(k-1))
    # f1 step
    f1 = 2
    while oracle(pow(f1, e, n) * c % n): f1 *= 2
    ...
```
