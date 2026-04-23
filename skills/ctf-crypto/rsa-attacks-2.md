# CTF Crypto — RSA Attacks (2025-2026 era)

RSA attacks from elite 2025-2026 CTFs. Base techniques (Wiener, Fermat, Hastad, Coppersmith structured primes, small-`d`, common-modulus, fixed-point) live in [rsa-attacks.md](rsa-attacks.md); oracle-style attacks (Bleichenbacher, Manger, blinding) in [rsa-attacks-oracle.md](rsa-attacks-oracle.md).

## Table of Contents
- [TLS RSA Bit-Flipped `d` via OOB-byte + Blinding Neutralization + Coppersmith Partial-`d` (source: PlaidCTF 2025 Tales from the Crypt)](#tls-rsa-bit-flipped-d-via-oob-byte--blinding-neutralization--coppersmith-partial-d-source-plaidctf-2025-tales-from-the-crypt)

---

## TLS RSA Bit-Flipped `d` via OOB-byte + Blinding Neutralization + Coppersmith Partial-`d` (source: PlaidCTF 2025 Tales from the Crypt)

**Trigger:**
- TLS 1.2 server using RSA-PKCS#1 v1.5 signatures (ServerKeyExchange or CertificateVerify) with RSA **blinding** enabled in the signing routine (`s = (r^e · m)^d · r^{-1} mod N` where `r = rand()`).
- An out-of-band channel (`MSG_OOB`, `send(..., MSG_OOB)`, or a side-channel like Rowhammer / laser injection) lets the attacker flip a small number of bits inside the private exponent `d` stored in server memory; the faulty `d_f = d XOR (rand3bits << 3*k)`.
- Same TCP session supports **renegotiation** — two handshakes sharing internal state (so the blinder's RNG state advances deterministically between them).

**Signals to grep:**
```
recv(sock, buf, 1, MSG_OOB)    # ← OOB-byte primitive corrupts a key byte
RSA_blinding_on                # ← the blinder is enabled
SSL_renegotiate / SSL_do_handshake twice on same BIO
Server sends ServerKeyExchange signed with long-term RSA
```

**Mechanic (3 phases):**

### Phase 1 — Neutralize the blinder via paired renegotiations

Because `r` advances deterministically (e.g. LCG inside OpenSSL's `BN_BLINDING`), two successive signatures `s1`, `s2` on messages `m1`, `m2` (whose blinders are linked: typically `r_2 = r_1^{-1}` after one "update" step, or `r_2 = 2·r_1` with some implementations) satisfy:

```
s1 = m1^{d_f} · r1^{-1}          # blinded by r1
s2 = m2^{d_f} · r2^{-1}          # blinded by r2 = f(r1)
```

If the relationship between `r1` and `r2` is known (e.g. `r2 = r1²`, or `r2 = 2·r1`), pick `m2 = m1²` so the blinders cancel:

```
s = s1² / s2  ≡  (m1^{2 d_f} · r1^{-2}) / (m1^{2 d_f} · r1^{-2})  ≡  m^{d_f} mod N
```

You now have a **pure** `m^{d_f} mod N` observation — no blinder left.

### Phase 2 — Recover partial `d` bit-by-bit from the fault

Each faulted signing event flips 3-8 bits of `d` at an attacker-chosen byte offset `k`. Since `(m^{d_f})^e ≠ m mod N` when bits are flipped, factor the difference:

```
m^{d_f} · m^{-d}  ≡  m^{d_f - d}  ≡  m^{Δd}  mod N
```

Compute `m^{Δd}` by knowing one valid signature (unfaulted) of the same `m` — gives you the shifted `Δd` pattern. Brute-force the 3-bit flip choice per byte position (≤ 8 candidates per byte) by checking `m^d_candidate · s^{-1} ≡ 1`. Accumulate byte-position fault observations until you have the **lower 768 bits** of `d`.

### Phase 3 — Coppersmith to finish

With `d_0 = d mod 2^768` recovered, use the classical Boneh-Durfee / Coppersmith partial-`d` attack (works when you have `≥ n/4` low bits of `d` for a balanced `n`-bit `N`):

```
e · d ≡ 1 mod lcm(p-1, q-1)
→ e·d_0 - 1 ≡ 0 mod (p-1) / 2   (approximately)
→ quadratic poly in p over Z, reducible by Coppersmith when d_0 length ≥ N/4
```

SageMath driver:
```python
# partial d recovery — Coppersmith small roots of f(p) over Z/N
PR.<x> = PolynomialRing(Zmod(N))
# e·d0 − 1 ≡ k·(p-1)(q-1)/2 for some k ≤ e;
# iterate candidate k, build f(x) = x² − (N − e*d0/k + 1)·x + N  (approx), find roots
for k in range(1, e+1):
    s_plus_q = isqrt( (N - e*d0//k + 1)**2 - 4*N )
    # then p + q = (e·d0/k + 1 + N)/…  — solve quadratic over Z
    roots = (x**2 - (N - e*d0//k + 1)*x + N).small_roots(X=2^384, beta=0.5)
    if roots:
        p = ZZ(roots[0]); q = N // p
        break
```

Recovered `p`, `q` → load into Wireshark's **RSA key log** (`.pem` from `p`,`q`,`e`) to decrypt the captured TLS application records and read the flag.

**Why this fires anywhere:** every blinding scheme must randomize BOTH `r` independently between signatures; deterministic linking + any fault primitive on `d` collapses to this attack. Check `BN_BLINDING_update`, custom Java `BigInteger` blinders, and any "improved fault countermeasure" that reuses RNG seeds.

**Companion reads:**
- [rsa-attacks-oracle.md](rsa-attacks-oracle.md) — Manger / Bleichenbacher oracles that complement blinding faults.
- [advanced-math.md](advanced-math.md) — Coppersmith & Boneh-Durfee general templates.
