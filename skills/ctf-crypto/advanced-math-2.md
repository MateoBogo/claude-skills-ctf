# CTF Crypto - Advanced Math (2024-2026)

Modern lattice / Coppersmith / algebraic attacks from 2024-2026. For the classical toolbox (isogenies, Pohlig-Hellman, LLL, Quaternion RSA, CVP/HNP template), see [advanced-math.md](advanced-math.md).

## Table of Contents
- [Coppersmith's Method (Structured Primes, LACTF 2026)](#coppersmiths-method-structured-primes-lactf-2026)
- [Clock Group (x^2+y^2=1 mod p) DLP (LACTF 2026)](#clock-group-x2y21-mod-p-dlp-lactf-2026)
- [Non-Permutation S-box Collision Attack (Nullcon 2026)](#non-permutation-s-box-collision-attack-nullcon-2026)
- [Polynomial CRT in GF(2)[x] (Nullcon 2026)](#polynomial-crt-in-gf2x-nullcon-2026)
- [Manger's RSA Padding Oracle Attack (Nullcon 2026)](#mangers-rsa-padding-oracle-attack-nullcon-2026)
- [LWE Lattice Attack via CVP (EHAX 2026)](#lwe-lattice-attack-via-cvp-ehax-2026)
- [Affine Cipher over Non-Prime Modulus (Nullcon 2026)](#affine-cipher-over-non-prime-modulus-nullcon-2026)
- [CSIDH Isogeny Power-Trace Side-Channel (404CTF 2024 "Sea Side Channel")](#csidh-isogeny-power-trace-side-channel-404ctf-2024-sea-side-channel)
- [Hill-Cipher / Classical Modulus Off-by-One (Midnightflag 2025)](#hill-cipher--classical-modulus-off-by-one-source-midnightflag-2025)
- [MD5 + SHA1 Dual-Suffix Joux Multicollision Cascade (FCSC 2025 Fun With Hash)](#md5--sha1-dual-suffix-joux-multicollision-cascade-source-fcsc-2025-fun-with-hash)
- [GEA-1 / GEA-2 LFSR Rank-Deficient Key Recovery (FCSC 2025 Make GEA Great Again)](#gea-1--gea-2-lfsr-rank-deficient-key-recovery-source-fcsc-2025-make-gea-great-again)
- [`dream_multiply` Digit-Concatenation Diophantine (SekaiCTF 2025 I Dream of Genni)](#dream_multiply-digit-concatenation-diophantine-source-sekaictf-2025-i-dream-of-genni)

---

## Coppersmith's Method (Structured Primes, LACTF 2026)

**Pattern (six-seven-again):** p = base + 10^k · x where base is fully known, x is small.

**Condition:** x < N^{1/e} for degree-e polynomial (≈ N^0.25 for linear).

**Attack:**
```python
# p = base + 10^k * x, so x ≡ -base * (10^k)^{-1} (mod p)
# Since p | N, construct polynomial with root x mod N
R.<x> = PolynomialRing(Zmod(N))
inv_10k = inverse_mod(10^k, N)
f = x + (base * inv_10k) % N  # Must be monic!
roots = f.small_roots(X=2^70, beta=0.5)
if roots:
    x_val = int(roots[0])
    p = base + 10^k * x_val
    q = N // p
```

**Key details:**
- Polynomial MUST be monic (leading coefficient 1)
- `beta=0.5` means we're looking for a factor ≥ N^0.5
- `X` parameter is upper bound on root size
- Works for any "partially known prime" pattern

## Clock Group (x^2+y^2=1 mod p) DLP (LACTF 2026)

**Pattern (the-clock):** Diffie-Hellman on the unit circle group.

**Group structure:**
```python
# Group law: (x1,y1) * (x2,y2) = (x1*y2 + y1*x2, y1*y2 - x1*x2)
# Identity: (0, 1)
# Inverse of (x, y): (-x, y)
# Group order: p + 1 (NOT p - 1!)

def clock_mul(P, Q, p):
    x1, y1 = P
    x2, y2 = Q
    return ((x1*y2 + y1*x2) % p, (y1*y2 - x1*x2) % p)

def clock_pow(P, n, p):
    result = (0, 1)  # identity
    base = P
    while n > 0:
        if n & 1:
            result = clock_mul(result, base, p)
        base = clock_mul(base, base, p)
        n >>= 1
    return result
```

**Recovering hidden prime p:**
```python
# Given points on the curve, p divides (x^2 + y^2 - 1)
from math import gcd
vals = [x**2 + y**2 - 1 for x, y in known_points]
p = reduce(gcd, vals)
# May need to remove small factors
```

**Pohlig-Hellman when p+1 is smooth:**
```python
order = p + 1
factors = factor(order)
# Standard Pohlig-Hellman in the clock group
# Solve d in each prime-power subgroup, CRT combine
```

**CRITICAL:** The order is p+1, isomorphic to norm-1 elements of GF(p²)*. This is different from multiplicative group (order p-1) and elliptic curves (order ≈ p).

## Non-Permutation S-box Collision Attack (Nullcon 2026)

**Detection:** Check if S-box is a permutation:
```python
sbox = [...]  # 256 entries
if len(set(sbox)) < 256:
    from collections import Counter
    counts = Counter(sbox)
    for val, cnt in counts.items():
        if cnt > 1:
            colliders = [i for i in range(256) if sbox[i] == val]
            delta = colliders[0] ^ colliders[1]
            print(f"S[{hex(colliders[0])}] = S[{hex(colliders[1])}] = {hex(val)}, delta = {hex(delta)}")
```

**Attack:** For each key byte position k (0-15):
1. Try all 256 values v: encrypt two plaintexts differing by `delta` at position k
2. When `ct1 == ct2`: S-box input at position k was in the collision set `{c0, c1}`
3. Deduce: `key[k] = v ^ round_const` OR `key[k] = v ^ round_const ^ delta`
4. 2-way ambiguity per byte -> 2^16 = 65,536 candidates, brute-force locally

**Total oracle queries:** 16 x 256 + 1 = 4,097 (reference ciphertext + probes).

**Key lessons:**
- SAT/SMT solvers time out on 15+ rounds of symbolic AES even with simplified S-box
- Integral/square attacks fail because non-permutation S-box breaks balance property
- Always check S-box for non-permutation FIRST before attempting complex cryptanalysis

---

## Polynomial CRT in GF(2)[x] (Nullcon 2026)

**Pattern:** Server gives `r = flag mod f` where `f` is a random polynomial over GF(2).

**Attack:** Chinese Remainder Theorem in polynomial ring GF(2)[x]:
1. Collect ~20 pairs `(r_i, f_i)` from server (each `f_i` is ~32-bit random polynomial)
2. Filter for coprime pairs using polynomial GCD
3. Apply CRT to combine: `flag = r_i (mod f_i)` for all i
4. With ~13-20 coprime 32-bit moduli (>= 400 bits combined), flag is unique

```python
def poly_crt(remainders, moduli):
    """CRT in GF(2)[x]: combine (r_i, f_i) pairs."""
    result, mod = remainders[0], moduli[0]
    for i in range(1, len(remainders)):
        g, s, t = poly_xgcd(mod, moduli[i])
        combined_mod = poly_mul(mod, moduli[i])
        result = poly_add(poly_mul(poly_mul(remainders[i], s), mod),
                         poly_mul(poly_mul(result, t), moduli[i]))
        result = poly_mod(result, combined_mod)
        mod = combined_mod
    return result, mod
```

---

## Manger's RSA Padding Oracle Attack (Nullcon 2026)

**Setup:**
- Key `k < 2^64` (small), RSA modulus `n` is large (1337+ bits)
- Oracle: "invalid padding" = `decrypt < threshold`, "error" = `decrypt >= threshold`
- No modular wrap-around because `k << n`

**Attack (simplified Manger's):**
```python
# Phase 1: Find f1 where k * f1 >= threshold
f1 = 1
while oracle(encrypt(f1)) == "below":  # multiply ciphertext by f1^e mod n
    f1 *= 2
# f1/2 < threshold/k <= f1, so k is in [threshold/f1, threshold/(f1/2)]

# Phase 2: Binary search for exact key
lo, hi = 0, threshold
while lo < hi:
    mid = (lo + hi) // 2
    f_test = ceil(threshold, mid + 1)  # f such that k*f >= threshold iff k > mid
    if oracle(encrypt(f_test)) == "above":
        hi = mid
    else:
        lo = mid + 1
key = lo  # ~64 queries for 64-bit key
```

**Total queries:** ~128 (64 for phase 1 + 64 for phase 2).

---

## LWE Lattice Attack via CVP (EHAX 2026)

**Pattern (Dream Labyrinth):** Multi-layer challenge ending with Learning With Errors (LWE) recovery. Secret vector `s` in {-1, 0, 1}^n, public matrix A, ciphertext `b = A*s + e (mod q)`.

**LWE solving with fpylll (CVP/Babai):**
```python
from fpylll import IntegerMatrix, LLL, CVP
import numpy as np

q = 3329  # Common LWE modulus (Kyber uses this)
n = 256   # Secret dimension
m = 512   # Number of samples

# A is m×n matrix, b is m-vector, all mod q
# Construct lattice basis for CVP approach
# Lattice: rows of [q*I_m | 0] on top, [A^T | I_n] below
# Target: b

def solve_lwe_cvp(A, b, q, n, m):
    # Build lattice basis (m+n) × (m+n)
    dim = m + n
    B = IntegerMatrix(dim, dim)

    # Top m rows: q*I_m (ensures solutions mod q)
    for i in range(m):
        B[i, i] = q

    # Bottom n rows: A columns + identity
    for j in range(n):
        for i in range(m):
            B[m + j, i] = int(A[i][j])
        B[m + j, m + j] = 1

    # LLL reduce the basis
    LLL.reduction(B)

    # Target vector: (b | 0...0)
    target = [int(b[i]) for i in range(m)] + [0] * n

    # CVP via Babai's nearest plane
    closest = CVP.babai(B, target)

    # Extract secret from last n components
    s_candidate = [closest[m + j] for j in range(n)]

    # Project to ternary {-1, 0, 1}
    s = []
    for val in s_candidate:
        val_mod = val % q
        if val_mod == 0:
            s.append(0)
        elif val_mod == 1:
            s.append(1)
        elif val_mod == q - 1:
            s.append(-1)
        else:
            # Try closest ternary value
            s.append(min([-1, 0, 1], key=lambda t: abs((val_mod - t) % q)))
    return s

s = solve_lwe_cvp(A, b, q, n, m)
```

**CRITICAL: Endianness gotcha.** Server may describe data as "big-endian" but actually use little-endian (or vice versa). If CVP produces garbage, try swapping byte order of the secret interpretation:
```python
# If server says big-endian but actually uses little-endian:
s_bytes_le = bytes([(v % 256) for v in s])  # little-endian
s_bytes_be = s_bytes_le[::-1]               # big-endian
# Try both interpretations for key derivation
```

**Key derivation after LWE recovery (common pattern):**
```python
import hashlib
from Cryptodome.Cipher import AES

s_bytes = bytes([(v % 256) for v in s])

# Recover session nonce: XOR wrapped_nonce with hash of secret
session_nonce = bytes(a ^ b for a, b in
    zip(wrapped_nonce, hashlib.sha256(s_bytes).digest()[:16]))

# Derive AES key from secret + nonce
aes_key = hashlib.sha256(s_bytes + session_nonce).digest()

# Decrypt AES-GCM
cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
```

**Layer patterns in multi-stage crypto challenges:**
- **Layer 1 (Geometry):** Reconstruct point positions from noisy distance measurements. Use least-squares or trilateration with multiple models. Compute convex hull of recovered points.
- **Layer 2 (Subspace):** Find hidden low-dimensional subspace in high-dimensional data. Self-dot products of candidate vectors identify correct answers (smallest self-dot products = closest to subspace).
- **Layer 3 (LWE):** Recover secret vector from lattice problem. Use CVP with fpylll, project result to expected domain (ternary, binary, etc.).

**References:** EHAX CTF 2026 "Dream Labyrinth". Related: Kyber/CRYSTALS lattice cryptography.

---

## Affine Cipher over Non-Prime Modulus (Nullcon 2026)

**Pattern:** `c = A @ p + b (mod m)` where A is nxn matrix, m may not be prime (e.g., 65).

**Chosen-plaintext attack:**
1. Send n+1 crafted inputs to get n+1 ciphertext blocks
2. Difference attack: `c_i - c_0 = A @ (p_i - p_0) (mod m)`
3. Build difference matrices D (plaintext) and E (ciphertext)
4. Solve: `A = E @ D^{-1} (mod m)` using Gauss-Jordan with GCD invertibility checks
5. Recover: `b = c_0 - A @ p_0 (mod m)`

**CRT approach for composite modulus (preferred):**
```python
def crt2(r1, m1, r2, m2):
    """CRT: x = r1 (mod m1) and x = r2 (mod m2)"""
    m1_inv = pow(m1, m2 - 2, m2)  # Fermat's little theorem
    t = ((r2 - r1) * m1_inv) % m2
    return (r1 + m1 * t) % (m1 * m2)

def gauss_elim(A, b, mod):
    """Gaussian elimination over Z/modZ. A=matrix, b=vector, returns solution x."""
    n = len(b)
    M = [list(A[i]) + [b[i]] for i in range(n)]  # augmented matrix
    for col in range(n):
        pivot = next((r for r in range(col, n) if M[r][col] % mod), None)
        if pivot is None: continue
        M[col], M[pivot] = M[pivot], M[col]
        inv = pow(M[col][col], -1, mod)
        M[col] = [x * inv % mod for x in M[col]]
        for r in range(n):
            if r != col and M[r][col] % mod:
                f = M[r][col]
                M[r] = [(M[r][j] - f * M[col][j]) % mod for j in range(n + 1)]
    return [M[i][n] % mod for i in range(n)]

# For m=65=5x13: Gaussian elimination in GF(5) and GF(13) separately
A5, b5 = A % 5, rhs % 5
A13, b13 = A % 13, rhs % 13
x5 = gauss_elim(A5, b5, mod=5)
x13 = gauss_elim(A13, b13, mod=13)
x = [crt2(x5[i], 5, x13[i], 13) for i in range(len(x5))]
```

---

## CSIDH Isogeny Power-Trace Side-Channel (404CTF 2024 "Sea Side Channel")

**Target:** CSIDH (Commutative Supersingular Isogeny Diffie-Hellman) — post-quantum key exchange where secret is a small integer vector `e = (e_1, ..., e_n)` with each `e_i` in a small range (e.g. `[-5, 5]`).

**Practical trick 1 — brute force the shared secret space:**
CSIDH's shared-secret keyspace is frequently tiny (≤ 419 distinct values for the 404CTF instance). Iterate all candidates, validate each against a known-plaintext AES oracle (if the shared secret feeds KDF → AES-GCM, ≤ 419 trial decryptions suffice). No isogeny computation needed.

**Practical trick 2 — Velu isogeny degree leaks via loop count:**
For each prime `l_i`, the Velu formula applies `l_i` point operations. Degree-3/5/7 isogenies produce distinctly sized power traces:
- degree 3 (`l=3`) → ~1940 frames
- degree 5 → ~3700 frames
- degree 7 → ~5440 frames

Count frames per isogeny step → directly read off `|e_i|` (sign decided later).

**Practical trick 3 — bypass constant-time padding via waveform shape:**
A "constant time" implementation pads each step to 7 operations so the *duration* no longer leaks `l_i`. Bypass it by looking at the **morphology** of the trace (shape of `P+1/4` pattern), not its length. Groups the 7-op step into A/B/C signatures:
```python
import numpy as np
# sliding min/max/mean over 100-sample window to denoise
def shape_features(trace, w=100):
    k = np.lib.stride_tricks.sliding_window_view(trace, w)
    return np.stack([k.min(-1), k.max(-1), k.mean(-1)], axis=-1)

# Cluster feature sequences by visual pattern (A/B/C) — each cluster maps to one l_i
```
Then pattern-match each step against reference A/B/C waveforms.

**Key lesson for CTFs:** when a crypto chall gives you power/EM/timing traces, first try duration analysis (loop counts). If that's padded, escalate to **waveform shape** — padding doesn't fix shape.

Source: [mathishammel.com/blog/writeup-404ctf-seaside](https://mathishammel.com/blog/writeup-404ctf-seaside).

---

## Hill-Cipher / Classical Modulus Off-by-One (source: Midnightflag 2025)

**Trigger:** Hill cipher (or any classical encoding) where the alphabet is printable-ASCII range 33–126 (94 chars) but the code uses modulus 94 — while the actual keyspace requires 93 (or vice versa).
**Signals:** challenge script with `mod = 94` on printable ASCII; small key-permutation space (≤ 6 orderings).
**Mechanic:** brute-force the key-permutation space AND sweep modulus ∈ {N−2, N−1, N}. Correct modulus gives readable plaintext; off-by-one gives garbled output. Pattern: any classical cipher using a printable-ASCII-sized modulus → try N−1 and N−2.

## MD5 + SHA1 Dual-Suffix Joux Multicollision Cascade (source: FCSC 2025 Fun With Hash)

**Trigger:** server requires `md5(p)` and `sha1(p)` to both end with a fixed 3-byte suffix (e.g. `FC 5C 25`); payload must also embed a time-limited `sha256(ts)`.
**Signals:** dual-hash suffix constraint, Merkle-Damgård hashes only (no BLAKE/KangarooTwelve), short handshake time.
**Mechanic:** Joux multicollision on MD5 — find `k = 24` pairs of colliding blocks → `2^24` MD5-equivalent payloads at cost `24·2^64 / 2^32 = 2^56` work (trivial with dedicated differential tool). Constrain blocks so the 3-byte MD5 suffix already holds, then enumerate the `2^24` free payloads until one also matches the SHA1 3-byte suffix. `P ≈ 2^24 · 2^−24 ≈ 63 %` success. Tool: hashclash (Marc Stevens) with custom target bytes.

## GEA-1 / GEA-2 LFSR Rank-Deficient Key Recovery (source: FCSC 2025 Make GEA Great Again)

**Trigger:** GPRS cipher GEA-1 or GEA-2; three/four LFSRs with weak key-setup (intentional rank deficiency in init reducing effective keyspace to ~40 bits); known plaintext prefix.
**Signals:** keystream length multiple of 8 bits; challenge explicitly references GEA/GPRS; short session key (64 bits).
**Mechanic:** use Beierle et al. (2021) — recover GEA-1 session key via 40-bit meet-in-the-middle on the rank-deficient register initialization. For GEA-2, use the algebraic attack (linearisation over `F_2`). Generic takeaway: any LFSR-based telephony cipher (GEA, A5/1, A5/2) → check for register-init "coincidence".

## `dream_multiply` Digit-Concatenation Diophantine (source: SekaiCTF 2025 I Dream of Genni)

**Trigger:** custom binary op `f(x,y) = int(str(x) + str(y))` or digit-shifting variant; service asks for `(x, y)` satisfying both `f(x, y) == T` and `x * y == T'`.
**Signals:** user-provided constraint involving `str(x) + str(y)`, `str(x).lstrip('0')`, or base-10 digit concatenation.
**Mechanic:** branch-and-prune over digit positions. `f(x, y)` = `x · 10^len(y) + y`, so the constraint becomes `x · 10^k + y = T` with `y < 10^k`. For each candidate `k ∈ [1, 10]`, solve `y = T − x · 10^k`, check `x · y == T'` → small search space. Z3 or plain backtracking in a few seconds.
