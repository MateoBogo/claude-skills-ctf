# CTF Crypto - Modern Ciphers (2024-2026)

Modern AEAD / MAC / S-box / differential attacks from 2024-2026. For the canonical toolbox (CBC padding oracle, Bleichenbacher, LFSR, length extension), see [modern-ciphers.md](modern-ciphers.md).

## Table of Contents
- [Non-Permutation S-box Collision Attack (Nullcon 2026)](#non-permutation-s-box-collision-attack)
- [LCG Partial Output Recovery (0xFun 2026)](#lcg-partial-output-recovery-0xfun-2026)
- [Affine Cipher over Composite Modulus (Nullcon 2026)](#affine-cipher-over-composite-modulus-nullcon-2026)
- [AES-GCM with Derived Keys (EHAX 2026)](#aes-gcm-with-derived-keys-ehax-2026)
- [Ascon-like Reduced-Round Differential Cryptanalysis (srdnlenCTF 2026)](#ascon-like-reduced-round-differential-cryptanalysis-srdnlenctf-2026)
- [Custom Linear MAC Forgery (Nullcon 2026)](#custom-linear-mac-forgery-nullcon-2026)
- [Shamir t-of-n with Roots-of-Unity Evaluation Points → FFT Recovery (SekaiCTF 2025 ssss)](#shamir-t-of-n-with-roots-of-unity-evaluation-points--fft-recovery-source-sekaictf-2025-ssss)
- [Single-Round AES Linear Inversion (HTB University 2025 Disguised)](#single-round-aes-linear-inversion-source-htb-university-2025-disguised)

---

## Non-Permutation S-box Collision Attack

**Pattern (Tetraes, Nullcon 2026):** Custom AES-like cipher with S-box collisions.

**Detection:** `len(set(sbox)) < 256` means collisions exist. Find collision pairs and their XOR delta.

**Attack:** For each key byte, try 256 plaintexts differing by delta. When `ct1 == ct2`, S-box input was in collision set. 2-way ambiguity per byte, 2^16 brute-force. Total: 4,097 oracle queries.

See [advanced-math.md](advanced-math.md) for full S-box collision analysis code.

---

## LCG Partial Output Recovery (0xFun 2026)

**Known parameters:** If LCG (Linear Congruential Generator) constants (M, A, C) are known and output is `state mod N`, iterate by N through modulus to find state:
```python
# output = state % N, state = (A * prev + C) % M
for candidate in range(output, M, N):
    # Check if candidate is consistent with next output
    next_state = (A * candidate + C) % M
    if next_state % N == next_output:
        print(f"State: {candidate}")
```

**Upper bits only (e.g., upper 32 of 64):** Brute-force lower 32 bits:
```python
for low in range(2**32):
    state = (observed_upper << 32) | low
    next_state = (A * state + C) % M
    if (next_state >> 32) == next_observed_upper:
        print(f"Full state: {state}")
```

---

## Affine Cipher over Composite Modulus (Nullcon 2026)

Affine encryption `c = A*x + b (mod M)` with composite M: split into prime factor fields, invert independently, CRT recombine. See [advanced-math.md](advanced-math.md#affine-cipher-over-non-prime-modulus-nullcon-2026) for full chosen-plaintext key recovery and implementation.

---

## AES-GCM with Derived Keys (EHAX 2026)

**Pattern:** Final decryption step after recovering a secret (e.g., from LWE, key exchange). Session nonce and AES key derived via SHA-256 hashing of the recovered secret.

```python
import hashlib
from Cryptodome.Cipher import AES

# Common key derivation chain:
# 1. Recover secret bytes (s_bytes) from crypto challenge
# 2. Unwrap session nonce: nonce = wrapped_nonce XOR SHA256(s_bytes)[:nonce_len]
# 3. Derive AES key: key = SHA256(s_bytes + session_nonce)
# 4. Decrypt AES-GCM

def decrypt_with_derived_key(s_bytes, wrapped_nonce, ciphertext, aes_nonce, tag, nonce_len=16):
    secret_hash = hashlib.sha256(s_bytes).digest()
    session_nonce = bytes(a ^ b for a, b in zip(wrapped_nonce, secret_hash[:nonce_len]))
    aes_key = hashlib.sha256(s_bytes + session_nonce).digest()
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
```

**Key insight:** When AES-GCM authentication fails (`ValueError: MAC check failed`), the derived key is wrong — usually means the upstream secret recovery was incorrect or endianness is swapped.

---

## Ascon-like Reduced-Round Differential Cryptanalysis (srdnlenCTF 2026)

**Pattern (Lightweight):** 4-round Ascon-like permutation with reduced diffusion. Key-dependent biases in output-bit differentials allow key recovery via chosen input differences.

**Attack:**
1. Reproduce the permutation exactly (critical: post-S-box x4 assignment order matters)
2. Invert the linear layer of x0 using a precomputed 64×64 GF(2) inverse matrix
3. For each bit position i, query with `diff = (1<<i, 1<<i)` across multiple samples
4. Measure empirical biases at output bits `j1 = (i+1) mod 64` and `j2 = (i+14) mod 64`
5. Classify key bits `(k0[i], k1[i])` via centroid-based clustering with sign-pattern mask
6. Verify candidate key in-session; refine low-margin bits with additional samples

**GF(2) linear layer inversion:**
```python
def build_inverse(shifts=(19, 28)):
    """Construct GF(2) inverse matrix for Ascon-like linear layer: x ^= rot(x,19) ^ rot(x,28)."""
    # Build 64x64 matrix over GF(2)
    M = [[0]*64 for _ in range(64)]
    for out_bit in range(64):
        M[out_bit][out_bit] = 1
        for shift in shifts:
            M[out_bit][(out_bit + shift) % 64] ^= 1
    # Gaussian elimination to find inverse
    aug = [row + [1 if i == j else 0 for j in range(64)] for i, row in enumerate(M)]
    for col in range(64):
        pivot = next(r for r in range(col, 64) if aug[r][col])
        aug[col], aug[pivot] = aug[pivot], aug[col]
        for r in range(64):
            if r != col and aug[r][col]:
                aug[r] = [a ^ b for a, b in zip(aug[r], aug[col])]
    return [row[64:] for row in aug]
```

**Centroid clustering for key classification:**
```python
# For each bit position, measure bias at two output positions
# 4 possible (k0[i], k1[i]) pairs → 4 centroid patterns
# Uses sign-pattern mask CMASK=0x73 to account for bit-position-dependent behavior
# Classify by minimum Euclidean distance in 2D bias space
CMASK = 0x73
for i in range(64):
    bias_j1, bias_j2 = measure_biases(i, samples)
    mask_bit = (CMASK >> (i % 8)) & 1
    centroids = centroid_table[mask_bit]  # Precomputed per-position centroids
    k0_bit, k1_bit = min(range(4), key=lambda c: euclidean_dist(
        (bias_j1, bias_j2), centroids[c]))
```

**Key insight:** Reduced-round lightweight ciphers (Ascon, GIFT, etc.) have exploitable biases when the number of rounds is insufficient for full diffusion. The linear layer's inverse can be computed algebraically, and differential biases measured across chosen-plaintext queries reveal individual key bits. This is practical even with noisy measurements if you collect enough samples.

---

## Custom Linear MAC Forgery (Nullcon 2026)

**Pattern (Pasty):** Server signs paste IDs with a custom SHA-256-based construction. The signature is linear in three 8-byte secret blocks derived from the key.

**Structure:** For each 8-byte output block `i`:
- `selector = SHA256(id)[i*8] % 3` → chooses which secret block to use
- `out[i] = hash_block[i] XOR secret[selector] XOR chain[i-1]`

**Recovery:** Create ~10 pastes to collect `(id, sig)` pairs. Each pair reveals `secret[selector]` for 4 selectors. With ~4-5 pairs, all 3 secret blocks are recovered. Then forge for target ID.

**Key insight:** Linearity in custom crypto constructions (XOR-based signing) makes them trivially forgeable. Always check if the MAC has the property: knowing the secret components lets you compute valid signatures for arbitrary inputs.

---

## Shamir t-of-n with Roots-of-Unity Evaluation Points → FFT Recovery (source: SekaiCTF 2025 ssss)

**Trigger:** Shamir secret-sharing where the chosen evaluation points are `t`-th roots of unity `ω^i` in `F_p` for `ω` of order `t`.
**Signals:** only `t` shares are issued (not `t+1`); evaluation points obey `x_i^t = 1`.
**Mechanic:** DFT property collapses the polynomial sum — `Σ_{i=0}^{t-1} P(ω^i) · ω^{-i·k} = t · (a_k + a_{k+t})` mod `p`. So `t` evaluations suffice to reconstruct (modulo the wrap-around). When `deg(P) < 2t`, this is exact; apply inverse FFT to get all coefficients and read the secret `P(0) = a_0`.

## Single-Round AES Linear Inversion (source: HTB University 2025 Disguised)

**Trigger:** custom AES with `Nr = 1` (or a homemade `aes_one_round(p, k)` primitive); known plaintext/ciphertext pair.
**Signals:** `Nr = 1` literal in code, or only one `AddRoundKey → SubBytes → ShiftRows → MixColumns → AddRoundKey` chain.
**Mechanic:** with a single round, the transformation is invertible from one PT/CT pair — invert `MixColumns` (linear), apply inverse `ShiftRows`, invert `SubBytes` via the S-box LUT, XOR against PT to get `K0`; key schedule recovers `K1`. Any "simplified AES" should be checked this way before attempting LC/DC.

## KDF Iteration Decay to Null Key (source: 404CTF 2025 Dérive dans l'espace)

**Trigger:** custom key-derivation function called `N` times where state shrinks each round (hash truncation, repeated XOR-fold, `k = h(k)[:len(k)-1]`); AES/ChaCha packets from a PCAP, >90% decrypt identically with `key = b"\x00" * keylen`.
**Signals:** KDF loop body visibly reduces entropy (e.g. `key = sha256(key)[:16] & mask` with zeroing mask, or `key ^= key >> 1; key &= key - 1`); PCAP has hundreds of short UDP packets all with same IV layout; `decrypt(pkt, b"\x00"*16) == plausible_plaintext` for any sample.
**Mechanic:** after enough rounds, the KDF's fixed point is `0`. Attackers do **not** need to break the KDF — just try the zero key on every packet. PNG magic (`89 50 4e 47 0d 0a 1a 0a`) or `\x1f\x8b` gzip magic in the plaintext is the giveaway.
```python
# Fast scan: decrypt every packet with the null key, look for magic bytes
from Crypto.Cipher import AES
MAGICS = [b"\x89PNG", b"\x1f\x8b", b"PK\x03\x04", b"RIFF", b"%PDF"]
for pkt in packets:
    ct, iv = pkt[:-16], pkt[-16:]
    pt = AES.new(b"\x00"*16, AES.MODE_CBC, iv).decrypt(ct)
    if any(m in pt for m in MAGICS):
        carve(pt)          # reassemble file from consecutive hits
```
**Why it fires anywhere:** every "homemade ratcheting key" primitive is vulnerable if the ratchet isn't bijective over a full-entropy state. Always try `key = 0` on the suspected ciphertexts before reversing the KDF.

## Extended-Block AES via Python Negative Indexing (source: Google CTF 2025 Underhanded)

**Trigger:** "underhanded" AES reference in Python where `shift_rows` and `mix_columns` iterate with hardcoded indices like `m[-8]`, `m[-4]`, `m[-1]` instead of `m[i + row*4]`; cipher accepts messages longer than 16 bytes without chaining.
**Signals:** grep the source for `[-` inside `shift_rows`/`mix_columns`; absence of an explicit `assert len(block) == 16`; the function returns `len(pt)` bytes of ciphertext in one shot.
**Mechanic:** Python's `m[-8]` wraps to `len(m)-8`. For a 32+ byte input, the "second column" of the state is actually a byte from a later column in the previous round's output, producing a **linear relation** between distant ciphertext bytes that only involves round-key bytes:
```
c[8] ⊕ c[n-8] = k10[8] ⊕ k10[r]          # after the last AddRoundKey
```
Each long-message encryption leaks one such relation per overflowed index. With 4-6 oracle queries on carefully sized inputs, you recover the last round key `K10`; then run key schedule backwards. A 24-bit + 16-bit meet-in-the-middle on the first 6 rounds finishes the key in ~5 min.
**Writeup principle:** whenever a crypto primitive is "extended" to variable length in an ad-hoc way, check for negative indices, integer wraparound in pointer arithmetic, or unsigned/signed confusion in block counters. These are the 3 classical underhanded crypto mistakes.

## bcrypt 72-Byte Truncation → Merkle-Leaf Collision (source: Google CTF 2025 Merkurated)

**Trigger:** Merkle tree (deposit / proof-of-reserves / airdrop) where leaves are `bcrypt(salt_fixed, user_value || aux_data)`; `len(user_value || aux_data)` can exceed 72 bytes.
**Signals:** `bcrypt.hashpw` or `py_bcrypt` in code on a user-controlled field; fixed salt (constant or deterministic from tree root); variable-length `value` field; proof verification re-hashes the leaf with `bcrypt` and checks tree path.
**Mechanic:** bcrypt silently truncates input to 72 bytes. Build two leaves `A = pad72 || "VALUE=10**9"` and `B = pad72 || "VALUE=10**18"` where the first 72 bytes are identical — they hash to the **same** bcrypt output. Commit tree with leaf `A` (small value, passes balance checks), later present the proof with leaf `B` claiming the large value.
```python
# Collision generator — find a 64-char suffix whose first 72 bytes match a target leaf
target = bcrypt.hashpw(desired_small_leaf, SALT)
for _ in range(2**14):
    candidate = prefix_72B + random_suffix()      # suffix ignored by bcrypt
    if bcrypt.hashpw(candidate, SALT) == target:  # always true modulo the first 72B
        submit_proof(candidate, claimed_value=HUGE)
```
**Generalizes to:** any hash with input-length cap (bcrypt 72, classic DES `crypt` 8, MySQL `OLD_PASSWORD` 8, LANMAN 14) used in an authentication or Merkle context where the trailing bytes carry semantic weight.
