# CTF Crypto - PRNG (2024-2026)

Modern PRNG attacks from 2024-2026. For classical MT19937, LCG, ChaCha20, V8 XorShift128+, see [prng.md](prng.md).

## Table of Contents
- [GF(2) Matrix PRNG Seed Recovery (0xFun 2026)](#gf2-matrix-prng-seed-recovery-0xfun-2026)
- [Middle-Square PRNG Brute Force (UTCTF 2024)](#middle-square-prng-brute-force-utctf-2024)
- [Deterministic RNG from Flag Bytes + Hill Climbing (VuwCTF 2025)](#deterministic-rng-from-flag-bytes--hill-climbing-vuwctf-2025)
- [Byte-by-Byte Oracle with Random Mode Matching (VuwCTF 2025)](#byte-by-byte-oracle-with-random-mode-matching-vuwctf-2025)
- [RSA Key Reuse / Replay (UTCTF 2024)](#rsa-key-reuse--replay-utctf-2024)
- [Logistic Map / Chaotic PRNG Seed Recovery (BYPASS CTF 2025)](#logistic-map--chaotic-prng-seed-recovery-bypass-ctf-2025)
- [Legendre-Symbol Bit Oracle → GF(p) State Recovery (HTB University 2025 One Trick Pony)](#legendre-symbol-bit-oracle--gfp-state-recovery-source-htb-university-2025-one-trick-pony)

---

## GF(2) Matrix PRNG Seed Recovery (0xFun 2026)

**Pattern (BitStorm):** PRNG using only XOR, shifts, and rotations is linear over GF(2).

**Key insight:** Express entire PRNG as matrix multiplication: `output_bits = M * seed_bits (mod 2)`. With enough outputs, Gaussian elimination recovers the seed.

```python
import numpy as np

def build_prng_matrix(prng_func, seed_bits=2048, output_bits=2048):
    """Build GF(2) matrix by running PRNG on unit vectors."""
    M = np.zeros((output_bits, seed_bits), dtype=np.uint8)
    for i in range(seed_bits):
        # Set bit i of seed
        seed = 1 << (seed_bits - 1 - i)
        output = prng_func(seed)
        for j in range(output_bits):
            M[j, i] = (output >> (output_bits - 1 - j)) & 1
    return M

# Given output, solve: M * seed = output (mod 2)
# Use GF(2) Gaussian elimination (see modern-ciphers.md solve_gf2)
seed = solve_gf2(M, output_bits_array)
```

**Identification:** Any PRNG using only `^`, `<<`, `>>`, bitwise rotate. DON'T try iterative state recovery — go straight to the matrix.

---

## Middle-Square PRNG Brute Force (UTCTF 2024)

**Pattern (numbers go brrr):** Middle-square method with small seed space.

```python
# PRNG: seed = int(str(seed * seed).zfill(12)[3:9])  — 6-digit seed
# Seed source: int(time.time() * 1000) % (10**6) — only 1M possibilities
# AES key: 8 rounds of PRNG, each produces seed % 2^16 as 2-byte fragment

def middle_square_keygen(seed):
    key = b''
    for _ in range(8):
        seed = int(str(seed * seed).zfill(12)[3:9])
        key += (seed % (2**16)).to_bytes(2, 'big')
    return key

# Brute-force: encrypt known plaintext, compare
for seed in range(10**6):
    key = middle_square_keygen(seed)
    if try_decrypt(ciphertext, key):
        print(f"Seed: {seed}")
        break
```

**Even with time-limited interactions:** 1 known-plaintext pair suffices for offline brute force.

---

## Deterministic RNG from Flag Bytes + Hill Climbing (VuwCTF 2025)

**Pattern (Totally Random Art):** Flag bytes seed Python `random.Random()`. First N bytes of flag are known format, remaining bytes produce deterministic output.

**Attack:** When PRNG seed is known/derivable from flag format, hill-climb unknown characters:
```python
import random

def render(flag_bytes):
    rng = random.Random()
    rng.seed(flag_bytes)
    grid = [[0]*10 for _ in range(5)]
    for b in flag_bytes:
        steps, stroke = divmod(b, 16)
        x, y = 0, 0
        for _ in range(steps):
            dx, dy = rng.choice([(0,1),(0,-1),(1,0),(-1,0)])
            x = (x + dx) % 10
            y = (y + dy) % 5
        grid[y][x] = (grid[y][x] + stroke) % 16
    return grid

# Hill climb: try each byte value, keep the one that maximizes grid match
target = parse_target_art()
flag = list(b'VuwCTF{')
for pos in range(7, 17):
    best_score, best_char = -1, 0
    for c in range(32, 127):
        candidate = bytes(flag + [c])
        score = sum(1 for y in range(5) for x in range(10)
                    if render(candidate)[y][x] == target[y][x])
        if score > best_score:
            best_score, best_char = score, c
    flag.append(best_char)
```

---

## Byte-by-Byte Oracle with Random Mode Matching (VuwCTF 2025)

**Pattern (Unorthodox IV):** Server encrypts with one of N random modes/IVs per encryption. Can submit own plaintexts.

**Attack strategy:**
1. Connect, get encrypted flag
2. Probe with known prefix to check if connection can "reach" the flag's mode (same mode = same ciphertext prefix). ~50 probes, if no match, reconnect.
3. Once reachable, test candidate characters. Mode match AND next byte match = correct char. Mode match but byte mismatch = eliminate candidate permanently.
4. Elimination persists across reconnections.

**Key insight:** Probe for mode reachability first to avoid wasting attempts. Elimination-based search is more efficient than confirmation-based when modes are randomized.

---

## RSA Key Reuse / Replay (UTCTF 2024)

**Pattern (simple signature):** RSA keys reused across rounds with alternating inputs.

**Attack:** Submit previously captured encrypted output back to the server. If keys are static across interactions, replay attacks are trivial. Always check if crypto keys change between rounds.

---

## Logistic Map / Chaotic PRNG Seed Recovery (BYPASS CTF 2025)

**Pattern (Chaotic Trust):** Stream cipher using the logistic map `x_{n+1} = r * x * (1 - x)` as PRNG. Keystream generated by packing iterated float values.

**Key insight:** Logistic map with `r ≈ 4.0` is chaotic but deterministic — recovering the seed (initial x value) enables full keystream reconstruction. Seed is usually a decimal between 0 and 1, such as 0.123456789.

```python
import struct

def logistic_map(x, r=3.99):
    return r * x * (1 - x)

def decrypt_logistic(cipher_hex, seed):
    cipher = bytes.fromhex(cipher_hex)
    x = seed
    stream = b""

    while len(stream) < len(cipher):
        x = logistic_map(x)
        # Pack float as bytes for keystream (check endianness)
        stream += struct.pack("<f", x)[-2:]  # or full 4 bytes

    stream = stream[:len(cipher)]
    return bytes(a ^ b for a, b in zip(cipher, stream))

# Brute-force seed precision
for precision in range(6, 12):
    for base in [123456, 234567, 314159, 271828]:
        seed = base / (10 ** precision)
        result = decrypt_logistic(cipher_hex, seed)
        if b"FLAG" in result or b"CTF" in result:
            print(f"Seed: {seed}, Flag: {result}")
```

**Variations:**
- **r parameter:** Usually `r = 3.99` or `r = 4.0` (full chaos regime)
- **Packing:** `struct.pack("<f", x)` (4 bytes), `struct.pack("<d", x)` (8 bytes), or `[-2:]` for 2-byte fragments
- **Seed range:** Often a recognizable decimal like `0.123456789` or derived from challenge hints

**Identification:** Challenge mentions "chaos", "logistic", "butterfly effect", or provides `r` parameter. Look for source code containing `x = r * x * (1 - x)` iteration.

---

## Legendre-Symbol Bit Oracle → GF(p) State Recovery (source: HTB University 2025 One Trick Pony)

**Trigger:** oracle outputs a single bit per query derived from `(x_i / p)` (Legendre symbol) where `x_i` is the internal PRNG state and `p` is a public prime; state evolves via a linear recurrence (LCG, simple LFSR-mod-p).
**Signals:** `jacobi_symbol(s, p)` in source; ~1 bit per query; prime `p` printed publicly.
**Mechanic:** each bit is a QR/NQR constraint over `GF(p)`. Collect few-hundred samples, translate to a CNF via `x_i` quadratic residuosity, solve with Z3 BitVec or lattice reduction (if recurrence is LCG-shaped: CVP on `a x + b = y` with Legendre constraint). Recovers seed in seconds. Pattern: any bit-oracle cipher whose single output is a squareness test over a known modulus is linearly solvable.
