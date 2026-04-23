---
name: ctf-crypto
description: Cryptography CTF attacks: RSA, AES, ECC, PRNG, hash length-extension, padding oracles, lattice/LWE/CVP, HNP, Coppersmith, Pollard, Wiener, ZKP/Circom/halo2, post-quantum KEM. Dispatch on prime shape, oracle type, or scheme artefact.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Cryptography

Quick reference for crypto CTF challenges. Each technique has a one-liner here; see supporting files for full details with code.

## Additional Resources

- [classic-ciphers.md](classic-ciphers.md) — Vigenere/Kasiski, XOR variants, OTP reuse, homophonic
- [modern-ciphers.md](modern-ciphers.md) — AES/CBC/GCM, padding oracle, Bleichenbacher, LFSR, length extension
- [modern-ciphers-2.md](modern-ciphers-2.md) — 2024-26: S-box collision, AES-GCM derived, Ascon diff, linear MAC, FFT Shamir
- [rsa-attacks.md](rsa-attacks.md) — small e/d, common mod, Wiener, Hastad, Fermat, Coppersmith, polynomial-prime
- [rsa-attacks-2.md](rsa-attacks-2.md) — 2025-26: TLS blinder-squaring + Coppersmith partial-`d`
- [rsa-attacks-oracle.md](rsa-attacks-oracle.md) — Manger's OAEP, padding/timing/blinding oracles
- [ecc-attacks.md](ecc-attacks.md) — invalid curve, Smart's, Pohlig-Hellman, ECDSA nonce, genus-1 variety
- [zkp-and-advanced.md](zkp-and-advanced.md) — Groth16/PLONK/halo2/Noir ZK, Z3, SSS, LogUp/ProtoStar
- [prng.md](prng.md) — MT19937, LCG, V8 XorShift128+, time-seed, ChaCha20 key recovery
- [prng-2.md](prng-2.md) — 2024-26: GF(2) matrix, middle-square, logistic, Legendre bit oracle
- [historical.md](historical.md) — Lorenz SZ40, book cipher
- [advanced-math.md](advanced-math.md) — CVP/Babai, LLL, Coppersmith, HNP, Pohlig-Hellman, Quaternion RSA
- [advanced-math-2.md](advanced-math-2.md) — 2024-26: LWE, clock group, CSIDH trace, Joux, GEA LFSR, Hill off-by-one
- [exotic-crypto.md](exotic-crypto.md) — braid-group DH, tropical, ePrint scheme killers, CSIDH sign-leak, PQ (Kyber/UOV)
---

## Pattern Recognition Index

Map **observable signals** (not challenge names) to the right technique. Scan this first.

| Signal in challenge | Technique → file |
|---|---|
| `pow(m, e, n) == m` for some `m` ∉ {0,1,n-1}; timing outlier on one input | RSA fixed-point factoring → rsa-attacks.md |
| Close primes (`|p - q|` small), or partial-known prime | Fermat / Coppersmith structured primes → rsa-attacks.md |
| Small `d` (Wiener bound), or small `e` + small `m` | Wiener / cube-root → rsa-attacks.md |
| Same `m` under same `e` to several `n_i` | Hastad broadcast / CRT → rsa-attacks.md |
| PKCS#1 v1.5 error side-channel on an RSA decrypt endpoint | Bleichenbacher / Manger → rsa-attacks-oracle.md, modern-ciphers.md |
| Two faulted RSA signatures, TLS renegotiation between them | Blinder `A` → `A²` bit recovery → rsa-attacks-oracle.md |
| Many linear eqs mod q with bounded error (ECDSA partial nonce, truncated LCG, HNP) | CVP/Babai (rkm0959 template) → advanced-math.md |
| Power/EM traces with uniform *length* but shape clustering | Waveform-morphology analysis (sliding min/max/mean) → advanced-math-2.md |
| CSIDH / isogeny + small secret vector + AES oracle | Brute force 419-element shared-secret space → advanced-math-2.md |
| Padding-oracle endpoint on CBC | Byte-by-byte CBC padding oracle → modern-ciphers.md |
| ECDSA with partial-nonce leak / same nonce reused | Pohlig-Hellman / nonce lattice → ecc-attacks.md, advanced-math.md |
| MT19937 outputs visible (624 words) | State recovery via Python `randcrack` or GF(2) matrix → prng.md |
| Boolean predicate + "find x such that f(x)=1" + N small | Qiskit Grover `k = π/4√(N/M)` → ctf-misc/ai-ml.md |
| Model weights file + accuracy-gate grader | Federated label-flip poisoning → ctf-misc/ai-ml.md |
| Two parsers for same URL/path/HTML (different libs in deps) | Parser differential → ctf-web/auth-and-access.md |
| halo2 circuit: `advice_values[…]` fill without RNG, ≥ N proofs same secret | Blinding-omission Lagrange recovery → zkp-and-advanced.md |
| LogUp/ProtoStar-style lookup over `F_p` with `p ≤ 2^32` | Characteristic-repetition bypass → zkp-and-advanced.md |
| Noir/Circom `sha256_var(buf, len)` with trailing buf unconstrained | Trailing-byte under-constraint → zkp-and-advanced.md |
| Obfuscated projective embedding, degree-2 coord relations, group order = small·large | Genus-1 variety → Weierstrass + BSGS/MOV/NFS → ecc-attacks.md |
| Jacobian `Point` class without `is_on_curve` check | Invalid-curve small-order pts → ecc-attacks.md |
| Scheme quoting ePrint, "homomorphism learning" / "entropic operator" | Linear-algebra scheme-killer → exotic-crypto.md |
| CSIDH/group-action KEM exposing `group_action(e, ±1)` | Sign-leak oracle → exotic-crypto.md |
| Distinguishable "invalid padding" vs "invalid message" on OAEP endpoint | Manger's attack → rsa-attacks-oracle.md |
| Modulus hex shows repeated-block structure (u·2^k + u·v + w) | Polynomial factorisation of n → rsa-attacks.md |
| Shamir t-of-n with x_i^t = 1 (roots of unity) | FFT collapse recovery → modern-ciphers-2.md |
| AES with `Nr=1` literal or one-round helper | Linear inversion from one PT/CT pair → modern-ciphers-2.md |
| Hill/classical cipher mod = printable-ASCII range (94) | Try N-1 and N-2 → advanced-math-2.md |
| Dual hash suffix constraint MD5 + SHA1 (3-byte) | Joux multicollision cascade → advanced-math-2.md |
| GEA-1/GEA-2 LFSR with known keystream prefix | Rank-deficient key MITM → advanced-math-2.md |
| Bit oracle on `(s_i / p)` Legendre symbol | Z3/lattice over GF(p) state → prng-2.md |
| Falcon-512/1024 ref-impl signing with `double`-based FPU math + many signature samples | FP subnormal / rounding leakage → exotic-crypto.md#falcon |
| ML-DSA / Dilithium signatures with hints `h` (ω-bounded) or filtered `z` | Hint-leak lattice primal attack → exotic-crypto.md#ml-dsa |
| SPHINCS+ / SLH-DSA signing where FORS idx can repeat (non-atomic counter) | Tree-reuse forgery → exotic-crypto.md#slh-dsa |
| CSIDH / CTIDH KEM accepts attacker-supplied Montgomery `A` with no twist check | Invalid-curve Pohlig-Hellman → exotic-crypto.md#invalid-curve-pq |
| Custom KDF iterated N times before encrypt, entropy-shrinking op inside; PCAP has hundreds of packets | Null-key fixed-point: try `key=0` first → modern-ciphers-2.md |
| AES ref-impl in Python with `m[-8]`/`m[-4]` negative indices + accepts `len > 16` | Extended-block linear byte relation → modern-ciphers-2.md |
| Merkle tree leaves = `bcrypt(fixed_salt, user_payload)` with variable-length payload | 72-byte truncation collision → modern-ciphers-2.md |
| TLS server with RSA signing + OOB-byte primitive corrupting `d`; two renegotiations per session | Blinder squaring + Coppersmith partial-`d` → rsa-attacks-2.md |

For each row the point is: **if you see the signal, go to the file — you never need to know the challenge's name.**

---

For inline code/cheatsheet quick references (grep patterns, one-liners, common payloads), see [quickref.md](quickref.md). The `Pattern Recognition Index` above is the dispatch table — always consult it first; load `quickref.md` only if you need a concrete snippet after dispatch.
