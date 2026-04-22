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
- [rsa-attacks.md](rsa-attacks.md) — small e/d, common mod, Wiener, Hastad, Fermat, Coppersmith, Manger, polynomial-prime
- [ecc-attacks.md](ecc-attacks.md) — invalid curve, Smart's, Pohlig-Hellman, ECDSA nonce, genus-1 variety
- [zkp-and-advanced.md](zkp-and-advanced.md) — Groth16/PLONK/halo2/Noir ZK, Z3, SSS, LogUp/ProtoStar
- [prng.md](prng.md) — MT19937, LCG, V8 XorShift128+, middle-square, Legendre bit oracle
- [historical.md](historical.md) — Lorenz SZ40, book cipher
- [advanced-math.md](advanced-math.md) — CVP/Babai, LLL, Coppersmith, HNP, Hill off-by-one, Joux, GEA LFSR
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
| PKCS#1 v1.5 error side-channel on an RSA decrypt endpoint | Bleichenbacher / Manger → rsa-attacks.md, modern-ciphers.md |
| Two faulted RSA signatures, TLS renegotiation between them | Blinder `A` → `A²` bit recovery → rsa-attacks.md |
| Many linear eqs mod q with bounded error (ECDSA partial nonce, truncated LCG, HNP) | CVP/Babai (rkm0959 template) → advanced-math.md |
| Power/EM traces with uniform *length* but shape clustering | Waveform-morphology analysis (sliding min/max/mean) → advanced-math.md |
| CSIDH / isogeny + small secret vector + AES oracle | Brute force 419-element shared-secret space → advanced-math.md |
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
| Distinguishable "invalid padding" vs "invalid message" on OAEP endpoint | Manger's attack → rsa-attacks.md |
| Modulus hex shows repeated-block structure (u·2^k + u·v + w) | Polynomial factorisation of n → rsa-attacks.md |
| Shamir t-of-n with x_i^t = 1 (roots of unity) | FFT collapse recovery → modern-ciphers.md |
| AES with `Nr=1` literal or one-round helper | Linear inversion from one PT/CT pair → modern-ciphers.md |
| Hill/classical cipher mod = printable-ASCII range (94) | Try N-1 and N-2 → advanced-math.md |
| Dual hash suffix constraint MD5 + SHA1 (3-byte) | Joux multicollision cascade → advanced-math.md |
| GEA-1/GEA-2 LFSR with known keystream prefix | Rank-deficient key MITM → advanced-math.md |
| Bit oracle on `(s_i / p)` Legendre symbol | Z3/lattice over GF(p) state → prng.md |

For each row the point is: **if you see the signal, go to the file — you never need to know the challenge's name.**

---

For inline code/cheatsheet quick references (grep patterns, one-liners, common payloads), see [quickref.md](quickref.md). The `Pattern Recognition Index` above is the dispatch table — always consult it first; load `quickref.md` only if you need a concrete snippet after dispatch.
