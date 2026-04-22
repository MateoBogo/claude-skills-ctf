---
name: ctf-crypto
description: Provides cryptography attack techniques for CTF challenges. Use when attacking encryption, hashing, signatures, ZKP, PRNG, or mathematical crypto problems involving RSA, AES, ECC, lattices, LWE, CVP, number theory, Coppersmith, Pollard, Wiener, padding oracle, GCM, key derivation, or stream/block cipher weaknesses.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Cryptography

Quick reference for crypto CTF challenges. Each technique has a one-liner here; see supporting files for full details with code.

## Additional Resources

- [classic-ciphers.md](classic-ciphers.md) - Classic ciphers: Vigenere (+ Kasiski examination), Atbash, substitution wheels, XOR variants (+ multi-byte frequency analysis), deterministic OTP, cascade XOR, book cipher, OTP key reuse / many-time pad, variable-length homophonic substitution
- [modern-ciphers.md](modern-ciphers.md) - Modern cipher attacks: AES (CFB-8, ECB leakage), CBC-MAC/OFB-MAC, padding oracle, S-box collisions, GF(2) elimination, LCG partial output recovery, CBC padding oracle (full block decryption), Bleichenbacher RSA PKCS#1 v1.5 padding oracle (ROBOT), birthday attack / meet-in-the-middle, LFSR stream cipher attacks (Berlekamp-Massey, correlation attack), CRC32 collision signature forgery, Blum-Goldwasser bit-extension oracle, hash length extension, compression oracle (CRIME-style), RC4 second-byte bias
- [rsa-attacks.md](rsa-attacks.md) - RSA attacks: small e (cube root), common modulus, Wiener's, Pollard's p-1, Hastad's broadcast, Fermat/consecutive primes, multi-prime, restricted-digit, Coppersmith structured primes, Manger oracle, polynomial hash, RSA p=q validation bypass, cube root CRT gcd(e,phi)>1, factoring from phi(n) multiple, multiplicative homomorphism signature forgery
- [ecc-attacks.md](ecc-attacks.md) - ECC attacks: small subgroup, invalid curve, Smart's attack (anomalous, with Sage code), fault injection, clock group DLP, Pohlig-Hellman, ECDSA nonce reuse, Ed25519 torsion side channel
- [zkp-and-advanced.md](zkp-and-advanced.md) - ZKP/graph 3-coloring, Z3 solver guide, garbled circuits, Shamir SSS, bigram constraint solving, race conditions, Groth16 broken setup, DV-SNARG forgery, KZG pairing oracle for permutation recovery
- [prng.md](prng.md) - PRNG attacks (MT19937, MT float recovery via GF(2) magic matrix for token prediction, LCG, GF(2) matrix PRNG, V8 XorShift128+ Math.random state recovery via Z3, middle-square, deterministic RNG hill climbing, random-mode oracle, time-based seeds, C srand/rand synchronization via ctypes, password cracking, logistic map chaotic PRNG)
- [historical.md](historical.md) - Historical ciphers (Lorenz SZ40/42, book cipher implementation)
- [advanced-math.md](advanced-math.md) - Advanced mathematical attacks (isogenies, Pohlig-Hellman, LLL, Coppersmith, quaternion RSA, GF(2)[x] CRT, S-box collision code, LWE lattice CVP attack, affine cipher over non-prime modulus)
- [exotic-crypto.md](exotic-crypto.md) - Exotic algebraic structures (braid group DH / Alexander polynomial, monotone function inversion, tropical semiring residuation)

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
