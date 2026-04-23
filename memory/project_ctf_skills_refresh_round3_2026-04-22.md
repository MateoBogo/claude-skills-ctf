---
name: CTF skills refresh round 3 (2026-04-22)
description: Elite-CTF additions 2025-2026 targeting 404CTF podium — 8 mechanics-first techniques from Google CTF 2025, PlaidCTF 2025, DEFCON 2025, 404CTF 2025; mechanics-only descriptions, budgets respected
type: project
originSessionId: 7e214332-4890-440e-87ef-4aa881885aab
---
On 2026-04-22, after round 2 and the audit-fix round, a third enrichment pass was run with agents' research (agents themselves were rate-limited at 6pm Paris reset; research completed by main agent via WebSearch/WebFetch on 404CTF 2025 hackropole + writeups.ayweth20.com + blog.reinom.com, Google CTF 2025 via chovid99 / mystiz / terjanq / utkar5hm, PlaidCTF 2025 via jsur.in / kako57, DEFCON 2025 quals via clowncs + SRLabs).

## 8 NEW techniques appended (mechanics-first, verified non-duplicates)

### ctf-crypto
- `modern-ciphers-2.md` — **KDF Iteration Decay to Null Key** (source: 404CTF 2025 Dérive dans l'espace): custom KDF that shrinks entropy per round has fixed point `0`; decrypt every packet with `key=b"\x00"*16` before reversing.
- `modern-ciphers-2.md` — **Extended-Block AES via Python Negative Indexing** (source: Google CTF 2025 Underhanded): `m[-8]` in shift_rows/mix_columns on blocks >16 bytes yields linear byte relations `c[8]^c[n-8]=k10[8]^k10[r]`; 4-6 queries → last round key → schedule inversion.
- `modern-ciphers-2.md` — **bcrypt 72-Byte Truncation → Merkle Collision** (source: Google CTF 2025 Merkurated): Merkle leaves hashed with bcrypt(fixed_salt, user_value) truncate to 72 bytes; build two leaves sharing first 72B, trailing content carries different semantic values (small deposit / huge withdraw).
- `rsa-attacks-2.md` (NEW) — **TLS RSA Bit-Flipped `d` via OOB + Blinding Neutralization + Coppersmith Partial-d** (source: PlaidCTF 2025 Tales from the Crypt): 3-phase. Deterministic blinder across renegotiations → pick `m2=m1²` so `s1²/s2 = m^{d_f}` un-blinded. Brute 3-bit fault per byte to recover 768 lower bits of `d`. Coppersmith/Boneh-Durfee finishes factoring, then Wireshark RSA keylog for TLS capture.

### ctf-reverse
- `tools-advanced-2.md` (NEW) — **GB-Scale PE with VirtualProtect-Gated Self-Decryption — Unicorn + angr Hybrid** (source: DEFCON 2025 Quals nfuncs1): Unicorn for layer-graph discovery (record every VirtualProtect+call rax), per-layer angr on isolated dumped code page for SAT-solve of per-byte input constraints. Key fence: no disassembly inside hooks (40× slowdown); use `UC_HOOK_BLOCK` not `UC_HOOK_CODE`.
- `patterns-ctf-3.md` (NEW) — **Genetic Algorithm over Opaque Additive Scoring** (source: PlaidCTF 2025 Prospectin'): flat `score += kN` chain with no equational structure defeats angr. Lift scoring to ctypes shared lib, then separability-probe → hill-climb → GA. Cross-arch recompile (aarch64 scoring → amd64 .so) works because arithmetic is portable.

### ctf-web
- `client-side-2.md` (NEW) — **Math.random-Salt Same-Origin Iframe Collision** (source: Google CTF 2025 Postviewer v5): 4-stage chain. (1) race via `location.replace(createObjectURL)` to leak salt via onload→postMessage repeatedly; (2) V8 xs128p recovery from 5 consecutive salts (LIFO cache-aware); (3) plant cached XSS file whose deterministic hash collides with predicted `H(salt_N)`; (4) flag frame renders on same origin, XSS reads contentDocument.

### ctf-forensics
- `disk-and-memory-2.md` — **Damaged `.git` in Docker Image Layers — Raw zlib_decode of Objects** (source: 404CTF 2025 Dockerflag): object files self-contained even when refs/HEAD missing; `pigz -dc < .git/objects/XX/YYY | grep CTF` across all loose objects; combine with docker layer-ordering (manifest.json) to recover deleted secrets from earlier layers.

## Already-covered (verified during research pass — NO action taken)

- **Google CTF 2025 Unicornel Trustzone** (uc_mem_read host/guest divergence) — already in `ctf-pwn/advanced-exploits-3.md#unicorn-emulator-hostguest-hook-divergence` from round 2.
- **V8 Math.random state recovery** — already in `ctf-crypto/prng.md § V8 XorShift128+ State Recovery` (Postviewer v5 references it and composes with it, doesn't duplicate).
- **aarch64 MTE bypass** — covered by TikTag speculative bypass in `ctf-app-system/elf-arm64.md:236`; Google CTF 2025 Classic Notes App uses OOB-write technique, not MTE-specific — normal heap-OOB pattern, no new section.
- **404CTF 2025 Qiskit Grover** — already in `ctf-misc/ai-ml.md#qiskit-grover-oracle-template`.
- **404CTF 2025 Du tatouage (ML watermark extraction)** — already in `ctf-misc/ai-ml.md#neural-network-watermark-extraction-tattooed`.
- **404CTF 2025 Rainbow Rocket (JWT alg=none)** — covered in `ctf-web/auth-jwt.md`.
- **404CTF 2025 hardware (POCSAG, I²C PulseView, flash-ADC op-amp ladder, IQ inverse-FFT)** — all covered in `ctf-forensics/signals-and-hardware.md` from round 2 audit.
- **404CTF 2025 Forensic et Mat UTF-16LE grep trick** — `ctf-forensics/windows.md:222-231` already documents UTF-16LE MFT search + `strings -el`; trivial generalization.
- **SECCON Beginners 2025** — mostly classics (ECB, ret2win, stack pivot); no elite-level new mechanic.
- **DEFCON 2025 Finals Jukebooox** — glibc heap UAF + unsorted-bin leak + ROP — covered in `ctf-pwn/advanced.md`.

## Pattern Recognition Index additions (5 SKILL.md)

- `ctf-crypto/SKILL.md`: +4 rows (KDF null-fixed-point, Python neg-index AES, bcrypt-72 Merkle, TLS OOB Coppersmith partial-d).
- `ctf-reverse/SKILL.md`: +2 rows (GB-scale PE Unicorn+angr, additive scoring GA/hill-climb).
- `ctf-web/SKILL.md`: +1 row (Math.random-salt same-origin collision).
- `ctf-forensics/SKILL.md`: +1 row (Docker damaged-git `.git/objects/*` zlib).

Additional Resources bullets added to 4 SKILL.md for `rsa-attacks-2.md`, `tools-advanced-2.md`, `patterns-ctf-3.md`, `client-side-2.md`.

## Budget check

| File | Lines | ~tokens |
|---|---|---|
| ctf-crypto/SKILL.md | 82 | 1025 |
| ctf-reverse/SKILL.md | 65 | 812 |
| ctf-web/SKILL.md | 86 | 1075 |
| ctf-forensics/SKILL.md | 60 | 750 |
| modern-ciphers-2.md | 203 | 2537 |
| rsa-attacks-2.md | 85 | 1062 |
| tools-advanced-2.md | 76 | 950 |
| patterns-ctf-3.md | 71 | 887 |
| client-side-2.md | 83 | 1037 |
| disk-and-memory-2.md | 434 | 5425 |

All SKILL.md < 100 lines (budget = 500). All support files < 500 lines. Descriptions unchanged (no bloat). disk-and-memory-2.md is getting close to the 500-line ceiling (434) — next addition should open a `-3.md`.

## Why this refresh

Target: 404CTF podium. The 2025 edition (3400 participants, 12 categories including Quantique/Réaliste AD/Hardware/AI) exposed techniques the library was missing in 4 categories:
- Crypto: custom-KDF degeneration, underhanded reference impls, post-truncation hash collisions in Merkle contexts.
- Web: content-sandbox iframe escapes via RNG-derived origins (2-solve tier: Google CTF Postviewer v5).
- Reverse: GB-scale PE unpacking (DEFCON Quals 2025 nfuncs1) and search-based reverse of additive-scoring crackmes (PlaidCTF 2025 Prospectin').
- Forensics: partial-git recovery from container layers (404CTF 2025 Dockerflag).

## How to apply

- When a challenge matches one of the 10 new PRI rows, jump directly to the named support file. Mechanics-first triggers — never search by challenge name.
- For TLS crypto chall with long-term RSA + any fault primitive: always check `ctf-crypto/rsa-attacks-2.md` before spending time on Bleichenbacher.
- For browser sandbox/preview chall: check for Math.random-derived origins first (`ctf-web/client-side-2.md`); composes with the existing V8 xs128p section in `prng.md`.
- For massive unpackers (PE ≥ 500 MB with layered VirtualProtect): go straight to the Unicorn+angr hybrid recipe — do NOT try angr alone.

## Research meta

The 4 background research agents (404CTF / DEFCON-Google-Plaid-RWCTF / ASIS-niche / non-anglophone) all hit the 18:00 Paris rate-limit window shortly after launch, returning no usable output. The main agent then performed the research directly via WebSearch + WebFetch, covering the top-yielding writeups in ~15 queries. Sources: hackropole.fr, writeups.ayweth20.com, blog.reinom.com, github.com/HackademINT/404CTF-2025, chovid99.github.io, mystiz.hk, utkar5hm.github.io, jsur.in, kako57.github.io, clowncs.github.io, srlabs.de, terjanq's gist.

Remaining unexplored (rate-limit): r3kapig/writeup 2025, TSG CTF 2025, LakeCTF 2025, m0leCon 2025, ASIS Finals 2025 deep content. Worth a future pass once rate limits recover.
