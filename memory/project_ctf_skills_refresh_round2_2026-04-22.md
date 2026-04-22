---
name: CTF skills refresh round 2 (2026-04-22)
description: Second-round enrichment adding ~55 mechanics-first techniques from SekaiCTF 2025/2026, DiceCTF 2026, idekCTF 2025, hxp 38C3/39C3, TFC CTF 2025, HTB Business/University 2025, pwn.college AoP 2025, ZK Hack V, FCSC 2025, Midnightflag 2025 — plus a new ctf-automation skill with 6 scripts
type: project
---
On 2026-04-22, round 2 enrichment pass completed. Three research agents audited writeups the first pass did not cover; one audit agent validated mechanics-first compliance of the existing library.

## New techniques appended (55 total, mechanics-first)

### ctf-pwn
- `advanced-exploits-2.md` — vkfs coord-indexed FS overflow (SekaiCTF 2025), MIPS `$gp`-pivot fake-GOT, FILE UAF + fstr bridge (HTB Business 2025), cross-thread `alloca` stack smash + partial-close leak (Midnightflag 2025), ObjC Isa-pointer UAF RCE, ARM64 PAC-key exfil via bounds-mismatch AAR, seccomp `cmp`-timing blind oracle, Traefik `X-Forwarded-*` → polyglot RCE chain
- `advanced-exploits.md` — House-of-Spirit via C++ vtable fudge (SekaiCTF 2025 learning-oop)
- `kernel-advanced.md` — zero-copy page aliasing via vmsplice-gift → vm_insert_page TOCTOU (hxp 39C3 folly)
- `sandbox-escape.md` — io_uring `IORING_SETUP_NO_MMAP` seccomp escape, SCM_RIGHTS fd smuggling, coredump race before in-memory wipe, eBPF FSM syscall-sequence gate (all pwn.college AoP 2025)

### ctf-crypto
- `zkp-and-advanced.md` — halo2 blinding-omission Lagrange recovery, LogUp/ProtoStar char-repetition bypass, Noir `sha256_var` trailing-byte under-constraint (ZK Hack V)
- `ecc-attacks.md` — obfuscated genus-1 variety → Weierstrass + hybrid BSGS/MOV/NFS (hxp 39C3 AlcoholicVariety), py_ecc Jacobian no-curve-check invalid-point (SekaiCTF 2025)
- `exotic-crypto.md` — ePrint scheme-killer linear-algebra patterns (hxp 39C3), CSIDH/group-action sign-leak (SekaiCTF 2025), FCSC 2025 Kzber/UOV pointers
- `rsa-attacks.md` — Manger's attack RSA-OAEP first-byte oracle (HTB Business 2025), structured-prime polynomial factorisation (HTB Business 2025)
- `modern-ciphers.md` — Shamir t-of-n roots-of-unity FFT collapse (SekaiCTF 2025 ssss), single-round AES linear inversion (HTB University 2025)
- `advanced-math.md` — Hill cipher mod N-1 off-by-one, MD5+SHA1 dual-suffix Joux cascade (FCSC 2025), GEA-1/2 LFSR rank-deficient recovery (FCSC 2025), `dream_multiply` digit-concat Diophantine (SekaiCTF 2025)
- `prng.md` — Legendre-symbol bit oracle → GF(p) state recovery (HTB University 2025 One Trick Pony)

### ctf-web
- `auth-and-access.md` — PHP `parse_url` double-colon host divergence (Midnightflag 2025), Next.js Next-Action + trustHostHeader SSRF chain (FCSC 2025), race on shared token Map (HTB University 2025), Chrome extension DNR→CDP→Puppeteer config.js RCE (FCSC 2025)
- `server-side-advanced.md` — JWT `base64_decode(strict=false)` smuggling + NFKD filename fold (hxp 38C3 phpnotes), Go handler shared `err` TOCTOU (hxp 38C3 FJWK), Vite proto-pollution → `spawn_sync` RCE (SekaiCTF 2025), NFS file-handle forgery (hxp 38C3 NFS), JS `String.replace` single-match traversal (idekCTF 2025), HQL → H2 CREATE ALIAS → jshell JDWP (SekaiCTF 2025), WP `wp_ajax_nopriv_*` option-update privesc (HTB University 2025), ORM type-confusion + zipslip + promise poison (HTB University 2025), Firebird ALTER DB DIFFERENCE FILE → webshell (HTB Business 2025), TAR/ELF polyglot upload-to-RCE (HTB Business 2025), S3 presign path traversal (HTB Business 2025)
- `server-side-deser.md` — HQL→H2→jshell cross-ref (SekaiCTF 2025)
- `client-side.md` — CSS `@starting-style` crash oracle (SekaiCTF 2025), xs-leak via `performance.memory` (SekaiCTF 2025)
- `web3.md` — Solidity `private` storage `eth_getStorageAt` (Midnightflag 2025), SELFDESTRUCT+CREATE2 code-swap (Midnightflag 2025), Ethereum `txpool_content` snoop (pwn.college AoP 2025), cross-function reentrancy guarded+unguarded pair (HTB Business 2025)

### ctf-reverse
- `patterns-ctf-2.md` — `perf_event_open` instruction-count byte oracle (idekCTF 2025), VM arch misidentification + banned-byte synthesis (idekCTF 2025 Lazy VM)
- `languages-compiled.md` — `.pyc` PEP-552 magic-header forgery (pwn.college AoP 2025), Go itab/interface `GoReSym` restore (HTB University 2025), eBPF FSM cross-ref
- `tools-advanced.md` — TTF GSUB ligature stego DAG reverse (TFC CTF 2025 font-leagues), AVX2 lane-wise Z3 lifting (pwn.college AoP 2025)

### ctf-misc
- `ai-ml.md` — Agent file-read via unscoped `fetch_article(url)` tool (HTB Business 2025), Keras Lambda marshal+b64 stego + `safe_mode=False` RCE (HTB Business 2025)
- `pyjails.md` — `literal_eval` dict-for-list type confusion → WOTS reuse (SekaiCTF 2025)

### ctf-forensics
- `network-advanced.md` — UA-gated C2 URL-path hex-XOR exfil (idekCTF 2025)

### ctf-malware
- `scripts-and-obfuscation.md` — VSCode `.vsix` `onStartupFinished` activation event → obfuscated `child_process` exfil (HTB University 2025 Snowy Extension)

## NEW skill: ctf-automation

`/home/ubuntu/.claude/skills/ctf-automation/` created — orchestrator + 6 scripts:
- `SKILL.md` — documents the pipeline
- `triage.sh` — master fingerprint (ELF/PE/WASM/APK/pyc/pcap/disk/memdump/PEM/ML model/QASM/Circom/Solidity/Vyper/audio/IQ/sigrok), manifest detection (package.json/requirements/go.mod/Cargo/foundry/hardhat/docker), AI hints, JWT detection, emits `.ctf-triage.json` + `.ctf-triage.md` with pointers into Pattern Recognition Indices
- `pwnsetup.sh` — checksec + libc.rip lookup + patchelf + pwntools template generation
- `cryptosetup.py` — RSA/ECDSA/lattice/PQ/Circom detection + SageMath/pycryptodome solver stubs
- `websetup.sh` — subfinder → httpx → katana → ffuf → nuclei chain, merged JSON
- `foreniq.sh` — sigrok/IQ/audio → sox → multimon-ng POCSAG512/1200/2400 / DTMF / AFSK pipeline
- `aiprobe.py` — 10-probe LLM endpoint battery: argv injection, language-gap, reverse-order, metadata exfil, literal-policy flip, DNS-rebind latency delta, external URL fetch, kubeconfig argv, format abuse

All scripts check `command -v` for required tools and print the exact `apt install` / `go install` / `pip install` command when missing, rather than crashing.

## Pattern Recognition Index updates

Added rows to SKILL.md index tables in: `ctf-pwn`, `ctf-crypto`, `ctf-web`, `ctf-reverse`, `ctf-forensics`, `ctf-misc`.
Created NEW Pattern Recognition Index in: `ctf-app-system`, `ctf-malware`, `ctf-osint` (previously missing, flagged by audit).

## Solve-challenge rewiring

`solve-challenge/SKILL.md` now calls `ctf-automation/triage.sh` as **Step 0** before any manual category guessing. The markdown report's pointers drive dispatch — the challenge title is never the trigger.

## Audit findings

Mechanics-first compliance was **clean** across the 2026-04-22 first-pass additions (all cite the CTF as a parenthetical source after a `Pattern:`/`Trigger:` block).

## Token-budget refactor (same day, after initial additions)

Official guidance: SKILL.md < 500 lines; description+when_to_use < 1536 chars; after compaction skills get 5k tokens retained each (25k shared). SKILL.md auto-loads on every invocation; supporting files load only when Claude reads them.

**Problem found:** our SKILL.md files carried 5-9k tokens of "Quick Reference" code sections (ctf-pwn 9326 tok, ctf-web 8153 tok, ctf-reverse 7222 tok, ctf-forensics 5912 tok, ctf-misc 5048 tok, ctf-crypto 5016 tok). Every dispatch burned 30-50k tokens on cheatsheet loading that was almost never relevant to the specific challenge.

**Applied:**
1. For 6 heavy SKILL.md, extracted everything after the Pattern Recognition Index ("Recognize the mechanic…") into `<skill>/quickref.md`. SKILL.md now holds only: frontmatter + brief intro + Additional Resources (file index) + Pattern Recognition Index + 1-line pointer to quickref.md.
2. Split oversized support files along era boundaries to keep under 500 lines each:
   - `ctf-pwn/advanced-exploits-2.md` (792 → 738) + NEW `advanced-exploits-3.md` (61) for 2025-2026 era (vkfs, MIPS $gp, FILE UAF, alloca, ObjC Isa, ARM64 PAC, cmp timing, Traefik chain)
   - `ctf-web/server-side-advanced.md` (683 → 617) + NEW `server-side-advanced-2.md` (73) for 2025-2026 mechanics (JWT smuggling, Go err TOCTOU, Vite pollution, NFS forgery, String.replace, HQL→jshell, WP option update, ORM+zipslip, Firebird, polyglot upload, S3 traversal)
   - `ctf-web/auth-and-access.md` (794 → 771) + NEW `auth-and-access-2.md` (30) for 2025-2026 mechanics (PHP parse_url, Next.js Next-Action, shared-token race, DNR→CDP chain)
3. Updated SKILL.md Additional Resources bullets + PRI row targets to point at the `-2.md` / `-3.md` files.

**Result:** SKILL.md token footprint dropped from ~48k to ~19k total across 10 skills (60% reduction). Each SKILL.md now loads 1.2-2.8k tokens on invoke instead of 5-9k.

| SKILL.md | lines before | lines after | tokens before | tokens after |
|---|---|---|---|---|
| ctf-pwn | 430 | 76 | 9326 | 2759 |
| ctf-web | 450 | 81 | 8153 | 2782 |
| ctf-reverse | 431 | 62 | 7222 | 1992 |
| ctf-crypto | 233 | 70 | 5016 | 1838 |
| ctf-forensics | 323 | 55 | 5912 | 1565 |
| ctf-misc | 423 | 52 | 5048 | 1348 |

## Remaining technical debt (not addressed this round)

Support files still > 600 lines (on-demand loaded, lower priority): ctf-web/server-side.md (834), ctf-forensics/disk-and-memory.md (670), ctf-crypto/advanced-math.md (670), ctf-crypto/prng.md (633), ctf-forensics/steganography.md (631), ctf-reverse/{tools-advanced,patterns,anti-analysis,tools-dynamic,platforms,languages}.md, ctf-pwn/advanced.md (621), ctf-crypto/{modern-ciphers,rsa-attacks}.md. Split along mechanic or era boundary when next touched.

**Why:** shift the library from "we have docs" to "full CLI + AI elite" by (a) capturing recent top-tier-CTF mechanics we were missing, (b) giving the solver an automated triage entrypoint so category dispatch stops being guess-work, and (c) respecting the Skill token budget so auto-invocation doesn't evict working context.

**How to apply:** when starting a CTF challenge, `bash ctf-automation/triage.sh <dir>` first; open the pointed sections; only fall back to prose-based categorisation if triage finds no artefacts. Mechanics-first sections are discoverable via each SKILL.md Pattern Recognition Index — grep the index first, never scan entire support files. When adding new techniques, append to the appropriate `-2.md` / `-3.md` era file and add ONE row to the PRI table — do NOT inline code into SKILL.md (code goes to quickref.md or era file).
