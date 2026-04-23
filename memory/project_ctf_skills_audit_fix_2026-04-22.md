---
name: CTF skills audit + fix round (2026-04-22)
description: Post-audit remediation of ctf-automation fil-rouge scripts and ctf-* library; closes all P0/P1/P2 and P3 (except P3-8 hardware) from the 2026-04-22 audit
type: project
originSessionId: 152bf5cc-8844-4bb3-860e-c9059ff606e6
---
On 2026-04-22, after the audit that flagged placeholder leaks in SKILL.md files and structural bugs in the fil-rouge scripts, ran a full fix round. All P0/P1/P2-1..6 + P2-8..9 + P3-1..7 + P3bis closed. P2-7 era-splits are ~6/11 done (forensics + crypto); remaining 5 files (ctf-web/server-side*, ctf-web/auth-and-access, ctf-pwn/advanced*, ctf-pwn/advanced-exploits-2) deferred — support files, on-demand-loaded, functional impact low.

## What changed

### Fil-rouge scripts (ctf-automation)

- **review.sh**: default answer flipped from `y` to `n`; non-interactive stdin now refuses to merge; placeholder-guard greps drafts for `<TODO` / `<observable signal for` before accepting; skill-name regex fixed to handle hyphenated skills (`ctf-app-system`, etc.); MEMORY.md dedup by mechanic.
- **learn.py**: added `extract_observables()` that pulls concrete file-level signals from chal dir + exploit (symbols, `libc.so.6` presence, RSA shape hints, format-string conversions…). Refuses to emit memory draft when no observable found. Added routing tables for `ctf-app-system`, `ctf-osint`, `ctf-malware`. `near_match()` now uses observables with threshold 0.35 and returns top-5.
- **exploit_loop.py**: exit contract fixed (0 on completion, not 1); `--worker-id` flag; writes flag into `.state.json` under fcntl lock; new `--sandbox {none,native,docker}` flag integrates sandbox.sh.
- **coordinator.py**: per-worker attempt attribution via worker_id tag in struggle.jsonl; flag reported via fcntl-locked state.json; parallelised cleanup (SIGTERM all, single 3s wait, SIGKILL survivors).
- **pwnsetup.sh**: awk column `$4 == "FUNC"` for libc symbol offsets; `LIBC_PATH = None` fallback when absent; `context.arch` line built outside heredoc so quotes don't get consumed; pre-existing `*80386*` case pattern quoted.
- **cryptosetup.py**: ECDSA detection precedence paren fix.
- **foreniq.sh**: raw-IQ path prints a csdr demod-chain hint + uses `remix -m 1,2` envelope rather than silently dropping Q channel.
- **websetup.sh**: jq merge rewritten with `--slurpfile`/`--rawfile` — previous `inputs[i]` indexing was broken.
- **sandbox.sh**: removed global `exec 2>/dev/null` that silenced every docker/patchelf/etc. diagnostic.
- **aiprobe.py**: new `--shape {raw, openai-chat, messages}` + `--model` + `requests.Session()` for multi-turn probes (reverse-order attack now actually chains turn 1 → turn 3 instead of disjoint POSTs).
- **triage.sh**: collapsed N per-file greps into 4 tree-wide greps (big speedup on large dirs); shopt state save/restore via EXIT trap so the script doesn't pollute callers; flag regex unified with exploit_loop.

### Library cleanup

- Deleted leaked placeholder rows from `ctf-pwn/SKILL.md:77` and `ctf-crypto/SKILL.md:71`, plus the auto-merged draft sections in `ctf-pwn/quickref.md` and `ctf-crypto/quickref.md`.
- Purged the two useless auto-captured lesson files `feedback_lesson_20260422T124401_ret2win.md` / `_rsa-wiener.md` and their MEMORY.md index entries.
- Renamed `ctf-app-system/winkern-x64.md` drift-violating section from `## Workflow Root-Me WinKern` to `## WinKern debug→exploit workflow (source: Root-Me WinKern SSH)`.
- Moved `ctf-automation/_round2_additions.md` → `memory/_archive/round2_additions_2026-04-22.md` (it wasn't a skill artefact).

### P3 coverage (new content for elite-level CTF)

- **ctf-pwn/browser-jit.md** (NEW): V8 Turbofan type-confusion, V8 pointer-compression era, v8_enable_sandbox bypass via ExternalPointerTable, SpiderMonkey IonMonkey range analysis, JSC DFG/FTL OSR-exit bugs.
- **ctf-pwn/rust-pwn.md** (NEW): panic-handler unwind `Drop` corruption, `mem::transmute`/`from_raw_parts` aliasing, `Vec::set_len` invariant break, `as` truncation, `async fn` state-machine confusion.
- **ctf-pwn/kernel-advanced.md**: eBPF verifier pointer-arith bypass (CVE-2024-1086 family), ringbuf stale-byte KASLR leak, offensive eBPF kprobes (fileless persistence).
- **ctf-web/web3.md**: Foundry invariant fuzzing, Halmos symbolic check, differential fuzzing between "reference" and "optimised" impls, Cast + Tenderly storage-diff workflow.
- **ctf-misc/ai-ml.md**: MCP tool-definition poisoning, image-OCR prompt injection (GPT-4V/Gemini/Claude Vision), agent self-persistence via CLAUDE.md / `.github/workflows`, long-context haystack distraction, agent tool-arg injection via env echo.
- **ctf-forensics/signals-and-hardware.md**: TVLA / Welch's *t*-test leakage assessment, morphology-over-duration side-channel (CSIDH-style), CPA on AES-TinyAES Hamming-weight.
- **ctf-crypto/exotic-crypto.md**: Falcon FP-rounding leakage, ML-DSA hint-leak lattice attack, SLH-DSA tree-reuse forgery, invalid-curve on CSIDH/CTIDH.

PRI rows added to all five affected SKILL.md files. Additional Resources bullets added for `browser-jit.md` and `rust-pwn.md`.

**Why:** the audit identified the library was leaking placeholder content into SKILL.md (nukes the always-loaded description budget), the fil-rouge loop was structurally broken (broken jq merges, silenced stderr, dead flag-reporting path), and elite 2025-2026 techniques were missing. Closing the loop lets `exploit_loop.py` → `learn.py` → `review.sh` run cleanly and the library match the mechanics seen in top CTFs 2025-2026.

**How to apply:**
1. Before accepting any `review.sh` merge, confirm the draft has a concrete `## Trigger:` line (no `<TODO`/`<observable signal for>`).
2. Non-interactive review runs are now refused — always run under a TTY.
3. `exploit_loop.py --sandbox {native,docker}` wraps each attempt in `sandbox.sh`; use this when you need reproducible crash-signal capture across distros.
4. For elite-level dispatch: the PRI indexes in ctf-pwn, ctf-web, ctf-misc, ctf-forensics, ctf-crypto now cover 2025-2026 mechanics (V8 JIT, Rust unwind, eBPF verifier, Foundry invariants, MCP poisoning, TVLA, PQ sig leaks). Grep the PRI first; if no match, then consider the support files.
5. Remaining tech debt: 5 support files still > 500 lines (ctf-web/server-side.md 834, auth-and-access.md 771, server-side-advanced.md 617, ctf-pwn/advanced-exploits-2.md 738, advanced.md 621). Split along era / mechanic boundary next time one is touched.
