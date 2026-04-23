# Memory Index

- [Root-Me ASLR per-process discovery (ch21)](project_rootme_aslr_lesson.md) — ASLR active per-process on Root-Me even with setarch -R; combined scan+exploit shellcode in one bash loop via paramiko
- [CTF skills refresh 2026-04](project_ctf_skills_refresh_2026-04.md) — research pass that enriched ctf-* files with 404CTF/Root-Me/top-CTF 2024-2026 techniques; added ctf-misc/ai-ml.md
- [CTF skills refresh round 2 (2026-04-22)](project_ctf_skills_refresh_round2_2026-04-22.md) — added ~55 mechanics-first techniques (SekaiCTF 2025, hxp 38C3/39C3, idekCTF 2025, HTB Biz/Uni 2025, pwn.college AoP 2025, ZK Hack V, FCSC 2025, Midnightflag 2025); new ctf-automation skill with 6 scripts; solve-challenge now triage.sh-first
- [CTF skills audit + fix round (2026-04-22)](project_ctf_skills_audit_fix_2026-04-22.md) — fixed all P0/P1/P2 script bugs + added P3 coverage (V8 JIT, Rust pwn, eBPF, Foundry invariant, MCP poisoning, TVLA, Falcon/ML-DSA) in ctf-* library
- [CTF skills refresh round 3 (2026-04-22)](project_ctf_skills_refresh_round3_2026-04-22.md) — 8 elite techniques for 404CTF podium: KDF null-fixed-point, neg-index AES, bcrypt-72 Merkle, TLS OOB Coppersmith partial-d, PE Unicorn+angr, GA scoring, Math.random salt collision, Docker damaged-git
- [CTF writeup-pattern shortcuts](feedback_ctf_writeup_patterns.md) — cross-cutting meta-patterns to try early on modern CTF challenges (parser diff, filter-decode split, waveform vs duration, argv whitelist, etc.)
- [Skills trigger on mechanics, not titles](feedback_skill_triggering_by_mechanics.md) — every technique must lead with observable signals; SKILL.md descriptions enumerate mechanics not CTF names; add pattern-recognition indexes mapping symptoms → section
- [Skill authoring token budgets](feedback_skill_authoring_budget.md) — SKILL.md < 500 lines / 2.5k tok; body = Additional Resources + PRI + pointer to quickref.md only; support files < 500 lines, split by era (-2/-3.md); descriptions < 1536 chars
