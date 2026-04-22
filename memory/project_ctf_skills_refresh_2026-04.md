---
name: CTF skills refresh — 404CTF / Root-Me / top CTFs 2024-2026
description: Summary of research done on 2026-04-22 that enriched ctf-* skill files with recent techniques
type: project
---
On 2026-04-22, ran a multi-agent web research pass over 404CTF (2022-2025), Root-Me (blog + community writeups), and top CTFs 2024-2026 (DEFCON, Google, PlaidCTF, SekaiCTF, LACTF, RealWorldCTF, corCTF, HackTheAgent, LakeCTF). Updated skill files in `/home/ubuntu/.claude/skills/ctf-*/`:

- `ctf-crypto/rsa-attacks.md` — RSA fixed-point factoring, RSA blinding + TLS renegotiation bit recovery
- `ctf-crypto/advanced-math.md` — CSIDH isogeny power-trace side-channel (waveform vs duration), CVP template for biased-nonce ECDSA / truncated LCG / HNP
- `ctf-pwn/advanced-exploits-2.md` — MOP (libc code-page zeroing via MAP_FIXED), pipe-backed folio_put page-UAF, strace byte-count side-channel, signed→size_t confusion, Unicorn host/guest hook divergence, runc 2025 symlink-race escape
- `ctf-web/auth-and-access.md` — two-parser URL differential, hop-by-hop header smuggling, node-mysql operator object + __proto__ pollution, declarative Shadow DOM NodeIterator bypass, Vyper @nonreentrant cross-function bug, L1/L2 bridge state-desync
- `ctf-forensics/signals-and-hardware.md` — POCSAG GQRX→sox→multimon-ng chain, IQ FFT masking, PulseView I2C + datasheet workflow, op-amp flash ADC recovery
- NEW `ctf-misc/ai-ml.md` — federated label-flip poisoning, TATTOOED NN watermark, Qiskit Grover template, quantum tomography via identity injection, LLM reverse-order injection, argument injection on pre-approved tools, DNS rebinding vs agents, language-guardrail gap, tool-metadata exfil, external-content injection via URL fetch, literal-policy logic trap
- `ctf-misc/SKILL.md` — description extended with AI/ML/quantum coverage

**Why:** dramatically broaden our CTF skills library to match the shift from pure math/heap to AI-agent exploitation, post-quantum side-channel, and bridge-protocol bugs observed in 2024-2026 competitions.

**How to apply:** when starting a CTF challenge, check `ctf-misc/ai-ml.md` first for AI/LLM challenges, and the new sections in the above files for categories previously covered. The `solve-challenge` skill already dispatches to `ctf-*` based on category.
