---
name: ctf-misc
description: Provides miscellaneous CTF challenge techniques. Use for encoding puzzles, RF/SDR signal processing, Python/bash jails, DNS exploitation, unicode steganography, floating-point tricks, QR codes, audio challenges, Z3 constraint solving, Kubernetes RBAC, WASM game patching, esoteric languages, game theory, commitment schemes, combinatorial games, AI/ML/LLM agent exploitation (prompt injection, federated learning poisoning, model watermark extraction, argument injection on pre-approved tools, DNS rebinding vs agents), quantum challenges (Qiskit Grover, quantum tomography), or challenges that don't fit other categories.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "false"
---

# CTF Miscellaneous

Quick reference for miscellaneous CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [pyjails.md](pyjails.md) - Python jail/sandbox escape techniques, quine context detection, restricted character repunit decomposition, func_globals module chain traversal, restricted charset number generation, class attribute persistence
- [bashjails.md](bashjails.md) - Bash jail/restricted shell escape techniques
- [encodings.md](encodings.md) - Encodings, QR codes, esolangs, Verilog/HDL, UTF-16 tricks, BCD encoding, multi-layer auto-decoding, Gray code cyclic encoding, indexed directory QR reassembly, multi-stage URL encoding chains, RTF custom tag extraction, SMS PDU decoding
- [rf-sdr.md](rf-sdr.md) - RF/SDR/IQ signal processing (QAM-16, carrier recovery, timing sync)
- [dns.md](dns.md) - DNS exploitation (ECS spoofing, NSEC walking, IXFR, rebinding, tunneling)
- [games-and-vms.md](games-and-vms.md) - WASM patching, Roblox place file reversing, PyInstaller, marshal (including code injection), Python env RCE, Z3, K8s RBAC, floating-point precision exploitation, multi-phase crypto games with HMAC commitment-reveal and GF(256) Nim, custom assembly language sandbox escape via Python MRO chain, Benford's Law bypass
- [games-and-vms-2.md](games-and-vms-2.md) - ML weight perturbation negation, cookie checkpoint game brute-forcing, Flask cookie game state leakage, WebSocket game manipulation, server time-only validation bypass, LoRA adapter weight merging and visualization, De Bruijn sequence, Brainfuck instrumentation, WASM linear memory manipulation, neural network encoder collision
- [linux-privesc.md](linux-privesc.md) - Sudo wildcard parameter injection (fnmatch), crafted pcap for sudoers.d, monit confcheck process injection, Apache -d override, backup cronjob SUID, PostgreSQL COPY TO PROGRAM RCE, PostgreSQL backup credential extraction, NFS share exploitation, SSH Unix socket tunneling, PaperCut Print Deploy privesc, Squid proxy pivoting, Zabbix admin password reset via MySQL, WinSSHTerm credential decryption
- [ai-ml.md](ai-ml.md) - AI / ML / LLM agent exploitation: federated-learning label-flip poisoning, NN watermark extraction (TATTOOED), Qiskit Grover oracle template, quantum identity-injection leakage, LLM reverse-order code injection, argument injection on pre-approved tools, DNS rebinding vs agent localhost blocks, language-guardrail gap, tool-metadata/system-prompt exfiltration, external-content injection via URL fetch, literal-policy logic trap

---

## Pattern Recognition Index

Dispatch on **observable artefacts**, not challenge titles.

| Signal | Technique → file |
|---|---|
| `python3` entry point + `input()`/`eval`/`exec` jail, restricted builtins | Python jail escape → pyjails.md |
| Restricted shell (`rbash`, `noprofile`), limited binaries | Bash jail escape → bashjails.md |
| Only DNS traffic allowed egress, or DNS records with long TXT blobs | DNS exploitation / tunneling → dns.md |
| `.iq`, `.cfile`, `.wav` with FM / AM signals, SDR / radio references | RF/SDR decoding → rf-sdr.md (for decoded hardware pipelines see `ctf-forensics/signals-and-hardware.md`) |
| Encoded text: unusual base, esolang, QR fragments | Encoding decoders → encodings.md |
| ML weights file, LLM endpoint, quantum circuit, federated training loop | AI/ML/quantum → ai-ml.md |
| WASM binary + in-browser game, VM state in JS | WASM patching → games-and-vms.md |
| Z3/SMT shape: "find x such that f(x) is true" for a small predicate | Z3 constraint solve → games-and-vms.md |
| Elevated-privilege needed, unusual sudoers / crontab / SUID binary | Linux privesc patterns → linux-privesc.md |
| LLM endpoint has a `fetch_*` / `read_*` tool without scheme allow-list | Agent file-read via `file://` in tool URL → ai-ml.md |
| `.keras`/`.h5` config has `"class_name":"Lambda"` with base64 function | Marshal stego + `safe_mode=False` RCE → ai-ml.md |
| `ast.literal_eval` consumer without `isinstance` check, downstream index-based access | Dict-for-list type confusion → pyjails.md |

Recognize the **mechanic**. Names lie; bytes don't.

---

For inline code/cheatsheet quick references (grep patterns, one-liners, common payloads), see [quickref.md](quickref.md). The `Pattern Recognition Index` above is the dispatch table — always consult it first; load `quickref.md` only if you need a concrete snippet after dispatch.
