---
name: ctf-misc
description: Miscellaneous CTF: Python/bash jails, encoding puzzles, Z3/SMT, QR codes, RF/SDR, WASM games, esoteric languages, game theory, commitment schemes, AI/ML/LLM agent exploitation (prompt injection, tool-arg injection, federated poisoning, quantum/Qiskit).
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch Skill
metadata:
  user-invocable: "false"
---

# CTF Miscellaneous

Quick reference for miscellaneous CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [pyjails.md](pyjails.md) — Python sandbox escape, quine ctx, charset tricks, class-attr persistence, literal_eval
- [bashjails.md](bashjails.md) — restricted shell escape
- [encodings.md](encodings.md) — QR, esolangs, Verilog, UTF-16, BCD, Gray code, RTF, SMS PDU
- [rf-sdr.md](rf-sdr.md) — RF/SDR/IQ processing, QAM-16, carrier/timing recovery
- [dns.md](dns.md) — ECS spoof, NSEC walk, IXFR, rebinding, tunneling
- [games-and-vms.md](games-and-vms.md) — WASM patch, PyInstaller, marshal, floating-point, K8s RBAC, Nim GF(256)
- [games-and-vms-2.md](games-and-vms-2.md) — ML weight perturbation, cookie games, WebSocket manip, LoRA merge
- [linux-privesc.md](linux-privesc.md) — sudo wildcard, monit confcheck, NFS, PostgreSQL COPY TO PROGRAM, Zabbix
- [ai-ml.md](ai-ml.md) — federated poison, NN watermark, Grover, LLM injection (arg/lang/reverse/policy), Lambda RCE
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
