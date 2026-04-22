---
name: ctf-automation
description: Orchestrator that triages a CTF challenge directory in one command. Fingerprints binaries (file/checksec/readelf/rabin2/strings), detects language deps (package.json, requirements.txt, go.mod, Cargo.toml, pyproject.toml), finds crypto artefacts (.pem, model files, .weights.h5, *.qasm, *.circom, *.halo2), finds forensics artefacts (.pcap, .sr, .raw, IQ complex*, .evtx, memdump), and emits a JSON+markdown report pointing directly at the relevant Pattern Recognition Index sections in ctf-*/SKILL.md. Also provides per-category setup scripts: pwnsetup.sh (libc.rip + patchelf + pwntools template), cryptosetup.py (RSA/ECDSA/lattice detection + SageMath preload), websetup.sh (ffuf/httpx/katana/nuclei chain w/ JSON output), foreniq.sh (GQRX/sox/multimon-ng chain + pulseview wrapper), aiprobe.py (LLM endpoint probe — argv injection, DNS rebind, language-gap, metadata exfil).
license: MIT
compatibility: Requires bash, Python 3, jq. Optional: checksec, rabin2, patchelf, ffuf, httpx, katana, nuclei, subfinder, multimon-ng, sox, pulseview, sagemath. Missing-tool detection prints exact install command instead of crashing.
allowed-tools: Bash Read Write Edit Glob Grep
metadata:
  user-invocable: "true"
  argument-hint: "<challenge-dir> [--json] [--category pwn|crypto|web|forensics|ai]"
---

# CTF Automation — one-shot triage and category setup

All scripts live in this directory. Every script emits JSON to stdout (when `--json` is given) so you can pipe into `jq` or the next stage of a chain.

## Entry point: triage

```bash
bash /home/ubuntu/.claude/skills/ctf-automation/triage.sh <challenge-dir>
```

Outputs:

1. `<challenge-dir>/.ctf-triage.json` — machine-readable fingerprint
2. `<challenge-dir>/.ctf-triage.md` — markdown report with **pointers into `ctf-*/SKILL.md#pattern-recognition-index`**

After triage, pick the indicated category script:

| If triage flags       | Run next                                      |
|-----------------------|-----------------------------------------------|
| `elf_dynamic=true`    | `pwnsetup.sh <binary>`                        |
| `crypto_artefacts>0`  | `python3 cryptosetup.py <challenge-dir>`      |
| `web_urls>0`          | `websetup.sh <url>`                           |
| `forensics_artefacts` | `foreniq.sh <file>`                           |
| `ai_endpoint`         | `python3 aiprobe.py <url>`                    |

## Tool inventory philosophy

Each script performs a `command -v` check for every external tool it uses. Missing tools do **not** crash — they print the exact `apt install …` / `go install …` / `pip install …` command for the missing binary and continue on what remains available.

## Scripts in this directory

- `triage.sh` — master triage; emits JSON + markdown pointing to Pattern Recognition Index sections
- `pwnsetup.sh` — `checksec` → detect libc → `libc.rip` lookup → `patchelf` → generate `exploit.py` pwntools template pre-wired for local+remote
- `cryptosetup.py` — parses challenge files; detects RSA (n,e,c), ECDSA sigs (r,s), lattice shapes, post-quantum params (Kyber/Dilithium/Falcon); generates a Sage script stub with correct imports
- `websetup.sh` — chained recon: `subfinder` → `httpx` → `katana` → `ffuf` → `nuclei`, merges to single JSON
- `foreniq.sh` — RF/audio/logic-analyzer pipeline: GQRX UDP / file → `sox` 22050Hz mono → `multimon-ng -a POCSAG512/1200/2400 -f alpha`; `.sr` files → `pulseview` CLI export
- `aiprobe.py` — LLM endpoint auto-attack: argument injection on tool-allow-lists, DNS rebind, language-guardrail-gap, metadata exfil, reverse-order prompt, literal-policy flip. Emits finding JSON per attack.

## Pattern Recognition dispatch

`triage.sh` reads the file list and dependency manifests, then writes pointers like:

```
ctf-pwn/SKILL.md#pattern-recognition-index → row "MAP_FIXED exposed"
ctf-crypto/SKILL.md#pattern-recognition-index → row "post-quantum KEM"
ctf-misc/ai-ml.md → section "Argument injection on allow-listed tools"
```

The calling agent (`/solve-challenge`) reads the markdown report and dispatches to the skill(s) indicated. This replaces guessing the category from the user prompt — we dispatch on **what is actually in the challenge folder**.

## Chain example

```bash
DIR=/tmp/ch-42
bash triage.sh "$DIR" --json | jq '.hints[]'
# If hints mention "libc":
bash pwnsetup.sh "$DIR/vuln"
# If hints mention "ai_endpoint":
python3 aiprobe.py http://chal.example/api --json > findings.json
```

## Exit codes

- `0` — triage ran, report written
- `2` — directory does not exist / unreadable
- `3` — no recognisable artefacts (empty, or only text README)

Never exit `1`; that's reserved for unexpected script errors, which indicate a bug to fix.
