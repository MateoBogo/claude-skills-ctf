# claude-skills-ctf

Personal Claude Code skill library for CTF work (pwn / crypto / web / reverse / forensics / misc / OSINT / malware / app-system / automation) plus associated auto-memory.

Built as a mechanics-first dispatch: every technique leads with an observable signal (binary artefacts, dependency manifests, protocol hints), never with the challenge title. SKILL.md files are lean dispatch tables (≤ 500 lines); quick-reference code and per-technique details live in support files loaded on demand.

## Layout

```
skills/
  ctf-automation/   # triage.sh + per-category setup scripts (pwnsetup, cryptosetup, websetup, foreniq, aiprobe)
  ctf-pwn/          # binary exploitation — classic → 2025-2026 era (split across -2.md / -3.md)
  ctf-crypto/       # RSA, ECC, lattice, PQ, ZK
  ctf-web/          # server-side, client-side, auth, web3 (split -advanced + -advanced-2.md, auth + auth-2.md)
  ctf-reverse/      # static + dynamic + language-specific
  ctf-forensics/    # disk, memory, network, signals, stego
  ctf-misc/         # jails, encodings, RF, AI/ML/LLM exploits
  ctf-malware/      # obfuscation, C2, PE/.NET
  ctf-osint/        # geolocation, social, web/DNS
  ctf-app-system/   # Root-Me SSH-only workflow (ELF x86/x64/ARM64, Windows kernel)
memory/
  MEMORY.md                          # index
  feedback_skill_authoring_budget.md # < 500 lines / < 2.5k tok per SKILL.md
  feedback_skill_triggering_by_mechanics.md
  feedback_ctf_writeup_patterns.md
  project_*.md                       # session artefacts (research passes, lessons)
install.sh                           # bootstrap a new machine (symlinks into ~/.claude)
```

## Install on a new machine

```bash
git clone git@github.com:MateoBogo/claude-skills-ctf.git ~/claude-skills-ctf
bash ~/claude-skills-ctf/install.sh
```

The install script symlinks every `skills/ctf-*` directory into `~/.claude/skills/` and every `memory/*.md` file into the active Claude Code project memory dir (default `~/.claude/projects/-home-ubuntu/memory/`). Re-run it any time the set of files changes.

## Working loop

1. Edit skills in-place (symlinks keep everything live under `~/.claude/skills/ctf-*`).
2. `cd ~/claude-skills-ctf && git status` → commit & push from the repo root.
3. On the other machine: `git pull` → next Claude Code session already has the updates.

## Rules when adding techniques

See `memory/feedback_skill_authoring_budget.md` and `memory/feedback_skill_triggering_by_mechanics.md`. In short:

- Every section leads with `Trigger:` / `Signals:` / `Pattern:` — observable only. Challenge name is a parenthetical source, never the dispatch hook.
- Never put code in SKILL.md; put it in the support file or `quickref.md`.
- Add ONE row per technique to `SKILL.md#pattern-recognition-index`.
- Support file > ~500 lines → spin off `-N.md` sibling (era boundary usually works: pre-2024 / 2024 / 2025-2026).

## Run the triage entrypoint

```bash
bash skills/ctf-automation/triage.sh <challenge-dir>
```

Writes `<dir>/.ctf-triage.{json,md}` pointing straight into the right `SKILL.md#pattern-recognition-index` rows.

## License

Personal use. No warranty.
