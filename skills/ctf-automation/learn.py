#!/usr/bin/env python3
"""learn.py — turn a solve (+ its struggle log) into ctf-skill drafts.

This is the fil rouge: no challenge leaves solved without the skill library
getting at least a draft PR. The human then reviews in review.sh — we never
auto-merge into SKILL.md.

Inputs:
    --chal-dir   directory of the challenge (holds the struggle log)
    --exploit    winning exploit script (we mine mechanics out of it)
    --flag       captured flag
    --struggle   path to .struggle.jsonl (defaults to <chal-dir>/.struggle.jsonl)
    --ctf-name   label for source attribution (default: basename of chal-dir)

Outputs in skills/ctf-automation/drafts/:
    <ts>-<skill>-<mechanic>.md    mechanics-first section (feedback_skill_triggering)
    <ts>-pri-row.txt              the row to paste into target SKILL.md PRI
    <ts>-memory.md                "lesson" memory entry (the struggle)
Plus: prints JSON summary on stdout, with near-match warnings.

Design choices:
 * Mechanic extraction is *heuristic*, not LLM. We key off imports +
   well-known pwntools / Crypto / requests primitives. Wrong guesses are
   fine — the human fixes them during review.
 * Duplicate detection uses a cheap normalised-token Jaccard (not full
   Levenshtein — faster, good enough on one-line signals). Score < 0.25
   is the "near match" threshold from the mission.
 * We never touch ctf-*/SKILL.md directly. review.sh is the only writer.
"""
from __future__ import annotations
import argparse, json, os, re, sys, time
from pathlib import Path
from collections import Counter

HERE = Path(__file__).resolve().parent
SKILLS_ROOT = HERE.parent  # ~/.claude/skills
DRAFTS = HERE / "drafts"
DRAFTS.mkdir(exist_ok=True)

# ---------- mechanic extraction ----------

PWN_PRIMITIVES = {
    "ret2win":       [r"elf\.sym(bols)?\[['\"]\w*win\w*['\"]\]",
                      r"p64\(\s*win\b", r"payload.*p64\(.*\bwin\b"],
    "stack-bof":     [r"b['\"]A['\"]\s*\*\s*\d+", r"cyclic\(\s*\d+",
                      r"padding\s*=\s*b['\"]A"],
    "ret2libc":      [r"\bsystem\(", r"libc\.sym\[['\"]system['\"]\]", r"\bbinsh\b",
                      r"next\(libc\.search\(b['\"]\/bin\/sh"],
    "ret2dlresolve": [r"Ret2dlresolvePayload", r"dlresolve", r"_dl_runtime_resolve"],
    "rop":           [r"\bROP\(", r"ropper", r"ROPgadget", r"rop\.raw\(", r"rop\.call\("],
    "srop":          [r"SigreturnFrame\(", r"\bsrop\b"],
    "format-string": [r"%\d*\$p", r"%\d*\$n", r"fmtstr_payload"],
    "fsop":          [r"_IO_FILE", r"IO_str_jumps", r"house of (apple|orange|emma)",
                      r"_IO_wstr_overflow", r"IO_stdin_used"],
    "heap-tcache":   [r"tcache", r"House of (Water|Tangerine|Apple|Rust|Corrosion)"],
    "shellcode":     [r"asm\(shellcraft", r"shellcraft\.", r"\x48\x31\xf6\x56"],
    "seccomp-bypass":[r"seccomp", r"SECCOMP", r"arch_prctl\(0x3001"],
    "brop":          [r"BROP", r"pwn_brop", r"brop\."],
    "fmt-leak":      [r"canary\s*=.*%\d*\$p"],
    "stack-pivot":   [r"leave\s*;\s*ret", r"pivot"],
}
CRYPTO_PRIMITIVES = {
    "rsa-common-modulus":  [r"gcd\s*\(.*e1.*e2", r"common modulus"],
    "rsa-coppersmith":     [r"coppersmith", r"small_roots", r"Coppersmith"],
    "rsa-wiener":          [r"wiener", r"continued_fraction"],
    "rsa-fermat":          [r"fermat", r"isqrt\(n\)"],
    "rsa-lsb-oracle":      [r"lsb.?oracle", r"parity oracle"],
    "aes-ecb-oracle":      [r"ECB", r"ecb_byte_at_a_time"],
    "aes-cbc-padding":     [r"padding[_ ]oracle", r"bit[_ ]flip"],
    "hash-length-ext":     [r"length.?extension", r"hashpumpy", r"sha1_length"],
    "lattice-lll":         [r"\bLLL\b", r"BKZ\(", r"lattice.?attack"],
    "hnp":                 [r"hidden.?number", r"\bHNP\b"],
    "prng-mt19937":        [r"MT19937", r"mersenne", r"untemper"],
    "ecdsa-nonce-reuse":   [r"ecdsa.*nonce", r"reused.?k"],
}
WEB_PRIMITIVES = {
    "ssrf":           [r"http://169\.254\.169\.254", r"gopher://", r"file://"],
    "sqli-union":     [r"\bUNION\s+SELECT", r"' OR '1'='1"],
    "sqli-time":      [r"SLEEP\(\d+\)", r"pg_sleep"],
    "ssti":           [r"\{\{[^}]*config", r"\{\{self", r"\{% for "],
    "jwt-none":       [r"\"alg\":\s*\"none\"", r"alg=None"],
    "jwt-confusion":  [r"HS256.*RS256", r"alg confusion"],
    "prototype-poll": [r"__proto__", r"constructor\.prototype"],
    "xxe":            [r"<!ENTITY", r"SYSTEM \"file://"],
    "http-smuggling": [r"Transfer-Encoding:\s*chunked.*Content-Length", r"CL.TE|TE.CL"],
    "parser-diff":    [r"two.?parser", r"normalisation.*differ"],
}
MISC_PRIMITIVES = {
    "z3-smt":         [r"from z3 import", r"z3\.Solver"],
    "pyjail":         [r"__builtins__", r"__class__\.__bases__", r"\beval\(", r"\bexec\("],
    "bash-jail":      [r"\$\{IFS", r"\$PATH", r"\$'\\\\x"],
    "prompt-inject":  [r"ignore (all )?previous", r"system prompt", r"</?s> ?\[INST\]"],
    "tool-arg-inj":   [r"tool_choice.*any", r"allowed_tools", r"function_call"],
}
FORENSICS_PRIMITIVES = {
    "volatility":     [r"vol(atility)?\.py", r"windows\.pslist"],
    "pcap-scapy":     [r"from scapy", r"rdpcap\("],
    "stego-lsb":      [r"LSB", r"steghide"],
    "sigrok":         [r"sigrok", r"\.sr\b", r"pulseview"],
    "rf-multimon":    [r"multimon-ng", r"POCSAG"],
}
REVERSE_PRIMITIVES = {
    "angr-symexec":   [r"import angr", r"project\.factory\.simulation"],
    "unicorn-emu":    [r"from unicorn", r"Uc\("],
    "qiling-emu":     [r"from qiling", r"Qiling\("],
    "frida-hook":     [r"frida\.attach", r"Interceptor\.attach"],
    "custom-vm":      [r"opcode", r"dispatch.*switch", r"bytecode"],
}
APPSYS_PRIMITIVES = {
    "rootme-ssh":     [r"ssh\s+-p\s*2222", r"paramiko\.SSHClient", r"exec_command"],
    "libc-rip":       [r"libc\.rip", r"libcdb\.query"],
    "patchelf":       [r"patchelf\s+--set", r"\.patched\b"],
}
OSINT_PRIMITIVES = {
    "wayback":        [r"web\.archive\.org", r"cdx_api"],
    "snowflake-id":   [r"snowflake", r"1288834974657"],
    "nitter":         [r"nitter\."],
    "exif-geo":       [r"ExifTool", r"GPSLatitude", r"MGRS"],
}
MALWARE_PRIMITIVES = {
    "marshal-b64":    [r"marshal\.loads", r"base64\.b64decode.*exec"],
    "pe-dotnet":      [r"dnlib|ILSpy|pythonnet"],
    "rc4-c2":         [r"rc4\(|RC4\("],
}

SKILL_OF: dict[str, str] = {}
for mech in PWN_PRIMITIVES:       SKILL_OF[mech] = "ctf-pwn"
for mech in CRYPTO_PRIMITIVES:    SKILL_OF[mech] = "ctf-crypto"
for mech in WEB_PRIMITIVES:       SKILL_OF[mech] = "ctf-web"
for mech in MISC_PRIMITIVES:      SKILL_OF[mech] = "ctf-misc"
for mech in FORENSICS_PRIMITIVES: SKILL_OF[mech] = "ctf-forensics"
for mech in REVERSE_PRIMITIVES:   SKILL_OF[mech] = "ctf-reverse"
for mech in APPSYS_PRIMITIVES:    SKILL_OF[mech] = "ctf-app-system"
for mech in OSINT_PRIMITIVES:     SKILL_OF[mech] = "ctf-osint"
for mech in MALWARE_PRIMITIVES:   SKILL_OF[mech] = "ctf-malware"

ALL_PRIMITIVES = {**PWN_PRIMITIVES, **CRYPTO_PRIMITIVES, **WEB_PRIMITIVES,
                  **MISC_PRIMITIVES, **FORENSICS_PRIMITIVES, **REVERSE_PRIMITIVES,
                  **APPSYS_PRIMITIVES, **OSINT_PRIMITIVES, **MALWARE_PRIMITIVES}


def scan_exploit(text: str) -> list[tuple[str, int]]:
    """Return mechanic → hit count, sorted desc."""
    hits: Counter = Counter()
    for mech, patterns in ALL_PRIMITIVES.items():
        for pat in patterns:
            n = len(re.findall(pat, text, flags=re.IGNORECASE))
            if n:
                hits[mech] += n
    return hits.most_common()


def pick_skill(hits: list[tuple[str, int]], exploit_text: str) -> tuple[str, str]:
    """Return (skill, primary_mechanic). Fall back to ctf-misc."""
    if not hits:
        # still classify by import signal
        if "from pwn import" in exploit_text:
            return "ctf-pwn", "unknown-pwn"
        if "from Crypto" in exploit_text or "sage" in exploit_text.lower():
            return "ctf-crypto", "unknown-crypto"
        if "requests" in exploit_text or "httpx" in exploit_text:
            return "ctf-web", "unknown-web"
        return "ctf-misc", "unknown"
    primary = hits[0][0]
    return SKILL_OF.get(primary, "ctf-misc"), primary


# ---------- struggle analysis ----------

def load_struggle(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    entries = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def struggle_narrative(entries: list[dict]) -> tuple[str, list[str]]:
    """Return (one-liner for 'Why I struggled', list of anti-patterns)."""
    if not entries:
        return "No struggle log available — solved on first shot.", []
    n = len(entries)
    clusters: Counter = Counter()
    tried_hyps = []
    for e in entries:
        hyp = e.get("hypothesis") or {}
        if hyp:
            tried_hyps.append(hyp)
        if e.get("result") == "crash" and e.get("crash_info"):
            sig = e["crash_info"].get("signal")
            if sig:
                clusters[f"signal {sig}"] += 1
        elif e.get("result") == "timeout":
            clusters["timeout"] += 1
    top_clusters = clusters.most_common(3)
    flag_entry = next((e for e in entries if e.get("result") == "flag"), None)
    winning = flag_entry.get("hypothesis") if flag_entry else None
    bits = [f"Burned {n} attempts."]
    if top_clusters:
        bits.append("Dominant failure modes: "
                    + ", ".join(f"{k} (×{v})" for k, v in top_clusters))
    if winning:
        bits.append(f"Winning hypothesis: {winning}")
    # anti-patterns = hypotheses tried that are NOT the winning one, de-duped
    anti = []
    if winning and tried_hyps:
        seen = set()
        for h in tried_hyps:
            if h == winning:
                continue
            key = json.dumps(h, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            anti.append(str(h))
    return " ".join(bits), anti[:5]


# ---------- observable extraction ----------

def extract_observables(chal_dir: Path, exploit_text: str, mechanic: str) -> list[str]:
    """Return concrete file-level signals a future agent can detect WITHOUT
    knowing the challenge name. Empty list => no memory lesson is emitted
    (per feedback_skill_triggering_by_mechanics)."""
    obs: list[str] = []
    if chal_dir.is_dir():
        files = [p for p in chal_dir.iterdir() if p.is_file()]
        exts = {p.suffix.lower() for p in files}
        # meaningful filenames
        names_lc = {p.name.lower() for p in files}
        if any(n.startswith("libc") for n in names_lc):
            obs.append("`libc.so.6` or `libc-*.so` present in chal dir")
        if any(n.startswith("ld-") for n in names_lc):
            obs.append("custom `ld-*.so` loader in chal dir (patchelf target)")
        if ".pcap" in exts or ".pcapng" in exts:
            obs.append("`.pcap`/`.pcapng` capture present")
        if {".key", ".pem", ".crt", ".pub"} & exts:
            obs.append("PEM/key material in chal dir")
        if {".circom", ".r1cs", ".zkey"} & exts:
            obs.append("Circom/ZK artefact present")
        if any(n == "foundry.toml" for n in names_lc):
            obs.append("`foundry.toml` at root (web3 project)")
        if any(n == "package.json" for n in names_lc):
            obs.append("`package.json` present")
        if {".sol", ".vy"} & exts:
            obs.append("Solidity/Vyper source present")
        if {".h5", ".pt", ".pth", ".pkl", ".onnx", ".safetensors"} & exts:
            obs.append("ML model weights present")
    # Parametrised knowns the exploit declared
    m = re.search(r'offset["\']?\s*[:=]\s*([0-9xA-Fa-f]+)', exploit_text)
    if m:
        obs.append(f"concrete stack offset {m.group(1)} used in exploit")
    if re.search(r'\bwin\b\s*\(|elf\.sym(bols)?\[.*win', exploit_text):
        obs.append("`win` symbol reachable in ELF symbol table")
    if re.search(r'continued_fraction|\bwiener\b', exploit_text, re.I):
        obs.append("RSA (n,e) with e close to n (Wiener-shape: e > n**0.25)")
    if re.search(r'fermat|isqrt\(n\)', exploit_text, re.I):
        obs.append("RSA p≈q (|p-q| small → Fermat shape)")
    if re.search(r'coppersmith|small_roots', exploit_text, re.I):
        obs.append("RSA small-e or known-prefix plaintext")
    if re.search(r'%\d*\$[pn]', exploit_text):
        obs.append("format-string conversion specifiers in payload")
    if re.search(r'SigreturnFrame', exploit_text):
        obs.append("`sigreturn()` or `rt_sigreturn` reachable gadget")
    # de-dup preserving order
    seen = set(); dedup: list[str] = []
    for o in obs:
        if o not in seen:
            seen.add(o); dedup.append(o)
    return dedup


# ---------- duplicate detection ----------

def tokens(s: str) -> set[str]:
    return set(re.findall(r"[a-zA-Z0-9_]+", s.lower()))


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def scan_pri_rows(skill: str) -> list[tuple[Path, int, str]]:
    """Return [(path, lineno, row_text)] for Pattern Recognition Index rows
    in the target skill's SKILL.md and support files."""
    rows: list[tuple[Path, int, str]] = []
    sdir = SKILLS_ROOT / skill
    if not sdir.is_dir():
        return rows
    for md in sdir.rglob("*.md"):
        try:
            lines = md.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        in_pri = False
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if re.match(r"^#+\s*pattern[- ]recognition", s, re.I):
                in_pri = True
                continue
            if in_pri and s.startswith("#"):
                in_pri = False
            if in_pri and s.startswith("-"):
                rows.append((md, i, s))
    return rows


def near_match(signals: list[str], skill: str, threshold: float = 0.35) -> list[str]:
    """Fuzzy-match each observable signal against existing PRI rows.
    Returns top-5 rows ranked by max similarity across signals (cheap token jaccard).
    Lower default threshold (0.35) because PRI rows are short and distinctive."""
    if not signals:
        return []
    sig_tokens = [tokens(s) for s in signals]
    scored: list[tuple[float, str]] = []
    for path, lineno, row in scan_pri_rows(skill):
        row_tok = tokens(row)
        best = max((jaccard(st, row_tok) for st in sig_tokens), default=0.0)
        if best >= threshold:
            rel = path.relative_to(SKILLS_ROOT.parent)
            scored.append((best, f"{rel}:{lineno}  (sim={best:.2f}) {row[:140]}"))
    scored.sort(reverse=True)
    return [s for _, s in scored[:5]]


# ---------- triage.sh enrichment proposal ----------

def propose_triage_rule(mechanic: str, exploit_text: str, chal_dir: Path) -> str | None:
    """If we can cheaply detect this from files alone, propose a triage.sh rule."""
    files = [p.name for p in chal_dir.iterdir() if p.is_file()] if chal_dir.is_dir() else []
    hints = []
    if any(f.endswith(".so") or f.startswith("libc") for f in files):
        hints.append("libc.so in dir → elf_dynamic=true already caught")
    if any(f.endswith(".pcap") or f.endswith(".pcapng") for f in files):
        hints.append("pcap in dir → PCAP_LIST path (forensics)")
    if any(f.endswith(".sage") or f.endswith(".sobj") for f in files):
        hints.append("sage artefact → crypto dispatch")
    if "z3" in exploit_text.lower() and not any("z3" in f.lower() for f in files):
        hints.append(f"# mechanic={mechanic} leaves no filename trace — skip triage rule")
    return "; ".join(hints) or None


# ---------- draft writers ----------

def write_mechanic_draft(ts: str, skill: str, mechanic: str, flag: str,
                         ctf_name: str, primary_hits: list[tuple[str, int]],
                         struggle_line: str, anti: list[str],
                         observables: list[str], chal_dir: Path) -> Path:
    path = DRAFTS / f"{ts}-{skill}-{mechanic}.md"
    primary_trigger = observables[0] if observables else \
        f"<REVIEW — no file-level observable extracted; describe what a future agent will see>"
    sig_bullets = "\n".join(f"- {o}" for o in observables) or \
        "- (none auto-extracted — reviewer MUST fill or drop this draft)"
    body = f"""# Draft: {mechanic} (target: {skill}/SKILL.md PRI)

<!-- Auto-generated by learn.py from a solve in {chal_dir}.
     Mechanics-first rule: the `## Trigger` line must be a file-level
     observable a future agent can spot WITHOUT knowing the CTF name.
     Review + edit, then review.sh merges it. -->

## Trigger: {primary_trigger}

**Pattern (source: {ctf_name}):** {mechanic} exploited end-to-end.

**Observable signals:**
{sig_bullets}

**Secondary mechanic hits (from exploit):** {", ".join(m for m, _ in primary_hits[1:4]) or "none"}

**Mechanic description:** <TODO — 2-3 sentence human insight; learn.py only extracts primitive names.>

**Why I struggled:** {struggle_line}

**Anti-pattern (kill-signals for triage):**
"""
    if anti:
        for a in anti:
            body += f"- Hypothesis `{a}` tried and failed — not the bug class.\n"
    else:
        body += "- (no dead-ends recorded — solved on first shot; consider whether this is reproducible.)\n"
    body += f"""
**Exploit fingerprint:**
```
primary mechanic: {mechanic}
all hits: {primary_hits}
flag: {flag}
```

**Merge target:** review.sh appends this section to `{skill}/quickref.md`
(or a new era-bucketed `-N.md` file if quickref exceeds 500 lines) and
adds ONE PRI row to `{skill}/SKILL.md`.
"""
    path.write_text(body)
    return path


def write_pri_row_draft(ts: str, skill: str, mechanic: str,
                        observables: list[str], chal_dir: Path) -> Path:
    path = DRAFTS / f"{ts}-pri-row.txt"
    signal = observables[0] if observables \
        else f"<REVIEW — no observable extracted for {mechanic}>"
    row = f"- {signal} → quickref.md#{mechanic}"
    path.write_text(
        f"# paste into {skill}/SKILL.md under ## Pattern Recognition Index:\n"
        f"{row}\n\n"
        f"# Mechanic: {mechanic}\n"
        f"# Source chal: {chal_dir}\n"
    )
    return path


def write_memory_draft(ts: str, mechanic: str, struggle_line: str,
                       anti: list[str], ctf_name: str,
                       observables: list[str]) -> Path | None:
    """Skip the memory draft entirely when there is no observable — a lesson
    without a trigger is untraceable for future agents (feedback_skill_triggering)."""
    if not observables:
        return None
    path = DRAFTS / f"{ts}-memory.md"
    obs_block = "\n".join(f"  - {o}" for o in observables)
    antifmt = "\n".join(f"  - {a}" for a in anti) or "  - (none recorded)"
    body = f"""---
name: Lesson from {ctf_name} ({mechanic})
description: Observable-anchored solve lesson so future triage jumps to {mechanic}
type: feedback
---
{struggle_line}

**Mechanic:** {mechanic}

**Observable trigger(s) (what a future agent should see):**
{obs_block}

**What I tried first that didn't work:**
{antifmt}

**How to apply:** When the observable(s) above are present, jump straight
to {mechanic} instead of sweeping the hypotheses listed here.
"""
    path.write_text(body)
    return path


# ---------- main ----------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--chal-dir", required=True)
    ap.add_argument("--exploit", required=True)
    ap.add_argument("--flag", required=True)
    ap.add_argument("--struggle", default=None)
    ap.add_argument("--ctf-name", default=None)
    args = ap.parse_args()

    chal_dir = Path(args.chal_dir).resolve()
    exploit = Path(args.exploit).resolve()
    if not exploit.is_file():
        print(json.dumps({"error": f"exploit not found: {exploit}"}))
        return 2
    struggle_path = Path(args.struggle) if args.struggle else chal_dir / ".struggle.jsonl"
    ctf_name = args.ctf_name or chal_dir.name

    exploit_text = exploit.read_text(errors="ignore")
    hits = scan_exploit(exploit_text)
    skill, mechanic = pick_skill(hits, exploit_text)

    entries = load_struggle(struggle_path)
    struggle_line, anti = struggle_narrative(entries)

    observables = extract_observables(chal_dir, exploit_text, mechanic)
    near = near_match(observables, skill)

    triage_rule = propose_triage_rule(mechanic, exploit_text, chal_dir)

    ts = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    d_mech = write_mechanic_draft(ts, skill, mechanic, args.flag, ctf_name,
                                  hits or [(mechanic, 0)], struggle_line, anti,
                                  observables, chal_dir)
    d_pri = write_pri_row_draft(ts, skill, mechanic, observables, chal_dir)
    d_mem = write_memory_draft(ts, mechanic, struggle_line, anti, ctf_name,
                               observables)

    out = {
        "skill": skill,
        "mechanic": mechanic,
        "all_mechanic_hits": hits[:10],
        "attempts_logged": len(entries),
        "observables": observables,
        "memory_emitted": d_mem is not None,
        "drafts": {
            "mechanic": str(d_mech),
            "pri_row": str(d_pri),
            "memory": str(d_mem) if d_mem else None,
        },
        "near_matches": near,
        "triage_rule_proposal": triage_rule,
        "review_cmd": f"bash {HERE}/review.sh",
    }
    if not observables:
        out["warning"] = ("No file-level observable auto-extracted — memory "
                          "skipped. Reviewer must add a Trigger line before merge.")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
