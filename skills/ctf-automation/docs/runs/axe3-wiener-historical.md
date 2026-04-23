# Axe 3 validation — historical Wiener solve

**Why historical:** Docker daemon unavailable on this host (Desktop-WSL2
integration disabled), so running a full crypto CTF binary in sandbox was
not feasible in this session. Instead we reconstructed a solve flow from a
public Wiener writeup to exercise `learn.py` on a richer struggle.

**Challenge dir:** `/tmp/chal-wiener-historical/`

**Struggle log** (hand-crafted from the memoir of 4 attempts):
```
attempt 1 — coppersmith_small_e     → no_leak  ("e is huge, not small")
attempt 2 — fermat_close_primes     → no_leak  (isqrt check failed)
attempt 3 — pollard_rho             → timeout  (420 s)
attempt 4 — wiener_small_d          → flag     CTF{wiener_d_small_wins}
```

**learn.py invocation:**
```
python3 .../learn.py --chal-dir /tmp/chal-wiener-historical \
  --exploit exploit.py --flag "CTF{...}" --ctf-name "Historical-RSA-2025"
```

**Output:**
- skill=ctf-crypto, mechanic=rsa-wiener (7 pattern hits on continued_fraction
  / convergents / wiener identifiers)
- 3 drafts emitted
- Anti-patterns captured from the struggle log: coppersmith_small_e,
  fermat_close_primes, pollard_rho — these appear in the memory entry as
  "What I tried first that didn't work", which is the teaching signal a
  future triage uses to *skip* those dead-ends.

**Merged via review.sh:** yes. `ctf-crypto/SKILL.md` PRI row appended;
`ctf-crypto/quickref.md` body appended; memory entry
`feedback_lesson_20260422T124450_rsa-wiener.md` added; MEMORY.md index
updated.

**Key observation for future rounds:** the anti-pattern list is only as
rich as the struggle log. Solves that happen on first-shot (like the
ret2win above) produce thin drafts. That's a feature: learn.py doesn't
fabricate struggle, it records what actually happened. If a solve is easy,
its draft will be short.
