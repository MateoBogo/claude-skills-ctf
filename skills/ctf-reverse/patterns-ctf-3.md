# CTF Reverse — Patterns (2025-2026 era, continued)

Third-era patterns. Base patterns in [patterns-ctf.md](patterns-ctf.md); 2024-era additions in [patterns-ctf-2.md](patterns-ctf-2.md).

## Table of Contents
- [Genetic Algorithm over Opaque Scoring Function (source: PlaidCTF 2025 Prospectin')](#genetic-algorithm-over-opaque-scoring-function-source-plaidctf-2025-prospectin)

---

## Genetic Algorithm over Opaque Scoring Function (source: PlaidCTF 2025 Prospectin')

**Trigger:**
- ELF/PE where `main()` reads a small input (≤ 256 bytes), then feeds it through a long chain of `if (input[i] op const) score += kN; else score += kM;` style predicates — often dozens to hundreds of such checks.
- The binary prints success when `score >= THRESHOLD` (e.g. `0x119`, `0x5f3`); no obvious single-byte flag check, no hashing, just additive scoring.
- Ghidra decompilation shows a flat chain of arithmetic / bitwise / boolean checks with branch-free `score += w` updates that all depend on `input[i]`.

**Signals to grep:**
```
objdump -d bin | awk '/add\s+\$0x[0-9a-f]+,\s*%e[a-z]x/' | wc -l      # many score-bumping adds
grep -oE 'score\s*[+\-*]=\s*\w+' decompile.c | sort -u                 # diverse weights
# fitness-style control flow: single exit with   if (score >= X) win();
```

**Why not symbolic execution:** angr chokes on hundreds of branches; z3 solve time blows up because there's no feasible conjunction of constraints — the scoring is *additive*, not *equational*. You don't need all checks to pass, just enough to hit the threshold.

**Recipe:**

1. **Lift the scoring loop to a callable** — two options:
   - (a) Ghidra → decompile → paste C → `gcc -shared -fPIC` → `ctypes.CDLL`.
   - (b) `patchelf --add-needed` a tiny shim, or use Qiling/Unicorn to wrap only the `score()` function as a Python callable.
   - Cross-arch? Decompile aarch64 → paste into amd64 .so; the scoring body is pure arithmetic and ports 1-1.

2. **GA driver:**
```python
import random, ctypes
scorer = ctypes.CDLL("./score.so").score    # (const char*, size_t) -> int
POP, GENS, LEN, THR = 500, 2000, INPUT_LEN, 0x5f3

def fitness(b):
    buf = ctypes.create_string_buffer(b, LEN)
    return scorer(buf, LEN)

def mutate(b):
    i = random.randrange(LEN)
    return b[:i] + bytes([random.randrange(256)]) + b[i+1:]

def crossover(a, b):
    k = random.randrange(LEN)
    return a[:k] + b[k:]

pop = [bytes(random.randrange(256) for _ in range(LEN)) for _ in range(POP)]
for gen in range(GENS):
    pop.sort(key=fitness, reverse=True)
    if fitness(pop[0]) >= THR:
        print(pop[0].hex()); break
    elite = pop[:POP//10]
    pop = elite + [mutate(crossover(random.choice(elite), random.choice(elite)))
                   for _ in range(POP - len(elite))]
```

3. **Tuning knobs that matter:**
   - Tournament selection > elitism if the fitness landscape is rugged.
   - Byte-wise mutation rate 1-3% optimal; too high destroys converged structure, too low stalls.
   - When charset is restricted (hex digits, printable ASCII), constrain `random.randrange(...)` accordingly — a 5-10× speedup.
   - If the scorer has independent per-byte contributions, **replace GA with hill-climbing**: vary one byte at a time, keep if score doesn't decrease. Often 100× faster than GA and provably optimal for separable scoring.

4. **Detecting separability (skip GA):**
   - Run the scorer with input `b"A"*N`, then flip byte `i` through 0..255. If the per-byte optimum is independent of other bytes, the scoring is **separable** — solve each byte independently.
   - Build a `256 × N` table `best[i][v]` = score contribution of byte `i = v`; pick argmax per column.

**Generalizes to:** license validators, "submit 32-byte key to unlock"-style crackmes with weighted scoring, ML-style classifier wrappers, puzzle games with score-based win conditions. First separability-probe, then hill-climb, then GA as fallback.
