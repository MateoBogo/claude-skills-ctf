# CTF Reverse — Advanced Tooling (2025-2026 era)

Heavy-weight tooling patterns from 2025-2026 elite CTFs. Base tooling (angr, Ghidra, IDA scripting, Unicorn standalone) lives in [tools-advanced.md](tools-advanced.md); dynamic-only tools (Frida, Qiling) in [tools-dynamic.md](tools-dynamic.md).

## Table of Contents
- [Massive PE (GB-scale) with Per-Layer VirtualProtect-Gated Self-Decryption — Unicorn + angr Hybrid (source: DEFCON 2025 Quals nfuncs1)](#massive-pe-gb-scale-with-per-layer-virtualprotect-gated-self-decryption--unicorn--angr-hybrid-source-defcon-2025-quals-nfuncs1)

---

## Massive PE (GB-scale) with Per-Layer VirtualProtect-Gated Self-Decryption — Unicorn + angr Hybrid (source: DEFCON 2025 Quals nfuncs1)

**Trigger:**
- A Windows PE binary ≥ 500 MB (often 3 GB+) where loading in IDA or Ghidra exhausts RAM.
- Each "layer" calls `VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old)` followed by an inline decryption loop (`xor`/`add`/`rol` with a per-layer key derived from earlier inputs), then `call rax`/`jmp rax` into the freshly-decrypted chunk.
- Many `read()` calls that validate each input byte against a lookup table or equality compare, then conditionally fall through to the next layer.

**Signals to grep:**
```
strings -a bin.exe | grep -iE 'VirtualProtect|NtProtectVirtualMemory'
objdump -d --start-address=... | grep -c '\s(xor|ror|rol)\s'   # many small crypto loops
pefile: count of sections with SizeOfRawData > 10 MB
```

**Why you cannot just angr it:** a symbolic engine running through `VirtualProtect` and self-modified code explodes on path count; a pure Unicorn emulator has no SMT to solve the per-byte input constraints.

**Hybrid approach (works in ≤ 1 h on 16 cores):**

1. **Unicorn-only warm-up** — emulate from entry with a fake `ReadFile`/`read` hook that feeds placeholder bytes. Record every `VirtualProtect` call (addr, size, prot) and every `call`/`jmp rax` that follows. This builds a **layer graph** without interpreting crypto semantically — each layer is a (decrypt-fn, entry-addr, key-source) tuple.

2. **Per-layer angr solve** — for each layer from Unicorn's graph:
   - Load only the decrypted bytes Unicorn observed (dump the code page right after the `VirtualProtect` with `RWX`).
   - Build a `CFGEmulated` rooted at `entry-addr`, stopping at the next `VirtualProtect` call (use a `state.inspect` breakpoint on `VirtualProtect` address).
   - Add constraints from input-byte lookup table checks (angr's `SimState.solver.add(buf[i] == const)` after matching the comparator pattern).
   - `state.solver.eval(input, cast_to=bytes)` → canonical input for that layer.

3. **Hook orchestration in Unicorn** — once layers 1..k are solved:
   ```python
   def hook_read(uc, buf_addr, count, user_data):
       uc.mem_write(buf_addr, LAYER_INPUTS[user_data["layer_idx"]])
       user_data["layer_idx"] += 1
       return count
   def hook_puts(uc, *_):          # skip diagnostic prints, they slow us 5×
       uc.reg_write(UC_X86_REG_RIP, uc.reg_read(UC_X86_REG_RIP) + uc.mem_read(RIP, 5))
   ```
   Let the binary cascade through all decrypted layers end-to-end; the final layer prints the flag.

4. **Performance fences:**
   - Do **NOT** disassemble inside hooks (Capstone/iced_x86 inside a per-instruction hook costs ~40× — measured on DEFCON 2025 nfuncs1 at 3 h without this fix).
   - Use `UC_HOOK_BLOCK`, not `UC_HOOK_CODE`, unless you need single-step.
   - Dump memory pages to disk between layers; don't hold 3 GB in Python.

**Template:**
```python
import unicorn, angr
uc = unicorn.Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(BASE, SIZE)
uc.mem_write(BASE, open(BIN, "rb").read())
LAYERS = []

def vp_hook(uc, addr, sz, user_data):
    # capture (addr, sz, code_bytes) right before exec
    LAYERS.append((addr, sz, uc.mem_read(addr, sz)))
uc.hook_add(UC_HOOK_CODE, vp_hook, begin=VP_ADDR, end=VP_ADDR+1)
uc.emu_start(ENTRY, STOP, timeout=3*60*10**6)

for addr, sz, code in LAYERS:
    proj = angr.Project.angr.load_shellcode(code, "amd64", load_address=addr)
    st = proj.factory.blank_state(addr=addr)
    buf = st.solver.BVS("buf", 8*INPUT_SZ)
    st.memory.store(INPUT_BUF, buf)
    sm = proj.factory.simulation_manager(st)
    sm.explore(find=SUCCESS_ADDR, avoid=FAIL_ADDR)
    LAYER_INPUT = sm.found[0].solver.eval(buf, cast_to=bytes)
```

**Generalizes to:** any multi-stage unpacker (VMProtect 3+, Themida, custom game protections) where each stage exposes a small `read()` oracle that gates progression. The key insight is *Unicorn to navigate, angr to solve per-stage constraints, never both at once.*
