---
name: ctf-reverse
description: Reverse engineering: ELF/PE/Mach-O, WASM, .NET, APK (Flutter/Dart), Python bytecode, Go/Rust/Swift/Kotlin, custom VMs, anti-debug/anti-VM, VMProtect/Themida, eBPF, Ghidra/IDA/radare2/Frida/angr/Qiling. Dispatch on file magic + loader signature.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Reverse Engineering

Quick reference for RE challenges. For detailed techniques, see supporting files.

## Additional Resources

- [tools.md](tools.md) — GDB, Ghidra, radare2, IDA, Binary Ninja, Unicorn, WASM, pyc, packed
- [tools-dynamic.md](tools-dynamic.md) — Frida, angr, lldb, x64dbg, Qiling, Triton, Pin instruction-counting
- [tools-advanced.md](tools-advanced.md) — VMProtect/Themida, BinDiff, D-810/GOOMBA, TTF GSUB, AVX2 Z3 lift
- [anti-analysis.md](anti-analysis.md) — Linux/Windows anti-debug, anti-VM, anti-DBI, MBA, self-hashing
- [patterns.md](patterns.md) — custom VMs, nanomites, LLVM obfuscation, S-box, SECCOMP/BPF, multi-thread
- [patterns-ctf.md](patterns-ctf.md) — comp patterns part 1: hidden opcodes, LD_PRELOAD, GBA MITM, maze kmod
- [patterns-ctf-2.md](patterns-ctf-2.md) — part 2: multi-layer brute, CVP integer, decision-tree, perf oracle, VM misident
- [languages.md](languages.md) — Python bytecode, pyarmor, UEFI, esolangs, HarmonyOS, Godot, Electron
- [languages-compiled.md](languages-compiled.md) — Go (GoReSym), Rust, Swift, Kotlin/JVM, C++ vtables, .pyc forgery
- [platforms.md](platforms.md) — Mach-O, iOS jailbreak, embedded firmware, kernel drivers, game engines, CAN
---

## Pattern Recognition Index

Dispatch on **observable binary features**, not challenge titles.

| Signal (from `file`, `readelf`, `strings`, `nm`) | Technique → file |
|---|---|
| ELF with `__libc_start_main`, small main, direct syscalls | Basic RE patterns → patterns.md |
| ELF with large unrecognised opcode-dispatch loop (switch on byte → handler) | Custom VM reversing → patterns.md |
| `readelf -l` shows RWX segment + self-writes to `.text` | Self-modifying / multi-layer decryption → patterns-ctf-2.md |
| Binary that modifies its round constants and re-encrypts output | Binary-as-keystream-oracle (patch I/O boundary) → patterns-ctf-2.md |
| `ptrace(PTRACE_TRACEME)` / `/proc/self/status TracerPid` / `rdtsc` timing | Anti-debug detection → anti-analysis.md |
| `__Py_*` or `PyMarshal` strings | Python bytecode / pyc reversing → languages.md |
| `runtime.` prefix in strings, `go.buildinfo` | Go reversing (GoReSym) → languages-compiled.md |
| Rust demangling (`_ZN`/`_RN`), `core::panicking` | Rust reversing → languages-compiled.md |
| Mach-O header `FEEDFACE`/`FEEDFACF` | macOS/iOS RE → platforms.md |
| `.wasm` magic (`00 61 73 6D`) | WASM → languages.md, ctf-misc/games-and-vms.md |
| `.apk`/`classes.dex`, `libflutter.so`, `kernel.dill` | APK / Flutter reversing → languages.md |
| Unicorn/QEMU used as a sandbox with host-side memory read helpers | Host/guest hook divergence → patterns-ctf-2.md (and ctf-pwn/advanced-exploits-2.md) |
| `.rodata` blob + XOR loop with known constants / stored expected bytes | Stack-string deobfuscation → patterns-ctf-2.md |
| `SHA-NI` instructions, per-layer key read from stdin | Multi-layer brute-force JIT → patterns-ctf-2.md |
| Per-char early-exit compare loop + local execution allowed | `perf_event_open` instruction-count oracle → patterns-ctf-2.md |
| Custom VM whose handlers are pop/push but docs claim "register-based" + banned bytes | Arch misidentification + banned-byte synthesis → patterns-ctf-2.md |
| `.pyc` with loader that checks only first 16 bytes | PEP-552 magic-header forgery → languages-compiled.md |
| Go binary with `runtime.itab` symbols intact but stripped strings | GoReSym/typelinks restore → languages-compiled.md |
| `bpftool prog list` shows non-standard eBPF prog | eBPF FSM syscall-sequence decomp → languages-compiled.md (+ ctf-pwn/sandbox-escape.md) |
| TTF/OTF with abnormally dense GSUB; glyphs named `hex_*`/`one`/`zero` | GSUB ligature stego DAG reverse → tools-advanced.md |
| AVX2 `vpaddb`/`vpshufb` in tight loop over input | Lane-wise Z3 lifting → tools-advanced.md |

Recognize the **artefact or opcode pattern**. The title is noise.

---

For inline code/cheatsheet quick references (grep patterns, one-liners, common payloads), see [quickref.md](quickref.md). The `Pattern Recognition Index` above is the dispatch table — always consult it first; load `quickref.md` only if you need a concrete snippet after dispatch.
