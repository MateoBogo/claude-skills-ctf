---
name: ctf-reverse
description: Provides reverse engineering techniques for CTF challenges. Use when analyzing binaries, game clients, obfuscated code, esoteric languages, custom VMs, anti-debugging, anti-analysis bypass, WASM, .NET, APK (including Flutter/Dart AOT with Blutter), HarmonyOS HAP/ABC, Python bytecode, Go/Rust/Swift/Kotlin binaries, VMProtect/Themida, Ghidra, GDB, radare2, Frida, angr, Qiling, Triton, binary diffing, macOS/iOS Mach-O, embedded firmware, kernel modules, game engines, or extracting flags from compiled executables.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Reverse Engineering

Quick reference for RE challenges. For detailed techniques, see supporting files.

## Additional Resources

- [tools.md](tools.md) - Static analysis tools (GDB, Ghidra, radare2, IDA, Binary Ninja, dogbolt.org, RISC-V with Capstone, Unicorn emulation, Python bytecode, WASM, Android APK, .NET, packed binaries)
- [tools-dynamic.md](tools-dynamic.md) (includes Intel Pin instruction-counting side channel for movfuscated binaries) - Dynamic analysis tools: Frida (hooking, anti-debug bypass, memory scanning, Android/iOS), angr symbolic execution (path exploration, constraints, CFG), lldb (macOS/LLVM debugger), x64dbg (Windows), Qiling (cross-platform emulation with OS support), Triton (dynamic symbolic execution)
- [tools-advanced.md](tools-advanced.md) - Advanced tools: VMProtect/Themida analysis, binary diffing (BinDiff, Diaphora), deobfuscation frameworks (D-810, GOOMBA, Miasm), Rizin/Cutter, RetDec, advanced GDB (Python scripting, conditional breakpoints, watchpoints, reverse debugging with rr, pwndbg/GEF), advanced Ghidra scripting, patching (Binary Ninja API, LIEF)
- [anti-analysis.md](anti-analysis.md) - Comprehensive anti-analysis: Linux anti-debug (ptrace, /proc, timing, signals, direct syscalls), Windows anti-debug (PEB, NtQueryInformationProcess, heap flags, TLS callbacks, HW/SW breakpoint detection, exception-based, thread hiding), anti-VM/sandbox (CPUID, MAC, timing, artifacts, resources), anti-DBI (Frida detection/bypass), code integrity/self-hashing, anti-disassembly (opaque predicates, junk bytes), MBA identification/simplification, bypass strategies
- [patterns.md](patterns.md) - Foundational binary patterns: custom VMs, anti-debugging, nanomites, self-modifying code, XOR ciphers, mixed-mode stagers, LLVM obfuscation, S-box/keystream, SECCOMP/BPF, exception handlers, memory dumps, byte-wise transforms, x86-64 gotchas, signal-based exploration, malware anti-analysis, multi-stage shellcode, timing side-channel, multi-thread anti-debug with decoy + signal handler MBA
- [patterns-ctf.md](patterns-ctf.md) - Competition-specific patterns (Part 1): hidden emulator opcodes, LD_PRELOAD key extraction, SPN static extraction, image XOR smoothness, byte-at-a-time cipher, mathematical convergence bitmap, Windows PE XOR bitmap OCR, two-stage RC4+VM loaders, GBA ROM meet-in-the-middle, Sprague-Grundy game theory, kernel module maze solving, multi-threaded VM channels, backdoored shared library detection via string diffing
- [patterns-ctf-2.md](patterns-ctf-2.md) - Competition-specific patterns (Part 2): multi-layer self-decrypting brute-force, embedded ZIP+XOR license, stack string deobfuscation, prefix hash brute-force, CVP/LLL lattice for integer validation, decision tree function obfuscation, GLSL shader VM, GF(2^8) Gaussian elimination, Z3 single-line Python circuit, sliding window popcount, keyboard LED Morse code via ioctl
- [languages.md](languages.md) - Language/platform-specific: Python bytecode & opcode remapping, Python version-specific bytecode, Pyarmor static unpack, DOS stubs, Unity IL2CPP, HarmonyOS HAP/ABC, Brainfuck/esolangs, UEFI, transpilation to C, code coverage side-channel, OPAL functional reversing, non-bijective substitution, Roblox place file analysis, Godot game asset extraction, Rust serde_json schema recovery, Verilog/hardware RE, Android JNI RegisterNatives, Ruby/Perl polyglot, Electron ASAR extraction + native binary analysis, Node.js npm runtime introspection
- [languages-compiled.md](languages-compiled.md) - Go binary reversing (GoReSym, goroutines, memory layout, channel ops, embed.FS), Rust binary reversing (demangling, Option/Result, Vec, panic strings), Swift binary reversing (demangling, protocol witness tables), Kotlin/JVM (coroutine state machines), C++ (vtable reconstruction, RTTI, STL patterns)
- [platforms.md](platforms.md) - Platform-specific RE: macOS/iOS (Mach-O, code signing, Objective-C runtime, Swift, dyld, jailbreak bypass), embedded/IoT firmware (binwalk, UART/JTAG/SPI extraction, ARM/MIPS, RTOS), kernel drivers (Linux .ko, eBPF, Windows .sys), game engines (Unreal Engine, Unity, anti-cheat, Lua), automotive CAN bus, RISC-V advanced

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
