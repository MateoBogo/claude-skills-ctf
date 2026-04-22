---
name: ctf-pwn
description: Binary exploitation (pwn): stack/heap/format-string/ROP, glibc heap (House-of-*, leakless, FSOP/FSOPAgain), seccomp bypass, sandbox escape, Linux & Windows kernel exploitation (KASLR/SMEP/SMAP, token steal, cred swap, PreviousMode), BROP. Dispatch on binary/checksec signals.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Binary Exploitation (Pwn)

Quick reference for binary exploitation (pwn) CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [overflow-basics.md](overflow-basics.md) — stack/global overflow, canary bypass, ret2win
- [rop-and-shellcode.md](rop-and-shellcode.md) — ret2libc, ret2csu, syscall ROP, exotic gadgets
- [rop-advanced.md](rop-advanced.md) — SROP, RETF arch-switch, .fini_array, ret2vdso, stack pivot
- [format-string.md](format-string.md) — fmt leaks, GOT/hook overwrite, blind fmt, argv[0] tricks
- [advanced.md](advanced.md) — heap/UAF classics (House of Orange/Spirit/Lore), ret2dlresolve, JIT
- [advanced-exploits.md](advanced-exploits.md) — 2024 era: GC UAF, VM bugs, FSOP+seccomp, custom sandboxes
- [advanced-exploits-2.md](advanced-exploits-2.md) — 2024-early-2025: io_uring SQE inj, TLS dtor, MOP, corphone
- [advanced-exploits-3.md](advanced-exploits-3.md) — 2025-2026: vkfs FS, MIPS $gp, alloca, ObjC, ARM64 PAC, cmp timing
- [sandbox-escape.md](sandbox-escape.md) — custom VM, FUSE/CUSE, busybox/restricted shell
- [heap-leakless.md](heap-leakless.md) — glibc 2.32-2.39+ leakless (Rust/Water/Tangerine/Corrosion)
- [kernel.md](kernel.md) — Linux kernel fundamentals, QEMU debug, spray structures
- [kernel-techniques.md](kernel-techniques.md) — tty_struct kROP, SLUB internals, userfaultfd, DiceCTF 2026
- [kernel-bypass.md](kernel-bypass.md) — KASLR/FGKASLR, KPTI, SMEP/SMAP, exploit delivery
- [kernel-advanced.md](kernel-advanced.md) — EntryBleed, SLUBStick, DirtyCred, folly page-aliasing
- [brop.md](brop.md) — Blind ROP full chain without binary access
---

## Pattern Recognition Index

Map **observable signals** (not challenge names) to the right technique. Scan this first when you're handed a binary and a remote.

| Signal observed in binary / source | Technique → file |
|---|---|
| `checksec`: NX but no canary, stack buffer + `read`/`gets` | Plain stack overflow → overflow-basics.md |
| Canary + forking server (pre-fork `accept` loop) | Byte-by-byte canary brute-force → overflow-basics.md |
| `int`/`ssize_t` length → `read(fd, buf, len)` with only `len > MAX` check | Signed→size_t confusion → advanced-exploits-2.md |
| `printf(user_ptr)` with no format string | Format-string leak + GOT overwrite → format-string.md |
| glibc 2.32+ tcache with Safe-Linking; no leaks possible | House of Rust / Water → heap-leakless.md |
| glibc 2.39+, no `free()` primitive exposed | House of Tangerine (malloc-only AAW) → heap-leakless.md |
| `mmap(MAP_FIXED)` exposed with controllable `addr`, `prot` | MOP — libc code-page zeroing → advanced-exploits-2.md |
| Fork/clone + tiny shared-mem handshake validating input char-by-char | strace byte-count side-channel → advanced-exploits-2.md |
| Kernel chall, unpriv userns, `splice()`/`vmsplice()` + large kmalloc free | Pipe-backed folio_put page-UAF → advanced-exploits-2.md |
| Container with custom bind-mounts on `/dev`, `/proc` under runc ≤ 1.1.x | runc 2025 symlink-race escape → advanced-exploits-2.md |
| Unicorn/QEMU sandbox with host-side helper reads | Host/guest hook divergence → advanced-exploits-2.md |
| Kernel io_uring SQE reachable via UAF / type confusion | io_uring worker abuse → kernel-advanced.md, advanced-exploits-2.md |
| KASLR + Linux ≥ 5.8 + prefetch available | EntryBleed → kernel-advanced.md |
| Windows driver IOCTL + NT kernel | PreviousMode / token stealing → kernel-advanced.md, advanced-exploits-2.md |
| No binary given, remote only, forking server with long timeout | Blind ROP (BROP) → brop.md |
| `seccomp` filter blocking execve, `open`/`read`/`write` allowed | ORW ROP → rop-and-shellcode.md, rop-advanced.md |
| MIPS ELF + overflow reachable + `$gp` loadable from writable region | `$gp`-pivot fake-GOT → advanced-exploits-3.md |
| Custom FS with `(mip,x,y)`-style path tuples + SHA256 hashing | Coord-indexed FS overflow → advanced-exploits-3.md |
| Format-string read + later FILE* UAF in same binary | FILE UAF + fstr bridge → advanced-exploits-3.md |
| `pthread` + user-controlled `alloca(n)` + `shutdown(fd, SHUT_WR)` | Cross-thread alloca smash + partial-close leak → advanced-exploits-3.md |
| `libobjc` linked + tcache-sized free followed by `objc_msgSend` | Isa-pointer UAF dispatch hijack → advanced-exploits-3.md |
| aarch64 kernel mod + `paciza`/`autiza` + IOCTL `sizeof` bound | ARM64 PAC-key exfil via bounds-mismatch AAR → advanced-exploits-3.md |
| seccomp kills `write`/`socket` + `/usr/bin/cmp` reachable + `/flag` readable | `cmp` timing oracle → advanced-exploits-3.md |
| C++ pwn with vtable dispatch + 0x110/0x480 chunk sizes | House of Spirit via C++ vtable → advanced-exploits.md |
| `SPLICE_F_GIFT` / `MSG_ZEROCOPY` / `TCP_ZEROCOPY_RECEIVE` in proxy | Zero-copy page aliasing TOCTOU → kernel-advanced.md |
| seccomp allows `io_uring_*` only, kernel ≥ 6.1 | `IORING_SETUP_NO_MMAP` escape → sandbox-escape.md |
| Sandboxed proc can recv from helper via AF_UNIX | SCM_RIGHTS fd smuggling → sandbox-escape.md |
| setuid binary scrubs secret after `read`, coredumps reachable | Coredump race → sandbox-escape.md |
| Non-standard eBPF prog on kprobe, flag gated by global state | eBPF FSM syscall-sequence → sandbox-escape.md |
| Traefik ≤ 2.11.13 front + Flask/Node admin routes | `X-Forwarded-*` reach → polyglot chain → advanced-exploits-3.md |

Recognize the **mechanic** first. The challenge title is never the signal.

---

For inline code/cheatsheet quick references (grep patterns, one-liners, common payloads), see [quickref.md](quickref.md). The `Pattern Recognition Index` above is the dispatch table — always consult it first; load `quickref.md` only if you need a concrete snippet after dispatch.
