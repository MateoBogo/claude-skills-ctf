---
name: ctf-pwn
description: Provides binary exploitation (pwn) techniques for CTF challenges. Use when exploiting buffer overflows, format strings, heap vulnerabilities (House of Water/Tangerine/Apple 2/Rust/Corrosion/Orange/Spirit/Lore/Einherjar, tcache stashing unlink, leakless heap glibc 2.32-2.39+), race conditions, kernel bugs (EntryBleed KASLR bypass, SLUBStick/CROSS-X cross-cache, DirtyCred credential swap, io_uring worker abuse, elastic objects, userfaultfd restrictions), ROP chains, ret2libc, ret2dlresolve, shellcode, GOT overwrite, use-after-free, seccomp bypass, FSOP/FSOPAgain (glibc 2.35+), stack pivot, sandbox escape, Blind ROP (BROP), Windows SEH overwrite, VirtualAlloc ROP, SeDebugPrivilege escalation, Windows PreviousMode write (CVE-2024-21338), Segment Heap exploitation, or Linux kernel exploitation (modprobe_path, tty_struct, userfaultfd, KASLR bypass, SLUB heap spray).
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Binary Exploitation (Pwn)

Quick reference for binary exploitation (pwn) CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [overflow-basics.md](overflow-basics.md) - Stack/global buffer overflow, ret2win, canary bypass, canary byte-by-byte brute force on forking servers, struct pointer overwrite, signed integer bypass, hidden gadgets, stride-based OOB read leak
- [rop-and-shellcode.md](rop-and-shellcode.md) - Core ROP chains (ret2libc, syscall ROP, rdx control, shell interaction), ret2csu, bad character XOR bypass, exotic x86 gadgets (BEXTR/XLAT/STOSB/PEXT), stack pivot via xchg rax,esp, sprintf() gadget chaining for bad character bypass
- [rop-advanced.md](rop-advanced.md) - Advanced ROP techniques: double stack pivot to BSS via leave;ret, SROP (Sigreturn-Oriented Programming) with UTF-8 constraints, seccomp bypass, RETF architecture switch (x64→x32) for seccomp bypass, shellcode with input reversal, .fini_array hijack, ret2vdso, pwntools template
- [format-string.md](format-string.md) - Format string exploitation (leaks, GOT overwrite, blind pwn, filter bypass, canary leak, __free_hook, .rela.plt patching, saved EBP overwrite for .bss pivot, argv[0] overwrite for stack smash info leak)
- [advanced.md](advanced.md) - Heap, UAF, JIT, esoteric GOT, custom allocators, DNS overflow, MD5 preimage, ASAN, rdx control, canary-aware overflow, CSV injection, path traversal, GC null-ref cascading corruption, io_uring UAF with SQE injection, integer truncation int32→int16 bypass, musl libc heap exploitation (meta pointer + atexit hijack), House of Orange/Spirit/Lore, ret2dlresolve, tcache stashing unlink attack
- [advanced-exploits.md](advanced-exploits.md) - Advanced exploit techniques (part 1): VM signed comparison, BF JIT shellcode, type confusion, off-by-one index corruption, DNS overflow, ASAN shadow memory, format string with encoding constraints, custom canary preservation, signed integer bypass, canary-aware partial overflow, CSV injection, MD5 preimage gadgets, VM GC UAF slab reuse, path traversal sanitizer bypass, FSOP + seccomp bypass, stack variable overlap, 1-byte overflow via 8-bit loop counter
- [advanced-exploits-2.md](advanced-exploits-2.md) - Advanced exploit techniques (part 2): bytecode validator bypass via self-modification, io_uring UAF with SQE injection, integer truncation int32→int16, GC null-reference cascading corruption, leakless libc via multi-fgets stdout FILE overwrite, signed/unsigned char underflow heap overflow, XOR keystream brute-force write primitive, tcache pointer decryption heap leak, unsorted bin promotion via forged chunk size, FSOP stdout TLS leak, TLS destructor hijack via `__call_tls_dtors`, custom shadow stack pointer overflow bypass, signed int overflow negative OOB heap write, XSS-to-binary pwn bridge, Windows SEH overwrite + pushad VirtualAlloc ROP, SeDebugPrivilege → SYSTEM
- [advanced-exploits-3.md](advanced-exploits-3.md) - 2025-2026 era exploits: coord-indexed custom FS overflow (SekaiCTF 2025 vkfs), MIPS `$gp`-pivot fake-GOT (SekaiCTF 2025), FILE UAF + format-string bridge (HTB Biz 2025), cross-thread `alloca` stack smash + partial-close leak (Midnightflag 2025), Objective-C Isa UAF dispatch hijack, ARM64 PAC-key exfil via bounds-mismatch AAR, `cmp` timing oracle in seccomp-write-killed jail, Traefik `X-Forwarded-*` admin reach + TAR/ELF polyglot RCE chain (HTB Biz 2025 novacore)
- [sandbox-escape.md](sandbox-escape.md) - Custom VM exploitation, FUSE/CUSE devices, busybox/restricted shell, shell tricks (cross-references ctf-misc/pyjails.md for Python jail techniques)
- [kernel.md](kernel.md) - Linux kernel exploitation fundamentals: environment setup, QEMU debug, heap spray structures (tty_struct, poll_list, user_key_payload, seq_operations), kernel stack overflow, canary leak, privilege escalation (ret2usr, kernel ROP), modprobe_path overwrite, core_pattern overwrite, kmalloc size mismatch heap overflow + struct file f_op corruption
- [kernel-techniques.md](kernel-techniques.md) - Kernel exploitation techniques: tty_struct kROP (fake vtable + stack pivot), AAW via ioctl register control, userfaultfd race stabilization, SLUB allocator internals (freelist hardening/obfuscation), leak via kernel panic, MADV_DONTNEED race window extension (DiceCTF 2026), cross-cache CPU-split attack (DiceCTF 2026), PTE overlap file write (DiceCTF 2026)
- [kernel-bypass.md](kernel-bypass.md) - Kernel protection bypass: KASLR/FGKASLR bypass (__ksymtab), KPTI bypass (swapgs trampoline, signal handler, modprobe_path/core_pattern via ROP), SMEP/SMAP bypass, GDB kernel module debugging, initramfs/virtio-9p workflow, exploit templates, exploit delivery
- [heap-leakless.md](heap-leakless.md) - Leakless heap exploitation (glibc 2.32-2.39+): Safe-Linking bypass, House of Rust (partial fd overwrite), House of Water (tcache_perthread_struct attack), House of Tangerine (malloc-only AAW, glibc 2.39+), House of Corrosion (global_max_fast via unsorted bin), Water+Apple2 full leakless chain
- [kernel-advanced.md](kernel-advanced.md) - Advanced kernel (2024-2025): EntryBleed KASLR bypass (CVE-2022-4543, prefetch TLB timing), SLUBStick/CROSS-X cross-cache (heap→page table AAR/AAW), DirtyCred credential swapping, io_uring worker thread abuse, elastic objects (msg_msg/pipe_buffer), userfaultfd restrictions (Linux 5.11+), Ubuntu 24.04 RANDOM_KMALLOC_CACHES, Windows PreviousMode write (CVE-2024-21338), Windows Segment Heap exploitation
- [brop.md](brop.md) - Blind ROP (BROP): canary bruteforce on forking servers, stop gadget discovery, BROP gadget (pop 6), PLT scanner, binary dump via puts(), full exploit chain without binary access

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
