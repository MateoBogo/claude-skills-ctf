---
name: ctf-app-system
description: Root-Me app-system (SSH-only): ELF x86/x64/ARM64 & Windows Kernel x64. No local GDB. Libc.rip fingerprint, patchelf, ret2libc/ROP/ret2dlresolve, FSOP glibc 2.35+, BROP, ARM64 AAPCS64 / PAC / TikTag MTE, Windows token steal / PreviousMode / Segment Heap.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, pwntools, GDB+pwndbg, ROPgadget, one_gadget, checksec, and SSH access to Root-Me challenge servers.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF App-System (Root-Me)

Skill spécialisé pour les challenges Root-Me de la catégorie **App - System**, accessibles via SSH. La difficulté principale : pas de GDB interactif sur le serveur, pas de pwntools installé, exploit développé localement puis transféré.

## Ressources complémentaires

- [rootme-ssh.md](rootme-ssh.md) — Workflow SSH Root-Me : connexion, fingerprint libc (libc.rip API), transfert exploit, patchelf, one_gadget remote, DynELF
- [elf-x86.md](elf-x86.md) — ELF 32-bit : cdecl (args sur pile), ret2libc 32-bit, shellcode i386, `int 0x80` syscalls, ret2dlresolve x86, format string 32-bit, ASLR brute-force, race condition TOCTOU
- [elf-x64.md](elf-x64.md) — ELF 64-bit : System V AMD64 (rdi/rsi/rdx), ret2csu, PIE+ASLR bypass, canary leak/brute, stack alignment fix, GOT overwrite, one_gadget, BROP, seccomp ORW, leakless heap techniques
- [elf-arm64.md](elf-arm64.md) — ARM64/AArch64 : AAPCS64 (x0-x7/LR=x30), LR overwrite, JOP vs ROP, PAC bypass (QEMU NOP), TikTag MTE bypass (2024), SROP ARM64, QEMU local testing, gadget rareté
- [winkern-x64.md](winkern-x64.md) — Windows Kernel x64 : token stealing (_EPROCESS offsets), PreviousMode write (CVE-2024-21338), pool overflow, IOCTL AAR/AAW, Segment Heap, Handle Table, SMEP bypass, Windows 11 VBS/HVCI/CFG mitigations, driver IDA analysis

---

## Pattern Recognition Index

Dispatch on **observable binary/remote signals**, not the Root-Me challenge number.

| Signal | Technique → file |
|---|---|
| `readelf -h` → ELFCLASS32, EM_386; args on stack | i386 cdecl ret2libc / int 0x80 shellcode → elf-x86.md |
| ELFCLASS64 EM_X86_64, stack buffer overflow, libc present | ret2libc + ret2csu + rdi gadget → elf-x64.md |
| ELFCLASS64 EM_AARCH64 | AAPCS64 LR overwrite / JOP → elf-arm64.md |
| Binary with BTI + PAC symbols (`paciasp`, `autiasp`) | PAC bypass / TikTag MTE leak → elf-arm64.md |
| PE64 driver (`.sys`) + IOCTL handlers | Token stealing / PreviousMode → winkern-x64.md |
| Remote only (no local binary), forking `accept` loop, long timeout | BROP from scratch → elf-x64.md (cross-ref ctf-pwn/brop.md) |
| SSH-only shell, no GDB / no pwntools on server | libc.rip fingerprint + patchelf local → rootme-ssh.md |
| Seccomp filter denies `execve` but allows `open`/`read`/`write` | ORW ROP chain → elf-x64.md |
| FSOP primitive reachable + glibc ≥ 2.35 | FSOPAgain → elf-x64.md |
| Heap primitive + glibc 2.32–2.39 | House of Rust/Water/Tangerine → elf-x64.md (cross-ref ctf-pwn/heap-leakless.md) |
| Windows kernel pool grooming + `SeDebugPrivilege` target | Segment Heap + Handle Table primitives → winkern-x64.md |

Recognize the **mechanic**, not the Root-Me title.

---

---

For inline snippets and quick-reference tables, see [quickref.md](quickref.md). The Pattern Recognition Index above is the dispatch table — always consult it first.
