---
name: Root-Me ASLR per-process discovery (ch21)
description: Key lesson from ELF x86 Hardened Binary 1: ASLR is active per-process on Root-Me even with setarch -R; scan and exploit must be in the same subprocess
type: project
---

Root-Me ch21 (ELF x86 Hardened Binary 1, 100pts) required a combined scan+exploit shellcode approach because `setarch i386 -R` does NOT fully disable ASLR on Root-Me servers — the stack address is re-randomized for every process invocation (~1.6 MB entropy).

**Why:** Any approach that finds the buffer address in one process and exploits it in another process will always fail (sz=0, SIGSEGV) because the address changed between invocations.

**How to apply:** For 32-bit shellcode challenges on Root-Me with ASLR:
1. Use a combined shellcode that does everything in ONE subprocess call (write ESP + open/read/write flag)
2. Run the brute-force loop in bash on the server (not in Python — server OOM)
3. Pilot via paramiko from local with ONE exec_command running the entire bash loop
4. Flag was: **OMFGwhostheWooWoo**
5. Documented fully in elf-x86.md ("ASLR par-processus sur Root-Me") and rootme-ssh.md ("Contraintes mémoire serveur")
