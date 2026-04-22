---
name: ctf-app-system
description: Provides Root-Me app-system exploitation techniques for ELF x86, ELF x64, ELF ARM64, and Windows Kernel x64 challenges accessed via SSH. Specializes in remote exploit development without live GDB access: static analysis, libc fingerprinting (libc.rip), patchelf, exploit transfer via SSH, ret2libc, ROP chains, format string, heap (House of Water/Tangerine/Rust leakless glibc 2.32-2.39+), ARM64 calling convention (x0-x7/LR/x30), JOP, TikTag MTE bypass, SROP ARM64, BROP (blind ROP without binary), seccomp ORW chains, FSOP glibc 2.35+ (FSOPAgain), Windows kernel token stealing, PreviousMode write (CVE-2024-21338), Segment Heap, IOCTL primitives, AAR/AAW, SMEP/KPTI bypass, Handle Table exploitation, CFG/CET mitigations.
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

## Reconnaissance initiale

```bash
# 1. Connexion SSH Root-Me
ssh -p 2222 <user>@<challenge>.root-me.org

# 2. Sur le serveur : identifier l'environnement
uname -a                          # kernel version
ldd --version                     # libc version
ls -la /challenge/ 2>/dev/null || ls ~
file ./challenge                  # architecture + linking
checksec --file=./challenge       # protections

# 3. Récupérer le binaire en local
scp -P 2222 user@host:~/challenge ./
# Ou depuis l'interface Root-Me (téléchargement direct)
```

## Stratégie selon les protections

| PIE | RELRO | Canary | NX | Stratégie |
|-----|-------|--------|----|-----------|
| Non | Partial | Non | Non | Shellcode ou ret2win direct (adresses fixes) |
| Non | Partial | Non | Oui | GOT overwrite via fmt string ou ret2libc |
| Non | Full | Oui | Oui | Leak canary via fmt string → ROP ret2libc |
| Oui | Full | Oui | Oui | Leak PIE+libc via fmt string → ROP |
| Oui | Full | Oui | Oui | Heap UAF → leak → tcache poison |

## Déterminer le type de vuln

```bash
# Analyser statiquement
objdump -d ./challenge | grep -A5 "gets\|scanf\|strcpy\|printf\|fgets"
strings ./challenge | grep -E "Enter|Input|Name|Message"

# Comportement à chaud (local)
python3 -c "print('A'*200)" | ./challenge   # crash = overflow
python3 -c "print('%p.'*30)" | ./challenge  # leak = format string

# Ghidra / radare2 pour la décompilation
r2 -A ./challenge
pdf @ main
```

## Workflow de résolution Root-Me

1. **Analyse statique locale** — `checksec`, `file`, Ghidra/r2, `strings`
2. **Identifier la vuln** — overflow, format string, UAF, race
3. **Fingerprint libc remote** — `ldd`, `strings /lib/x86_64-linux-gnu/libc.so.6 | grep GLIBC`, ou `libc-database`
4. **Patcher le binaire local** — `patchelf` pour matcher la libc du serveur
5. **Développer l'exploit localement** — avec `process()` pwntools
6. **Switcher sur `remote()`** — ou transférer via SSH + exécuter
7. **Récupérer le flag** — `/passwd`, `/home/user/.passwd`, `/challenge/.passwd`

## Emplacement du flag sur Root-Me

```bash
# Emplacements classiques Root-Me
cat /challenge/.passwd
cat ~/.passwd
find / -name ".passwd" 2>/dev/null
cat /passwd  # rare
```

## Outils essentiels

```bash
# Installation rapide si manquant
pip install pwntools
pip install ROPgadget
pip install one_gadget  # ou gem install one_gadget

# Commandes clés
checksec --file=./binary
ROPgadget --binary ./binary --rop | grep "pop rdi"
one_gadget ./libc.so.6
strings ./libc.so.6 | grep "GLIBC_"
objdump -d ./binary | grep -A3 "<puts@plt>"
readelf -s ./libc.so.6 | grep " system"
```

## Template pwntools universel

```python
from pwn import *

# Configuration
elf = ELF('./challenge')
libc = ELF('./libc.so.6')  # libc locale patché
context.arch = 'amd64'     # ou 'i386' ou 'aarch64'
context.log_level = 'debug'

# Local vs remote
LOCAL = False
if LOCAL:
    io = process('./challenge')
    # io = process(['./challenge'], env={"LD_PRELOAD": "./libc.so.6"})
else:
    io = remote('challenge01.root-me.org', 2222)
    # ou via SSH : io = ssh('user', 'host', port=2222).process('./challenge')

# GDB attach (local seulement)
if LOCAL and args.GDB:
    gdb.attach(io, '''
        break *main+42
        continue
    ''')

# === EXPLOIT ===

io.interactive()
```

Voir les fichiers spécialisés pour les techniques par architecture.
