# ctf-app-system — Quick Reference

Inline code / one-liners / common payloads. Loaded on demand from `SKILL.md`. Detailed techniques live in the category-specific support files listed in `SKILL.md`.


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
