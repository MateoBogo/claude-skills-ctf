# CTF Forensics - Disk and Memory Analysis

## Table of Contents
- [Memory Forensics (Volatility 3)](#memory-forensics-volatility-3)
- [Disk Image Analysis](#disk-image-analysis)
- [VM Forensics (OVA/VMDK)](#vm-forensics-ovavmdk)
- [VMware Snapshot Forensics](#vmware-snapshot-forensics)
- [Coredump Analysis](#coredump-analysis)
- [Deleted Partition Recovery](#deleted-partition-recovery)
- [RAID 5 Disk Recovery via XOR (Crypto-Cat)](#raid-5-disk-recovery-via-xor-crypto-cat)
- [PowerShell Ransomware Analysis](#powershell-ransomware-analysis)

For 2024-2026 era techniques (ZFS, GPT GUID, KAPE, APFS snapshots, ransomware key recovery), see [disk-and-memory-2.md](disk-and-memory-2.md).
- [Android Forensics](#android-forensics)
- [Container Forensics (Docker)](#container-forensics-docker)
- [Cloud Storage Forensics (AWS S3 / GCP / Azure)](#cloud-storage-forensics-aws-s3--gcp--azure)

---

## Memory Forensics (Volatility 3)

```bash
vol3 -f memory.dmp windows.info
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.cmdline
vol3 -f memory.dmp windows.netscan
vol3 -f memory.dmp windows.filescan
vol3 -f memory.dmp windows.dumpfiles --physaddr <addr>
vol3 -f memory.dmp windows.mftscan | grep flag
```

**Common plugins:**
- `windows.pslist` / `windows.pstree` - Process listing
- `windows.cmdline` - Command line arguments
- `windows.netscan` - Network connections
- `windows.filescan` - File objects in memory
- `windows.dumpfiles` - Extract files by physical address
- `windows.mftscan` - MFT FILE objects in memory (timestamps, filenames). Note: `mftparser` was Volatility 2 only; Vol3 uses `mftscan`

---

## Disk Image Analysis

```bash
# Mount read-only
sudo mount -o loop,ro image.dd /mnt/evidence

# Autopsy / Sleuth Kit
fls -r image.dd              # List files recursively
icat image.dd <inode>        # Extract file by inode

# Carving deleted files
photorec image.dd
foremost -i image.dd
```

---

## VM Forensics (OVA/VMDK)

```bash
# OVA = TAR archive containing VMDK + OVF
tar -xvf machine.ova

# 7z reads VMDK directly (no mount needed)
7z l disk.vmdk | head -100
7z x disk.vmdk -oextracted "Windows/System32/config/SAM" -r
```

**Key files to extract from VM images:**
- `Windows/System32/config/SAM` - Password hashes
- `Windows/System32/config/SYSTEM` - Boot key
- `Windows/System32/config/SOFTWARE` - Installed software
- `Users/*/NTUSER.DAT` - User registry
- `Users/*/AppData/` - Browser data, credentials

---

## VMware Snapshot Forensics

**Converting VMware snapshots to memory dumps:**
```bash
# .vmss (suspended state) + .vmem (memory) → memory.dmp
vmss2core -W path/to/snapshot.vmss path/to/snapshot.vmem
# Output: memory.dmp (analyzable with Volatility/MemprocFS)
```

**Malware hunting in snapshots (Armorless):**
1. Check Amcache for executed binaries near encryption timestamp
2. Look for deceptive names (Unicode lookalikes: `ṙ` instead of `r`)
3. Dump suspicious executables from memory
4. If PyInstaller-packed: `pyinstxtractor` → decompile `.pyc`
5. If PyArmor-protected: use PyArmor-Unpacker

**Ransomware key recovery via MFT:**
- Even if original files deleted, MFT preserves modification timestamps
- Seed-based encryption: recover mtime → derive key
```bash
vol3 -f memory.dmp windows.mftscan | grep flag
# mtime as Unix epoch → seed for PRNG → derive encryption key
```

---

## Coredump Analysis

```bash
gdb -c core.dump
(gdb) info registers
(gdb) x/100x $rsp
(gdb) find 0x0, 0xffffffff, "flag"
```

---

## Deleted Partition Recovery

**Pattern (Till Delete Do Us Part):** USB image with deleted partition table.

**Recovery workflow:**
```bash
# Check for partitions
fdisk -l image.img              # Shows no partitions

# Recover partition table
testdisk image.img              # Interactive recovery

# Or use kpartx to map partitions
kpartx -av image.img            # Maps as /dev/mapper/loop0p1

# Mount recovered partition
mount /dev/mapper/loop0p1 /mnt/evidence

# Check for hidden directories
ls -la /mnt/evidence            # Look for .dotfolders
find /mnt/evidence -name ".*"   # Find hidden files
```

**Flag hiding:** Path components as flag chars (e.g., `/.Meta/CTF/{f/l/a/g}`)

---

## RAID 5 Disk Recovery via XOR (Crypto-Cat)

**Pattern:** RAID 5 array with one damaged/missing disk. Two working disks are provided and the third must be reconstructed using XOR parity.

**How RAID 5 parity works:** Data is striped across N disks with distributed parity. For any stripe, `Disk1 XOR Disk2 XOR ... XOR DiskN = 0`. If one disk is missing, XOR the remaining disks to recover it.

**Recovery script:**
```python
# Recover missing disk2 from disk1 and disk3
with open('disk1.img', 'rb') as f:
    disk1 = f.read()
with open('disk3.img', 'rb') as f:
    disk3 = f.read()

# XOR byte-by-byte to recover the missing disk
disk2 = bytes(a ^ b for a, b in zip(disk1, disk3))

with open('disk2.img', 'wb') as f:
    f.write(disk2)
```

**After recovery:**
```bash
# Reassemble the RAID array
mdadm --create /dev/md0 --level=5 --raid-devices=3 \
  disk1.img disk2.img disk3.img

# Or mount individual recovered disk if it contains a filesystem
mount -o loop,ro disk2.img /mnt/recovered
```

**Key insight:** RAID 5 uses XOR parity across all disks in each stripe. XOR is self-inverse: if `A XOR B XOR C = 0`, then `B = A XOR C`. For N-disk RAID 5, XOR all N-1 working disks together to recover the missing one.

**Detection:** Challenge provides multiple disk images of identical size, mentions "array", "redundancy", or "parity". `file` command may identify them as filesystem images or raw data.

---

## PowerShell Ransomware Analysis

**Pattern (Email From Krampus):** PowerShell memory dump + network capture.

**Analysis workflow:**
1. Extract script blocks from minidump:
```bash
python power_dump.py powershell.DMP
# Or: strings powershell.DMP | grep -A5 "function\|Invoke-"
```

2. Identify encryption (typically AES-CBC with SHA-256 key derivation)

3. Extract encrypted attachment from PCAP:
```bash
# Filter SMTP traffic in Wireshark
# Export attachment, base64 decode
```

4. Find encryption key in memory dump:
```bash
# Key often generated with Get-Random, regex search:
strings powershell.DMP | grep -E '^[A-Za-z0-9]{24}$' | sort | head
```

5. Find archive password similarly, decrypt layers

---

### Android Forensics

```bash
# Extract APK from device
adb pull /data/app/com.target.app/base.apk

# Analyze APK contents
apktool d base.apk -o decompiled/
# Check: AndroidManifest.xml, res/values/strings.xml, shared_prefs/

# Extract data from Android backup
adb backup -apk -shared -all -f backup.ab
java -jar abe.jar unpack backup.ab backup.tar
tar xf backup.tar

# SQLite databases (contacts, messages, browser history)
sqlite3 /data/data/com.android.providers.contacts/databases/contacts2.db ".tables"
sqlite3 /data/data/com.android.providers.telephony/databases/mmssms.db "SELECT * FROM sms"

# Parse Android filesystem image
mkdir android_mount && mount -o ro android_image.img android_mount/
# Key locations:
# /data/data/<app>/databases/     — app SQLite databases
# /data/data/<app>/shared_prefs/  — app preferences (XML)
# /data/system/packages.xml       — installed packages
# /data/misc/wifi/wpa_supplicant.conf — saved WiFi passwords
```

**Key insight:** Android stores app data in `/data/data/<package>/` with SQLite databases and XML shared preferences. `adb backup` captures the full app state. For CTFs, check `shared_prefs/` for hardcoded secrets and `databases/` for flags.

---

### Container Forensics (Docker)

```bash
# Export Docker image layers
docker save IMAGE:TAG -o image.tar
tar xf image.tar
# Each layer is a directory with layer.tar containing filesystem changes
# Check: layer.tar files for added/modified files, deleted files (.wh.* whiteout)

# Inspect image history for build commands (may contain secrets)
docker history IMAGE:TAG --no-trunc
# Shows every Dockerfile instruction including ARGs and ENV values

# Extract filesystem without running the container
docker create --name extract IMAGE:TAG
docker export extract -o container_fs.tar
docker rm extract

# Analyze with dive (layer-by-layer diff viewer)
dive IMAGE:TAG

# Common forensic targets in container images:
# /app/.env, /app/config/* — application secrets
# /root/.bash_history     — build-time commands
# /etc/shadow             — leaked credentials
# Deleted files visible in earlier layers even if removed in later ones
```

**Key insight:** Docker images are layered — a file deleted in a later layer still exists in the earlier layer's tar. Use `docker history --no-trunc` to see full Dockerfile commands including secrets passed via `ARG` or `ENV`. The `dive` tool visualizes layer diffs interactively.

---

### Cloud Storage Forensics (AWS S3 / GCP / Azure)

```bash
# Enumerate public S3 buckets
aws s3 ls s3://target-bucket/ --no-sign-request
aws s3 cp s3://target-bucket/flag.txt . --no-sign-request

# Check bucket versioning (previous versions may contain deleted flags)
aws s3api list-object-versions --bucket target-bucket --no-sign-request
aws s3api get-object --bucket target-bucket --key secret.txt --version-id VERSION_ID out.txt

# GCP Cloud Storage
gsutil ls gs://target-bucket/
gsutil cp gs://target-bucket/flag.txt .

# Azure Blob Storage
az storage blob list --container-name target --account-name storageaccount
az storage blob download --container-name target --name flag.txt --account-name storageaccount
```

**Key insight:** Cloud storage versioning preserves deleted objects. Even if a flag file is deleted from the bucket, previous versions may still be accessible via `list-object-versions`. Always check for versioning-enabled buckets.
