---
name: ctf-forensics
description: Provides digital forensics and signal analysis techniques for CTF challenges. Use when analyzing disk images, memory dumps, event logs, network captures, cryptocurrency transactions, steganography, PDF analysis, Windows registry, Volatility, PCAP, Docker images, coredumps, side-channel power traces, DTMF audio spectrograms, packet timing analysis, or recovering deleted files and credentials.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Forensics & Blockchain

Quick reference for forensics CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [3d-printing.md](3d-printing.md) - 3D printing forensics (PrusaSlicer binary G-code, QOIF, heatshrink)
- [windows.md](windows.md) - Windows forensics (registry, SAM, event logs, recycle bin, USN journal, PowerShell history, Defender MPLog, WMI persistence, Amcache)
- [network.md](network.md) - Network forensics basics (tcpdump, TLS/SSL keylog decryption, TLS master key extraction from coredump, Wireshark, PCAP, port scanning, SMB3 decryption, 5G/NR protocols, WordPress recon, credentials, USB HID steno, BCD encoding, HTTP file upload exfiltration, split archive reassembly via timestamp ordering)
- [network-advanced.md](network-advanced.md) - Advanced network forensics (packet interval timing encoding, USB HID mouse/pen drawing recovery, NTLMv2 hash cracking, TCP flag covert channel, DNS last-byte steganography, DNS trailing byte binary encoding, multi-layer PCAP with XOR + ZIP and mDNS key, Brotli decompression bomb seam analysis, SMB RID recycling via LSARPC, Timeroasting MS-SNTP hash extraction)
- [disk-and-memory.md](disk-and-memory.md) - Disk/memory forensics (Volatility, disk mounting/carving, VM/OVA/VMDK, coredumps, deleted partitions, ZFS, VMware snapshots, ransomware analysis, GPT GUID encoding, VMDK sparse parsing, APFS snapshot recovery, Windows KAPE triage, WordPerfect macro XOR extraction, minidump ISO 9660 recovery, RAID 5 XOR recovery, Android forensics, Docker container forensics, cloud storage forensics)
- [steganography.md](steganography.md) - Image steganography (binary border stego, PDF multi-layer stego, SVG keyframes, PNG reorder, file overlays, JPEG unused DQT table LSB, BMP bitplane QR extraction, image puzzle reassembly, F5 JPEG DCT ratio detection, PNG unused palette entry stego, QR code tile reconstruction, seed-based pixel permutation + multi-bitplane QR, JPEG thumbnail pixel-to-text mapping, conditional LSB with pixel filtering, GIF frame diff Morse code, GZSteg + spammimic)
- [stego-advanced.md](stego-advanced.md) - Advanced steganography (FFT frequency domain, DTMF audio, SSTV+LSB, custom frequency dual-tone keypad, multi-track audio differential subtraction, cross-channel multi-bit LSB, audio FFT musical notes, audio metadata octal encoding, nested tar whitespace encoding, audio waveform binary encoding, audio spectrogram hidden QR, video frame accumulation, reversed audio)
- [linux-forensics.md](linux-forensics.md) - Linux/app forensics (log analysis, Docker image forensics, attack chains, browser credentials, Firefox history, TFTP, TLS weak RSA, USB audio, Git directory recovery, KeePass v4 cracking, Git reflog/fsck squash recovery, browser artifact analysis (Chrome/Chromium/Firefox history, cookies, downloads, local storage, session restore), corrupted git blob repair via byte brute-force)
- [signals-and-hardware.md](signals-and-hardware.md) - Hardware signal decoding with decode code (VGA frame parsing, HDMI TMDS symbol decode, DisplayPort 8b/10b + LFSR descrambler), Voyager Golden Record audio, Saleae Logic 2 UART decode, Flipper Zero .sub files, side-channel power analysis (DPA), keyboard acoustic side-channel, POCSAG pager decoding, IQ FFT masking, PulseView I2C+datasheet workflow, op-amp flash ADC recovery

---

## Pattern Recognition Index

Dispatch on **observed file types / byte signals**, not challenge titles.

| Signal in provided material | Technique → file |
|---|---|
| `.pcap` / `.pcapng` | network.md (then network-advanced.md for timing/covert channels) |
| `.sr` / `.srzip` / `.logicdata` (logic analyser) with SCL/SDA channels | PulseView I²C decoder + datasheet → signals-and-hardware.md |
| `.sr` / `.logicdata` with single data line, start/stop bits | Saleae UART decode → signals-and-hardware.md |
| `complex64`/`complex128` binary + sample-rate in prompt | IQ FFT masking / GQRX pipeline → signals-and-hardware.md |
| Audio with pager-like chirps, narrow FM channel | POCSAG → GQRX→sox→multimon-ng → signals-and-hardware.md |
| Schematic with stack of op-amps + resistor ladder on shared input | Flash ADC recovery → signals-and-hardware.md |
| Power traces shape `(positions, guesses, traces, samples)` | DPA / CPA → signals-and-hardware.md |
| `.raw` / `.vmem` / `.dmp` / `.lime` (memory dump) | Volatility → disk-and-memory.md |
| `.E01` / `.dd` / `.img` / VMDK | Disk carving / partitioning → disk-and-memory.md |
| `.evtx`, `SAM`, `NTUSER.DAT`, `SRUDB.dat` | Windows forensics → windows.md |
| Audio WAV with sync spikes or steady tones | Spectrogram / DTMF / SSTV → stego-advanced.md |
| PNG/JPEG/BMP with suspicious size or LSB patterns | Image stego → steganography.md |
| `.git/` directory fragment / dangling blob | Git reflog / fsck / blob repair → linux-forensics.md |
| RAID disks with one missing, equal-size members | RAID5 XOR recovery → disk-and-memory.md |
| PCAP where only a specific User-Agent gets non-default responses + hex-looking paths | UA-gated C2 URL-path hex-XOR exfil → network-advanced.md |

Recognize **artefacts and bytes**, not names. If the file type matches, the section applies regardless of challenge title.

---

For inline code/cheatsheet quick references (grep patterns, one-liners, common payloads), see [quickref.md](quickref.md). The `Pattern Recognition Index` above is the dispatch table — always consult it first; load `quickref.md` only if you need a concrete snippet after dispatch.
