---
name: ctf-forensics
description: Digital forensics: disk/memory images (Volatility), PCAP + network steganography, Windows event logs & registry, side-channel power/EM traces, RF/SDR/DTMF/POCSAG decode, logic-analyzer (sigrok), image/audio stego, cryptocurrency tracing. Dispatch on file magic.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Forensics & Blockchain

Quick reference for forensics CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Additional Resources

- [3d-printing.md](3d-printing.md) — PrusaSlicer G-code, QOIF, heatshrink
- [windows.md](windows.md) — registry, SAM, event logs, Amcache, WMI persistence, MPLog
- [network.md](network.md) — tcpdump, TLS keylog, SMB3 decrypt, USB HID steno, split-archive reassembly
- [network-advanced.md](network-advanced.md) — packet-timing, NTLMv2, DNS stego, SMB RID recycle, UA-gated C2 hex-XOR
- [disk-and-memory.md](disk-and-memory.md) — Volatility, VMDK/VHD/APFS, ZFS, RAID5 XOR, Docker/cloud forensics
- [steganography.md](steganography.md) — image stego: LSB, DQT, QR reassembly, seed-permuted, F5 JPEG
- [stego-advanced.md](stego-advanced.md) — FFT audio, DTMF/SSTV, multi-track diff, video frame accum
- [linux-forensics.md](linux-forensics.md) — log analysis, Docker image, browser artifacts, git recovery, KeePass v4
- [signals-and-hardware.md](signals-and-hardware.md) — VGA/HDMI/DP decode, POCSAG, PulseView I²C, flash ADC, DPA
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
