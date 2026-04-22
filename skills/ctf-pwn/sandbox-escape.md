# CTF Pwn - Sandbox Escape and Restricted Environments

## Table of Contents
- [Python Sandbox Escape](#python-sandbox-escape)
- [VM Exploitation (Custom Bytecode)](#vm-exploitation-custom-bytecode)
- [FUSE/CUSE Character Device Exploitation](#fusecuse-character-device-exploitation)
- [Busybox/Restricted Shell Escalation](#busyboxrestricted-shell-escalation)
- [Shell Tricks](#shell-tricks)

---

## Python Sandbox Escape

Python jail/sandbox escape techniques (AST bypass, audit hook bypass, MRO-based builtin recovery, decorator chains, restricted charset tricks, and more) are covered comprehensively in [ctf-misc/pyjails.md](../ctf-misc/pyjails.md).

## VM Exploitation (Custom Bytecode)

**Pattern (TerViMator, Pragyan 2026):** Custom VM with registers, opcodes, syscalls. Full RELRO + NX + PIE.

**Common vulnerabilities in VM syscalls:**
- **OOB read/write:** `inspect(obj, offset)` and `write_byte(obj, offset, val)` without bounds checking allows read/modify object struct data beyond allocated buffer
- **Struct overflow via name:** `name(obj, length)` writing directly to object struct allows overflowing into adjacent struct fields

**Exploitation pattern:**
1. Allocate two objects (data + exec)
2. Use OOB `inspect` to read exec object's XOR-encoded function pointer to leak PIE base
3. Use `name` overflow to rewrite exec object's pointer with `win() ^ KEY`
4. `execute(obj)` decodes and calls the patched function pointer

## FUSE/CUSE Character Device Exploitation

**FUSE** (Filesystem in Userspace) / **CUSE** (Character device in Userspace)

**Identification:**
- Look for `cuse_lowlevel_main()` or `fuse_main()` calls
- Device operations struct with `open`, `read`, `write` handlers
- Device name registered via `DEVNAME=backdoor` or similar

**Common vulnerability patterns:**
```c
// Backdoor pattern: write handler with command parsing
void backdoor_write(const char *input, size_t len) {
    char *cmd = strtok(input, ":");
    char *file = strtok(NULL, ":");
    char *mode = strtok(NULL, ":");
    if (!strcmp(cmd, "b4ckd00r")) {
        chmod(file, atoi(mode));  // Arbitrary chmod!
    }
}
```

**Exploitation:**
```bash
# Change /etc/passwd permissions via custom device
echo "b4ckd00r:/etc/passwd:511" > /dev/backdoor

# 511 decimal = 0777 octal (rwx for all)
# Now modify passwd to get root
echo "root::0:0:root:/root:/bin/sh" > /etc/passwd
su root
```

**Privilege escalation via passwd modification:**
1. Make `/etc/passwd` writable via the backdoor
2. Replace root line with `root::0:0:root:/root:/bin/sh` (no password)
3. `su root` without password prompt

## Busybox/Restricted Shell Escalation

When in restricted environment without sudo:
1. Find writable paths via character devices
2. Target system files: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
3. Modify permissions then content to gain root

## Shell Tricks

**File descriptor redirection (no reverse shell needed):**
```bash
# Redirect stdin/stdout to client socket (fd 3 common for network)
exec <&3; sh >&3 2>&3

# Or as single command string
exec<&3;sh>&3
```
- Network servers often have client connection on fd 3
- Avoids firewall issues with outbound connections
- Works when you have command exec but limited chars

**Find correct fd:**
```bash
ls -la /proc/self/fd           # List open file descriptors
```

**Short shellcode alternatives:**
- `sh<&3 >&3` - minimal shell redirect
- Use `$0` instead of `sh` in some shells

---

## io_uring Seccomp Escape with `IORING_SETUP_NO_MMAP` (source: pwn.college AoP 2025 Sleigh)

**Trigger:** seccomp filter allowlists `io_uring_{setup,enter,register}` and `exit_group` only; kernel ≥ 6.1.
**Signals:** `prctl(PR_SET_NO_NEW_PRIVS)` followed by bpf filter printed in the challenge; `/proc/self/status` shows Seccomp:2; kernel version >= 6.1.
**Mechanic:** `IORING_SETUP_NO_MMAP` (added in 6.1) lets userspace supply the SQ/CQ ring memory pages directly, removing the need for `mmap` which seccomp blocked. Allocate ring buffers inside pre-mapped regions (stack, BSS), enter io_uring, submit SQEs for `openat("/flag") + read + write(stdout)`. Fully bypasses seccomp-ORW filters that forgot io_uring existed.
Template: see `liburing`'s `test/nomap.c`.

## SCM_RIGHTS FD Smuggling Across Sandbox Boundary (source: pwn.college AoP 2025)

**Trigger:** two cooperating processes where the privileged helper is reachable via AF_UNIX socket, and the sandboxed side denies `open`/`openat`.
**Signals:** `socket(AF_UNIX, SOCK_DGRAM)` or `SOCK_SEQPACKET`, presence of a companion binary launched by the challenge, seccomp filter with CMSG unrestricted.
**Mechanic:** helper opens `/flag` and sends the FD via `sendmsg(...SCM_RIGHTS...)`; sandboxed process reads it with `read(received_fd, buf, n)`. Seccomp that blocks `open*` typically doesn't model FD-passing. Minimal client:
```c
struct msghdr mh = {...}; struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
c->cmsg_level=SOL_SOCKET; c->cmsg_type=SCM_RIGHTS; *(int*)CMSG_DATA(c)=fd;
```

## Coredump Race Before In-Memory Wipe (source: pwn.college AoP 2025 CLAUS)

**Trigger:** setuid binary that `read`s secret into buffer then overwrites with `#` or `\0`; coredumps enabled (`ulimit -c unlimited` or `/proc/sys/kernel/core_pattern` writable).
**Signals:** `setuid` bit, very short window between secret read and scrub, `core_pattern = /tmp/core.%p` or similar attacker-readable location.
**Mechanic:** send SIGQUIT (or other dumping signal) during the tiny window; core contains the unscrubbed secret. Use `signalfd` + tight loop to hit the window; on pwn.college practice mode coredumps land where the solver can read them. Pattern applies to any "scrub after read" flow with signal reachability.

## eBPF FSM Gated by Syscall Sequence (source: pwn.college AoP 2025 day 4)

**Trigger:** eBPF program attached to a kprobe (`linkat`, `openat`, `prctl`); flag release depends on global state flipped by the BPF program; BPF bytecode extractable via `bpftool prog dump xlated`.
**Signals:** `bpftool prog list` shows one non-standard program; `/sys/kernel/debug/tracing/events/*` modified.
**Mechanic:** decompile bytecode → recover finite-state machine; map each transition to the syscall argument hash it checks; craft an exact sequence of calls (e.g. `linkat("/tmp/a","/tmp/b"); linkat("/tmp/c","/tmp/d"); …`) to reach accept state. Automation: feed bytecode to angr symbolic executor with `bpf-ir` lifter, solve for input sequence.
