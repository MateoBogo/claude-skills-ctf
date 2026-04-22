#!/usr/bin/env bash
# pwnsetup.sh <binary> [libc-path]
# Fingerprint a pwn binary, resolve remote libc via libc.rip, patchelf, and emit an exploit.py template.
set -u
BIN="${1:-}"
LIBC_HINT="${2:-}"
[[ -z "$BIN" ]] && { echo "usage: $0 <binary> [libc-path]" >&2; exit 2; }
[[ ! -f "$BIN" ]] && { echo "not a file: $BIN" >&2; exit 2; }

has() { command -v "$1" >/dev/null 2>&1; }
miss() { echo "[miss] $1 — $2" >&2; }
has checksec   || miss checksec "apt install checksec"
has patchelf   || miss patchelf "apt install patchelf"
has readelf    || miss readelf  "apt install binutils"
has curl       || miss curl     "apt install curl"
has python3    || miss python3  "apt install python3 python3-pip"
has pwn        || miss pwntools "pip install pwntools"

OUT="$(dirname "$(realpath "$BIN")")"
NAME="$(basename "$BIN")"

# --- checksec ---
if has checksec; then
  echo "[*] checksec:"
  checksec --file="$BIN" 2>/dev/null || checksec "$BIN" 2>/dev/null
fi

# --- arch / libc needed ---
ARCH="unknown"
LIBC_NEEDED=""
if has readelf; then
  MACH=$(readelf -h "$BIN" 2>/dev/null | awk -F: '/Machine/ {print $2}' | xargs)
  case "$MACH" in
    *X86-64*|*x86-64*) ARCH="amd64";;
    *80386*|*Intel 80386*) ARCH="i386";;
    *AArch64*)        ARCH="aarch64";;
    *ARM*)            ARCH="arm";;
  esac
  LIBC_NEEDED=$(readelf -d "$BIN" 2>/dev/null | awk -F: '/NEEDED.*libc/ {print $2}' | tr -d ' []')
fi
echo "[*] arch=$ARCH needed=$LIBC_NEEDED"

# --- libc fingerprinting via libc.rip ---
LIBC_PATH="$LIBC_HINT"
LIBC_JSON=""
if [[ -z "$LIBC_PATH" ]]; then
  for candidate in "$OUT/libc.so.6" "$OUT/libc-"*.so "$OUT/$LIBC_NEEDED"; do
    [[ -f "$candidate" ]] && LIBC_PATH="$candidate" && break
  done
fi
if [[ -n "$LIBC_PATH" && -f "$LIBC_PATH" ]] && has curl; then
  echo "[*] libc.rip lookup for $LIBC_PATH"
  # extract 4 common symbols -> offsets
  SYMS=""
  for s in puts printf read system __libc_start_main; do
    off=$(readelf -a "$LIBC_PATH" 2>/dev/null | awk -v s="$s" '$8==s && $5 ~ /FUNC/ {print $2; exit}')
    [[ -n "$off" ]] && SYMS+="\"$s\":\"0x$off\","
  done
  SYMS="{${SYMS%,}}"
  LIBC_JSON=$(curl -s -m 8 -H 'Content-Type: application/json' -d "{\"symbols\":$SYMS}" https://libc.rip/api/find 2>/dev/null | head -c 4096 || true)
  echo "[*] libc.rip response (truncated): $(head -c 200 <<<"$LIBC_JSON")"
fi

# --- patchelf for local run if libc provided ---
LD_PATH=""
for cand in "$OUT/ld-"*.so "$OUT/ld-linux-x86-64.so.2" "$OUT/ld-linux.so.2"; do
  [[ -f "$cand" ]] && LD_PATH="$cand" && break
done
if [[ -n "$LIBC_PATH" && -n "$LD_PATH" ]] && has patchelf; then
  cp "$BIN" "$OUT/${NAME}.patched"
  patchelf --set-interpreter "$LD_PATH" --set-rpath "$(dirname "$LIBC_PATH")" "$OUT/${NAME}.patched"
  chmod +x "$OUT/${NAME}.patched"
  echo "[*] patched binary -> $OUT/${NAME}.patched"
fi

# --- pwntools exploit template ---
TEMPLATE="$OUT/exploit.py"
if [[ -f "$TEMPLATE" ]]; then
  echo "[!] $TEMPLATE exists — not overwriting"
else
  cat > "$TEMPLATE" <<PY
#!/usr/bin/env python3
from pwn import *

BIN = "./${NAME}"
LIBC_PATH = ${LIBC_PATH:+\"$LIBC_PATH\"}
context.binary = ELF(BIN)
context.arch = "${ARCH}"
context.log_level = "info"

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(args.HOST or "localhost", int(args.PORT or 1337))
    if args.GDB:
        return gdb.debug([BIN] + argv, gdbscript="c", *a, **kw)
    return process([BIN] + argv, *a, **kw)

libc = ELF(LIBC_PATH) if LIBC_PATH else context.binary.libc

io = start()
# --- leak ---
# io.recvuntil(b"...")
# io.sendline(cyclic(72))
# leak = u64(io.recvline().rstrip().ljust(8, b"\x00"))
# libc.address = leak - libc.sym.puts
# log.success(f"libc @ {libc.address:#x}")
# --- pwn ---
# rop = ROP(libc)
# rop.call("system", [next(libc.search(b"/bin/sh"))])
# io.sendline(flat(b"A"*72, rop.chain()))
io.interactive()
PY
  chmod +x "$TEMPLATE"
  echo "[*] wrote $TEMPLATE"
fi

# --- JSON summary ---
cat <<EOF
{
  "binary": "$(realpath "$BIN")",
  "arch": "$ARCH",
  "libc_needed": "$LIBC_NEEDED",
  "libc_path": "${LIBC_PATH:-}",
  "ld_path": "${LD_PATH:-}",
  "patched": "${OUT}/${NAME}.patched",
  "template": "$TEMPLATE",
  "libc_rip_hit": $([[ -n "$LIBC_JSON" ]] && echo true || echo false)
}
EOF
