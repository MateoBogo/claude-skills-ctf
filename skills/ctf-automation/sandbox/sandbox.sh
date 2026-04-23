#!/usr/bin/env bash
# sandbox.sh — thin wrapper around a ctf-sandbox Docker image.
#
# Usage:
#   sandbox.sh run <binary> [args...]        exec binary inside container, binary mounted RO
#   sandbox.sh attach <binary>               GDB session; gdbscript on stdin
#   sandbox.sh shell <dir>                   interactive shell with <dir> mounted at /work
#   sandbox.sh qemu-kernel <bzImage> <initrd> kernel-pwn env (run.sh expected inside initrd)
#   sandbox.sh build [--sage]                build the image
#   sandbox.sh check                         probe daemon, print status JSON
#
# Output: all modes emit a JSON summary on fd 3 (or stdout if fd 3 unset):
#   {mode, binary, exit, signal, stdout_b64, stderr_b64, crash: {signal,addr,regs?}}
#
# Docker daemon absent → print exact install/enable commands and exit 4.
set -u
IMAGE="${CTF_SANDBOX_IMAGE:-ctf-sandbox:latest}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JSON_FD=3
# Route JSON summary to fd 3. Keep stderr intact for diagnostics; callers
# who want silence can `2>/dev/null` themselves. (Previously we dropped all
# stderr here, which hid every docker/patchelf/etc. failure from the user.)
exec 3>&1

# best-effort JSON output helper (no jq dependency)
emit_json() {
  local k v out=""
  out="{"
  while [[ $# -gt 0 ]]; do
    k="$1"; shift
    v="$1"; shift
    # naive escape of backslash and double-quote
    v="${v//\\/\\\\}"; v="${v//\"/\\\"}"
    out+="\"$k\":\"$v\","
  done
  out="${out%,}}"
  printf '%s\n' "$out" >&"$JSON_FD" 2>/dev/null || printf '%s\n' "$out"
}

has() { command -v "$1" >/dev/null 2>&1; }

docker_ready() {
  has docker || return 1
  docker info >/dev/null 2>&1
}

usage() {
  sed -n '2,12p' "$0"
  exit 2
}

missing_docker_msg() {
  cat >&2 <<'EOF'
[ctf-sandbox] Docker daemon not reachable.

To enable:
  # WSL2 on Windows:
  #   → open Docker Desktop → Settings → Resources → WSL Integration
  #     and toggle on your distro. Restart this shell.
  # Native Linux:
  apt install docker.io
  systemctl start docker
  sudo usermod -aG docker "$USER"   # then: newgrp docker

Once docker is available:
  bash sandbox.sh build
EOF
  emit_json mode check status docker_absent
  exit 4
}

image_ready() {
  docker image inspect "$IMAGE" >/dev/null 2>&1
}

cmd_check() {
  if docker_ready; then
    if image_ready; then
      emit_json mode check status ok image "$IMAGE"
    else
      emit_json mode check status image_missing image "$IMAGE" hint "bash sandbox.sh build"
    fi
  else
    missing_docker_msg
  fi
}

cmd_build() {
  docker_ready || missing_docker_msg
  local sage_arg=""
  [[ "${1:-}" == "--sage" ]] && sage_arg="--build-arg SAGE=1"
  docker build $sage_arg -t "$IMAGE" "$HERE" 1>&2
  emit_json mode build status ok image "$IMAGE"
}

# Run binary inside container, capture exit + signal + stdout/stderr.
# --native flag runs on host (degraded; no container isolation) so exploit_loop
# can iterate even where Docker is unreachable (CI, WSL w/o Desktop).
cmd_run() {
  local native=false
  if [[ "${1:-}" == "--native" ]]; then native=true; shift; fi
  local bin="${1:-}"; shift || true
  [[ -z "$bin" ]] && usage
  [[ ! -f "$bin" ]] && { emit_json mode run status missing_binary binary "$bin"; exit 3; }
  if ! $native; then
    docker_ready || {
      echo "[ctf-sandbox] Docker absent — falling back to --native (use --native to silence)." >&2
      native=true
    }
  fi
  if $native; then
    local abs out err status signal=""
    abs="$(realpath "$bin")"
    out="$(mktemp)"; err="$(mktemp)"
    set +e
    ( ulimit -c unlimited; "$abs" "$@" >"$out" 2>"$err" )
    status=$?
    set -e
    [[ $status -gt 128 ]] && signal="$((status-128))"
    emit_json mode run-native binary "$abs" exit "$status" signal "$signal" \
      stdout_b64 "$(base64 -w0 "$out" 2>/dev/null || base64 "$out")" \
      stderr_b64 "$(base64 -w0 "$err" 2>/dev/null || base64 "$err")"
    rm -f "$out" "$err"
    return
  fi
  image_ready  || cmd_build

  local abs host_dir name
  abs="$(realpath "$bin")"; host_dir="$(dirname "$abs")"; name="$(basename "$abs")"
  local out err status
  out="$(mktemp)"; err="$(mktemp)"
  set +e
  docker run --rm --network=none \
    --cap-drop=ALL --security-opt=no-new-privileges \
    --pids-limit=256 --memory=1g --cpus=1 \
    --ulimit core=-1 \
    -v "$host_dir":/work:ro \
    -w /work \
    "$IMAGE" \
    /work/"$name" "$@" >"$out" 2>"$err"
  status=$?
  set -e
  local signal=""
  # 128 + sig → name
  if [[ $status -gt 128 ]]; then signal="$((status-128))"; fi
  emit_json mode run binary "$abs" exit "$status" signal "$signal" \
    stdout_b64 "$(base64 -w0 "$out" 2>/dev/null || base64 "$out")" \
    stderr_b64 "$(base64 -w0 "$err" 2>/dev/null || base64 "$err")"
  rm -f "$out" "$err"
  # stdout (raw) on fd 1 is already consumed above; keep JSON on fd 3
}

# Start GDB against the binary, feed gdbscript from stdin, collect output.
cmd_attach() {
  local bin="${1:-}"
  [[ -z "$bin" ]] && usage
  [[ ! -f "$bin" ]] && { emit_json mode attach status missing_binary; exit 3; }
  docker_ready || missing_docker_msg
  image_ready  || cmd_build
  local abs host_dir name script
  abs="$(realpath "$bin")"; host_dir="$(dirname "$abs")"; name="$(basename "$abs")"
  script="$(mktemp)"; cat > "$script"
  docker run --rm -i \
    --cap-add=SYS_PTRACE --security-opt=seccomp=unconfined \
    --ulimit core=-1 \
    -v "$host_dir":/work:ro \
    -v "$script":/tmp/cmds.gdb:ro \
    -w /work \
    "$IMAGE" \
    gdb --batch -x /tmp/cmds.gdb /work/"$name"
  local status=$?
  rm -f "$script"
  emit_json mode attach binary "$abs" exit "$status"
}

cmd_shell() {
  local dir="${1:-$PWD}"
  [[ ! -d "$dir" ]] && { emit_json mode shell status missing_dir; exit 3; }
  docker_ready || missing_docker_msg
  image_ready  || cmd_build
  docker run --rm -it \
    --cap-add=SYS_PTRACE --security-opt=seccomp=unconfined \
    -v "$(realpath "$dir")":/work \
    -w /work \
    "$IMAGE" bash
}

cmd_qemu_kernel() {
  local kernel="${1:-}" initrd="${2:-}"
  [[ -z "$kernel" || -z "$initrd" ]] && usage
  docker_ready || missing_docker_msg
  image_ready  || cmd_build
  local kd="$(dirname "$(realpath "$kernel")")"
  docker run --rm -it \
    -v "$kd":/work \
    -w /work \
    "$IMAGE" \
    qemu-system-x86_64 \
      -kernel "$(basename "$kernel")" \
      -initrd "$(basename "$initrd")" \
      -append "console=ttyS0 nokaslr quiet" \
      -nographic -m 256M -no-reboot
  emit_json mode qemu-kernel kernel "$kernel" initrd "$initrd"
}

case "${1:-}" in
  run)          shift; cmd_run "$@" ;;
  attach)       shift; cmd_attach "$@" ;;
  shell)        shift; cmd_shell "$@" ;;
  qemu-kernel)  shift; cmd_qemu_kernel "$@" ;;
  build)        shift; cmd_build "$@" ;;
  check)        cmd_check ;;
  ""|-h|--help) usage ;;
  *) echo "unknown mode: $1" >&2; usage ;;
esac
