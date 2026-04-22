#!/usr/bin/env bash
# triage.sh <challenge-dir> [--json]
# Fingerprint a CTF challenge folder and emit pointers into ctf-*/SKILL.md.
set -u
DIR="${1:-}"
JSON_ONLY=false
[[ "${2:-}" == "--json" ]] && JSON_ONLY=true
[[ -z "$DIR" ]] && { echo "usage: $0 <challenge-dir> [--json]" >&2; exit 2; }
[[ ! -d "$DIR" ]] && { echo "not a dir: $DIR" >&2; exit 2; }

has() { command -v "$1" >/dev/null 2>&1; }
need() { has "$1" || echo "[miss] $1 — install: $2" >&2; }

# Missing-tool advisories (non-fatal)
need file          "apt install file"
need checksec      "apt install checksec"
need readelf       "apt install binutils"
need rabin2        "apt install radare2"
need jq            "apt install jq"
need strings       "apt install binutils"
need pyelftools    "pip install pyelftools"

# ---- scan ----
ELF_LIST=()
PE_LIST=()
WASM_LIST=()
APK_LIST=()
PYC_LIST=()
PCAP_LIST=()
DISK_LIST=()
MEMDUMP_LIST=()
PEM_LIST=()
MODEL_LIST=()
QASM_LIST=()
CIRCOM_LIST=()
SOL_LIST=()
VYPER_LIST=()
PDF_LIST=()
AUDIO_LIST=()
IMG_LIST=()
SR_LIST=()
IQ_LIST=()
PACKAGE_JSON=false
REQUIREMENTS=false
GO_MOD=false
CARGO=false
PYPROJECT=false
FOUNDRY=false
HARDHAT=false
DOCKERFILE=false
COMPOSE=false
AI_HINTS=0
WEB_URLS=()
JWT_FILES=()
RAW_FLAG_HITS=0

shopt -s globstar nullglob nocaseglob

while IFS= read -r -d '' f; do
  b="$(basename "$f")"
  lb="${b,,}"
  case "$lb" in
    *.pcap|*.pcapng)   PCAP_LIST+=("$f");;
    *.dd|*.e01|*.img|*.vhd|*.vmdk|*.qcow2) DISK_LIST+=("$f");;
    *.raw|*.mem|*.vmem|*.dmp) MEMDUMP_LIST+=("$f");;
    *.apk|*.aab)       APK_LIST+=("$f");;
    *.wasm)            WASM_LIST+=("$f");;
    *.pyc)             PYC_LIST+=("$f");;
    *.pem|*.key|*.crt|*.pub|*.priv) PEM_LIST+=("$f");;
    *.h5|*.pt|*.pth|*.pkl|*.onnx|*.safetensors|*.weights) MODEL_LIST+=("$f");;
    *.qasm)            QASM_LIST+=("$f");;
    *.circom|*.r1cs|*.zkey|*.vkey) CIRCOM_LIST+=("$f");;
    *.sol)             SOL_LIST+=("$f");;
    *.vy)              VYPER_LIST+=("$f");;
    *.pdf)             PDF_LIST+=("$f");;
    *.wav|*.flac|*.ogg|*.mp3) AUDIO_LIST+=("$f");;
    *.png|*.jpg|*.jpeg|*.gif|*.bmp|*.tif|*.tiff) IMG_LIST+=("$f");;
    *.sr|*.srzip)      SR_LIST+=("$f");;
    *.cfile|*.iq|*.cu8|*.cs8|*.cs16|*.cf32) IQ_LIST+=("$f");;
    package.json)      PACKAGE_JSON=true;;
    requirements.txt|requirements-*.txt) REQUIREMENTS=true;;
    go.mod)            GO_MOD=true;;
    cargo.toml)        CARGO=true;;
    pyproject.toml)    PYPROJECT=true;;
    foundry.toml)      FOUNDRY=true;;
    hardhat.config.*)  HARDHAT=true;;
    dockerfile)        DOCKERFILE=true;;
    docker-compose*)   COMPOSE=true;;
  esac
  # Strings-based AI/LLM hints
  if [[ "$lb" =~ \.(py|js|ts|json|md|txt|html)$ ]]; then
    if grep -liE 'openai|anthropic|claude|chatgpt|langchain|llama|gemini|system.prompt|allow.?list.*tool' "$f" >/dev/null 2>&1; then
      AI_HINTS=$((AI_HINTS+1))
    fi
    while IFS= read -r url; do WEB_URLS+=("$url"); done < <(grep -oE 'https?://[A-Za-z0-9._:/?&=%+#-]+' "$f" 2>/dev/null | head -5)
    if grep -loE 'eyJ[A-Za-z0-9_-]{10,}\.eyJ' "$f" >/dev/null 2>&1; then JWT_FILES+=("$f"); fi
    if grep -lE '(CTF|flag|FLAG|HTB|picoCTF|ENO)\{' "$f" >/dev/null 2>&1; then RAW_FLAG_HITS=$((RAW_FLAG_HITS+1)); fi
  fi
done < <(find "$DIR" -maxdepth 4 -type f -print0 2>/dev/null)

# ELF / PE classification requires `file`
if has file; then
  while IFS= read -r -d '' f; do
    t="$(file -b "$f" 2>/dev/null)"
    case "$t" in
      ELF*)       ELF_LIST+=("$f");;
      PE32*|MS-DOS*executable*) PE_LIST+=("$f");;
    esac
  done < <(find "$DIR" -maxdepth 4 -type f -size +100c -print0 2>/dev/null)
fi

shopt -u nocaseglob

# ---- ELF fingerprinting ----
ELF_DETAILS=()
for e in "${ELF_LIST[@]}"; do
  cs=""
  if has checksec; then
    cs="$(checksec --file="$e" --output=json 2>/dev/null | head -1)"
  fi
  rp=""
  if has readelf; then
    rp="$(readelf -d "$e" 2>/dev/null | grep -E 'NEEDED|libc' | head -5 | tr -d '\n' | sed 's/"/\\"/g')"
  fi
  map_fixed=false; io_uring=false; userfaultfd=false; mprotect=false
  if has strings; then
    s="$(strings -a "$e" 2>/dev/null)"
    grep -q "MAP_FIXED" <<<"$s" && map_fixed=true
    grep -q "io_uring" <<<"$s" && io_uring=true
    grep -q "userfaultfd" <<<"$s" && userfaultfd=true
    grep -q "mprotect" <<<"$s" && mprotect=true
  fi
  ELF_DETAILS+=("{\"path\":\"$e\",\"checksec\":${cs:-null},\"needed\":\"${rp}\",\"map_fixed\":$map_fixed,\"io_uring\":$io_uring,\"userfaultfd\":$userfaultfd,\"mprotect\":$mprotect}")
done

# ---- hint generation (mechanics-first) ----
HINTS=()
add_hint() { HINTS+=("{\"signal\":\"$1\",\"pointer\":\"$2\"}"); }

[[ ${#ELF_LIST[@]} -gt 0 ]] && add_hint "ELF binary present" "ctf-pwn/SKILL.md#pattern-recognition-index"
[[ ${#PE_LIST[@]} -gt 0 ]] && add_hint "PE/Windows binary" "ctf-pwn/advanced-exploits-2.md (Windows sections) + ctf-reverse/platforms.md"
[[ ${#WASM_LIST[@]} -gt 0 ]] && add_hint "WASM module" "ctf-reverse/languages-compiled.md#wasm"
[[ ${#APK_LIST[@]} -gt 0 ]] && add_hint "APK (check for Flutter/Dart AOT)" "ctf-reverse/platforms.md + ctf-reverse/languages-compiled.md"
[[ ${#PYC_LIST[@]} -gt 0 ]] && add_hint "Python bytecode" "ctf-reverse/languages.md#pyc"
[[ ${#PCAP_LIST[@]} -gt 0 ]] && add_hint "PCAP capture" "ctf-forensics/network.md + network-advanced.md"
[[ ${#DISK_LIST[@]} -gt 0 ]] && add_hint "Disk image" "ctf-forensics/disk-and-memory.md"
[[ ${#MEMDUMP_LIST[@]} -gt 0 ]] && add_hint "Memory dump" "ctf-forensics/disk-and-memory.md (Volatility)"
[[ ${#PEM_LIST[@]} -gt 0 ]] && add_hint "PEM/key material" "ctf-crypto/SKILL.md#pattern-recognition-index"
[[ ${#MODEL_LIST[@]} -gt 0 ]] && add_hint "ML model weights present" "ctf-misc/ai-ml.md (federated poisoning / TATTOOED NN watermark)"
[[ ${#QASM_LIST[@]} -gt 0 ]] && add_hint "Qiskit / QASM file" "ctf-misc/ai-ml.md#quantum"
[[ ${#CIRCOM_LIST[@]} -gt 0 ]] && add_hint "Circom / ZK artefact (.r1cs/.zkey)" "ctf-crypto/zkp-and-advanced.md"
[[ ${#SOL_LIST[@]} -gt 0 ]] && add_hint "Solidity contract" "ctf-web/web3.md"
[[ ${#VYPER_LIST[@]} -gt 0 ]] && add_hint "Vyper contract (check @nonreentrant cross-function)" "ctf-web/auth-and-access.md#vyper-nonreentrant"
[[ ${#AUDIO_LIST[@]} -gt 0 ]] && add_hint "Audio file (DTMF / POCSAG / SSTV?)" "ctf-forensics/signals-and-hardware.md + ctf-misc/rf-sdr.md"
[[ ${#SR_LIST[@]} -gt 0 ]] && add_hint "sigrok .sr logic capture" "ctf-forensics/signals-and-hardware.md#pulseview"
[[ ${#IQ_LIST[@]} -gt 0 ]] && add_hint "Raw IQ capture (complex samples)" "ctf-forensics/signals-and-hardware.md#iq-fft"
[[ ${#IMG_LIST[@]} -gt 0 ]] && add_hint "Image(s) — candidate stego" "ctf-forensics/steganography.md + stego-advanced.md"
[[ ${#PDF_LIST[@]} -gt 0 ]] && add_hint "PDF present" "ctf-forensics/disk-and-memory.md#pdf"
[[ ${#JWT_FILES[@]} -gt 0 ]] && add_hint "JWT token found in source" "ctf-web/auth-jwt.md"

$PACKAGE_JSON && add_hint "package.json present — check two-parser URL diffs (url-parse vs parse-url vs URL)" "ctf-web/auth-and-access.md#two-parser-url-differential"
$REQUIREMENTS && add_hint "Python requirements — check pickle, yaml.load, eval" "ctf-web/server-side-deser.md"
$GO_MOD && add_hint "Go module — check reflect/unsafe, template.HTML" "ctf-web/server-side.md"
$CARGO && add_hint "Rust/Cargo — check unwrap() paths, unsafe blocks" "ctf-pwn/advanced-exploits.md + ctf-reverse/languages-compiled.md"
$FOUNDRY && add_hint "Foundry Web3 project" "ctf-web/web3.md (accounting desync, ERC4626, reentrancy)"
$HARDHAT && add_hint "Hardhat Web3 project" "ctf-web/web3.md"
$DOCKERFILE && add_hint "Dockerfile — check user/perms/COPY scope" "ctf-misc/linux-privesc.md"
$COMPOSE && add_hint "docker-compose multi-service — check inter-service trust" "ctf-web/auth-and-access.md"
[[ $AI_HINTS -gt 0 ]] && add_hint "LLM/agent references in source ($AI_HINTS files)" "ctf-misc/ai-ml.md"
[[ $RAW_FLAG_HITS -gt 0 ]] && add_hint "Flag-like strings in text (likely decoys)" "validate uniqueness — check solve-challenge SKILL.md flag rules"

for d in "${ELF_DETAILS[@]}"; do
  if grep -q '"map_fixed":true' <<<"$d"; then add_hint "ELF: MAP_FIXED exposed — MOP candidate" "ctf-pwn/advanced-exploits-2.md#mop"; fi
  if grep -q '"io_uring":true' <<<"$d"; then add_hint "ELF: io_uring present — worker abuse / SQE injection" "ctf-pwn/kernel-advanced.md"; fi
  if grep -q '"userfaultfd":true' <<<"$d"; then add_hint "ELF: userfaultfd — race stabilization" "ctf-pwn/kernel-techniques.md"; fi
done

# ---- JSON assembly ----
join_json() {
  local IFS=,
  local arr=("$@")
  echo "[${arr[*]}]"
}
esc_list() { for s in "$@"; do printf '"%s"\n' "$(sed 's/"/\\"/g' <<<"$s")"; done | paste -sd, -; }

JSON="$(cat <<EOF
{
  "dir": "$DIR",
  "counts": {
    "elf": ${#ELF_LIST[@]},
    "pe":  ${#PE_LIST[@]},
    "wasm": ${#WASM_LIST[@]},
    "apk": ${#APK_LIST[@]},
    "pyc": ${#PYC_LIST[@]},
    "pcap": ${#PCAP_LIST[@]},
    "disk": ${#DISK_LIST[@]},
    "memdump": ${#MEMDUMP_LIST[@]},
    "pem": ${#PEM_LIST[@]},
    "model": ${#MODEL_LIST[@]},
    "qasm": ${#QASM_LIST[@]},
    "circom": ${#CIRCOM_LIST[@]},
    "solidity": ${#SOL_LIST[@]},
    "vyper": ${#VYPER_LIST[@]},
    "audio": ${#AUDIO_LIST[@]},
    "image": ${#IMG_LIST[@]},
    "sigrok_sr": ${#SR_LIST[@]},
    "iq_raw": ${#IQ_LIST[@]},
    "pdf": ${#PDF_LIST[@]}
  },
  "manifests": {
    "package_json": $PACKAGE_JSON,
    "requirements_txt": $REQUIREMENTS,
    "go_mod": $GO_MOD,
    "cargo_toml": $CARGO,
    "pyproject_toml": $PYPROJECT,
    "foundry_toml": $FOUNDRY,
    "hardhat_config": $HARDHAT,
    "dockerfile": $DOCKERFILE,
    "docker_compose": $COMPOSE
  },
  "ai_hints": $AI_HINTS,
  "web_urls": [$(esc_list "${WEB_URLS[@]:-}")],
  "elf_details": $(join_json "${ELF_DETAILS[@]:-}"),
  "hints": $(join_json "${HINTS[@]:-}")
}
EOF
)"

OUTJSON="$DIR/.ctf-triage.json"
OUTMD="$DIR/.ctf-triage.md"
echo "$JSON" | { has jq && jq . || cat; } > "$OUTJSON"

# Markdown report
{
  echo "# CTF triage — $(basename "$DIR")"
  echo
  echo "Generated $(date -u +%FT%TZ). Scanned \`$DIR\`."
  echo
  echo "## File counts"
  echo '```json'
  has jq && jq '.counts' "$OUTJSON" || grep -A 20 '"counts"' "$OUTJSON"
  echo '```'
  echo
  echo "## Dispatch pointers (mechanics → Pattern Recognition Index)"
  echo
  if [[ ${#HINTS[@]} -eq 0 ]]; then
    echo "_no artefacts recognised — likely pure text / README. Read the prompt._"
  else
    for h in "${HINTS[@]}"; do
      sig="$(sed -n 's/.*"signal":"\([^"]*\)".*/\1/p' <<<"$h")"
      ptr="$(sed -n 's/.*"pointer":"\([^"]*\)".*/\1/p' <<<"$h")"
      echo "- **$sig** → \`$ptr\`"
    done
  fi
  echo
  echo "## Next steps"
  echo
  [[ ${#ELF_LIST[@]} -gt 0 ]] && echo "- \`bash pwnsetup.sh \"${ELF_LIST[0]}\"\`"
  [[ ${#PEM_LIST[@]} -gt 0 || ${#CIRCOM_LIST[@]} -gt 0 ]] && echo "- \`python3 cryptosetup.py \"$DIR\"\`"
  [[ ${#WEB_URLS[@]} -gt 0 ]] && echo "- \`bash websetup.sh \"${WEB_URLS[0]}\"\`"
  [[ ${#SR_LIST[@]} -gt 0 || ${#IQ_LIST[@]} -gt 0 || ${#AUDIO_LIST[@]} -gt 0 ]] && echo "- \`bash foreniq.sh <file>\`"
  [[ $AI_HINTS -gt 0 ]] && echo "- \`python3 aiprobe.py <endpoint-url>\`"
} > "$OUTMD"

if $JSON_ONLY; then
  cat "$OUTJSON"
else
  cat "$OUTMD"
  echo
  echo "[triage] JSON: $OUTJSON"
  echo "[triage] MD:   $OUTMD"
fi

[[ ${#HINTS[@]} -eq 0 ]] && exit 3 || exit 0
