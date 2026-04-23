#!/usr/bin/env bash
# foreniq.sh <file> [--freq FREQ_HZ] [--mode POCSAG512|POCSAG1200|POCSAG2400|DTMF|SSTV]
# Forensics/signal pipeline: raw IQ → sox → multimon-ng; .sr → pulseview export.
set -u
F="${1:-}"
MODE="POCSAG1200"
FREQ="22050"
shift 1 || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --freq) FREQ="$2"; shift 2;;
    *) echo "[warn] unknown arg: $1" >&2; shift;;
  esac
done
[[ -z "$F" ]] && { echo "usage: $0 <file> [--mode POCSAG1200|DTMF|SSTV] [--freq 22050]" >&2; exit 2; }
[[ ! -f "$F" ]] && { echo "not a file: $F" >&2; exit 2; }

has() { command -v "$1" >/dev/null 2>&1; }
advise() { echo "[miss] $1 — install: $2" >&2; }
has sox         || advise sox         "apt install sox"
has multimon-ng || advise multimon-ng "apt install multimon-ng"
has pulseview   || advise pulseview   "apt install pulseview"
has sigrok-cli  || advise sigrok-cli  "apt install sigrok-cli"
has ffmpeg      || advise ffmpeg      "apt install ffmpeg"
has python3     || advise python3     "apt install python3"

EXT="${F##*.}"; EXT="${EXT,,}"
OUT="${F%.*}.out"

case "$EXT" in
  sr|srzip)
    if has sigrok-cli; then
      sigrok-cli -i "$F" -O csv > "${OUT}.csv"
      echo "[*] decoded logic-analyzer samples -> ${OUT}.csv"
      # Try common protocol decoders:
      for dec in uart i2c spi ir_nec onewire can; do
        sigrok-cli -i "$F" -P "$dec" 2>/dev/null | head -200 > "${OUT}.${dec}.txt"
        [[ -s "${OUT}.${dec}.txt" ]] && echo "[*] $dec decoded -> ${OUT}.${dec}.txt"
      done
    fi
    ;;
  cfile|iq|cu8|cs8|cs16|cf32)
    # Raw IQ data = paired (I, Q) complex samples. Collapsing to mono via
    # sox destroys phase → multimon never hits. Proper path is FM demod
    # (`csdr fmdemod_quadri_cf`) or magnitude envelope (`csdr amdemod_cf`)
    # BEFORE resampling to audio rate. We keep the sox path only as a
    # magnitude-envelope approximation (remix 1,2 sums I+Q instead of
    # dropping Q) and warn the user to use csdr/GNU Radio for real work.
    cat >&2 <<EOF
[foreniq] WARNING: raw IQ (.$EXT) needs a proper demod chain.
  Recommended (FM/NFM, 250 kHz IQ @ 1024000 sps):
    csdr convert_u8_f < "$F" | csdr fmdemod_quadri_cf | \\
    csdr dc_block_ff | csdr fractional_decimator_ff \$((1024000/22050)) | \\
    csdr convert_f_s16 | sox -t raw -r 22050 -c 1 -e signed-integer -b 16 - -t wav "${OUT}.wav"
  Then:  multimon-ng -a $MODE -f alpha -t wav "${OUT}.wav"

Falling back to sox magnitude-envelope approximation (often noisy):
EOF
    if has sox; then
      # heuristic: .cu8 is unsigned 8-bit, .cs16 signed 16-bit; others => float32
      # Use `remix -m 1,2` to sum I and Q channels → rough magnitude envelope
      # (better than dropping Q silently).
      case "$EXT" in
        cu8) sox -r "$FREQ" -c 2 -e unsigned-integer -b 8 -t raw "$F" -c 1 -t wav "${OUT}.wav" remix -m 1,2 2>/dev/null || true;;
        cs8) sox -r "$FREQ" -c 2 -e signed-integer -b 8 -t raw "$F" -c 1 -t wav "${OUT}.wav" remix -m 1,2 2>/dev/null || true;;
        cs16|iq) sox -r "$FREQ" -c 2 -e signed-integer -b 16 -t raw "$F" -c 1 -t wav "${OUT}.wav" remix -m 1,2 2>/dev/null || true;;
        cf32|cfile) sox -r "$FREQ" -c 2 -e floating-point -b 32 -t raw "$F" -c 1 -t wav "${OUT}.wav" remix -m 1,2 2>/dev/null || true;;
      esac
      if [[ -f "${OUT}.wav" && -s "${OUT}.wav" ]] && has multimon-ng; then
        multimon-ng -a "$MODE" -f alpha -t wav "${OUT}.wav" > "${OUT}.decoded.txt" 2>&1 || true
        echo "[*] multimon-ng($MODE) on envelope -> ${OUT}.decoded.txt"
      fi
    fi
    ;;
  wav|flac|ogg|mp3)
    WAV="$F"
    if [[ "$EXT" != "wav" ]] && has sox; then
      WAV="${OUT}.wav"
      sox "$F" -r "$FREQ" -c 1 "$WAV" 2>/dev/null || true
    fi
    if has multimon-ng; then
      for m in POCSAG512 POCSAG1200 POCSAG2400 DTMF AFSK1200 AFSK2400; do
        multimon-ng -a "$m" -f alpha -t wav "$WAV" > "${OUT}.${m}.txt" 2>&1 || true
        if grep -qE '[A-Za-z0-9]{3,}' "${OUT}.${m}.txt"; then
          echo "[hit] $m -> ${OUT}.${m}.txt"
        fi
      done
    fi
    ;;
  *)
    echo "[!] extension .$EXT not mapped. Try: .sr, .cfile, .iq, .cu8, .wav" >&2
    exit 3
    ;;
esac

# JSON summary
OUTS=$(ls "${OUT}."* 2>/dev/null | awk 'BEGIN{printf "["} NR>1{printf ","} {printf "\"%s\"", $0} END{printf "]"}')
[[ -z "$OUTS" ]] && OUTS="[]"
cat <<EOF
{
  "input": "$(realpath "$F")",
  "ext": "$EXT",
  "mode": "$MODE",
  "freq": $FREQ,
  "outputs": $OUTS,
  "pointer": "ctf-forensics/signals-and-hardware.md"
}
EOF
