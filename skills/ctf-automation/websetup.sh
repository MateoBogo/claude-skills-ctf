#!/usr/bin/env bash
# websetup.sh <target-url-or-domain> [--fast]
# Chained recon: subfinder -> httpx -> katana -> ffuf -> nuclei. Merge to JSON.
set -u
TARGET="${1:-}"
FAST=false
[[ "${2:-}" == "--fast" ]] && FAST=true
[[ -z "$TARGET" ]] && { echo "usage: $0 <url-or-domain> [--fast]" >&2; exit 2; }

has() { command -v "$1" >/dev/null 2>&1; }
advise() { echo "[miss] $1 — install: $2" >&2; }

has subfinder || advise subfinder "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
has httpx     || advise httpx     "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
has katana    || advise katana    "go install github.com/projectdiscovery/katana/cmd/katana@latest"
has ffuf      || advise ffuf      "go install github.com/ffuf/ffuf/v2@latest"
has nuclei    || advise nuclei    "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
has jq        || advise jq        "apt install jq"

HOST="$(echo "$TARGET" | sed -E 's#https?://##; s#/.*##')"
STAMP=$(date +%s)
OUTDIR="/tmp/websetup-${HOST}-${STAMP}"
mkdir -p "$OUTDIR"

SUBS="$OUTDIR/subs.txt"
LIVE="$OUTDIR/live.json"
URLS="$OUTDIR/urls.txt"
FUZZ="$OUTDIR/ffuf.json"
NUC="$OUTDIR/nuclei.json"
MERGED="$OUTDIR/merged.json"

if has subfinder; then
  subfinder -d "$HOST" -silent -o "$SUBS" 2>/dev/null || echo "$HOST" > "$SUBS"
else
  echo "$HOST" > "$SUBS"
fi

if has httpx; then
  httpx -l "$SUBS" -silent -json -tech-detect -title -status-code -o "$LIVE" 2>/dev/null || true
else
  : > "$LIVE"
fi

if has katana && [[ -s "$LIVE" ]]; then
  # feed live URLs
  has jq && jq -r '.url // .input' "$LIVE" > "$OUTDIR/livehosts.txt" || echo "https://$HOST" > "$OUTDIR/livehosts.txt"
  DEPTH=2; $FAST && DEPTH=1
  katana -silent -d $DEPTH -jc -o "$URLS" -list "$OUTDIR/livehosts.txt" 2>/dev/null || true
else
  echo "https://$HOST" > "$URLS"
fi

if has ffuf && ! $FAST; then
  WL="/usr/share/wordlists/dirb/common.txt"
  [[ -f "$WL" ]] || WL="/usr/share/seclists/Discovery/Web-Content/common.txt"
  if [[ -f "$WL" ]]; then
    ffuf -u "https://$HOST/FUZZ" -w "$WL" -mc 200,204,301,302,307,401,403 -of json -o "$FUZZ" -s 2>/dev/null || true
  else
    echo "[miss] wordlist — apt install seclists" >&2
  fi
fi

if has nuclei; then
  TEMPLATES=""; $FAST && TEMPLATES="-t http/technologies -severity high,critical"
  nuclei -silent -u "https://$HOST" -jsonl -o "$NUC" $TEMPLATES 2>/dev/null || true
fi

# Merge — one jq -n call with --slurpfile / --rawfile so each source is
# loaded as a named JSON value. No stdin-juggling, no broken `inputs[]`.
if has jq; then
  SUBS_JSON="$OUTDIR/subs.json"
  URLS_JSON="$OUTDIR/urls.json"
  # text lists -> JSON arrays
  jq -R -s 'split("\n") | map(select(length > 0))' "$SUBS" > "$SUBS_JSON" 2>/dev/null || echo '[]' > "$SUBS_JSON"
  jq -R -s 'split("\n") | map(select(length > 0))' "$URLS" > "$URLS_JSON" 2>/dev/null || echo '[]' > "$URLS_JSON"
  # httpx emits one JSON obj per line -> slurp into array
  if [[ -s "$LIVE" ]]; then
    jq -s '.' "$LIVE" > "$OUTDIR/live.slurp.json" 2>/dev/null || echo '[]' > "$OUTDIR/live.slurp.json"
  else
    echo '[]' > "$OUTDIR/live.slurp.json"
  fi
  if [[ ! -s "$FUZZ" ]]; then echo '{}' > "$FUZZ"; fi
  if [[ ! -s "$NUC"  ]]; then echo '' > "$NUC"; fi

  jq -n --arg target "$TARGET" \
        --slurpfile subs "$SUBS_JSON" \
        --slurpfile live "$OUTDIR/live.slurp.json" \
        --slurpfile urls "$URLS_JSON" \
        --slurpfile ffuf "$FUZZ" \
        --rawfile   nuc  "$NUC" \
        '{target: $target,
          subs:   $subs[0],
          live:   $live[0],
          urls:   $urls[0],
          ffuf:   ($ffuf[0] // {}),
          nuclei: ($nuc | split("\n") | map(select(length > 0) | fromjson? // {}) )}' \
        > "$MERGED" 2>/dev/null || cat "$LIVE" > "$MERGED"
else
  echo "{\"target\":\"$TARGET\",\"outdir\":\"$OUTDIR\"}" > "$MERGED"
fi

echo "[*] outdir: $OUTDIR"
echo "[*] merged: $MERGED"
cat "$MERGED"
