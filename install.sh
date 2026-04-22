#!/usr/bin/env bash
# install.sh — symlink the repo's skills + memory into the active Claude Code config.
# Idempotent. Re-run after pulling updates.
set -u

REPO="$(cd "$(dirname "$0")" && pwd)"
SKILLS_DST="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
# Auto-detect the active Claude project memory dir. Override with CLAUDE_MEMORY_DIR if needed.
MEM_DST="${CLAUDE_MEMORY_DIR:-}"
if [[ -z "$MEM_DST" ]]; then
  # Pick the project dir that matches the user's home slug (default layout on Linux/WSL).
  slug="-$(echo "$HOME" | sed 's|^/||; s|/|-|g')"
  MEM_DST="$HOME/.claude/projects/$slug/memory"
fi

mkdir -p "$SKILLS_DST" "$MEM_DST"

link() {
  local src="$1" dst="$2"
  if [[ -L "$dst" ]]; then
    local cur; cur="$(readlink -f "$dst")"
    if [[ "$cur" == "$(readlink -f "$src")" ]]; then
      echo "  [ok] $(basename "$dst") already linked"
      return
    fi
    echo "  [!] $dst is a symlink to $cur — replacing"
    rm "$dst"
  elif [[ -e "$dst" ]]; then
    local bak="${dst}.backup.$(date +%s)"
    echo "  [!] $dst exists (not a symlink) — moving to $bak"
    mv "$dst" "$bak"
  fi
  ln -s "$src" "$dst"
  echo "  [+] linked $(basename "$dst") -> $src"
}

echo "[*] skills → $SKILLS_DST"
for d in "$REPO"/skills/ctf-*; do
  [[ -d "$d" ]] || continue
  link "$d" "$SKILLS_DST/$(basename "$d")"
done

echo
echo "[*] memory → $MEM_DST"
for f in "$REPO"/memory/*.md; do
  [[ -f "$f" ]] || continue
  link "$f" "$MEM_DST/$(basename "$f")"
done

echo
echo "[*] done."
echo "    To remove the symlinks later:"
echo "      find \"$SKILLS_DST\" -maxdepth 1 -type l -name 'ctf-*' -delete"
echo "      find \"$MEM_DST\" -maxdepth 1 -type l -delete"
