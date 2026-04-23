#!/usr/bin/env bash
# review.sh — interactive merge loop for learn.py drafts.
#
# A draft is three files in drafts/: <ts>-<skill>-<mechanic>.md,
# <ts>-pri-row.txt, <ts>-memory.md. We walk them one triplet at a time,
# show the diff with the target section, and offer Y/n/e.
#   Y = accept (write into skill + append PRI row + add memory + commit)
#   n = skip (leave draft in place for next run)
#   d = drop (delete draft triplet, no merge)
#   e = edit (open $EDITOR, then re-prompt)
#
# Atomic commit per draft — iff the skills dir is a git repo. If not, we
# still merge, just without a commit; the mission says "commits atomic
# quand possible".
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRAFTS="$HERE/drafts"
SKILLS_ROOT="$(dirname "$HERE")"
MEMORY_DIR="${CLAUDE_MEMORY_DIR:-/home/ubuntu/.claude/projects/-home-ubuntu/memory}"
EDITOR="${EDITOR:-vi}"

[[ -d "$DRAFTS" ]] || { echo "no drafts/ dir at $DRAFTS"; exit 0; }

mapfile -t MECH_DRAFTS < <(ls -1 "$DRAFTS"/*-ctf-*.md 2>/dev/null | sort)
if [[ ${#MECH_DRAFTS[@]} -eq 0 ]]; then
  echo "[review] no pending drafts in $DRAFTS"
  exit 0
fi

echo "[review] ${#MECH_DRAFTS[@]} pending draft(s) in $DRAFTS"
echo

git_commit_if_repo() {
  local msg="$1"; shift
  # tolerate non-repo silently (mission: repo optional)
  git -C "$SKILLS_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 0
  git -C "$SKILLS_ROOT" add -- "$@" || return 0
  git -C "$SKILLS_ROOT" commit -m "$msg" >/dev/null 2>&1 || true
}

for mech_file in "${MECH_DRAFTS[@]}"; do
  base="$(basename "$mech_file" .md)"        # e.g. 20260422T123456-ctf-pwn-ret2libc or ctf-app-system-foo
  ts="$(echo "$base" | awk -F- '{print $1}')"
  # Find the longest matching skill dir under SKILLS_ROOT (handles ctf-app-system etc.)
  skill=""
  for cand in ctf-app-system ctf-automation ctf-crypto ctf-forensics ctf-malware \
              ctf-misc ctf-osint ctf-pwn ctf-reverse ctf-web; do
    if [[ "$base" == *"-${cand}-"* ]] && [[ -d "$SKILLS_ROOT/$cand" ]]; then
      skill="$cand"
      break
    fi
  done
  if [[ -z "$skill" ]]; then
    echo "[review] cannot parse skill from $base — skipping" >&2
    continue
  fi
  mechanic="$(echo "$base" | sed -E "s/^[^-]+-${skill}-(.*)$/\\1/")"
  pri_file="$DRAFTS/${ts}-pri-row.txt"
  mem_file="$DRAFTS/${ts}-memory.md"

  echo "───────────────────────────────────────────────"
  echo "DRAFT ts=$ts skill=$skill mechanic=$mechanic"
  echo "  mechanic: $mech_file"
  echo "  pri row : $pri_file"
  echo "  memory  : $mem_file"
  echo "───────────────────────────────────────────────"

  # Show a compact preview of each piece
  echo
  echo "── MECHANIC SECTION (first 30 lines) ──"
  sed -n '1,30p' "$mech_file"
  echo "── PRI ROW ──"
  cat "$pri_file"
  if [[ -f "$mem_file" ]]; then
    echo "── MEMORY ENTRY ──"
    sed -n '1,20p' "$mem_file"
  fi
  echo

  target_skill_md="$SKILLS_ROOT/$skill/SKILL.md"
  target_body="$SKILLS_ROOT/$skill/quickref.md"

  echo "Target: $target_skill_md (PRI row) + $target_body (section)"
  [[ ! -f "$target_skill_md" ]] && { echo "  [!] $target_skill_md does not exist"; }
  [[ ! -f "$target_body"   ]] && { echo "  [!] $target_body will be created"; }

  while true; do
    if [ -t 0 ]; then
      read -r -p "[y]es / [N]ext / [d]rop / [e]dit ? " ans </dev/tty
    else
      # non-interactive run must NOT auto-accept; bail out so no placeholder leaks into SKILL.md
      echo "[review] non-interactive stdin — refusing to auto-merge. Run under a TTY." >&2
      break
    fi
    ans="${ans:-n}"
    # reject merge if draft still carries placeholder tokens
    if [[ "$ans" =~ ^(y|yes)$ ]]; then
      if grep -qE '<TODO|<observable signal for' "$mech_file" "$pri_file" 2>/dev/null; then
        echo "[review] draft still contains <TODO> / <observable signal> placeholders — edit first." >&2
        ans="e"
      fi
    fi
    case "${ans,,}" in
      y)
        # 1) append mechanic section to quickref.md (create if missing)
        if [[ ! -f "$target_body" ]]; then
          echo "# ${skill} quickref" > "$target_body"
          echo "" >> "$target_body"
        fi
        # Strip the first H1 from mech_file — it's a draft banner — and append.
        {
          echo ""
          echo "<!-- merged from draft $base on $(date -u +%FT%TZ) -->"
          # everything below the first blank line after H1
          tail -n +2 "$mech_file"
        } >> "$target_body"
        # 2) append PRI row — drop the leading comment lines that start with #
        if [[ -f "$target_skill_md" ]]; then
          # Find the PRI heading; if absent, append one.
          if grep -q -E '^#+\s*Pattern Recognition Index' "$target_skill_md"; then
            # append to end (good enough — reviewer can re-order)
            pri_line="$(grep -v '^#' "$pri_file" | head -1)"
            [[ -n "$pri_line" ]] && {
              printf '\n%s\n' "$pri_line" >> "$target_skill_md"
            }
          else
            {
              echo ""
              echo "## Pattern Recognition Index"
              grep -v '^#' "$pri_file" | head -1
            } >> "$target_skill_md"
          fi
        fi
        # 3) copy memory entry (dedup by mechanic — drop the older file, keep latest)
        if [[ -f "$mem_file" ]]; then
          mkdir -p "$MEMORY_DIR"
          mem_name="feedback_lesson_${ts}_${mechanic}.md"
          # Remove any existing feedback_lesson_*_${mechanic}.md so mechanic stays unique.
          find "$MEMORY_DIR" -maxdepth 1 -name "feedback_lesson_*_${mechanic}.md" \
               ! -name "$mem_name" -delete 2>/dev/null || true
          cp "$mem_file" "$MEMORY_DIR/$mem_name"
          if [[ -f "$MEMORY_DIR/MEMORY.md" ]]; then
            # Drop any prior index line for this mechanic, then append.
            sed -i -E "/feedback_lesson_[0-9TZ]+_${mechanic}\.md/d" "$MEMORY_DIR/MEMORY.md"
            printf -- '- [Lesson %s (%s)](%s) — auto-captured via learn.py\n' \
              "$ts" "$mechanic" "$mem_name" >> "$MEMORY_DIR/MEMORY.md"
          fi
        fi
        # 4) atomic commit
        git_commit_if_repo "$skill: add $mechanic (from draft $base)" \
          "$target_body" "$target_skill_md"
        # 5) remove drafts
        rm -f "$mech_file" "$pri_file" "$mem_file"
        echo "[review] merged $base"
        break ;;
      n)
        echo "[review] skipped $base"
        break ;;
      d)
        rm -f "$mech_file" "$pri_file" "$mem_file"
        echo "[review] dropped $base"
        break ;;
      e)
        "$EDITOR" "$mech_file" "$pri_file" "$mem_file" </dev/tty >/dev/tty 2>&1 || true
        echo "[review] re-prompting after edit"
        continue ;;
      *)
        echo "answer Y / n / d / e" ;;
    esac
  done
  echo
done

echo "[review] done"
