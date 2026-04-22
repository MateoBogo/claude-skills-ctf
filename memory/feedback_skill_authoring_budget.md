---
name: Skill authoring — respect token budgets
description: Concrete token/line budgets and structure rules for Claude Code skills; learned 2026-04-22 after a too-heavy SKILL.md refactor
type: feedback
---
Keep skills cheap to load. SKILL.md auto-loads on every invocation — treat it as always-in-context.

**Why:** user flagged 2026-04-22 that bloating SKILL.md with inline code references ("Quick Reference" sections) nukes the LLM's working context. Research on docs.claude.com confirms: SKILL.md < 500 lines, description+when_to_use < 1536 chars, post-compaction budget is 5k tok/skill (25k total shared). We had ctf-pwn/SKILL.md at 9326 tokens — one dispatch burned 30k+ tokens in aggregate.

**How to apply:**

1. **SKILL.md is a dispatch table, not a manual.** Body must contain only:
   - `Additional Resources` — bullet list of support files with 1-line descriptions
   - `Pattern Recognition Index` — observable signal → technique + target file
   - A 1-line pointer to `quickref.md` for inline snippets
   Never embed code, payloads, or tables of commands in SKILL.md. Move them to `quickref.md` or to the specific support file.

2. **Support files < 500 lines.** Split along mechanic or era boundary (e.g. `advanced-exploits-2.md` 2024 era, `advanced-exploits-3.md` 2025-2026 era). When a support file grows past ~500 lines, spin off a `-N.md` sibling and update the SKILL.md Additional Resources bullet + PRI target rows.

3. **Descriptions are always loaded.** `description` + `when_to_use` together must stay under 1536 chars. Every word drives auto-invocation matching; prune redundant synonyms.

4. **Don't auto-load supporting files.** Supporting files load only when Claude reads them from SKILL.md links. Reference them with `See [foo.md](foo.md)` — never inline the content.

5. **quickref.md is the cheatsheet bucket.** Grep patterns, common payloads, one-liners, syntax reminders live there. It loads only when the agent explicitly needs a snippet after dispatch.

6. **New technique checklist:**
   - [ ] append a `## Trigger: …` section to the appropriate support file (era `-2/-3.md` preferred if base is > 400 lines)
   - [ ] add ONE row to the SKILL.md Pattern Recognition Index (observable signal → file#anchor)
   - [ ] if snippet is < 15 lines of code, put it in the section body; else link to quickref.md or a standalone helper script under the skill directory
   - [ ] never add to SKILL.md outside the PRI row

7. **Measuring before a release:** `wc -c SKILL.md` divided by 4 ≈ tokens. Target < 2.5k tokens per SKILL.md. If over, find a quickref to extract.

Reference snapshot: `project_ctf_skills_refresh_round2_2026-04-22.md` has the pre/post table of this refactor.
