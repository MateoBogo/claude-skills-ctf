---
name: Skill authoring — respect token budgets
description: Concrete token/line budgets and structure rules for Claude Code skills; learned 2026-04-22 after a too-heavy SKILL.md refactor
type: feedback
originSessionId: daf9c4c7-3d60-4a53-b955-e10096c45d3e
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

7. **Measuring before a release:** `wc -c SKILL.md` divided by 4 ≈ tokens. Target < 2k tokens per SKILL.md and < 300 chars per description. If over, attack in this order: (a) tighten description to mechanics-only, (b) collapse Additional Resources to 1-line-per-file, (c) extract inline code/cheatsheets to quickref.md.

8. **Additional Resources must be one line per file.** Format: `- [file.md](file.md) — <60-char purpose>`. Multi-paragraph descriptions here duplicate the PRI table (which already dispatches) and inflate SKILL.md by 34-51 %. Eliminate ruthlessly.

9. **Descriptions enumerate mechanics, not technique names.** Writing "House of Water / Tangerine / Apple 2 / Rust / Corrosion / …" costs 400 chars; "glibc heap (House-of-*, leakless, FSOP)" costs 50 and matches the same auto-invoke triggers. Lists of proper nouns are waste.

Reference snapshot: `project_ctf_skills_refresh_round2_2026-04-22.md` has the pre/post table of the initial round 2 refactor. After a round-3 optimization pass the numbers were:

| Budget bucket                         | Before initial | After round 2 | After round 3 |
|---------------------------------------|----------------|---------------|---------------|
| Descriptions (ALWAYS loaded)          | 1394 tok       | 1394 tok      | **608 tok**   |
| SKILL.md bodies (loaded on invoke)    | 48 000 tok     | 19 000 tok    | **11 763 tok**|
| Largest single SKILL.md               | 9 326 tok      | 2 782 tok     | **1 907 tok** |
| quickref.md (on-demand only, 10 skills) | n/a          | 29 500 tok    | 32 930 tok    |

Round-3 moves that produced the savings: tighten descriptions (-56 %), collapse Additional Resources to 1-line-per-file (-40 % of SKILL.md body), extract remaining inline content from ctf-app-system / ctf-malware / ctf-osint into their own quickref.md.
