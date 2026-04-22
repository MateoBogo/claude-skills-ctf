---
name: Skills must trigger on mechanics, not titles or keywords
description: Core principle for how CTF skills and other pattern-based skills should be designed and invoked
type: feedback
---
Skills must be triggered by recognition of **mechanics / signals / patterns**, not by challenge titles, CTF names, or keyword matches.

**Why:** User pointed out 2026-04-22 that many additions to the ctf-* library are titled after the challenge that first exhibited the pattern (e.g. "Root-Me Proxifier", "404CTF Nanocombattants"). That framing only helps when someone already names the source challenge — useless when confronting a brand-new problem that exhibits the same mechanics. The research pass created titles like this en masse; needs to be corrected.

**How to apply:**

1. **Every technique section must lead with observable signals**, not the challenge name. Put "Pattern:", "Signals:", or "Spot this when:" blocks before the exploit code. Observable signals include:
   - Files present (e.g. `.weights.h5`, `package.json` with two URL libs)
   - API surface (e.g. `app.all("/path")` Express + nginx front)
   - Binary artefacts (e.g. comparator op-amps + resistor ladder; `mmap()` with `MAP_FIXED` exposed)
   - Behaviours (e.g. `pow(m, e, n) == m` — fixed point)
   - Version strings / library combinations (e.g. Vyper < 0.3, glibc 2.39+)

2. **Section headers should lead with the mechanic**, with the CTF name as a parenthetical source. Bad: `## Proxifier URL Bypass`. Good: `## Two-Parser URL Differential (source: Root-Me Proxifier)`.

3. **Skill `description` frontmatter must enumerate mechanics, not CTF names** — these descriptions drive automatic skill-loading, so any mention of "Root-Me" or "404CTF" wastes tokens. Instead: "URL parser differential", "federated learning label-flip", "RSA fixed-point factoring".

4. **Every SKILL.md should have a Pattern Recognition Index** mapping symptoms → location. Example:
   ```
   - Two URL parsers in deps / URL in allow-list but file:// hint → auth-and-access.md#two-parser
   - `@nonreentrant("lock")` on >= 2 Vyper functions sharing storage → auth-and-access.md#vyper-nonreentrant
   ```
   This index is how an agent that *doesn't know the CTF name* finds the right technique.

5. **When using a skill, dispatch on what's observed** in the challenge files / source / binary — not on what the challenge is called. If the challenge title sounds inspiring, ignore it; read the code.

6. **Writing future skill entries**: lead every entry with a 1-line "Trigger:" describing the observable. If you cannot write that trigger line, the section is not useful — it will never fire.

Reference: `project_ctf_skills_refresh_2026-04.md` lists the files enriched on 2026-04-22 that should be audited against this rule over time.
