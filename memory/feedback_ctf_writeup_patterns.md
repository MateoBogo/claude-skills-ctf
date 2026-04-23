---
name: CTF writeup-pattern shortcuts for 2024-2026 competitions
description: High-leverage pattern recognisers to try early on modern CTF challenges
type: feedback
originSessionId: 9d467641-4764-48fa-87e3-59464c21abb5
---
Cross-cutting patterns extracted from 404CTF / Root-Me / DEF CON / Google / PlaidCTF / SekaiCTF / HackTheAgent writeups (2024-2026). Try these *before* diving into category-specific deep dives.

**Why:** research pass on 2026-04-22 showed the same meta-patterns recurring across very different categories — recognising them early saves hours.

**How to apply:**
- **Two-parser differential.** Any time two libraries parse the same user input (URL, HTML, SQL, JSON, MIME), check they agree. Common victims: url-parse vs parse-url, nginx vs Express `%2F`, HAProxy vs backend, url-parse vs Node built-in `URL`.
- **Filter-sees-forward, model-sees-decoded.** For any "sanitiser" that runs before a transform (reverse, decode, translate, render), evade by sending the transformed form — reverse-order code, base64, emoji-encoded payloads, rot13, Unicode normalisation.
- **Constant-time padding doesn't fix shape.** Side-channel defences that equalise *duration* rarely equalise *waveform morphology*. When power/EM traces look uniform in length, look at shape features (min/max/mean sliding window, per-op clustering).
- **Signed→size_t confusion.** Any `int` length passed to a `size_t` API is a candidate. Upper-bound checks alone aren't enough; look for missing `len < 0` guards. Applies to C pwn *and* to Vyper/Solidity style unsigned conversions.
- **Ledger mismatch = bridge bug.** Whenever two systems record the same event (L1/L2 bridge, frontend/backend, two microservices), a bug frequently lives in their mismatch. Test what happens when the "amount" side matches but the "token" side doesn't, or vice versa.
- **Whitelist command ≠ whitelist argv.** Agents/scripts that approve a command but pass through arbitrary arguments are RCE-adjacent. Common weaponisation: `--exec`, `--config`, `--kubeconfig`, `--format`, `-o ProxyCommand`, `-exec sh`.
- **Policy conditionals are permissive by default.** Agent rules phrased as "if X, else Y" let attacker force the X→false branch. Look for ways to make the condition trivially false.
- **Reference & tool shortcuts:**
  - CVP/Babai for HNP-shaped problems: use `rkm0959/Inequality_Solving_with_CVP` as the template.
  - POCSAG decode: GQRX UDP → `sox` to 22050 Hz mono → `multimon-ng -a POCSAG512/1200/2400 -f alpha`.
  - Qiskit Grover iteration count: `k = floor(pi/4 * sqrt(N/M))` — never guess.
  - Agent-system-prompt exfil: third turn is more permissive than first; try after a refusal.
