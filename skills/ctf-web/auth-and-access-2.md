# Auth & Access — Part 2 (2025-2026)

Spin-off of `auth-and-access.md` grouping 2025-2026 mechanics (Midnightflag 2025, FCSC 2025, HTB University 2025). Keep pre-2025 auth-bypass patterns in `auth-and-access.md`; new ones land here.


## PHP `parse_url()` vs `readfile()` Host Divergence on Double-Colon (source: Midnightflag 2025)

**Trigger:** PHP SSRF filter using `parse_url($u)['host']` to deny `localhost`/`127.0.0.1`, followed by `readfile($u)` or `file_get_contents($u)`.
**Signals:** `parse_url(...)['host']` in deny-list logic; subsequent fetch of the same `$u`.
**Mechanic:** `http://localhost:8080:/flag.php` — the second `:` confuses `parse_url` into returning `null` or a mangled host (bypassing the deny check), while the PHP URL-wrapper in `readfile` parses the first `:8080` as port and routes to `localhost` anyway. Filter-decode split. Other divergences: trailing `.` (`localhost.`), uppercase host (`LOCALHOST`), IPv6 brackets.

## Next.js Next-Action Header Forgery + trustHostHeader SSRF (source: FCSC 2025 Under Nextruction)

**Trigger:** Next.js 14+ app with React Server Actions (POST with `Next-Action: <hash>` header); `next.config.js` has `trustHostHeader: true`; middleware that reflects headers to responses via `NextResponse.next()`.
**Signals:** `"use server"` directive; `Next-Action` hash in `.next/server/` manifest; `trustHostHeader: true` in config.
**Mechanic:** (1) compute the action-id hash of a hidden server-action (e.g. internal `register()`) from the build manifest and POST with forged `Next-Action` to invoke it without UI exposure → (2) host-header SSRF via `trustHostHeader` triggers outbound revalidate carrying `x-prerender-revalidate` to attacker → (3) re-inject via middleware copy-all to smuggle `Location` into the internal flag service. Combines auth-bypass + SSRF + header-smuggling in one chain.
Source: [vozec.fr/writeups/under-construction-fcsc-2025](https://vozec.fr/writeups/under-construction-fcsc-2025/).

## Shared-Token-Map Race Between Node Workers (source: HTB University 2025 DeadRoute)

**Trigger:** Express/Koa middleware assigns `req.user = tokens[req.body.id]` *before* the auth check; token store is a shared `Map` or in-memory DB reused across requests.
**Signals:** `tokens.set(id, user)` in a login path, `tokens.get(id)` in middleware, no per-request scope, many workers/threads.
**Mechanic:** concurrent bursts to login (as normal user) + `/admin` endpoint — one worker reads the admin entry populated by a parallel admin-login, captures the token, replays against `/download?file=../../flag`. Distinct from TOCTOU file races: the race is on an in-process Map shared between requests. Trigger with `wrk -c 20 -d 10s`.

## Chrome Extension DNR + CDP + Puppeteer config.js RCE (source: FCSC 2025 DOM Monitor)

**Trigger:** browser extension with `declarativeNetRequest` permission; sidepanel/devtools page handling `MessageEvent` with origin-check only; bot driven via Puppeteer; Chromium `--remote-debugging-port` on localhost; `innerHTML` DOM sink.
**Signals:** `manifest.json` with `"declarativeNetRequest"` + `"host_permissions": ["<all_urls>"]`; `postMessage` handler that trusts `event.source.location.origin`.
**Mechanic:** (1) spoof origin of `MessageEvent` via nested iframe to open sidepanel → (2) `innerHTML` sink enables DOM-clobber of extension globals → (3) manipulate DNR rules to add `Access-Control-Allow-Origin: *` and strip `Origin` on WS upgrade to `127.0.0.1:<dbg-port>` → (4) via CDP call `Page.setDownloadBehavior({downloadPath: "/tmp/.config/puppeteer/"})` → (5) next Puppeteer spawn auto-`require`s `config.js` from that path → RCE inside the bot. End-to-end 5-primitive browser-extension chain.
Source: [worty.fr/post/writeups/fcsc2025/dom-monitor](https://worty.fr/post/writeups/fcsc2025/dom-monitor/).
