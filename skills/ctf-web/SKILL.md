---
name: ctf-web
description: Web exploitation: SQLi, XSS, SSTI, SSRF, CSRF, XXE, JWT, OAuth/OIDC, SAML, prototype pollution, file-upload/path-traversal, HTTP smuggling, cache poisoning, Web3/Solidity, auth/parser differentials. Dispatch on manifest + framework signals.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Web Exploitation

Quick reference for web CTF challenges. Each technique has a one-liner here; see supporting files for full details with payloads and code.

## Additional Resources

- [server-side.md](server-side.md) — SQLi, SSTI, SSRF, XXE, cmdinj, file-upload, PHP tricks, Thymeleaf/ERB/Jinja
- [server-side-2.md](server-side-2.md) — 2024-26: Jinja2 __dict__ quote bypass, Thymeleaf SpEL + FileCopyUtils WAF
- [server-side-deser.md](server-side-deser.md) — Java ysoserial, Python pickle, race conditions (TOCTOU, double-spend)
- [server-side-advanced.md](server-side-advanced.md) — ExifTool CVE, zip symlink, path bypass, Flask debug, Castor XML, React Flight
- [server-side-advanced-2.md](server-side-advanced-2.md) — 2025-2026: JWT-strict=false, Go err TOCTOU, Vite RCE, NFS, HQL→jshell, Firebird, polyglot
- [client-side.md](client-side.md) — XSS, CSRF, CSPT, cache-poisoning, DOM, xs-leaks, PBKDF2 timing
- [client-side-2.md](client-side-2.md) — 2025-26: Math.random-salt same-origin iframe collision (content-sandbox escape)
- [auth-and-access.md](auth-and-access.md) — NoSQL bypass, parser diffs, IDOR, LLM jailbreak, subdomain takeover
- [auth-and-access-2.md](auth-and-access-2.md) — 2025-2026: PHP parse_url, Next.js Next-Action SSRF, token-Map race, DNR→CDP chain
- [auth-jwt.md](auth-jwt.md) — JWT alg none, RS256→HS256, JWK/JKU, KID traversal, JWE forgery
- [auth-infra.md](auth-infra.md) — OAuth/OIDC, CORS, CI/CD theft, SAML, TeamCity RCE, git history leaks
- [node-and-prototype.md](node-and-prototype.md) — prototype pollution, VM escape, Happy-DOM, flatnest
- [web3.md](web3.md) — Solidity, proxies, ABI tricks, Foundry, transient-storage collision
- [cves.md](cves.md) — Next.js middleware, urllib scheme, ExifTool DjVu, Ruby-SAML XPath, PaperCut
---

## Pattern Recognition Index

Dispatch on **observed signals**, not challenge titles.

| Signal in the target | Technique → file |
|---|---|
| `package.json` has *two* URL parsers (e.g. `url-parse` + `parse-url`, Node built-in + custom) and an allow-list check | Two-parser URL differential → auth-and-access.md |
| Node gateway in front of backend + `app.all("/strict/path", ...)` + nginx/Varnish proxy | `%2F` middleware bypass OR hop-by-hop header strip → auth-and-access.md |
| Flask/Django behind a reverse proxy reading `X-Real-IP`/`X-Forwarded-For` without proxy-identity check | Hop-by-hop header smuggling → auth-and-access.md |
| Node `mysql`/`mysql2` + `.query(q, req.body)` without explicit `String()` coercion | Operator-object injection + `__proto__` pollution → auth-and-access.md |
| Custom HTML sanitizer using `createNodeIterator`/`TreeWalker` then `innerHTML` | Declarative Shadow DOM bypass (`<template shadowrootmode>`) → auth-and-access.md |
| Vyper `< 0.3.x` with `@nonreentrant("lock")` on multiple funcs sharing storage, external call hook on path | Cross-function lock scope bug → auth-and-access.md |
| L1/L2 bridge storing `(token, amount)` on deposit but minting a canonical asset on withdraw | Ledger state-desync → auth-and-access-2.md, web3.md |
| Object in `req.body` treated as password or filter criterion (`{"$gt":""}`, `{"$ne":null}`) | NoSQL auth bypass → auth-and-access.md |
| Template rendering user input in Jinja2 / Twig / Freemarker / ERB | SSTI → server-side.md |
| `jwt.decode` without `verify=True`, or RS256 keys reachable at `/pubkey.pem` | RS256 → HS256 confusion → auth-jwt.md |
| URL contains `redirect_uri=` and app is OAuth/OIDC | redirect_uri bypass / open redirect → auth-infra.md |
| Uploads path + `<?php` or `.phar` accepted / magic-bytes-only check | File upload RCE → server-side.md |
| File fetch with user URL, internal services in scope | SSRF (11 IP bypass techniques) → server-side.md |
| 2 HTTP frontends (Cloudflare+nginx, HAProxy+Apache) with mismatched parsing | HTTP request smuggling → server-side.md, auth-infra.md |
| `libxml2` XML parsing with user entities / external DOCTYPE | XXE → server-side.md |
| Prototype pollution sink (`_.merge`, `Object.assign`, `req.body.__proto__`) | Prototype pollution chain → node-and-prototype.md |
| `parse_url($u)['host']` deny-list + subsequent `readfile($u)` (PHP) | Double-colon host divergence → auth-and-access-2.md |
| Next.js 14+ with `"use server"` + `trustHostHeader: true` in config | Next-Action forgery + host SSRF chain → auth-and-access-2.md |
| Shared `tokens` Map/object assigned in login, read in middleware pre-auth | Race on shared token map → auth-and-access-2.md |
| Extension `manifest.json` with `declarativeNetRequest` + `innerHTML` DOM sink | DNR→CDP→Puppeteer chain → auth-and-access-2.md |
| Traefik ≤ 2.11.13 reverse-proxy in front of app routes | `X-Forwarded-Prefix` admin reach + polyglot → auth-and-access-2.md, ctf-pwn/advanced-exploits-3.md |
| PHP JWT lib calling `base64_decode($sig, false)` (strict=false) | Smuggle CR/LF via JWT sig + NFKD fold → server-side-advanced-2.md |
| Package-level `var err error` + handler assigns `err = …` | Go shared `err` TOCTOU race → server-side-advanced-2.md |
| Vite dev server exposed + internal `object.merge` | Proto-pollution → `spawn_sync` RCE → server-side-advanced-2.md |
| `/etc/exports` without `subtree_check` directive | NFS handle forgery → server-side-advanced-2.md |
| `String(path).replace('/static/','uploads/')` (string not regex) | Single-match traversal → server-side-advanced-2.md |
| Hibernate HQL concat + H2 on classpath + `jshell` module | HQL → CREATE ALIAS → JDWP RCE → server-side-advanced-2.md, server-side-deser.md |
| `wp_ajax_nopriv_*` handler calling `update_option($_POST['k'], …)` | WP option-update privesc → server-side-advanced-2.md |
| Node ORM query with `req.body.id` uncoerced + zip upload + unhandled promise | `{$gt:0}` + zipslip + worker poison → server-side-advanced-2.md |
| Firebird banner on TCP 3050 + IIS on same host | `ALTER DATABASE DIFFERENCE FILE` webshell → server-side-advanced-2.md |
| Upload accepts TAR + exec endpoint referencing uploaded filename | TAR/ELF polyglot traversal → server-side-advanced-2.md |
| API returns presigned S3 URL + bucket allows ListBucket | Path traversal in presign parameter → server-side-advanced-2.md |
| Chromium ≥ 123 target + CSP allows inline style + admin bot iframe | CSS `@starting-style`/slow-selector crash oracle → client-side.md |
| Admin bot + cross-origin iframe + Chromium | xs-leak via `performance.memory` delta → client-side.md |
| Content-sandbox iframe where per-item origin derives from `Math.random().toString(36)` + parent posts `{body, salt}` | Salt-prediction chain → same-origin XSS → client-side-2.md |
| Solidity `private` state vars + live RPC URL | `eth_getStorageAt` slot enumeration → web3.md |
| Contract validates `extcodesize` once then `CALL`s stored addr + CREATE2 deploy allowed | SELFDESTRUCT+CREATE2 code-swap → web3.md |
| RPC exposes `txpool_content` / `eth_pendingTransactions` | Mempool snoop / front-run → web3.md |
| `nonReentrant` on one function, sibling shares storage without guard | Cross-function reentrancy → web3.md |
| `foundry.toml` + `test/` with `invariant_*()` / `statefulFuzz_*()` / `StdInvariant` import | Foundry invariant fuzzing → web3.md#foundry-invariant |
| Solidity contract with bounded loops + assertable invariant + Halmos installable | Halmos symbolic check → web3.md#halmos |
| Two contracts with identical external interface (`FooV1.sol` / `FooV2.sol`, `Safe.sol` / `Optimized.sol`) | Differential fuzzing → web3.md#differential-fuzzing |

Recognize the **mechanic** first. Never dispatch on the challenge's name.

---

For inline code/cheatsheet quick references (grep patterns, one-liners, common payloads), see [quickref.md](quickref.md). The `Pattern Recognition Index` above is the dispatch table — always consult it first; load `quickref.md` only if you need a concrete snippet after dispatch.
