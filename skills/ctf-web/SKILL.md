---
name: ctf-web
description: Provides web exploitation techniques for CTF challenges. Use when solving web security challenges involving XSS, SQLi, SSTI, SSRF, CSRF, XXE, file upload bypasses, JWT attacks, prototype pollution, path traversal, command injection, LaTeX injection, request smuggling, DOM clobbering, Web3/blockchain, authentication bypass, SAML exploitation, OAuth/OIDC, open redirect chains, subdomain takeover, or CI/CD credential theft.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
---

# CTF Web Exploitation

Quick reference for web CTF challenges. Each technique has a one-liner here; see supporting files for full details with payloads and code.

## Additional Resources

- [server-side.md](server-side.md) - Core server-side injection attacks: SQLi (including EXIF metadata injection, keyword fragmentation bypass, MySQL column truncation, DNS record injection), SSTI, SSRF (Host header, DNS rebinding), XXE, command injection, LaTeX injection RCE, code injection (Ruby/Perl/Python/Prolog), ReDoS, file upload→RCE, eval bypass, PHP type juggling, PHP file inclusion / php://filter, PHP extract() variable overwrite, PHP preg_replace /e RCE, SSTI `__dict__.update()` quote bypass, ERB SSTI Sequel bypass, Thymeleaf SpEL SSTI + Spring FileCopyUtils WAF bypass, XPath blind injection
- [server-side-deser.md](server-side-deser.md) - Deserialization and execution attacks: Java deserialization (ysoserial gadget chains, JNDI injection, blind detection), Python pickle RCE (`__reduce__`, restricted unpickler bypass, STOP opcode chaining), race conditions (TOCTOU async exploits, double-spend, coupon reuse)
- [server-side-advanced.md](server-side-advanced.md) - Advanced server-side techniques: ExifTool CVE-2021-22204, Go rune/byte mismatch, zip symlink traversal, path traversal bypasses (brace stripping, double URL encoding, os.path.join, %2f), Flask/Werkzeug debug mode, XXE external DTD filter bypass, WeasyPrint SSRF, MongoDB regex injection, Pongo2 Go template injection, ZIP PHP webshell, basename() bypass, React Server Components Flight RCE (CVE-2025-55182), SSRF→Docker API RCE chain, Castor XML xsi:type deserialization (Atlas HTB), Apache ErrorDocument expression file read (Zero HTB), SQLite file path traversal to bypass string equality
- [server-side-advanced-2.md](server-side-advanced-2.md) - 2025-2026 era server-side mechanics: JWT base64-strict-false smuggling + NFKD fold (hxp 38C3), Go shared `err` TOCTOU (hxp 38C3), Vite proto-pollution → `spawn_sync` RCE (SekaiCTF 2025), NFS file-handle forgery (hxp 38C3), JS `String.replace` single-match traversal (idekCTF 2025), HQL → H2 `CREATE ALIAS` → jshell JDWP (SekaiCTF 2025), WP `wp_ajax_nopriv_*` option-update privesc (HTB Uni 2025), ORM type-confusion + zipslip + worker poison (HTB Uni 2025), Firebird `ALTER DB DIFFERENCE FILE` → webshell (HTB Biz 2025), TAR/ELF polyglot upload-to-RCE (HTB Biz 2025), S3 presigned-URL path traversal (HTB Biz 2025)
- [client-side.md](client-side.md) - Client-side attacks: XSS, CSRF, CSPT, cache poisoning, DOM tricks, React input filling, hidden elements, XS-Leak timing oracle, GraphQL CSRF, Unicode case folding XSS bypass (long-s U+017F), CSS font glyph container query exfiltration, Hyperscript CDN CSP bypass, PBKDF2 prefix timing oracle, client-side HMAC bypass via leaked JS secret
- [auth-and-access.md](auth-and-access.md) - Auth/authz attacks: password inference, weak validation, client-side gates, NoSQL auth bypass, HAProxy/Express.js bypass, IDOR on WIP endpoints, HTTP TRACE method bypass, LLM/AI chatbot jailbreak, open redirect chains (OAuth token theft), subdomain takeover, Apache mod_status info disclosure + session forging
- [auth-and-access-2.md](auth-and-access-2.md) - 2025-2026 era auth/access: PHP `parse_url` vs `readfile` double-colon host divergence (Midnightflag 2025), Next.js Next-Action header + trustHostHeader SSRF chain (FCSC 2025), race on shared token Map between Node workers (HTB Uni 2025), Chrome extension DNR → CDP → Puppeteer config.js RCE (FCSC 2025)
- [auth-jwt.md](auth-jwt.md) - JWT/JWE token attacks: algorithm none, RS256→HS256 confusion, weak secret, unverified signature, JWK/JKU header injection, KID path traversal, balance replay, JWE forgery with exposed public key
- [auth-infra.md](auth-infra.md) - Infrastructure auth: OAuth/OIDC exploitation (redirect_uri bypass, token manipulation, state CSRF), CORS misconfiguration, git history credential leakage, CI/CD variable theft, identity provider API takeover (authentik/Keycloak), SAML SSO flow automation, Guacamole parameter extraction, login page poisoning, TeamCity REST API RCE
- [node-and-prototype.md](node-and-prototype.md) - Node.js: prototype pollution, VM sandbox escape, Happy-DOM chain, flatnest CVE, Lodash+Pug AST injection
- [web3.md](web3.md) - Blockchain/Web3: Solidity exploits, proxy patterns, ABI encoding tricks, transient storage clearing collision (0.8.28-0.8.33), Foundry tooling
- [cves.md](cves.md) - CVE-specific exploits: Next.js middleware bypass, curl credential leak, Uvicorn CRLF, urllib scheme bypass, ExifTool DjVu, broken auth, AAEncode/JJEncode, protocol multiplexing, React Server Components Flight RCE (CVE-2025-55182), Ruby-SAML XPath digest smuggling (CVE-2024-45409, Barrier HTB), PaperCut NG auth bypass + RCE (CVE-2023-27350, Bamboo HTB), Zabbix blind SQLi (CVE-2024-22120, Watcher HTB)

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
| L1/L2 bridge storing `(token, amount)` on deposit but minting a canonical asset on withdraw | Ledger state-desync → auth-and-access.md, web3.md |
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
| Solidity `private` state vars + live RPC URL | `eth_getStorageAt` slot enumeration → web3.md |
| Contract validates `extcodesize` once then `CALL`s stored addr + CREATE2 deploy allowed | SELFDESTRUCT+CREATE2 code-swap → web3.md |
| RPC exposes `txpool_content` / `eth_pendingTransactions` | Mempool snoop / front-run → web3.md |
| `nonReentrant` on one function, sibling shares storage without guard | Cross-function reentrancy → web3.md |

Recognize the **mechanic** first. Never dispatch on the challenge's name.

---

For inline code/cheatsheet quick references (grep patterns, one-liners, common payloads), see [quickref.md](quickref.md). The `Pattern Recognition Index` above is the dispatch table — always consult it first; load `quickref.md` only if you need a concrete snippet after dispatch.
