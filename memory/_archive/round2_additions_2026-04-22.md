# Round-2 additions staging (2026-04-22)

Tracking file — records what's been appended to which ctf-* file. Do not delete; future audits reference it.

| Target file | Sections appended |
|---|---|
| ctf-pwn/advanced-exploits-2.md | vkfs coord-indexed FS overflow · MIPS `$gp`-pivot fake-GOT · FILE UAF + fstr bridge · cross-thread `alloca` stack smash · ObjC Isa-pointer UAF RCE · ARM64 PAC-key exfil via bounds-mismatch AAR · seccomp `cmp`-timing blind oracle · Traefik `X-Forwarded-*` → Flask pivot chain |
| ctf-pwn/advanced-exploits.md | HoS-via-C++-vtable (adjacent-size fudge + vmethod dispatch) |
| ctf-pwn/kernel-advanced.md | folly zero-copy page aliasing (vmsplice-gift → vm_insert_page TOCTOU) |
| ctf-pwn/sandbox-escape.md | io_uring `NO_MMAP` seccomp escape · SCM_RIGHTS fd smuggling across sandbox · coredump-race before in-memory wipe · eBPF FSM syscall-sequence gate |
| ctf-crypto/zkp-and-advanced.md | halo2 blinding-omission Lagrange recovery · LogUp/ProtoStar char-repetition bypass · Noir `sha256_var` trailing-byte under-constraint |
| ctf-crypto/ecc-attacks.md | genus-1 obfuscated variety → Weierstrass + hybrid BSGS/MOV/NFS · py_ecc Jacobian no-curve-check invalid-point |
| ctf-crypto/exotic-crypto.md | ePrint scheme killer linear-algebra patterns · CSIDH/group-action sign-leak oracle · Kzber/UOV post-quantum heuristics |
| ctf-crypto/rsa-attacks.md | Manger's attack (RSA-OAEP first-byte oracle) · structured-prime polynomial factorisation |
| ctf-crypto/modern-ciphers.md | Shamir t-of-n with roots-of-unity evaluation → FFT recovery · single-round AES linear inversion |
| ctf-crypto/advanced-math.md | Hill/printable-ASCII modulus off-by-one · MD5+SHA1 dual-suffix Joux multicollision cascade · GEA-1/2 LFSR rank-deficient key recovery · `dream_multiply` digit-concatenation Diophantine |
| ctf-crypto/prng.md | Legendre-symbol bit oracle → GF(p) state recovery |
| ctf-web/auth-and-access.md | PHP `parse_url()` vs `readfile()` double-colon host divergence · Next.js Next-Action header + trustHostHeader SSRF chain · race on shared token Map between Node workers · Chrome extension DNR→CDP→Puppeteer config.js RCE chain |
| ctf-web/server-side-advanced.md | JWT `base64_decode(strict=false)` request-smuggling + NFKD filename fold · Go handler shared package `err` TOCTOU · Vite dev-server proto-pollution → spawn_sync RCE · NFS handle forgery across exported subtree · JS `String.replace` single-match traversal · WordPress `wp_ajax_nopriv_*` update_option privilege escalation · ORM type-confusion `{$gt:0}` + zipslip + unhandled-promise worker-poison · Firebird `ALTER DATABASE ADD DIFFERENCE FILE` → webshell · TAR/ELF polyglot upload-to-RCE · S3 presigned-URL path traversal to private prefix |
| ctf-web/server-side-deser.md | HQLi → H2 `CREATE ALIAS` → jdk.jshell JDWP RCE chain |
| ctf-web/client-side.md | CSS `@starting-style`/attribute-selector parser-crash oracle · xs-leak via `performance.memory.usedJSHeapSize` heap delta |
| ctf-web/web3.md | Solidity `private` storage leak via `eth_getStorageAt` · SELFDESTRUCT+CREATE2 code-swap post-size-check · Ethereum `txpool_content` snoop/front-run · cross-function reentrancy (guarded vs unguarded pair) |
| ctf-reverse/patterns-ctf-2.md | `perf_event_open` instruction-count side-channel byte oracle · VM architecture misidentification (stack pretending register) + banned-byte synthesis |
| ctf-reverse/languages-compiled.md | `.pyc` PEP-552 magic-header forgery · Go interface/itab `GoReSym` vtable restore · eBPF kprobe FSM gated by syscall-sequence |
| ctf-reverse/tools-advanced.md | TTF GSUB ligature steganography (`ttx -t GSUB` DAG reverse) · AVX2 lane-wise Z3 lifting |
| ctf-misc/ai-ml.md | Agent file-read via unscoped `fetch_article(url)` tool (file:// scheme accepted) · Keras Lambda `marshal+base64` stego container + `safe_mode=False` RCE |
| ctf-misc/pyjails.md | `literal_eval` dict-for-list type confusion → WOTS/OTS signature index reuse |
| ctf-forensics/network-advanced.md | UA-gated C2 URL-path hex-XOR exfil |
| ctf-malware/scripts-and-obfuscation.md | VSCode `.vsix` `onStartupFinished` activation event → marshal/b64 child_process exfil |
| SKILL.md — pwn/crypto/web/reverse/forensics/misc/malware | Pattern Recognition Index rows added for the above |
| SKILL.md — app-system/malware/osint | NEW Pattern Recognition Index section created |
