# Browser / JIT Exploitation (V8, SpiderMonkey, JSC)

Mechanics-first index for JIT-engine challenges. Run `d8`/`js` shells, Turbofan IR inspection, and patch diffs against upstream are the unifying primitives.

## Triggering on the challenge

**Signals the target is JIT pwn (not random JS):**
- Binary is `d8` (V8), `js` (SpiderMonkey JSShell), or `jsc` (JSC).
- Challenge ships a **patch file** (`*.patch`, `*.diff`) modifying `turbofan`, `ionmonkey`, `b3`, or `dfg` sources — the diff IS the bug.
- Patched `v8/src/compiler/*-reducer.cc`, `typer.cc`, `representation-change.cc`, `simplified-lowering.cc`.
- README cites a CVE (`CVE-2024-4761`, `CVE-2024-5274`, `CVE-2025-6554`, etc.) — replay of a public bug.

## V8 Turbofan Type-Confusion

**Trigger:** patch adds a new typer rule (`Typer::Visitor::TypeFoo`) that returns too narrow a `Type::Range` or `Type::OtherNumber`; subsequent `CheckBounds` elision on array accesses lets the attacker OOB-read/-write the BackingStore.

**Workflow:**
1. `d8 --allow-natives-syntax` + a helper lib (`utils.js` from any CTF repo) providing `ftoi`, `itof`, `hex`, `addrof`, `fakeobj`.
2. Write a small function that the patched typer over-optimises:
   ```js
   function leak(idx) {
     let a = [1.1, 2.2, 3.3];  // PACKED_DOUBLE_ELEMENTS
     return a[idx];            // CheckBounds eliminated → OOB read
   }
   for (let i = 0; i < 0x10000; i++) leak(0);  // warm Turbofan
   %OptimizeFunctionOnNextCall(leak); leak(0);
   leak(<large>); // OOB
   ```
3. Build `addrof` / `fakeobj` primitives via corrupted map pointers (pre-V8 pointer-compression) or corrupted `length` (post-PC).
4. Overwrite a WASM instance's code-page pointer → shellcode (V8 allocates WASM code RWX on many configs; if not, use `Sandbox::CallbackTable` bypass).

**Key grep patterns on the patch:**
```
grep -nE 'Type::(Range|OtherNumber|MinusZero|Unsigned31)' patch.diff
grep -nE 'CheckBounds|kRemoveUnreachable|kRelaxedEquals' patch.diff
grep -nE 'kTypedArray|kJSArray|kBackingStore' patch.diff
```

## V8 Pointer-Compression Era (≥ 8.0)

**Mechanic change:** heap pointers are 32-bit offsets into an 8 GB "cage"; classic `addrof` using object-to-double confusion reads the compressed tagged word. `fakeobj` needs a **cage-relative** target — use uninitialised TypedArrays or crafted `PropertyCell`s. Upgrading an arbitrary 32-bit R/W inside the cage to native code exec requires an **escape gadget** (WASM code page, `JIT_Unprotect`, or sandbox bypass via `ExternalPointerTable`).

## V8 Sandbox Bypass (`v8_enable_sandbox = true`)

**Signals:** build flags include `v8_enable_sandbox`; challenge ship a `d8` with `--sandbox-testing`; attacker only has a cage-internal primitive.
**Mechanic:** corrupt an `ExternalPointer` tagged as `kEmbedderPointerTag` but redirected to a real target. Known bypasses:
- `TypedArray.buffer` rewritten to an external `ArrayBuffer` whose backing store is a V8 function pointer.
- `JSDataView` byteOffset overflow — skips bounds, reads cage-external.
- `WebAssembly.Instance.exports.fn.table` exploited via `WasmDispatchTable` corruption.

Reference: Samuel Groß's "V8 Heap Sandbox" whitepapers + Maddie Stone's 2025 Project-Zero writeups.

## SpiderMonkey IonMonkey Range Analysis Bugs

**Trigger:** patch touches `js/src/jit/RangeAnalysis.cpp` or `ValueNumbering.cpp`; added/removed `MDefinition::computeRange`.
**Signals:** patched `MUrsh`, `MMod`, `MAdd` ranges; `MToInt32` bound changes.
**Mechanic:** craft an arithmetic loop where the patched range claims a tighter bound than truth; Ion elides a bounds check on a typed array indexed by the mis-ranged value. Primitives follow: `addrof` via `ObjectElements`, `fakeobj` via fake `Shape`. Dev build: `./configure --enable-debug --disable-optimize --disable-jemalloc` then `gdb --args ./js jsshell-test.js`.

## JSC DFG / FTL OSR-Exit Bugs

**Trigger:** WebKit patch modifies `Source/JavaScriptCore/dfg/DFGSpeculativeJIT.cpp` or `ftl/FTLLowerDFGToB3.cpp`.
**Signals:** challenge uses `jsc` CLI; patch adds / removes `speculationCheck` or `jsValueToDouble` coercions.
**Mechanic:** arrange OSR-exit with a register that the exit-snapshot claims is `Int32` but runtime holds a `double` / `JSCell`. On exit, baseline sees a misinterpreted value and the interpreter hands it to a subsequent `GetByVal` → type confusion → primitives.

## Exploit-Dev Tooling

- **V8 diff reader:** `tools/turbolizer` (in-tree) shows the IR graph for each phase; compare pre/post-patch.
- **Heap poking:** `--no-enable-short-builtin-calls`, `--trace-opt`, `--print-opt-code`, `--allow-natives-syntax`.
- **Corruption readers:** `%DebugPrint(obj)` / `%SystemBreak()` / `readline()`.
- **SpiderMonkey:** `os.getenv`, `serialize()`/`deserialize()`, `js -f test.js` with `--fuzzing-safe`.
- **JSC:** `describe(o)`, `describeArray(a)`, `edenGC()`, `fullGC()` — trigger GC between steps.

## Pattern Recognition Index additions (add to ctf-pwn/SKILL.md)

| Signal | Technique → file |
|---|---|
| `d8` / `js` / `jsc` binary + `*.patch` file modifying JIT compiler sources | JIT type-confusion → browser-jit.md |
| V8 build with `v8_enable_sandbox=true`; primitive only inside cage | ExternalPointerTable bypass → browser-jit.md#v8-sandbox-bypass |
| Turbofan typer patch touching `Type::Range` / `Type::OtherNumber` | Range-analysis type confusion → browser-jit.md |
| IonMonkey `RangeAnalysis.cpp` diff | SpiderMonkey range bug → browser-jit.md |
| JSC `DFGSpeculativeJIT.cpp` / `FTLLowerDFGToB3.cpp` diff | OSR-exit misassumption → browser-jit.md |

References: [v8.dev/blog](https://v8.dev/blog), [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com), [trailofbits.com/blog](https://blog.trailofbits.com).
