# Rust Binary Exploitation

Mechanics unique to `rustc`-compiled binaries. Triage on file fingerprint + presence of `.cargo`, `Cargo.toml`, or strings like `panicked at 'index out of bounds'`, `thread 'main' panicked`, or rustc symbols (`core::panicking::panic_bounds_check`, `_ZN4core3fmt3num50_`).

## Panic-Handler Stack Unwind Corruption (source: 2025 pwn.college / DiceCTF)

**Trigger:** binary catches panics (`std::panic::catch_unwind` or custom `#[panic_handler]`), then continues execution; heap or stack layout differs across the unwind.
**Signals:** panic messages thrown from a library the challenge loads (not from user code); panic is *recovered* and program continues; `personality` section present in readelf.
**Mechanic:** Rust unwinding traverses the stack via DWARF EH tables. If the unwinder's `Landing Pad` table is corruptible (e.g. via an OOB write the challenge exposes), re-aim it at attacker code. Even without EH table corruption, an `UnwindSafe` bound violation lets `Drop` impls run on objects whose invariants are broken — a corrupted `Vec` with `len > cap` causes arbitrary-length free during unwind. Primitive: write attacker bytes into `Vec::raw_parts`, force a panic in a sibling thread, observe `Drop::drop(self: &mut Vec)` calling `__rust_dealloc(ptr, wrong_size, align)` → heap corruption.

## `unsafe { transmute }` Lifetime Laundering

**Trigger:** code uses `mem::transmute` / `from_raw_parts` / `std::slice::from_raw_parts_mut` on user-derived pointers or lengths.
**Signals:** grep `transmute|from_raw_parts|slice::from_raw` — every hit is a bug candidate.
**Mechanic:** transmute doesn't change memory; it changes the compiler's type assumption. If attacker controls the length passed to `slice::from_raw_parts_mut(ptr, len)`, the resulting `&mut [u8]` has fake length → OOB R/W on any subsequent indexed access. Also: transmute between `&T` and `&mut T` via `*const T → *mut T` bypasses the borrow checker → double-mut-borrow undefined behaviour, which Rust expects to be impossible, so safe code downstream mis-optimises (e.g. LLVM hoists a load across a write because it thought the write couldn't happen).

## `Vec::set_len` / `Box::leak` Invariant Break

**Trigger:** unsafe path calls `v.set_len(n)` after `v.reserve(n)` but without writing all `n` elements; challenge then reads `v[i]`.
**Signals:** `reserve(…)` + `set_len(…)` pair without intervening `push`/`write`/`unsafe { write_unchecked }` loop of exactly `n` iterations.
**Mechanic:** `set_len` is `unsafe` precisely because it asserts initialised memory. If uninitialised, a `Vec<MyStruct>` read materialises garbage; worse, if `MyStruct` has a `Drop` impl, drop runs on garbage → arbitrary `vtable` jump (since dropping dispatches through `<dyn Trait>::drop`). Find a "garbage struct" whose fake vtable points at libc gadgets and win.

## Integer Conversion — `as` Truncation in Release Mode

**Trigger:** user-supplied `u64` cast via `as u32`/`as usize`; debug build panics on overflow, release build truncates silently.
**Signals:** `cargo run --release` behaves differently from `cargo run`; `as usize` on a subtraction result.
**Mechanic:** Rust `as` is truncation, not saturation. A common pattern: `let idx = (header.len - 16) as usize;` where `header.len: u32` and `header.len < 16` wraps to a massive u32 → huge `usize` → OOB. Works across platforms but 64-bit hosts give you the largest effective oracle.

## `async` Future State-Machine Confusion

**Trigger:** async function mixes `&mut self` borrow across an `.await` point with raw-pointer aliasing underneath.
**Signals:** `Pin<&mut Self>` projection + `unsafe impl Send`/`Sync` on a generator struct; challenge uses `tokio` or `smol`.
**Mechanic:** the compiler transforms async fn into a hand-woven state machine. A borrow held across `.await` but also captured into a `raw pointer` (via transmute or `ptr::addr_of_mut`) lets an attacker observe the same memory through two different "live" references when the future is resumed. Race with another task → TOCTOU inside the future's state.

## Rustc Symbol Demangling + Type Recovery

Rust symbols are mangled in two formats:
- **Legacy v0 (`_ZN4core...`)**: demangles via `c++filt` or `rustfilt`.
- **v1 (`_R...`)**: rustfilt only, or `llvm-cxxfilt --format=rust`.

`rustc --print sysroot` tells you the toolchain version; match `cargo about` or `cargo-audit` to infer crate versions from embedded strings. `strings` often leaks dependency paths: `~/.cargo/registry/src/index.crates.io-*/serde-1.0.204/…`.

## Reverse Engineering: Closures, Traits, Vtables

Closures compile to anonymous structs implementing `Fn/FnMut/FnOnce` traits. A closure capturing `&mut x` becomes `struct Closure { x: &mut X }` with an auto-derived `call(&mut self)`. Virtual-dispatch `dyn Trait` uses a `(*const data, *const vtable)` fat-pointer pair. Find the vtable: it's a symbol-named `_ZN...VT...` or a literal `[fn; N+3]` constant in `.rodata` where first three slots are `drop`, `size`, `align`.

## Tooling

- **rustfilt**: `cargo install rustfilt`; pipe binary symbols through it.
- **gdb-rust**: `cargo install gdb-rust-pretty-printer` for `Vec`/`HashMap` pretty-printing.
- **cargo-binutils**: `cargo install cargo-binutils` then `cargo objdump -- -d` with rust-aware annotation.
- **lldb** with `type category -e rust` for Rust type recognition.
- **r2 rust plugin**: `r2pm -ci rust` adds rustc-aware disasm.

## Pattern Recognition Index additions (add to ctf-pwn/SKILL.md)

| Signal | Technique → file |
|---|---|
| Rust panic caught + recovered with unsafe state between | Unwind-path `Drop` corruption → rust-pwn.md |
| `mem::transmute` / `slice::from_raw_parts_mut` on user-controlled len | Sliced-length OOB → rust-pwn.md |
| `Vec::reserve(n)` + `set_len(n)` without n writes | Uninitialised-drop vtable hijack → rust-pwn.md |
| `as u32` / `as usize` on subtraction result in release build | Truncation overflow → rust-pwn.md |
| `async fn` with `Pin<&mut Self>` across `.await` + raw-ptr aliasing | Future state-machine confusion → rust-pwn.md |

Reference: Ralf Jung's `unsafe` papers + 2025 RustConf exploit-dev talks.
