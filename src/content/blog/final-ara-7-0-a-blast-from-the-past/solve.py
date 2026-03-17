#!/usr/bin/env python3
"""
Solver for the ARA7 reverse challenge "chimera.exe".

Approach:
1) Recover input #1 from hidden DOS TEA block.
2) Recover input #2 from hidden DOS xorshift stream logic.
3) Recover input #3 from PE-side XORed hint string.
4) Feed all 3 inputs to chimera.exe (via wine) to generate runme.com.
5) Decode flag from runme.com.
"""

from __future__ import annotations

import argparse
import os
import struct
import subprocess
from pathlib import Path


PART3_ENC = b'/***G.G0()#"5G0/"5"G7&534GVG&)#GUG.4III'


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def extract_dos_load_module(pe: bytes) -> bytes:
    cblp = u16(pe, 0x02)
    cp = u16(pe, 0x04)
    cparhdr = u16(pe, 0x08)
    if cblp == 0:
        cblp = 512
    file_size_dos = (cp - 1) * 512 + cblp
    header_size = cparhdr * 16
    return pe[header_size:file_size_dos]


def tea_decrypt_block(v0: int, v1: int, key_words: tuple[int, int, int, int]) -> tuple[int, int]:
    delta = 0x9E3779B9
    total = (delta * 32) & 0xFFFFFFFF
    k0, k1, k2, k3 = key_words
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + total) ^ ((v0 >> 5) + k3))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + total) ^ ((v1 >> 5) + k1))) & 0xFFFFFFFF
        total = (total - delta) & 0xFFFFFFFF
    return v0, v1


def recover_part1(load_module: bytes) -> str:
    key = load_module[0x24A:0x25A]
    ct = load_module[0x25A:0x262]
    k = struct.unpack("<4I", key)
    v0, v1 = struct.unpack("<2I", ct)
    p0, p1 = tea_decrypt_block(v0, v1, k)
    return struct.pack("<2I", p0, p1).decode("ascii")


def xorshift16_step(x: int) -> int:
    x &= 0xFFFF
    x ^= (x << 7) & 0xFFFF
    x ^= x >> 9
    x ^= (x << 8) & 0xFFFF
    return x & 0xFFFF


def recover_part2(load_module: bytes) -> str:
    lm = bytearray(load_module)
    stage_off = 0x270
    stage_len = 0x1AB
    for i in range(stage_off, stage_off + stage_len):
        lm[i] ^= 0xAB

    seed = u16(lm, stage_off + 0x19A)
    target = bytes(lm[stage_off + 0x13A:stage_off + 0x13A + 0x60])

    out = bytearray()
    state = seed
    for b in target:
        state = xorshift16_step(state)
        out.append(b ^ (state & 0xFF))
    return out.decode("ascii")


def recover_part3(pe: bytes) -> str:
    if PART3_ENC not in pe:
        raise ValueError("Could not locate part #3 encoded marker in binary.")
    return bytes(c ^ 0x67 for c in PART3_ENC).decode("ascii")


def run_chimera(binary_path: Path, part1: str, part2: str, part3: str, cwd: Path) -> None:
    stdin_data = f"{part1}\n{part2}\n{part3}\n".encode("utf-8")
    env = os.environ.copy()
    env["WINEDEBUG"] = "-all"
    # Program may return non-zero on success; we do not enforce return code here.
    subprocess.run(
        ["wine", str(binary_path)],
        cwd=str(cwd),
        input=stdin_data,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=env,
    )


def decode_flag_from_runme(runme: bytes) -> str:
    if len(runme) < 0x51:
        raise ValueError("runme.com too short.")
    return bytes(b ^ 0x67 for b in runme[0x1F:0x51]).decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve chimera.exe and recover ARA7 flag.")
    parser.add_argument("binary", nargs="?", default="chimera.exe", help="Path to challenge binary")
    parser.add_argument(
        "--runme-path",
        default="runme.com",
        help="Path to runme.com output (default: runme.com in binary directory)",
    )
    parser.add_argument(
        "--skip-run",
        action="store_true",
        help="Do not execute chimera.exe; only decode existing runme.com",
    )
    args = parser.parse_args()

    binary_path = Path(args.binary).resolve()
    pe = binary_path.read_bytes()
    load_module = extract_dos_load_module(pe)

    part1 = recover_part1(load_module)
    part2 = recover_part2(load_module)
    part3 = recover_part3(pe)

    runme_path = Path(args.runme_path)
    if not runme_path.is_absolute():
        runme_path = (binary_path.parent / runme_path).resolve()

    if not args.skip_run:
        run_chimera(binary_path, part1, part2, part3, binary_path.parent)

    runme = runme_path.read_bytes()
    flag = decode_flag_from_runme(runme)

    print(f"[+] part1: {part1}")
    print(f"[+] part2: {part2}")
    print(f"[+] part3: {part3}")
    print(f"[+] flag: {flag}")


if __name__ == "__main__":
    main()
