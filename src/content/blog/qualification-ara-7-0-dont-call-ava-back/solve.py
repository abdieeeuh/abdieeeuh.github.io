#!/usr/bin/env python3
import math
import struct
from dataclasses import dataclass
from typing import Dict, List

import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RBP


@dataclass(frozen=True)
class Model:
    bias: np.ndarray
    weight: np.ndarray
    k: np.ndarray


def u32_to_f32(u: int) -> np.float32:
    """Reinterpret 32-bit int bits as float32."""
    return np.frombuffer(struct.pack("<I", u & 0xFFFFFFFF), dtype=np.float32)[0]


def fma32(a: np.float32, b: np.float32, c: np.float32) -> np.float32:
    """
    Approximate float32 FMA.
    CPU instr is fused (single rounding). For this challenge, non-fused
    arithmetic is still good enough because the threshold is abs(sum) < 0.5.
    """
    return np.float32(np.float64(a) * np.float64(b) + np.float64(c))


def extract_stores(exe_path: str, blob_off: int, blob_len: int, blob_va: int) -> Dict[int, int]:
    """
    Extract instructions of the form:
      mov dword [rbp + disp], imm32
    and keep the first write for each displacement.
    """
    with open(exe_path, "rb") as f:
        f.seek(blob_off)
        blob = f.read(blob_len)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    first_write: Dict[int, int] = {}
    for ins in md.disasm(blob, blob_va):
        if ins.mnemonic != "mov" or len(ins.operands) != 2:
            continue

        dst, src = ins.operands
        if dst.type != X86_OP_MEM or src.type != X86_OP_IMM:
            continue

        mem = dst.mem
        if mem.base != X86_REG_RBP or mem.index != 0:
            continue

        if dst.size != 4:
            continue

        disp = mem.disp
        if disp > 0x7FFFFFFFFFFF:
            disp -= 1 << 64
        if disp < 0:
            continue

        if disp not in first_write:
            first_write[disp] = src.imm & 0xFFFFFFFF

    return first_write


def build_model(first_write: Dict[int, int]) -> Model:
    """
    Constant layout recovered from the blob:
      [rbp + 0x00] = dead XOR key (first write)
      [rbp + 0x08 .. 0x24] = raw bias u32 values
      [rbp + 0x28 .. 0x44] = raw weight u32 values
      [rbp + 0x50 .. 0x12C] = raw K u32 values
    """
    dead = first_write[0x00]
    if dead != 0xDEADBEEF:
        raise ValueError(f"unexpected dead key: {dead:#x} (expected 0xdeadbeef)")

    bias = np.array([u32_to_f32(dead ^ first_write[0x08 + 4 * j]) for j in range(8)], dtype=np.float32)
    weight = np.array([u32_to_f32(dead ^ first_write[0x28 + 4 * j]) for j in range(8)], dtype=np.float32)
    k = np.array([u32_to_f32(dead ^ first_write[0x50 + 4 * i]) for i in range(56)], dtype=np.float32)

    return Model(bias=bias, weight=weight, k=k)


def term(model: Model, byte_val: int, pos: int) -> float:
    """Compute term_i = (x*w + b)^2 + K[i] using float32 operations."""
    j = pos % 8
    x = np.float32(byte_val)
    y = fma32(x, model.weight[j], model.bias[j])
    t = fma32(y, y, model.k[pos])
    return float(t)


def solve(model: Model) -> bytes:
    """
    For each position i:
      find x in 0..255 that makes term(i) as close to zero as possible.

    Since term = y^2 + K, the target is y ~= +/-sqrt(-K).
    """
    out: List[int] = []

    for i in range(56):
        j = i % 8
        k = float(model.k[i])

        target = math.sqrt(-k)
        candidates = set()

        for sgn in (+1.0, -1.0):
            x_real = (sgn * target - float(model.bias[j])) / float(model.weight[j])
            lo = int(math.floor(x_real)) - 3
            hi = int(math.ceil(x_real)) + 3
            for b in range(lo, hi + 1):
                if 0 <= b <= 255:
                    candidates.add(b)

        best = min(candidates, key=lambda b: abs(term(model, b, i)))
        out.append(best)

    return bytes(out)


def main() -> None:
    exe_path = "chall.exe"
    blob_va = 0x14000C080
    blob_off = 0x9800 + 0x80
    blob_len = 0x4B0

    first_write = extract_stores(exe_path, blob_off, blob_len, blob_va)
    model = build_model(first_write)

    flag = solve(model)
    total = sum(term(model, flag[i], i) for i in range(56))

    print(flag.decode("ascii"))
    print(f"[check] sum={total:.6f}  abs(sum) < 0.5 => {abs(total) < 0.5}")


if __name__ == "__main__":
    main()
