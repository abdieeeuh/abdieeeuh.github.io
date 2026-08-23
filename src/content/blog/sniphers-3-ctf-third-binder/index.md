---
title: "Third Binder"
date: 2026-08-23
description: 'Peeling legacy encodings and a patched VM to recover a forensic flag.'
category: '$n1phers-3-0-ctf'
discipline: 'forensics'
authors: ['abdieeuh']
draft: false
---

## Challenge Overview

The challenge provides `mx.bin`, an ASCII-looking binder/printer artifact. The description points to old mail transport encoding, an alternate alphabet, and a repeating letter-shift scrambler.

The solve is fully static. The recovered DOS program is never executed. The final flag is recovered by decoding the container layers, patching the embedded VM bytecode in memory, and inverting the key schedule using the known flag format.

The technique chain is:

1. Known-plaintext recovery of the printable repeating Caesar key
2. Printable-only repeating Caesar decryption
3. xxdecode extraction of `Ex0rcists.COM`
4. Static analysis of the fake-MZ DOS `.COM` program
5. VM opcode deobfuscation
6. Deterministic key inversion and flag decryption

## Challenge Features

| Feature | Security relevance |
|---|---|
| ASCII-only artifact | The file is not the final payload; it is a transformed old-mail encoded blob. |
| `begin 644` header | Gives deterministic known plaintext for the first layer. |
| Printable Caesar over 95 characters | The shift is applied only to printable bytes; newlines do not advance the key stream. |
| xxencode alphabet | The body uses the `+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` alphabet, not normal uuencode. |
| Fake `MZ` prefix | The recovered executable looks like DOS MZ data but behaves as a `.COM`-style program starting with a short jump. |
| Embedded VM | The flag is produced by a tiny bytecode interpreter, so running the program is unnecessary. |

## Attack Vector

The challenge wording maps directly to the encoding layers.

| Hint | Verified meaning |
|---|---|
| `mailed it the old way` | Old `begin 644 <name>` mail-encoding container. |
| `the other alphabet` | xxencode rather than uuencode. |
| `letter-shifting repeating scrambler` | Repeating Caesar/Vigenere-style shift over printable ASCII. |
| `Third binder` | The supplied `mx.bin` is a container layer, not the direct flag. |
| `this copy will not just cough up secret` | The extracted `Ex0rcists.COM` still needs static reversing. |

## Root Cause

### Layer 1: Printable Repeating Caesar

The encrypted file begins with:

```text
s~ ~ 9NIE9]
```

Old mail encodings commonly begin with:

```text
begin 644
```

Subtracting the known plaintext from the ciphertext over printable ASCII (`0x20` through `0x7e`) gives the repeating shift pattern:

```text
1985
```

The important implementation detail is that only printable bytes consume key characters. Newlines are preserved and do not advance the key index. Under that rule, the first line decrypts cleanly to:

```text
begin 644 Ex0rcists.COM
```

### Layer 2: xxencode

The decrypted body does not match normal uuencode because its line length and data alphabet are from xxencode. The alphabet is:

```text
+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
```

Decoding the xxencoded body yields an 1828-byte DOS binary named:

```text
Ex0rcists.COM
```

The file begins with `4d 5a eb 1c`, but the `MZ` bytes are part of a fake `.COM` layout. The short jump reaches the actual code body without requiring execution.

## Static Reverse Engineering

### Opcode Decryption

At the real entry, the program computes a byte from fixed header offsets:

```text
0x104, 0x106, 0x108, 0x10c, 0x110, 0x114, 0x118, 0x11e
```

The computed value is:

```text
0xe3
```

It is used to decrypt nine VM opcodes at `0x27a`:

```text
[1, 8, 2, 3, 8, 4, 5, 6, 7]
```

Opcode `8` is a no-op. The useful VM sequence for each flag byte is therefore:

```text
load encrypted byte
load cyclic transformed key byte
xor
add 0x3b
rol 3
store output byte
```

So each plaintext byte is:

```python
plain[i] = rol8(((enc[i] ^ transformed_key[i % 12]) + 0x3b) & 0xff, 3)
```

### Input Key Transform

The visible program asks for an exorcism key. Static analysis shows it transforms 12 input bytes into a 12-byte cyclic key using four 256-byte position tables and one final 256-byte table.

For input byte `key[i]`:

```text
internal = table[i % 4][key[i]] XOR previous_internal
transformed_key[i] = table2[internal]
previous_internal = internal
```

Because all five tables are permutations, this transform can be inverted directly.

### Deterministic Key Recovery

The flag format gives the first 12 bytes of plaintext, including the DOS byte used for the euro glyph:

```text
$N1PHÕRSxTCT
```

Those 12 known plaintext bytes cover every position of the 12-byte cyclic key. Therefore no guessing or brute force is needed:

```python
before_rol = (ror8(known_plain[i], 3) - 0x3b) & 0xff
transformed_key[i] = enc[i] ^ before_rol
```

Inverting the input key transform gives:

```text
Ex0rc1st1985
```

Using this transformed key decrypts the full 57-byte flag.

## Solution

| Stage | Standard technique | Result |
|---|---|---|
| 1 | Known plaintext against printable Caesar | Recovered repeating key `1985` |
| 2 | Printable-only decryption | Recovered xxencoded `begin 644 Ex0rcists.COM` text |
| 3 | xxdecode | Extracted static DOS `.COM` binary |
| 4 | Static disassembly | Located opcode patching, tables, encrypted flag, and VM |
| 5 | Known flag prefix | Derived all 12 transformed key bytes |
| 6 | Table inversion | Recovered exorcism key and decrypted the flag |

Run the solver against the supplied artifact:

```bash
python3 solve_mx.py 'mx.bin'
```

Expected output:

```text
printable Caesar key: 1985
VM opcode XOR base: 0xe3
VM opcodes: [1, 8, 2, 3, 8, 4, 5, 6, 7]
exorcism key: Ex0rc1st1985
$N1PH€RSxTCTF{wh1t3b0x_VM_und3r_a_f4k3_MZ_3x0rc1sed_1985}
```

## Exploit Success

The solver was validated locally against the provided `mx.bin` evidence. The recovered DOS program was not executed; the script only parses bytes, applies the encoding transforms, and emulates the VM arithmetic.

```text
$N1PH€RSxTCTF{wh1t3b0x_VM_und3r_a_f4k3_MZ_3x0rc1sed_1985}
```

## Appendix

**Solver**

The complete solver starts from the original `mx.bin` and ends by printing the exorcism key and final flag.

```python
#!/usr/bin/env python3
from pathlib import Path
import sys

PRINT_MIN = 0x20
PRINT_MAX = 0x7e
PRINT_RANGE = 95
XX_ALPHABET = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
XX_INDEX = {c: i for i, c in enumerate(XX_ALPHABET)}
KNOWN_HEADER = b'begin 644 '
KNOWN_FLAG_PREFIX = b'$N1PH' + bytes([0xD5]) + b'RSxTCTF{'


def minimal_period(values):
    for period in range(1, len(values) + 1):
        if all(values[i] == values[i % period] for i in range(len(values))):
            return values[:period]
    return values


def decrypt_printable_repeating_caesar(data):
    shifts = [((data[i] - KNOWN_HEADER[i]) % PRINT_RANGE)
              for i in range(len(KNOWN_HEADER))]
    key_shifts = minimal_period(shifts)

    out = bytearray()
    printable_index = 0
    for byte in data:
        if PRINT_MIN <= byte <= PRINT_MAX:
            shift = key_shifts[printable_index % len(key_shifts)]
            out.append(((byte - PRINT_MIN - shift) % PRINT_RANGE) + PRINT_MIN)
            printable_index += 1
        else:
            out.append(byte)

    key_text = ''.join(chr(s + PRINT_MIN) for s in key_shifts)
    return bytes(out), key_text


def xxdecode(text):
    lines = text.decode('ascii').splitlines()
    if not lines or not lines[0].startswith('begin '):
        raise ValueError('missing begin header after Caesar layer')

    out = bytearray()
    for line in lines[1:]:
        if line == 'end':
            break
        if not line:
            continue
        length = XX_INDEX[line[0]]
        decoded_line = bytearray()
        for pos in range(1, len(line), 4):
            group = line[pos:pos + 4]
            if len(group) < 4:
                break
            value = 0
            for ch in group:
                value = (value << 6) | XX_INDEX[ch]
            decoded_line.extend(value.to_bytes(3, 'big'))
        out.extend(decoded_line[:length])
    return bytes(out)


def at(blob, addr, size=1):
    start = addr - 0x100
    return blob[start:start + size]


def u8(blob, addr):
    return blob[addr - 0x100]


def rol8(value, count):
    count &= 7
    return ((value << count) | (value >> (8 - count))) & 0xff


def ror8(value, count):
    count &= 7
    return ((value >> count) | (value << (8 - count))) & 0xff


def inverse_table(table):
    inv = [None] * 256
    for i, value in enumerate(table):
        inv[value] = i
    if any(v is None for v in inv):
        raise ValueError('table is not a permutation')
    return bytes(inv)


def decrypt_vm_opcodes(blob):
    # The program intentionally starts with fake MZ bytes. The real entry jumps
    # to 0x120, where a checksum-derived byte decrypts nine VM opcodes at 0x27a.
    checksum_addrs = [0x104, 0x106, 0x108, 0x10c, 0x110, 0x114, 0x118, 0x11e]
    al = 0
    for addr in checksum_addrs:
        al = (al + u8(blob, addr)) & 0xff
    opcode_key = ((al ^ 0x5a) + 7) & 0xff

    mutable = bytearray(blob)
    for i in range(9):
        mutable[0x27a - 0x100 + i] ^= (opcode_key + 5 * i) & 0xff
    opcodes = bytes(mutable[0x27a - 0x100:0x283 - 0x100])
    if opcodes != bytes([1, 8, 2, 3, 8, 4, 5, 6, 7]):
        raise ValueError(f'unexpected VM opcodes: {opcodes.hex()}')
    return bytes(mutable), opcode_key, opcodes


def derive_transformed_key(blob, flag_prefix=KNOWN_FLAG_PREFIX):
    enc = at(blob, 0x283, 0x39)
    transformed_key = []
    # The first 12 known bytes of the flag format cover every position of the
    # 12-byte cyclic key.
    for i, plain in enumerate(flag_prefix[:12]):
        before_rol = (ror8(plain, 3) - 0x3b) & 0xff
        transformed_key.append(enc[i] ^ before_rol)
    return bytes(transformed_key)


def invert_user_key(blob, transformed_key):
    t2_inv = inverse_table(at(blob, 0x6bc, 256))
    table_inverses = [inverse_table(at(blob, 0x2bc + 0x100 * i, 256))
                      for i in range(4)]

    user_key = bytearray()
    previous_internal = 0
    for i, tk_byte in enumerate(transformed_key):
        internal = t2_inv[tk_byte]
        table_output = internal ^ previous_internal
        user_key.append(table_inverses[i & 3][table_output])
        previous_internal = internal
    return bytes(user_key)


def transform_user_key(blob, user_key):
    out = bytearray()
    previous_internal = 0
    for i, byte in enumerate(user_key):
        table_output = u8(blob, 0x2bc + 0x100 * (i & 3) + byte)
        internal = table_output ^ previous_internal
        previous_internal = internal
        out.append(u8(blob, 0x6bc + internal))
    return bytes(out)


def decrypt_flag(blob, transformed_key):
    enc = at(blob, 0x283, 0x39)
    out = bytearray()
    for i, byte in enumerate(enc):
        value = byte ^ transformed_key[i % len(transformed_key)]
        value = (value + 0x3b) & 0xff
        out.append(rol8(value, 3))
    return bytes(out)


def render_flag(flag_bytes):
    # The DOS binary emits 0xd5 for the euro glyph used in the challenge's flag
    # format. Render it as the visible flag character for the final output.
    return ''.join('€' if b == 0xD5 else chr(b) for b in flag_bytes)


def solve(path):
    original = Path(path).read_bytes()
    caesar_plain, caesar_key = decrypt_printable_repeating_caesar(original)
    com_blob = xxdecode(caesar_plain)
    patched_blob, opcode_key, opcodes = decrypt_vm_opcodes(com_blob)
    transformed_key = derive_transformed_key(patched_blob)
    user_key = invert_user_key(patched_blob, transformed_key)

    if transform_user_key(patched_blob, user_key) != transformed_key:
        raise RuntimeError('user key inversion failed')

    flag_bytes = decrypt_flag(patched_blob, transformed_key)
    flag = render_flag(flag_bytes)
    if not (flag.startswith('$N1PH€RSxTCTF{') and flag.endswith('}')):
        raise RuntimeError(f'flag format check failed: {flag!r}')

    print(f'printable Caesar key: {caesar_key}')
    print(f'VM opcode XOR base: 0x{opcode_key:02x}')
    print(f'VM opcodes: {list(opcodes)}')
    print(f'exorcism key: {user_key.decode("ascii")}')
    print(flag)


if __name__ == '__main__':
    solve(sys.argv[1] if len(sys.argv) > 1 else 'mx.bin')
```

## Flag

```text
$N1PH€RSxTCTF{wh1t3b0x_VM_und3r_a_f4k3_MZ_3x0rc1sed_1985}
```
