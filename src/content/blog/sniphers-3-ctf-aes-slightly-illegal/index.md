---
title: "AES… but make it slightly illegal"
date: 2026-08-23
description: 'Breaking a custom AES-like cipher with its chosen-plaintext oracle.'
category: '$n1phers-3-0-ctf'
discipline: 'cryptography'
authors: ['abdieeuh']
draft: false
---

# AES… but make it slightly illegal

## Challenge Overview

The service implements a custom AES-like block cipher. It prints one session leak, `encrypt(key, key)`, then lets us encrypt chosen hex messages under the same random 16-byte key.

The break is caused by an invalid AES S-box: two different input bytes map to the same output byte. That turns the encryption oracle into a deterministic key-byte collision oracle.

The technique chain is:

1. Identify the non-bijective S-box collision.
2. Use the inverse of the first linear layer to place a controlled difference before the first S-box.
3. Recover two candidates for every key byte using ciphertext collisions.
4. Resolve the remaining `2^16` orientations with the public `encrypt(key, key)` leak.
5. Submit the recovered key to unlock the flag.

## Challenge Features

| Feature | Security relevance |
|---|---|
| Session key generated with `os.urandom(16)` | The key itself is random, but it is reused for all oracle queries in one connection. |
| `cipher = encrypt(key, key)` leak | Gives an exact offline verifier for the recovered key. |
| Chosen-plaintext encryption oracle | Allows controlled collision tests against the first S-box layer. |
| Corrupted S-box | Makes the cipher non-injective for selected internal states. |
| 5000-query limit | The attack needs only 16 oracle queries, far below the limit. |

## Attack Vector

The important part of the encryption is:

```python
state = ShiftRows(message)
state = MixColumns(state)
state = AddRoundKey(state, key, 0)
state = Sbox(state)
```

For byte position `(row, col)`, the first S-box input is:

```text
T(P)[row][col] xor key[4 * row + col] xor diag
```

where `T = MixColumns(ShiftRows(P))`, and `diag = 0x33` only when `row == col` because the custom `ark()` also xors `r ^ 0x33` into diagonal cells during round 0.

The S-box contains this collision:

```text
S[0x37] == S[0x92] == 0x9a
0x37 xor 0x92 = 0xa5
```

So if two chosen plaintexts cause the same internal byte to become `0x37` and `0x92`, the whole cipher state after the S-box is identical, and the final ciphertext blocks collide.

## Root Cause

### Non-permutation S-box

AES requires the S-box to be a permutation. Here one entry was duplicated: input `0x37` and input `0x92` both produce output `0x9a`.

That means two different pre-S-box states can collapse into the same post-S-box state. Once the state collapses, all later rounds are deterministic and produce the same ciphertext.

### Controllable first-round difference

The first linear layer `T = MixColumns(ShiftRows(.))` is invertible. For each key byte position, the solver builds 128 plaintext pairs where the internal byte before `ark()` differs by `0xa5` and every other byte is equal.

For a trial value `v`, the pair tests:

```text
v                 and                 v xor 0xa5
```

A ciphertext collision happens only for the unique pair where these two values become `0x37` and `0x92` after xoring the unknown key byte and the diagonal constant.

That gives:

```text
key_byte ∈ {v xor diag xor 0x37, v xor diag xor 0x92}
```

So every byte is recovered up to one binary choice.

## Solution

| Stage | Technique | Result |
|---|---|---|
| 1 | Parse the leaked `encrypt(key, key)` value | Get a public verifier for the session key. |
| 2 | Batch 128 collision pairs for one byte into one oracle query | Recover two candidates for that key byte. |
| 3 | Repeat for all 16 positions | Get `2^16` possible keys. |
| 4 | Test all `2^16` candidates offline against `encrypt(candidate, candidate)` | Recover one unique 16-byte key. |
| 5 | Send `end`, then submit the recovered key in hex | Service prints the flag. |

The final `2^16` search is not guessing the flag or relying on randomness. It is the exact deterministic candidate set left by the S-box collision ambiguity, and it is tiny enough to check locally.

## Exploit Command

```bash
python3 solve.py --source "main.py" --host 13.203.69.239 --port 31000
```

**Exploit**

```python
#!/usr/bin/env python3
import argparse
import importlib.util
import re
import socket
import time


def load_challenge(path):
    spec = importlib.util.spec_from_file_location('chall', path)
    chall = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chall)
    return chall


def xtime(a):
    return ((a << 1) ^ 0x11B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def gmul(a, b):
    res = 0
    while b:
        if b & 1:
            res ^= a
        a = xtime(a)
        b >>= 1
    return res


def make_inv_T(chall):
    def inv_mix_column(state):
        mat = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
        out = [[0] * 4 for _ in range(4)]
        for col in range(4):
            c = [state[row][col] for row in range(4)]
            for row in range(4):
                out[row][col] = (
                    gmul(mat[row][0], c[0]) ^ gmul(mat[row][1], c[1]) ^
                    gmul(mat[row][2], c[2]) ^ gmul(mat[row][3], c[3])
                )
        return out

    def inv_shift_rows(state):
        return [chall.rotate(state[i], -i) for i in range(4)]

    def inv_T(preark_state):
        state = inv_shift_rows(inv_mix_column(preark_state))
        return bytes(sum(state, []))

    return inv_T


def recv_until(sock, token, timeout=30):
    sock.settimeout(timeout)
    data = b''
    while token not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


def extract_ciphertext(blob):
    text = blob.decode('utf-8', errors='replace')
    matches = re.findall(r'Ciphertext morphed into:\s*([0-9a-fA-F]+)', text)
    if not matches:
        raise RuntimeError('Could not find ciphertext in response:\n' + text[-500:])
    return bytes.fromhex(matches[-1])


def query(sock, msg):
    sock.sendall(msg.hex().encode() + b'\n')
    data = recv_until(sock, b'Feed the BOX', timeout=30)
    return extract_ciphertext(data)


def recover_key(chall, sock, secret):
    inv_T = make_inv_T(chall)
    delta = 0x37 ^ 0x92
    reps = [v for v in range(256) if v < (v ^ delta)]

    collision_inputs = [x for x in range(256) if chall.S[x] == chall.S[x ^ delta]]
    if sorted(collision_inputs) != [0x37, 0x92]:
        raise RuntimeError(f'Unexpected S-box collision set: {collision_inputs!r}')

    byte_candidates = []
    zero_ct = None

    for pos in range(16):
        row, col = divmod(pos, 4)
        blocks = []
        for v in reps:
            a = [[0] * 4 for _ in range(4)]
            b = [[0] * 4 for _ in range(4)]
            a[row][col] = v
            b[row][col] = v ^ delta
            blocks.append(inv_T(a))
            blocks.append(inv_T(b))

        ct = query(sock, b''.join(blocks))
        cblocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
        if len(cblocks) != len(blocks):
            raise RuntimeError(f'Unexpected ciphertext size at byte {pos}')
        if pos == 0:
            zero_ct = cblocks[0]  # first chosen plaintext block is all zero

        found = []
        for i, v in enumerate(reps):
            if cblocks[2 * i] == cblocks[2 * i + 1]:
                found.append(v)
        if len(found) != 1:
            raise RuntimeError(f'Byte {pos}: expected exactly one collision, got {found}')

        diag = 0x33 if row == col else 0
        v = found[0]
        byte_candidates.append((v ^ diag ^ 0x37, v ^ diag ^ 0x92))
        print(f'byte {pos:02d}: candidates {byte_candidates[-1][0]:02x}/{byte_candidates[-1][1]:02x}')

    print('Resolving 2^16 remaining orientation choices...')
    t0 = time.time()
    matches = []
    for mask in range(1 << 16):
        cand = bytes(byte_candidates[i][(mask >> i) & 1] for i in range(16))
        if chall.encrypt(cand, cand) == secret and chall.encrypt(b'\x00' * 16, cand) == zero_ct:
            matches.append(cand)
    print(f'orientation search finished in {time.time() - t0:.2f}s')

    if len(matches) != 1:
        raise RuntimeError(f'Expected a unique key, got {len(matches)}: {[m.hex() for m in matches]}')
    return matches[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', default='main.py', help='path to the provided challenge source file')
    ap.add_argument('--host', default='13.203.69.239')
    ap.add_argument('--port', type=int, default=31000)
    args = ap.parse_args()

    chall = load_challenge(args.source)

    with socket.create_connection((args.host, args.port), timeout=15) as sock:
        banner = recv_until(sock, b'Feed the BOX', timeout=30)
        print(banner.decode(errors='replace'), end='')
        m = re.search(rb'The whispers of secret:\s*([0-9a-fA-F]{32})', banner)
        if not m:
            raise RuntimeError('Could not parse the leaked encrypt(key,key) value')
        secret = bytes.fromhex(m.group(1).decode())
        print('\nleak =', secret.hex())

        key = recover_key(chall, sock, secret)
        print('recovered key =', key.hex())

        sock.sendall(b'end\n')
        print(recv_until(sock, b'Master Key', timeout=30).decode(errors='replace'), end='')
        sock.sendall(key.hex().encode() + b'\n')

        sock.settimeout(10)
        out = b''
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                out += chunk
        except socket.timeout:
            pass
        print(out.decode(errors='replace'))


if __name__ == '__main__':
    main()

```

## Flag

```text
$N1PH€RSxTCTF{Pr3_D1ffus10n_M4kes_S-B0x_c0ll1s10ns_c0upl3d_@cr0ss_c0lumns:D}
```
