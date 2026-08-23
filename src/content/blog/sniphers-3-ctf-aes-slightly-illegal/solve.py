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