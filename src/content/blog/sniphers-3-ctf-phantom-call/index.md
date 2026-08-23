---
title: "METAL GOT SOLID FLAGS: THE PHANTOM CALL"
date: 2026-08-22
description: 'Reversing a deliberately miswired decryptor to recover the encrypted flag.'
category: '$n1phers-3-0-ctf'
discipline: 'reverse-engineering'
authors: ['abdieeuh']
draft: false
---

## Challenge Overview

This is a reverse-engineering challenge built around a misleading decryptor. The archive provides `enc`, `dec`, `liblib.so`, and `ciphertext.bin`.

At first glance, recovering the flag should only require running the decryptor against the ciphertext. Instead, the supplied `dec` binary deliberately resolves the wrong PLT relocations at runtime, causing the apparent decryption path to call the wrong functions and fail with a fake corruption message.

The technique chain is:

1. Triage the ELF files and confirm the raw decryptor is sabotaged.
2. Identify that `enc`/`dec` depend on `liblib.so` and operate on block data.
3. Inspect the ELF section headers, dynamic tags, and program headers.
4. Find the overlaid runtime relocation table at file offset `0x2000` mapped to virtual address `0x1000`.
5. Patch the runtime relocation table with the clean `.rela.plt` table from file offset `0x1000`.
6. Run the patched decryptor and verify the plaintext by re-encrypting it.

## Challenge Features

The challenge uses the following high-value reverse-engineering features.

| Feature | Security relevance |
|---|---|
| Separate `liblib.so` | The interesting cipher routines are imported through PLT entries instead of being statically obvious inside the main executable. |
| Matching `enc` and `dec` programs | The encoder provides a deterministic verification oracle for the recovered plaintext. |
| Broken section metadata | `readelf` reports an invalid `.rel.plt.sec` section, hinting that the ELF layout is intentionally abnormal. |
| Overlapping loader view | Static tools show the clean `.rela.plt` table at file offset `0x1000`, but the loader maps a different file region to the same virtual address. |
| Relocation-table sabotage | The dynamic loader follows `DT_JMPREL = 0x1000`, so runtime symbol binding uses the overlaid relocation data instead of the clean table. |

## Attack Vector

The provided files have these roles:

| File | Verified role |
|---|---|
| `ciphertext.bin` | Encrypted challenge payload. |
| `enc` | Correct encryptor used to validate the final plaintext. |
| `dec` | Decryptor with sabotaged runtime PLT relocations. |
| `liblib.so` | Shared library containing the cipher helper functions imported by `enc` and `dec`. |

Running the decryptor directly gives the intended dead end:

```bash
LD_LIBRARY_PATH=. ./dec < ciphertext.bin
```

```text
len is corrupted. decryption is abnormal :((
Psst: Even Big Boss's story has an order to it. Don't let Ocelot catch you skipping ahead :)
```

The hint about "order" points at call ordering or binding order rather than corrupted ciphertext.

## Root Cause

### ELF Loader Mismatch

The important dynamic entries in `dec` are:

```text
0x0000000000000002 (PLTRELSZ)  1344 (bytes)
0x0000000000000014 (PLTREL)    RELA
0x0000000000000017 (JMPREL)    0x1000
```

`PLTRELSZ = 1344 = 0x540`, so the runtime PLT relocation table is 0x540 bytes long. `DT_JMPREL` says that this table starts at virtual address `0x1000`.

Static section headers show a normal-looking `.rela.plt` table:

```text
[ 9] .rela.plt  RELA  vaddr 0x1000  file offset 0x1000  size 0x540
```

However, the program headers reveal a second loader mapping:

```text
LOAD  offset 0x2000  vaddr 0x1000  filesz 0x540  memsz 0x540  RW
```

That means the bytes actually mapped at virtual address `0x1000` during program loading come from file offset `0x2000`, not the clean section-table view at file offset `0x1000`.

### Sabotaged PLT Binding

The decryptor's visible code looks trustworthy, but imported calls are resolved through the manipulated relocation table. As a result, the apparent decrypt pipeline calls the wrong helper functions from `liblib.so`.

This explains why direct execution reaches the fake length-corruption path even though the ciphertext is valid.

The fix is to make the runtime relocation view match the clean static relocation view:

```text
copy dec[0x1000 : 0x1000 + 0x540]
into dec[0x2000 : 0x2000 + 0x540]
```

## Solution

The solution patches only the malicious runtime relocation overlay. No guessing, randomness, or brute force is needed.

| Stage | Standard technique | Result |
|---|---|---|
| 1 | Run the raw decryptor | Confirm fake corruption path. |
| 2 | Inspect `DT_JMPREL` and `PLTRELSZ` | Runtime PLT relocation table is `vaddr 0x1000`, size `0x540`. |
| 3 | Compare section headers and program headers | Static `.rela.plt` is at file offset `0x1000`; runtime overlay is at file offset `0x2000`. |
| 4 | Patch the overlay | Restore intended PLT symbol binding. |
| 5 | Run patched `dec` | Recover the flag. |
| 6 | Re-encrypt plaintext with `enc` | Verify regenerated ciphertext matches `ciphertext.bin` exactly. |

A minimal deterministic solver is:

```python
#!/usr/bin/env python3
from pathlib import Path
import hashlib
import os
import stat
import subprocess

ROOT = Path(__file__).resolve().parent
DEC = ROOT / "dec"
ENC = ROOT / "enc"
CIPHERTEXT = ROOT / "ciphertext.bin"
PATCHED_DEC = ROOT / "dec_patched"

CLEAN_RELA_PLT_OFF = 0x1000
RUNTIME_RELA_PLT_OFF = 0x2000
RELA_PLT_SIZE = 0x540

# Patch the runtime-mapped relocation overlay with the clean static table.
data = bytearray(DEC.read_bytes())
data[RUNTIME_RELA_PLT_OFF:RUNTIME_RELA_PLT_OFF + RELA_PLT_SIZE] = \
    data[CLEAN_RELA_PLT_OFF:CLEAN_RELA_PLT_OFF + RELA_PLT_SIZE]
PATCHED_DEC.write_bytes(data)
PATCHED_DEC.chmod(PATCHED_DEC.stat().st_mode | stat.S_IXUSR)

# Run the repaired decryptor.
env = os.environ.copy()
env["LD_LIBRARY_PATH"] = str(ROOT)
plaintext = subprocess.check_output([str(PATCHED_DEC)],
                                    input=CIPHERTEXT.read_bytes(),
                                    env=env)

# Deterministic verification: encrypting the recovered plaintext must reproduce
# the original ciphertext exactly.  Keep the trailing newline during validation.
regenerated = subprocess.check_output([str(ENC)], input=plaintext, env=env)
assert regenerated == CIPHERTEXT.read_bytes(), (
    hashlib.sha256(regenerated).hexdigest(),
    hashlib.sha256(CIPHERTEXT.read_bytes()).hexdigest(),
)

print(plaintext.decode("utf-8").strip())
```

Run it from the extracted challenge directory:

```bash
python3 solve.py
```

## Exploit Success

The patched decryptor prints the flag:

```text
$N1PH€RSxTCTF{n0W_d0_Y0u_r3M3M83r_wh0_y0u_4r3_wh47_y0u_4R3_m34N7_70_D0_b9ab326df6}
```

The verification step also confirms that the recovered plaintext is not an accidental printable string:

```text
orig_sha256  d679eb1e8432dbf2f017c4a1c1929d62748d629254120a642aac23d3a596526e
regen_sha256 d679eb1e8432dbf2f017c4a1c1929d62748d629254120a642aac23d3a596526e
match        True
```

The decrypted plaintext includes a trailing newline. The submitted flag is the brace-delimited value without that trailing newline.

## Appendix

### Manual Patch Command

```bash
python3 - <<'PY'
from pathlib import Path

data = bytearray(Path("dec").read_bytes())
data[0x2000:0x2000 + 0x540] = data[0x1000:0x1000 + 0x540]
Path("dec_patched").write_bytes(data)
PY

chmod +x dec_patched
LD_LIBRARY_PATH=. ./dec_patched < ciphertext.bin
```

### Validation Command

```bash
LD_LIBRARY_PATH=. ./dec_patched < ciphertext.bin > plaintext.txt
LD_LIBRARY_PATH=. ./enc < plaintext.txt > regenerated.bin
sha256sum ciphertext.bin regenerated.bin
cmp ciphertext.bin regenerated.bin
```

## Flag

```text
$N1PH€RSxTCTF{n0W_d0_Y0u_r3M3M83r_wh0_y0u_4r3_wh47_y0u_4R3_m34N7_70_D0_b9ab326df6}
```
