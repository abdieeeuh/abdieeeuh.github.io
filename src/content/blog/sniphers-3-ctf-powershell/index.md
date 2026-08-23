---
title: "powershell"
date: 2026-08-23
description: 'Statically decoding an encoded PowerShell payload to recover its IPv4 flag.'
category: '$n1phers-3-0-ctf'
discipline: 'reverse-engineering'
authors: ['abdieeuh']
draft: false
---

## Challenge Overview

The challenge provides a hidden PowerShell command using `-EncodedCommand` and asks us to decode it. The required flag format contains an IPv4 address, so the goal is to statically unpack the payload and recover the network indicator.

The technique chain is:

1. Decode the PowerShell `-EncodedCommand` as UTF-16LE
2. Extract the embedded base64 gzip blob
3. Decompress the gzip stream to recover the second-stage PowerShell
4. Extract the second-stage base64 byte array
5. XOR-decode the shellcode with the key used by the loader
6. Recover the C2 IP address from decoded shellcode strings

No payload execution is required. The entire solve is static and deterministic.

## Challenge Features

The payload uses the following high-value features.

| Feature | Reverse-engineering relevance |
|---|---|
| `%COMSPEC% /b /c start /b /min` | Starts PowerShell in a minimized/background process. This is launch noise, not part of the cryptography. |
| `powershell -nop -w hidden -encodedcommand` | The command body is base64 encoded as UTF-16LE, which is the normal PowerShell `-EncodedCommand` format. |
| `FromBase64String("H4sI...")` | The first decoded script contains a gzip-compressed second stage. |
| `GzipStream(... Decompress ...)` | The second stage is recovered by gzip decompression. |
| `IEX (...)` | The script would execute the decompressed stage, but for the solve we only read it as text. |
| Inner base64 byte array | The second stage stores shellcode as base64. |
| XOR byte transform | Each shellcode byte is XORed with `0x23` before execution. |
| IPv4 flag format | The final useful artifact is the decoded C2 IP address. |

## Attack Vector

The command components have these roles:

| Artifact | Verified role |
|---|---|
| Outer `-EncodedCommand` blob | UTF-16LE PowerShell script. |
| Outer script | Creates a `MemoryStream` from a base64 gzip blob, decompresses it, then passes it to `IEX`. |
| Gzip stream | Contains the second-stage loader. |
| Second-stage loader | Decodes base64 shellcode and XORs it with `0x23`. |
| Decoded shellcode | WinINet-style x86 stager containing the C2 network strings. |
| Extracted IPv4 address | Final flag content. |

## Root Cause

### Main Primitive: PowerShell EncodedCommand

PowerShell's `-EncodedCommand` expects a base64 string of UTF-16LE text. Decoding the provided blob produces a script with this structure:

```powershell
$s = New-Object IO.MemoryStream(
    ,[Convert]::FromBase64String("H4sI...")
);
IEX (
    New-Object IO.StreamReader(
        New-Object IO.Compression.GzipStream(
            $s,
            [IO.Compression.CompressionMode]::Decompress
        )
    )
).ReadToEnd();
```

The important point is that the dangerous part is `IEX`. We do not need to execute it. Reading the decompressed text is enough.

### Second Stage

The gzip output is another PowerShell loader. Its important behavior is:

```text
base64 shellcode -> byte array -> XOR each byte with 0x23 -> execute in memory
```

The decoded shellcode starts with:

```text
fc e8 89 00 00 00 60 89 e5
```

That is a common x86 position-independent shellcode prologue. The shellcode also contains readable WinINet/network strings after XOR decoding.

## Static Indicators

After base64 decoding and XORing each byte with `0x23`, the useful strings include:

```text
wininet
/EZWf
149.28.81.19
```

The shellcode also encodes HTTPS port `443`. The only IPv4 address recovered from the decoded payload is:

```text
149.28.81.19
```

Because the challenge flag format is `$N1PH€RSxTCTF{x.x.x.x}`, the flag is built directly from this IP address.

## Solution

The solve is fully deterministic and uses only static decoding.

| Stage | Standard technique | Result |
|---|---|---|
| 1 | Base64 decode as UTF-16LE | Outer PowerShell script |
| 2 | Extract `H4sI...` blob | Compressed second stage |
| 3 | Gzip decompress | Second-stage PowerShell loader |
| 4 | Extract inner base64 shellcode | Encoded byte array |
| 5 | XOR with `0x23` | Decoded x86 shellcode |
| 6 | Extract IPv4 strings | `149.28.81.19` |
| 7 | Apply flag format | `$N1PH€RSxTCTF{149.28.81.19}` |

Run the solver by saving the original challenge command to `command.txt` and executing:

```bash
python3 solve.py < command.txt
```

Expected output:

```text
[+] recovered IPv4 addresses:
149.28.81.19
[+] flag:
$N1PH€RSxTCTF{149.28.81.19}
```

## Appendix

**Solver**

The solver never executes the payload. It only decodes, decompresses, XORs, and extracts strings.

```python
#!/usr/bin/env python3
import base64
import gzip
import re
import sys


FLAG_PREFIX = "$N1PH€RSxTCTF"


def extract_encoded_command(text: str) -> str:
    """Return the PowerShell -EncodedCommand blob from a full command line."""
    match = re.search(r"-encodedcommand\s+([A-Za-z0-9+/=]+)", text, re.I)
    if match:
        return match.group(1)

    # Also support input containing only the base64 blob.
    compact = re.sub(r"\s+", "", text)
    if re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return compact

    raise ValueError("could not find a PowerShell -EncodedCommand blob")


def b64decode_utf16le(blob: str) -> str:
    return base64.b64decode(blob).decode("utf-16le")


def extract_base64_argument(script: str, prefix: str | None = None) -> str:
    """Extract the first FromBase64String('...') or FromBase64String(\"...\") argument."""
    pattern = r"FromBase64String\(\s*(['\"])([A-Za-z0-9+/=]+)\1\s*\)"
    matches = list(re.finditer(pattern, script, re.I))
    if not matches:
        raise ValueError("could not find FromBase64String(...) data")

    if prefix is None:
        return matches[0].group(2)

    for match in matches:
        candidate = match.group(2)
        if candidate.startswith(prefix):
            return candidate

    raise ValueError(f"could not find base64 argument starting with {prefix!r}")


def extract_xor_key(script: str) -> int:
    match = re.search(r"-bxor\s+(0x[0-9a-fA-F]+|\d+)", script, re.I)
    if not match:
        raise ValueError("could not find XOR key in second-stage script")
    return int(match.group(1), 0)


def printable_strings(data: bytes, minimum: int = 4) -> list[str]:
    found = re.findall(rb"[\x20-\x7e]{%d,}" % minimum, data)
    return [item.decode("ascii", errors="replace") for item in found]


def main() -> None:
    command = sys.stdin.read()

    outer_blob = extract_encoded_command(command)
    stage1 = b64decode_utf16le(outer_blob)

    gzip_b64 = extract_base64_argument(stage1, prefix="H4sI")
    stage2 = gzip.decompress(base64.b64decode(gzip_b64)).decode(
        "utf-8", errors="replace"
    )

    shellcode_b64 = extract_base64_argument(stage2)
    encoded_shellcode = base64.b64decode(shellcode_b64)

    xor_key = extract_xor_key(stage2)
    shellcode = bytes(byte ^ xor_key for byte in encoded_shellcode)

    strings = printable_strings(shellcode)
    joined = "\n".join(strings).encode()

    ips = sorted(
        set(ip.decode("ascii") for ip in re.findall(rb"(?:\d{1,3}\.){3}\d{1,3}", joined))
    )

    if not ips:
        raise SystemExit("no IPv4 address found in decoded shellcode")

    print("[+] recovered IPv4 addresses:")
    for ip in ips:
        print(ip)

    # The challenge asks for an IPv4-only flag. The decoded payload contains one C2 IP.
    if len(ips) != 1:
        raise SystemExit(f"expected exactly one IP, got {ips!r}")

    print("[+] flag:")
    print(f"{FLAG_PREFIX}{{{ips[0]}}}")


if __name__ == "__main__":
    main()
```

## Flag

```text
$N1PH€RSxTCTF{149.28.81.19}
```
