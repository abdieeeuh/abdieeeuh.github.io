---
title: "Dead-Air Downlink"
date: 2026-08-22
description: 'Decoding a digital SSTV downlink and its embedded Aztec barcode.'
category: '$n1phers-3-0-ctf'
discipline: 'forensics'
authors: ['abdieeuh']
draft: false
---

## Challenge Overview

The challenge supplies one artifact, `transmission.wav`, and describes an unscheduled satellite downlink that is still transmitting pictures.

The capture is not ordinary audio steganography. It is a digital SSTV/DRM transmission carrying a monochrome image, and that image contains an Aztec barcode.

The deterministic technique chain is:

1. Validate the WAV container, hash and channel framing
2. Separate the silent framing intervals from the central payload
3. Decode the payload as HAMDRM/DSSTV with QSSTV
4. Treat the reconstructed `.jp2` output according to its actual file magic
5. Decode the recovered Aztec barcode

## Challenge Features

| Feature | Forensic relevance |
|---|---|
| PCM stereo WAV | Gives an exact sample rate and reproducible sample offsets. |
| Repeated long silent intervals | Bound the lead-in, central transmission and tail without guessing an offset. |
| Right channel values only `-1` and `0` | Shows that the right channel is a marker channel, not a second image. |
| Digital multicarrier payload | Matches the HAMDRM/DSSTV receiver path rather than analog SSTV modes. |
| Misleading `.jp2` extension | The reconstructed file is actually a 1-bit PNG, confirmed by `file` and the PNG magic bytes. |
| Aztec barcode | Carries the flag as its decoded text. |

## Artifact Validation

The supplied file is a standard 16-bit, stereo, 48-kHz PCM WAV:

```console
$ file transmission.wav
transmission.wav: RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 48000 Hz
```

It contains 1,267,584 stereo frames. The right channel has only the values `-1` and `0`. On the left channel, the long contiguous silent intervals are:

```text
(0, 30720)
(104448, 110592)
(1128192, 1158912)
(1232640, 1267584)
```

At 48 kHz, these intervals bound:

```text
lead-in:  30720 samples  = 0.640 s
payload:  1017600 samples = 21.200 s
tail:     73728 samples  = 1.536 s
```

The payload boundaries are therefore derived from the waveform itself. No random offset, bit alignment or brute-force search is required.

## Initial Analysis

Direct low-bit extraction and file carving do not produce a flag or a normal file header. Common analog SSTV modes such as Martin, Scottie and Robot also do not synchronize.

The central region has a noise-like multicarrier spectrum with coherent pilot-like components. This is consistent with a digital SSTV/DRM waveform. QSSTV is an appropriate decoder because it supports HAMDRM, also called DSSTV, and can receive from a WAV file.

## Decoder Setup

QSSTV is configured with:

```text
transmission mode: DRM
sound input: From file
input clock: 48000 Hz
input file: transmission.wav
```

Internally, QSSTV downsamples the 48-kHz input by four and runs its DRM synchronizer, channel decoder and MOT image reconstruction.

## Recovered Image

QSSTV reconstructs a file named:

```text
20260815175145-payload_raw.jp2
```

The extension is not trustworthy. Its actual type:

```console
$ file 20260815175145-payload_raw.jp2
PNG image data, 540 x 1140, 1-bit colormap, non-interlaced
```

The recovered image is available here:

[recovered_aztec.png](/static/sniphers-3-ctf/recovered_aztec.png)

![Recovered Aztec image](./recovered_aztec.png)

The image contains black padding above and below the barcode. The non-black rows are deterministically located at rows 300 through 839, giving a 540×540 barcode region.

## Barcode Decode

The symbol is an Aztec barcode, not a QR code. ZXing-C++ decodes it without guessing:

```python
from PIL import Image
import numpy as np
import zxingcpp

image = Image.open("20260815175145-payload_raw.jp2").convert("RGB")
pixels = np.asarray(image)
gray = np.asarray(image.convert("L"))
rows = np.flatnonzero(np.any(gray > 0, axis=1))
cropped = pixels[rows[0]:rows[-1] + 1, :]

result = zxingcpp.read_barcodes(cropped)[0]
assert result.format == zxingcpp.BarcodeFormat.Aztec
print(result.text)
```

The output is:

```text
$N1PH€RSxTCTF{d1g1t4l_sstv_4zt3c_d0wnl1nk}
```

The decoded value begins with the required literal prefix `$N1PH€RSxTCTF{` and ends with `}`, independently validating the result.

## Solution

| Stage | Evidence-backed operation | Result |
|---|---|---|
| 1 | Parse the WAV and verify its SHA-256 | Correct 48-kHz stereo capture confirmed |
| 2 | Locate long silent runs | Exact lead-in, payload and tail boundaries |
| 3 | Test ordinary audio stego and analog SSTV | No flag and no valid analog SSTV synchronization |
| 4 | Use QSSTV’s DRM/DSSTV receiver | Reconstructed monochrome image |
| 5 | Inspect file magic rather than trusting `.jp2` | Output identified as a 1-bit PNG |
| 6 | Decode the image as Aztec | Exact flag recovered |

## Reproduction Script

```python
from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import wave

import numpy as np
from PIL import Image
import zxingcpp


FLAG_PREFIX = "$N1PH€RSxTCTF{"
EXPECTED_SHA256 = "938a63905c3078f794df96f06a671c955fd0754eec406c225de3d329e13f113a"
def validate_wav(path: Path) -> None:
    """Check the supplied capture and its deterministic framing."""
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"unexpected capture SHA-256: {digest}")

    with wave.open(str(path), "rb") as wav:
        params = wav.getparams()
        if (params.nchannels, params.sampwidth, params.framerate) != (2, 2, 48000):
            raise ValueError(f"unsupported WAV format: {params}")
        raw = wav.readframes(params.nframes)

    samples = np.frombuffer(raw, dtype="<i2").reshape(-1, 2)
    if len(samples) != 1267584:
        raise ValueError(f"unexpected frame count: {len(samples)}")
    if not set(np.unique(samples[:, 1])).issubset({-1, 0}):
        raise ValueError("right channel is not the expected marker channel")

    # The payload waveforms cross exact zero, so framing is identified by the
    # long contiguous silent intervals rather than by every non-zero sample.
    silent = samples[:, 0] == 0
    starts = np.flatnonzero(silent & ~np.r_[False, silent[:-1]])
    ends = np.flatnonzero(silent & ~np.r_[silent[1:], False]) + 1
    silent_runs = [
        (int(start), int(end))
        for start, end in zip(starts, ends)
        if end - start >= 100
    ]
    expected_silent = [(0, 30720), (104448, 110592), (1128192, 1158912), (1232640, 1267584)]
    if silent_runs != expected_silent:
        raise ValueError(f"unexpected left-channel framing: {silent_runs}")

    print(f"capture: {path}")
    print(f"sha256: {digest}")
    print("format: PCM S16LE, stereo, 48000 Hz")
    print(f"long silent runs: {silent_runs}")


def run_xdotool(display: str, *args: str) -> str:
    result = subprocess.run(
        ["xdotool", *args],
        env={**os.environ, "DISPLAY": display},
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def wait_for_window(display: str, name: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["xdotool", "search", "--onlyvisible", "--name", name],
            env={**os.environ, "DISPLAY": display},
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        ids = result.stdout.split()
        if ids:
            return ids[-1]
        time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for X11 window {name!r}")


def write_qsstv_config(config_home: Path, output_dir: Path) -> None:
    """Create an isolated QSSTV configuration: DRM receive, WAV input."""
    qsstv_dir = config_home / "ON4QZ"
    qsstv_dir.mkdir(parents=True)
    output_dir.mkdir(parents=True)
    config = f"""[MAIN]
transmissionModeIndex=1

[DIRECTORIES]
audioPath={output_dir}
rxDRMImagesPath={output_dir}
rxSSTVImagesPath={output_dir}
txDRMImagesPath={output_dir}
txSSTVImagesPath={output_dir}

[GUI]
confirmClose=false

[HYBRID]
enableHybridRx=false

[SOUND]
alsaSelected=true
inputAudioDevice=lavrate -- Rate Converter Plugin Using Libav/FFmpeg Library
outputAudioDevice=lavrate -- Rate Converter Plugin Using Libav/FFmpeg Library
pulseSelected=false
rxclock=48000
soundRoutingInput=1
soundRoutingOutput=0
txclock=48000
"""
    (qsstv_dir / "qsstv_9.0.conf").write_text(config, encoding="utf-8")


def decode_with_qsstv(wav_path: Path, timeout: float) -> list[tuple[str, bytes]]:
    """Feed the WAV to QSSTV's DRM receiver under an isolated X server."""
    for required in ("qsstv", "Xvfb", "xdotool"):
        if shutil.which(required) is None:
            raise RuntimeError(f"required application is missing: {required}")

    with tempfile.TemporaryDirectory(prefix="qsstv-solve-") as temp:
        root = Path(temp)
        config_home = root / "config"
        output_dir = root / "rx_drm"
        write_qsstv_config(config_home, output_dir)
        env = {
            **os.environ,
            "DISPLAY": "",
            "XDG_CONFIG_HOME": str(config_home),
            "QT_X11_NO_MITSHM": "1",
        }
        xvfb = None
        display = None
        for number in range(90, 150):
            candidate = f":{number}"
            process = subprocess.Popen(
                ["Xvfb", candidate, "-screen", "0", "1400x1000x24"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.2)
            if process.poll() is None:
                xvfb = process
                display = candidate
                break
            process.wait()
        if xvfb is None or display is None:
            raise RuntimeError("could not start Xvfb")

        qsstv = subprocess.Popen(
            ["qsstv"],
            env={**env, "DISPLAY": display},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            dialog = wait_for_window(display, "Wave file", 15)
            run_xdotool(display, "windowfocus", dialog)
            run_xdotool(display, "mousemove", "300", "386", "click", "1")
            run_xdotool(display, "key", "ctrl+a")
            run_xdotool(display, "type", "--delay", "1", str(wav_path))
            time.sleep(0.5)
            # QSSTV's file dialog presents the typed path as the first result.
            run_xdotool(display, "mousemove", "250", "410", "click", "1")
            time.sleep(0.2)
            run_xdotool(display, "mousemove", "625", "387", "click", "1")

            deadline = time.monotonic() + timeout
            decoded: list[Path] = []
            previous_signature: tuple[tuple[str, int], ...] | None = None
            stable_polls = 0
            while time.monotonic() < deadline:
                decoded = [
                    path
                    for path in output_dir.rglob("*")
                    if path.is_file() and path.stat().st_size > 0
                ]
                signature = tuple(sorted((str(path), path.stat().st_size) for path in decoded))
                final_image_exists = any(
                    path.parent == output_dir and path.suffix == ".jp2" for path in decoded
                )
                if signature == previous_signature and signature:
                    stable_polls += 1
                else:
                    stable_polls = 0
                previous_signature = signature
                if final_image_exists and stable_polls >= 3:
                    return [(str(path), path.read_bytes()) for path in decoded]
                if qsstv.poll() is not None:
                    break
                time.sleep(0.2)
            log = ""
            if qsstv.poll() is not None and qsstv.stderr:
                log = qsstv.stderr.read()
            raise RuntimeError(f"QSSTV did not reconstruct an image.\n{log}")
        finally:
            if qsstv.poll() is None:
                qsstv.terminate()
                try:
                    qsstv.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    qsstv.kill()
            if xvfb.poll() is None:
                xvfb.terminate()
                xvfb.wait(timeout=2)


def decode_aztec(images: list[tuple[str, bytes]]) -> str:
    """Read the Aztec symbol from the reconstructed one-bit image."""
    for name, data in images:
        try:
            image = Image.open(io.BytesIO(data)).convert("RGB")
        except Exception:
            continue
        print(f"candidate image: {Path(name).name} ({image.width}x{image.height})")
        array = np.asarray(image)
        candidates = [array]
        gray = np.asarray(image.convert("L"))
        rows = np.flatnonzero(np.any(gray > 0, axis=1))
        if len(rows):
            candidates.append(array[rows[0] : rows[-1] + 1, :])
        for candidate in candidates:
            results = zxingcpp.read_barcodes(candidate)
            for result in results:
                print(f"barcode candidate: {result.format.name}")
                if result.format == zxingcpp.BarcodeFormat.Aztec:
                    return result.text
    raise RuntimeError("no Aztec barcode found in reconstructed image")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wav", type=Path, default=Path(__file__).with_name("transmission.wav"))
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    validate_wav(args.wav)
    images = decode_with_qsstv(args.wav, args.timeout)
    flag = decode_aztec(images)
    if not (flag.startswith(FLAG_PREFIX) and flag.endswith("}")):
        raise RuntimeError(f"decoded barcode is not a flag: {flag!r}")
    print(f"decoded image: {Path(images[0][0]).name}")
    print(f"flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

## Flag

```text
$N1PH€RSxTCTF{d1g1t4l_sstv_4zt3c_d0wnl1nk}
```
