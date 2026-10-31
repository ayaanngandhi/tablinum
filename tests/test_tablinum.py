#!/usr/bin/env python3
"""Tests for Tablinum. Standard library only — run with:

    .venv/bin/python -m unittest discover -s tests -v

Covers the parts that must never silently regress: password handling, session
token integrity, throttling, path containment, and the build guard that stops a
locked shelf from being exported in the clear.
"""

import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tablinum as T  # noqa: E402


def start_server(root, auth, cfg=None):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), T.make_handler(root, cfg or {}, auth, False))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


class Fake:
    """Tiny HTTP client that keeps cookies, so flows can be followed."""

    def __init__(self, port):
        self.port = port
        self.cookies = {}

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = dict(headers or {})
        if self.cookies:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if body is not None:
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
            if isinstance(body, dict):
                body = urllib.parse.urlencode(body)
        conn.request(method, path, body=(body.encode() if isinstance(body, str) else body), headers=hdrs)
        resp = conn.getresponse()
        data = resp.read()
        for raw in resp.headers.get_all("Set-Cookie") or []:
            pair = raw.split(";")[0]
            if "=" in pair:
                k, v = pair.split("=", 1)
                if v in ("", '""'):
                    self.cookies.pop(k.strip(), None)
                else:
                    self.cookies[k.strip()] = v
        conn.close()
        return resp.status, dict(resp.getheaders()), data


class UnitTests(unittest.TestCase):
    def test_password_round_trip(self):
        h = T.hash_password("correct-horse-battery-staple", rounds=4)
        self.assertTrue(h.startswith("$2"))
        self.assertNotIn("correct", h)          # the password itself is never stored
        self.assertTrue(T.verify_password("correct-horse-battery-staple", h))
        self.assertFalse(T.verify_password("correct-horse-battery-stapl", h))
        self.assertFalse(T.verify_password("", h))
        self.assertFalse(T.verify_password("x", "not-a-hash"))  # malformed hash, no crash

    def test_session_token_integrity(self):
        s = T.Sessions(os.urandom(32).hex(), hours=1)
        token, ttl = s.issue()
        self.assertTrue(s.valid(token))
        self.assertEqual(ttl, 3600)
        self.assertFalse(s.valid(None))
        self.assertFalse(s.valid(""))
        self.assertFalse(s.valid("garbage"))
        self.assertFalse(s.valid(token + "0"))            # tampered signature
        exp, nonce, sig = token.split(".")
        self.assertFalse(s.valid(f"{int(exp) + 60}.{nonce}.{sig}"))  # extended expiry
        self.assertFalse(T.Sessions(os.urandom(32).hex()).valid(token))  # wrong key

    def test_expired_session_rejected(self):
        s = T.Sessions(os.urandom(32).hex(), hours=0)
        token, _ = s.issue()
        self.assertFalse(s.valid(token))

    def test_clean_text(self):
        self.assertEqual(T.clean_text("plain"), "plain")
        self.assertEqual(T.clean_text(" spaces kept "), " spaces kept ")
        self.assertIsNone(T.clean_text(None))
        self.assertIsNone(T.clean_text("nul\x00byte"))
        self.assertIsNone(T.clean_text("new\nline"))
        self.assertIsNone(T.clean_text("x" * (T.MAX_PASSWORD_LEN + 1)))

    def test_rate_limiter_backoff(self):
        rl = T.RateLimiter(per_ip_limit=3, global_limit=100, window=60, max_delay=300)
        for _ in range(3):
            self.assertEqual(rl.blocked_for("1.2.3.4"), 0)
            rl.record_failure("1.2.3.4")
        self.assertGreater(rl.blocked_for("1.2.3.4"), 0)
        self.assertEqual(rl.blocked_for("9.9.9.9"), 0)  # other clients unaffected
        rl.reset("1.2.3.4")
        self.assertEqual(rl.blocked_for("1.2.3.4"), 0)


class ResolveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "files")
        os.makedirs(os.path.join(self.root, "sub"))
        for name in ("a.html", "b.pdf", os.path.join("sub", "c.txt")):
            with open(os.path.join(self.root, name), "w") as fh:
                fh.write("x")
        with open(os.path.join(self.tmp, "secret.txt"), "w") as fh:
            fh.write("outside the shelf")

    def test_normal_paths(self):
        self.assertTrue(T.resolve(self.root, "/files/a.html").endswith("a.html"))
        self.assertTrue(T.resolve(self.root, "/files/sub/c.txt").endswith("c.txt"))

    def test_extensionless_html_alias(self):
        self.assertTrue(T.resolve(self.root, "/files/a").endswith("a.html"))
        self.assertIsNone(T.resolve(self.root, "/files/nope"))

    def test_traversal_blocked(self):
        for attack in (
            "/files/../secret.txt",
            "/files/../../etc/passwd",
            "/files/sub/../../secret.txt",
            "/files/%2e%2e/secret.txt",
            "/files/..%2fsecret.txt",
            "/files//etc/passwd",
        ):
            self.assertIsNone(T.resolve(self.root, attack), attack)

    def test_prefix_outside_root_blocked(self):
        sibling = self.root + "-evil"
        os.makedirs(sibling, exist_ok=True)
        with open(os.path.join(sibling, "x.txt"), "w") as fh:
            fh.write("x")
        self.assertIsNone(T.resolve(self.root, "/files/../files-evil/x.txt"))

    def test_mount_prefix_required(self):
        self.assertIsNone(T.resolve(self.root, "/a.html"))
        self.assertIsNone(T.resolve(self.root, "/"))


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.root = os.path.join(cls.tmp, "files")
        os.makedirs(cls.root)
        with open(os.path.join(cls.root, "notes.html"), "w") as fh:
            fh.write("<h1>hello</h1>")
        cls.auth = {
            "password_hash": T.hash_password("correct-horse-battery-staple", rounds=4),
            "secret": os.urandom(32).hex(),
            "session_hours": 1,
        }
        cls.httpd, cls.port = start_server(cls.root, cls.auth)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        self.c = Fake(self.port)

    def _csrf(self):
        status, _headers, body = self.c.request("GET", "/login")
        self.assertEqual(status, 200)
        token = self.c.cookies.get(T.CSRF_COOKIE)
        self.assertTrue(token)
        return token

    def login(self, password="correct-horse-battery-staple"):
        csrf = self._csrf()
        return self.c.request("POST", "/login", {"csrf": csrf, "password": password})


class AuthFlowTests(ServerTests):
    def test_index_requires_login(self):
        status, headers, _ = self.c.request("GET", "/")
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("Location"), "/login")

    def test_file_requires_login(self):
        status, headers, _ = self.c.request("GET", "/files/notes")
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("Location"), "/login")

    def test_login_page_has_csrf_and_no_password_field_value(self):
        status, headers, body = self.c.request("GET", "/login")
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn('name="password"', text)
        self.assertIn('type="password"', text)
        self.assertIn("form-action 'self'", headers.get("Content-Security-Policy", ""))
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")

    def test_wrong_password_rejected(self):
        status, _headers, body = self.login("wrong-password")
        self.assertEqual(status, 401)
        self.assertIn("not right", body.decode())
        self.assertNotIn(T.COOKIE, self.c.cookies)

    def test_missing_csrf_rejected(self):
        status, _headers, _ = self.c.request("POST", "/login", {"password": "correct-horse-battery-staple"})
        self.assertEqual(status, 400)
        self.assertNotIn(T.COOKIE, self.c.cookies)

    def test_non_form_content_type_rejected(self):
        status, _headers, _ = self.c.request(
            "POST", "/login", "password=x", {"Content-Type": "application/json"})
        self.assertEqual(status, 415)

    def test_oversized_body_rejected(self):
        status, _headers, _ = self.c.request("POST", "/login", "x" * (T.MAX_BODY + 10))
        self.assertEqual(status, 413)

    def test_successful_login_grants_access(self):
        status, headers, _ = self.login()
        self.assertEqual(status, 303)
        self.assertIn(T.COOKIE, self.c.cookies)
        # two cookies must arrive as two Set-Cookie headers — joined with a comma
        # a real browser keeps only the first, and the session is quietly lost
        raw = headers.get("Set-Cookie", "")
        self.assertNotIn(", tablinum_csrf", raw)
        cookie = headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

        status, _h, body = self.c.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"notes.html", body)
        self.assertIn(b"sign out", body)

        status, _h, body = self.c.request("GET", "/files/notes")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"<h1>hello</h1>")

    def test_noindex_and_security_headers(self):
        self.login()
        _status, headers, body = self.c.request("GET", "/")
        self.assertIn("noindex", body.decode())
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")
        self.assertIn("nonce-", headers.get("Content-Security-Policy", ""))

    def test_logout_clears_session(self):
        self.login()
        self.assertEqual(self.c.request("GET", "/")[0], 200)
        status, _h, _b = self.c.request("POST", "/logout", "")
        self.assertEqual(status, 303)
        self.assertNotIn(T.COOKIE, self.c.cookies)
        self.assertEqual(self.c.request("GET", "/")[0], 303)

    def test_tampered_cookie_rejected(self):
        self.login()
        token = self.c.cookies[T.COOKIE]
        self.c.cookies[T.COOKIE] = token[:-1] + ("0" if token[-1] != "0" else "1")
        self.assertEqual(self.c.request("GET", "/")[0], 303)

    def test_traversal_needs_a_login_first(self):
        self.assertEqual(self.c.request("GET", "/files/../auth.json")[0], 303)
        self.login()
        status, _h, body = self.c.request("GET", "/files/../auth.json")
        self.assertIn(status, (404, 200))
        self.assertNotIn(b"password_hash", body)  # never leaks the hash

    def test_login_sends_one_set_cookie_header_per_cookie(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/login")
        resp = conn.getresponse()
        csrf = resp.headers["Set-Cookie"].split(";")[0].split("=", 1)[1]
        resp.read()
        body = urllib.parse.urlencode({"csrf": csrf, "password": "correct-horse-battery-staple"})
        conn.request("POST", "/login", body=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "Cookie": f"{T.CSRF_COOKIE}={csrf}"})
        resp = conn.getresponse()
        resp.read()
        cookies = resp.headers.get_all("Set-Cookie") or []
        origins = [c.split(";")[0].split("=", 1)[0].strip() for c in cookies]
        self.assertEqual(resp.status, 303)
        self.assertIn(T.COOKIE, origins)
        for c in cookies:
            self.assertNotIn(",", c.split(";")[0], f"cookie value contains a comma: {c}")
        conn.close()

    def test_healthz_is_open(self):
        status, _h, body = self.c.request("GET", "/healthz")
        self.assertEqual((status, body.strip()), (200, b"ok"))


class ThrottleTests(ServerTests):
    def test_repeated_failures_are_throttled(self):
        for _ in range(T.RateLimiter().per_ip_limit):
            status, _h, _b = self.login("nope")
            self.assertIn(status, (401, 429))
        status, headers, _b = self.login("nope")
        self.assertEqual(status, 429)
        self.assertIn("Retry-After", headers)

    def test_throttle_blocks_a_correct_password_too(self):
        # brute-force protection must not be bypassable by guessing right afterwards
        for _ in range(T.RateLimiter().per_ip_limit + 1):
            self.login("nope")
        status, _h, _b = self.login()
        self.assertEqual(status, 429)


class BuildGuardTests(unittest.TestCase):
    def test_static_export_refuses_while_locked(self):
        tmp = tempfile.mkdtemp()
        root = os.path.join(tmp, "files")
        os.makedirs(root)
        with open(os.path.join(root, "x.html"), "w") as fh:
            fh.write("x")
        original = T.AUTH_PATH
        try:
            T.AUTH_PATH = os.path.join(tmp, "auth.json")
            T.write_auth({"password_hash": T.hash_password("pw", rounds=4),
                          "secret": os.urandom(32).hex()})
            code = T.build(root, os.path.join(tmp, "dist"), allow_public=False)
            self.assertEqual(code, 4)
            self.assertFalse(os.path.exists(os.path.join(tmp, "dist")))
            code = T.build(root, os.path.join(tmp, "dist"), allow_public=True)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(os.path.join(tmp, "dist", "files", "x.html")))
            with open(os.path.join(tmp, "dist", "index.html")) as fh:
                self.assertNotIn("sign out", fh.read())
        finally:
            T.AUTH_PATH = original

    def test_auth_file_is_0600(self):
        tmp = tempfile.mkdtemp()
        original = T.AUTH_PATH
        try:
            T.AUTH_PATH = os.path.join(tmp, "auth.json")
            T.write_auth({"password_hash": T.hash_password("pw", rounds=4),
                          "secret": os.urandom(32).hex()})
            mode = oct(os.stat(T.AUTH_PATH).st_mode & 0o777)
            self.assertEqual(mode, "0o600")
            with open(T.AUTH_PATH) as fh:
                data = json.load(fh)
            self.assertTrue(data["password_hash"].startswith("$2"))
        finally:
            T.AUTH_PATH = original


class CollectTests(unittest.TestCase):
    def test_skips_dotfiles_and_venv(self):
        tmp = tempfile.mkdtemp()
        root = os.path.join(tmp, "files")
        os.makedirs(os.path.join(root, ".venv"))
        os.makedirs(os.path.join(root, "docs"))
        for name in ("keep.html", ".hidden", os.path.join(".venv", "gone.txt"),
                     os.path.join("docs", "kept.pdf")):
            with open(os.path.join(root, name), "w") as fh:
                fh.write("x")
        found = {f["rel"] for f in T.collect(root)}
        self.assertEqual(found, {"keep.html", "docs/kept.pdf"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
