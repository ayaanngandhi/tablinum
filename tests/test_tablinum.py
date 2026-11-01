#!/usr/bin/env python3
"""Tests for Tablinum. Standard library only — run with:

    .venv/bin/python -m unittest discover -s tests -v

Covers the parts that must never silently regress: profile config, glob
matching, dotenv loading, session token integrity, throttling, path containment,
per-profile authorisation, and the build guard that stops a locked shelf from
being exported in the clear.
"""

import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
import re
import urllib.parse
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tablinum as T  # noqa: E402

# Keep tests away from the project's real auth.json, and make session keys
# deterministic per run without touching disk.
os.environ["TABLINUM_SECRET"] = "ab" * 32
T.AUTH_PATH = os.path.join(tempfile.mkdtemp(), "auth.json")


def book(**specs):
    """Build a ProfileBook. Each kwarg is a password, or (password, include)."""
    data = {
        "default": {"include": ["*"], "password_env": "TABLINUM_PASSWORD"},
        "profiles": [],
    }
    env = {}
    for name, spec in specs.items():
        if name == "default":
            if spec is None:
                continue
            password, include = spec if isinstance(spec, tuple) else (spec, ["*"])
            data["default"]["include"] = list(include)
            env["TABLINUM_PASSWORD"] = password
        else:
            entry = {
                "name": name,
                "include": ["*"],
                "password_env": "TABLINUM_PASSWORD_" + name.upper().replace("-", "_"),
            }
            if spec is not None:
                password, include = spec if isinstance(spec, tuple) else (spec, ["*"])
                entry["include"] = list(include)
                env[entry["password_env"]] = password
            data["profiles"].append(entry)
    return T.ProfileBook.from_mapping(data, env)


def start_server(root, profiles, cfg=None):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0),
                                T.make_handler(root, cfg or {}, profiles, False))
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


class GlobTests(unittest.TestCase):
    def test_star_matches_nested_paths(self):
        self.assertTrue(T.matches("short-term/saarthi-v7/review.html", ["*"]))
        self.assertTrue(T.matches("a/b/c.txt", ["*"]))

    def test_folder_star_includes_nested_files(self):
        self.assertTrue(T.matches("short-term/a.html", ["short-term/*"]))
        self.assertTrue(T.matches("short-term/deep/b.png", ["short-term/*"]))
        self.assertFalse(T.matches("secret/hidden.pdf", ["short-term/*"]))

    def test_exact_path(self):
        self.assertTrue(T.matches("short-term/a.html", ["short-term/a.html"]))
        self.assertFalse(T.matches("short-term/a.html", ["short-term/b.html"]))

    def test_question_mark_is_one_character(self):
        self.assertTrue(T.matches("a.html", ["?.html"]))
        self.assertFalse(T.matches("ab.html", ["?.html"]))

    def test_case_insensitive(self):
        self.assertTrue(T.matches("Short-Term/A.HTML", ["short-term/*"]))
        self.assertTrue(T.matches("notes/ReadMe.md", ["NOTES/readme.MD"]))

    def test_empty_pattern_list_matches_nothing(self):
        self.assertFalse(T.matches("anything.txt", []))

    def test_leading_slash_and_dot_slash_stripped(self):
        self.assertTrue(T.matches("a.html", ["/a.html"]))
        self.assertTrue(T.matches("a.html", ["./a.html"]))
        self.assertTrue(T.matches("deep/a.html", ["./deep/*"]))

    def test_dotdot_rejected(self):
        with self.assertRaises(T.ConfigError):
            T.matches("x.txt", ["../x.txt"])
        with self.assertRaises(T.ConfigError):
            T.ProfileBook.from_mapping(
                {"default": {"include": ["a/../x"], "password_env": "P"}}, {"P": "pw"})


class ConfigTests(unittest.TestCase):
    def test_default_only_file_works(self):
        b = T.ProfileBook.from_mapping(
            {"default": {"include": ["*"], "password_env": "P"}}, {"P": "pw"})
        self.assertTrue(b)
        self.assertIn("default", b.profiles)
        self.assertIsNotNone(b.default)
        self.assertEqual(b.default.name, "default")

    def test_unset_env_disables_a_profile(self):
        data = {
            "default": {"include": ["*"], "password_env": "P"},
            "profiles": [{"name": "shared", "include": ["s/*"], "password_env": "Q"}],
        }
        b = T.ProfileBook.from_mapping(data, {"Q": "shared-pw"})
        self.assertTrue(b)
        self.assertNotIn("default", b.profiles)
        self.assertIsNone(b.get("default"))
        self.assertIsNotNone(b.default)
        self.assertFalse(b.default.enabled)
        self.assertIn("shared", b.profiles)

    def test_missing_include_raises(self):
        with self.assertRaises(T.ConfigError):
            T.ProfileBook.from_mapping(
                {"default": {"password_env": "P"}}, {"P": "pw"})

    def test_missing_password_env_raises(self):
        with self.assertRaises(T.ConfigError):
            T.ProfileBook.from_mapping({"default": {"include": ["*"]}}, {})

    def test_bad_profile_name_raises(self):
        for name in ("Shared", "../x", "", "a" * 33):
            with self.assertRaises(T.ConfigError, msg=name):
                T.ProfileBook.from_mapping({
                    "default": {"include": ["*"], "password_env": "P"},
                    "profiles": [{"name": name, "include": ["*"], "password_env": "Q"}],
                }, {"P": "pw", "Q": "other"})

    def test_duplicate_profile_name_raises(self):
        with self.assertRaises(T.ConfigError):
            T.ProfileBook.from_mapping({
                "default": {"include": ["*"], "password_env": "P"},
                "profiles": [
                    {"name": "shared", "include": ["*"], "password_env": "Q"},
                    {"name": "shared", "include": ["*"], "password_env": "R"},
                ],
            }, {"P": "pw", "Q": "one", "R": "two"})

    def test_duplicate_enabled_password_names_both_env_vars(self):
        data = {
            "default": {"include": ["*"], "password_env": "TABLINUM_PASSWORD"},
            "profiles": [{"name": "shared", "include": ["*"],
                          "password_env": "TABLINUM_PASSWORD_SHARED"}],
        }
        with self.assertRaises(T.ConfigError) as caught:
            T.ProfileBook.from_mapping(
                data, {"TABLINUM_PASSWORD": "same-secret",
                       "TABLINUM_PASSWORD_SHARED": "same-secret"})
        message = str(caught.exception)
        self.assertIn("TABLINUM_PASSWORD", message)
        self.assertIn("TABLINUM_PASSWORD_SHARED", message)
        self.assertNotIn("same-secret", message)


class EnvTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, ".env")

    def test_comments_blank_lines_export_and_quotes(self):
        with open(self.path, "w") as fh:
            fh.write("# a comment\n\nA=1\nexport B=two\nC='three'\nD=\"four five\"\n")
        got = T.load_env(self.path)
        self.assertEqual(got, {"A": "1", "B": "two", "C": "three", "D": "four five"})

    def test_missing_file_is_empty(self):
        self.assertEqual(T.load_env(os.path.join(self.tmp, "nope")), {})

    def test_real_environment_wins(self):
        os.environ["TABLINUM_TEST_ENV_KEY"] = "real"
        try:
            with open(self.path, "w") as fh:
                fh.write("TABLINUM_TEST_ENV_KEY=from-file\nOTHER=kept\n")
            got = T.load_env(self.path)
            self.assertNotIn("TABLINUM_TEST_ENV_KEY", got)
            self.assertEqual(got["OTHER"], "kept")
        finally:
            os.environ.pop("TABLINUM_TEST_ENV_KEY", None)


class SessionTests(unittest.TestCase):
    def test_session_token_carries_the_profile(self):
        s = T.Sessions(os.urandom(32).hex(), hours=1)
        token, ttl = s.issue("shared")
        self.assertEqual(ttl, 3600)
        self.assertEqual(token.count("."), 3)
        self.assertEqual(s.valid(token), "shared")
        self.assertIsNone(s.valid(None))
        self.assertIsNone(s.valid(""))
        self.assertIsNone(s.valid("garbage"))
        self.assertIsNone(s.valid(token + "0"))            # tampered signature
        self.assertIsNone(T.Sessions(os.urandom(32).hex()).valid(token))  # wrong key

    def test_tampering_with_the_profile_invalidates_it(self):
        s = T.Sessions(os.urandom(32).hex(), hours=1)
        token, _ = s.issue("shared")
        exp, _profile, nonce, sig = token.split(".")
        self.assertIsNone(s.valid(f"{exp}.default.{nonce}.{sig}"))

    def test_old_two_field_token_rejected(self):
        s = T.Sessions(os.urandom(32).hex(), hours=1)
        self.assertIsNone(s.valid("123.nonce.sig"))

    def test_expired_session_rejected(self):
        s = T.Sessions(os.urandom(32).hex(), hours=0)
        token, _ = s.issue("default")
        self.assertIsNone(s.valid(token))

    def test_extended_expiry_rejected(self):
        s = T.Sessions(os.urandom(32).hex(), hours=1)
        token, _ = s.issue("default")
        exp, profile, nonce, sig = token.split(".")
        self.assertIsNone(s.valid(f"{int(exp) + 60}.{profile}.{nonce}.{sig}"))


class CleanTextTests(unittest.TestCase):
    def test_clean_text(self):
        self.assertEqual(T.clean_text("plain"), "plain")
        self.assertEqual(T.clean_text(" spaces kept "), " spaces kept ")
        self.assertIsNone(T.clean_text(None))
        self.assertIsNone(T.clean_text("nul\x00byte"))
        self.assertIsNone(T.clean_text("new\nline"))
        self.assertIsNone(T.clean_text("x" * (T.MAX_PASSWORD_LEN + 1)))


class RateLimiterTests(unittest.TestCase):
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

    def test_rel_after_alias_resolution(self):
        target = T.resolve(self.root, "/files/a")
        self.assertEqual(T.rel_to(self.root, target), "a.html")

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
        cls.book = book(default="correct-horse-battery-staple")
        cls.httpd, cls.port = start_server(cls.root, cls.book)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        self.c = Fake(self.port)

    def _csrf(self):
        status, _headers, body = self.c.request("GET", "/login")
        self.assertEqual(status, 200)
        m = re.search(r'name="csrf" value="([^"]+)"', body.decode())
        self.assertTrue(m, "the login form must carry a csrf token")
        return m.group(1)

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
        self.assertNotIn("shared", text.lower())

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
        self.assertIn(b"default", body)

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
        self.assertNotIn(b"password_hash", body)  # never leaks the old hash

    def test_login_sets_only_the_session_cookie(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/login")
        resp = conn.getresponse()
        page = resp.read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        body = urllib.parse.urlencode({"csrf": csrf, "password": "correct-horse-battery-staple"})
        conn.request("POST", "/login", body=body,
                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        resp.read()
        cookies = resp.headers.get_all("Set-Cookie") or []
        origins = [c.split(";")[0].split("=", 1)[0].strip() for c in cookies]
        self.assertEqual(resp.status, 303)
        self.assertIn(T.COOKIE, origins)
        # the CSRF token travels in the form only — a second cookie is a second
        # thing to desynchronise, and that is exactly how the login died
        self.assertNotIn(T.CSRF_COOKIE, origins)
        for c in cookies:
            self.assertNotIn(",", c.split(";")[0], f"cookie value contains a comma: {c}")
        conn.close()

    def test_healthz_is_open(self):
        status, _h, body = self.c.request("GET", "/healthz")
        self.assertEqual((status, body.strip()), (200, b"ok"))


class ProfileAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.root = os.path.join(cls.tmp, "files")
        os.makedirs(os.path.join(cls.root, "short-term", "deep"))
        os.makedirs(os.path.join(cls.root, "secret"))
        for name, content in (
            ("top.txt", b"top"),
            (os.path.join("short-term", "note.html"), b"<h1>note</h1>"),
            (os.path.join("short-term", "deep", "img.png"), b"png"),
            (os.path.join("secret", "hidden.pdf"), b"pdf"),
        ):
            with open(os.path.join(cls.root, name), "wb") as fh:
                fh.write(content)
        cls.book = book(default="default-pw", shared=("shared-pw", ["short-term/*"]))
        cls.httpd, cls.port = start_server(cls.root, cls.book)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def setUp(self):
        self.c = Fake(self.port)

    def _csrf(self):
        status, _headers, body = self.c.request("GET", "/login")
        self.assertEqual(status, 200)
        return re.search(r'name="csrf" value="([^"]+)"', body.decode()).group(1)

    def login(self, password):
        return self.c.request("POST", "/login",
                              {"csrf": self._csrf(), "password": password})

    def index(self):
        status, _h, body = self.c.request("GET", "/")
        self.assertEqual(status, 200)
        return body.decode()

    def test_shared_sees_only_its_shelf(self):
        self.assertEqual(self.login("shared-pw")[0], 303)
        text = self.index()
        self.assertIn("note.html", text)
        self.assertIn("img.png", text)
        self.assertNotIn("hidden.pdf", text)
        self.assertNotIn("top.txt", text)
        self.assertIn("signed in as", text)
        self.assertIn("shared", text)

    def test_shared_can_fetch_its_own_file(self):
        self.login("shared-pw")
        status, _h, body = self.c.request("GET", "/files/short-term/note")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"<h1>note</h1>")

    def test_shared_gets_404_off_its_shelf(self):
        self.login("shared-pw")
        for path in ("/files/secret/hidden.pdf", "/files/secret/hidden",
                     "/files/top.txt"):
            status, _h, body = self.c.request("GET", path)
            self.assertEqual(status, 404, path)
            self.assertIn(b"Not found", body)

    def test_default_sees_everything(self):
        self.assertEqual(self.login("default-pw")[0], 303)
        text = self.index()
        for name in ("note.html", "img.png", "hidden.pdf", "top.txt"):
            self.assertIn(name, text)
        status, _h, body = self.c.request("GET", "/files/secret/hidden.pdf")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"pdf")

    def test_unknown_profile_name_in_token_is_rejected(self):
        self.login("shared-pw")
        token = self.c.cookies[T.COOKIE]
        exp, _profile, nonce, sig = token.split(".")
        # sign a token for a profile that is no longer in the book
        session = T.Sessions(os.environ["TABLINUM_SECRET"], hours=1)
        forged = f"{exp}.gone.{nonce}.{session._sign(f'{exp}.gone.{nonce}')}"
        self.c.cookies[T.COOKIE] = forged
        status, headers, _ = self.c.request("GET", "/")
        self.assertEqual(status, 303)
        self.assertEqual(headers.get("Location"), "/login")
        self.assertNotIn(T.COOKIE, self.c.cookies)


class NoAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.root = os.path.join(cls.tmp, "files")
        os.makedirs(os.path.join(cls.root, "secret"))
        for name in ("top.txt", os.path.join("secret", "hidden.pdf")):
            with open(os.path.join(cls.root, name), "w") as fh:
                fh.write("x")
        cls.httpd, cls.port = start_server(cls.root, None)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def test_no_auth_serves_everything_without_sign_out(self):
        c = Fake(self.port)
        status, _h, body = c.request("GET", "/")
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertIn("public shelf", text)
        self.assertNotIn("sign out", text)
        self.assertEqual(c.request("GET", "/files/secret/hidden.pdf")[0], 200)


class CsrfRecoveryTests(ServerTests):
    """The bug that made a correct password look wrong.

    A failed login re-rendered the form with a brand-new CSRF token but did not
    refresh the cookie, so every retry from that page failed with 400 "session
    expired" no matter what was typed. Own server class = its own rate limiter.
    """

    def test_retry_after_a_wrong_password_uses_the_same_token(self):
        csrf = self._csrf()
        status, _h, _b = self.c.request("POST", "/login", {"csrf": csrf, "password": "wrong"})
        self.assertEqual(status, 401)
        status, _h, _b = self.c.request("POST", "/login",
                                        {"csrf": csrf, "password": "correct-horse-battery-staple"})
        self.assertEqual(status, 303)
        self.assertIn(T.COOKIE, self.c.cookies)

    def test_token_survives_the_page_being_fetched_again(self):
        # a reload, a second tab, or an edge prefetch must not invalidate the
        # form that is already on screen
        csrf = self._csrf()
        for _ in range(3):
            self._csrf()
        status, _h, _b = self.c.request("POST", "/login",
                                        {"csrf": csrf, "password": "correct-horse-battery-staple"})
        self.assertEqual(status, 303)

    def test_correct_password_after_two_failures(self):
        for _ in range(2):
            self.c.request("POST", "/login", {"csrf": self._csrf(), "password": "nope"})
        status, _h, _b = self.c.request("POST", "/login",
                                        {"csrf": self._csrf(), "password": "correct-horse-battery-staple"})
        self.assertEqual(status, 303)
        self.assertEqual(self.c.request("GET", "/")[0], 200)

    def test_a_forged_or_expired_token_is_still_rejected(self):
        for bad in ("123.deadbeef", "0." + "0" * 32, "no-dot-here", ""):
            status, _h, _b = self.c.request("POST", "/login",
                                            {"csrf": bad, "password": "correct-horse-battery-staple"})
            self.assertEqual(status, 400, f"accepted a forged token: {bad!r}")
            self.assertNotIn(T.COOKIE, self.c.cookies)


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
    def test_static_export_refuses_while_profiles_exist(self):
        tmp = tempfile.mkdtemp()
        root = os.path.join(tmp, "files")
        os.makedirs(root)
        with open(os.path.join(root, "x.html"), "w") as fh:
            fh.write("x")
        original_profiles = T.PROFILES_PATH
        original_env = T.ENV_PATH
        try:
            T.PROFILES_PATH = os.path.join(tmp, "profiles.json")
            T.ENV_PATH = os.path.join(tmp, ".env")
            with open(T.PROFILES_PATH, "w") as fh:
                json.dump({"default": {"include": ["*"],
                                       "password_env": "TABLINUM_BUILD_TEST_PW"}}, fh)
            os.environ["TABLINUM_BUILD_TEST_PW"] = "pw"
            code = T.build(root, os.path.join(tmp, "dist"), allow_public=False)
            self.assertEqual(code, 4)
            self.assertFalse(os.path.exists(os.path.join(tmp, "dist")))
            code = T.build(root, os.path.join(tmp, "dist"), allow_public=True)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.exists(os.path.join(tmp, "dist", "files", "x.html")))
            with open(os.path.join(tmp, "dist", "index.html")) as fh:
                self.assertNotIn("sign out", fh.read())
        finally:
            T.PROFILES_PATH = original_profiles
            T.ENV_PATH = original_env
            os.environ.pop("TABLINUM_BUILD_TEST_PW", None)

    def test_auth_file_is_0600_and_holds_no_password(self):
        tmp = tempfile.mkdtemp()
        original = T.AUTH_PATH
        try:
            T.AUTH_PATH = os.path.join(tmp, "auth.json")
            T.write_auth({"secret": "ab" * 32, "session_hours": 12, "updated": 0})
            mode = oct(os.stat(T.AUTH_PATH).st_mode & 0o777)
            self.assertEqual(mode, "0o600")
            with open(T.AUTH_PATH) as fh:
                data = json.load(fh)
            self.assertEqual(data["secret"], "ab" * 32)
            self.assertNotIn("password_hash", data)
        finally:
            T.AUTH_PATH = original

    def test_load_secret_upgrades_an_old_auth_file(self):
        tmp = tempfile.mkdtemp()
        original = T.AUTH_PATH
        saved = os.environ.pop("TABLINUM_SECRET", None)
        try:
            T.AUTH_PATH = os.path.join(tmp, "auth.json")
            secret = "cd" * 32
            with open(T.AUTH_PATH, "w") as fh:
                json.dump({"password_hash": "$2b$old", "secret": secret,
                           "session_hours": 7}, fh)
            got = T.load_secret()
            self.assertEqual(got["secret"], secret)
            with open(T.AUTH_PATH) as fh:
                data = json.load(fh)
            self.assertNotIn("password_hash", data)
            self.assertEqual(data["secret"], secret)
            self.assertEqual(data["session_hours"], 7)
        finally:
            T.AUTH_PATH = original
            if saved is not None:
                os.environ["TABLINUM_SECRET"] = saved


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
