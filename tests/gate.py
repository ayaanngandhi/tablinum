#!/usr/bin/env python3
"""Standalone end-to-end gate for Tablinum profiles.

Prints exactly one line and exits 0 or 1:
    GATE_PASS
    GATE_FAIL: <reason>
"""

import http.client
import os
import re
import sys
import tempfile
import threading
import urllib.parse
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tablinum as T  # noqa: E402


class GateFailure(Exception):
    pass


def check(condition, reason):
    if not condition:
        raise GateFailure(reason)


class Client:
    def __init__(self, port):
        self.port = port
        self.cookies = {}

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urllib.parse.urlencode(body)
        conn.request(method, path, body=body.encode() if isinstance(body, str) else body,
                     headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        for raw in resp.headers.get_all("Set-Cookie") or []:
            pair = raw.split(";")[0]
            if "=" in pair:
                key, value = pair.split("=", 1)
                if value in ("", '""'):
                    self.cookies.pop(key.strip(), None)
                else:
                    self.cookies[key.strip()] = value
        result = (resp.status, dict(resp.getheaders()), data)
        conn.close()
        return result

    def login(self, password):
        status, _headers, body = self.request("GET", "/login")
        check(status == 200, f"GET /login returned {status}")
        match = re.search(r'name="csrf" value="([^"]+)"', body.decode())
        check(match is not None, "login form had no csrf token")
        status, _headers, _body = self.request(
            "POST", "/login", {"csrf": match.group(1), "password": password})
        check(status == 303, f"login as {password!r} returned {status}")
        check(T.COOKIE in self.cookies, "login did not set a session cookie")


def main():
    tmp = tempfile.mkdtemp()
    root = os.path.join(tmp, "files")
    os.makedirs(os.path.join(root, "short-term", "deep"))
    os.makedirs(os.path.join(root, "secret"))
    for name, content in (
        ("top.txt", b"top"),
        (os.path.join("short-term", "note.html"), b"<h1>note</h1>"),
        (os.path.join("short-term", "deep", "img.png"), b"png"),
        (os.path.join("secret", "hidden.pdf"), b"pdf"),
    ):
        with open(os.path.join(root, name), "wb") as fh:
            fh.write(content)

    os.environ["TABLINUM_SECRET"] = "ab" * 32
    os.environ["TABLINUM_PASSWORD"] = "gate-default"
    os.environ["TABLINUM_PASSWORD_SHARED"] = "gate-shared"
    data = {
        "default": {"include": ["*"], "password_env": "TABLINUM_PASSWORD"},
        "profiles": [{"name": "shared", "include": ["short-term/*"],
                      "password_env": "TABLINUM_PASSWORD_SHARED"}],
    }
    env = {"TABLINUM_PASSWORD": "gate-default",
           "TABLINUM_PASSWORD_SHARED": "gate-shared"}
    profiles = T.ProfileBook.from_mapping(data, env)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0),
                                T.make_handler(root, {}, profiles, False))
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    client = Client(port)
    try:
        client.login("gate-shared")
        status, _headers, body = client.request("GET", "/")
        check(status == 200, f"shared index returned {status}")
        text = body.decode()
        check("note.html" in text, "shared index is missing note.html")
        check("img.png" in text, "shared index is missing img.png")
        check("hidden.pdf" not in text, "shared index leaks hidden.pdf")
        check("top.txt" not in text, "shared index leaks top.txt")

        status, _headers, body = client.request("GET", "/files/short-term/note")
        check(status == 200 and body == b"<h1>note</h1>",
              f"shared's own file returned {status}")
        status, _headers, _body = client.request("GET", "/files/secret/hidden.pdf")
        check(status == 404, f"off-shelf file returned {status}, expected 404")

        status, _headers, _body = client.request("POST", "/logout", "")
        check(status == 303, f"logout returned {status}")
        status, headers, _body = client.request("GET", "/")
        check(status == 303 and headers.get("Location") == "/login",
              "after logout the index was not gated")

        client.login("gate-default")
        status, _headers, body = client.request("GET", "/files/secret/hidden.pdf")
        check(status == 200 and body == b"pdf",
              f"default could not read hidden.pdf ({status})")
    except GateFailure as exc:
        print(f"GATE_FAIL: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001 - a gate must never traceback
        print(f"GATE_FAIL: {type(exc).__name__}: {exc}")
        return 1
    finally:
        httpd.shutdown()
    print("GATE_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
