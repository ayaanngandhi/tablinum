#!/usr/bin/env python3
"""
Tablinum — a small document shelf with a lock on the door.

In a Roman house the tablinum was the record room opening off the atrium: the
place the family's papers were kept. This is that room, for files — and unlike a
real tablinum, it can be locked.

    python3 tablinum.py serve --port 6320       # live server, listing files/
    python3 tablinum.py status                  # profiles, files, sessions
    python3 tablinum.py build --out dist        # static export (refuses while locked)

Profiles live in profiles.json; each has its own password, kept in .env, and its
own set of glob patterns over files/. The login asks for a password only — the
password itself says which shelf opens. Sessions are HMAC-signed cookies. No
database, no user accounts, no external services.

Requires: Python 3.8+ and the standard library only.

MIT licensed. https://github.com/ayaanngandhi/tablinum
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import html
import json
import os
import posixpath
import re
import secrets
import shutil
import sys
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping, Sequence
from urllib.parse import quote, unquote, urlsplit

__version__ = "3.0.0"

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.join(HERE, "files")
AUTH_PATH = os.path.join(HERE, "auth.json")
PROFILES_PATH = os.path.join(HERE, "profiles.json")
ENV_PATH = os.path.join(HERE, ".env")
MOUNT = "/files"  # files are always served under this prefix, in both modes

COOKIE = "tablinum_session"
CSRF_COOKIE = "tablinum_csrf"
MAX_BODY = 4096           # a login form is tiny; anything larger is not a login
CSRF_TTL = 3600           # how long a rendered login form stays submittable
MAX_PASSWORD_LEN = 1024

SKIP = {".DS_Store", "Thumbs.db", ".git", "__pycache__", ".venv"}

CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".mp3": "audio/mpeg",
    ".m4a": "audio/mp4",
    ".wav": "audio/wav",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".epub": "application/epub+zip",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}

# badge label + hue class for the file-type chip
BADGES = {
    ".html": ("HTML", "web"), ".htm": ("HTML", "web"),
    ".pdf": ("PDF", "doc"),
    ".md": ("MD", "note"), ".txt": ("TXT", "note"),
    ".csv": ("CSV", "data"), ".json": ("JSON", "data"),
    ".xlsx": ("XLS", "data"), ".docx": ("DOC", "doc"), ".pptx": ("PPT", "doc"),
    ".png": ("PNG", "img"), ".jpg": ("JPG", "img"), ".jpeg": ("JPG", "img"),
    ".webp": ("WEBP", "img"), ".gif": ("GIF", "img"), ".svg": ("SVG", "img"),
    ".mp4": ("MP4", "vid"), ".webm": ("WEBM", "vid"),
    ".mp3": ("MP3", "aud"), ".m4a": ("M4A", "aud"), ".wav": ("WAV", "aud"),
    ".zip": ("ZIP", "bin"), ".epub": ("EPUB", "doc"),
}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


# --------------------------------------------------------------------------
# library scanning
# --------------------------------------------------------------------------

def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB"):
        n /= 1024.0
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if n >= 10 else f"{n:.1f} {unit}"
    return f"{n:.0f} GB"


def collect(root: str) -> list[dict]:
    """Every file under root, as plain dicts. Skips dotfiles and junk."""
    out = []
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in SKIP)
        for name in filenames:
            if name.startswith(".") or name in SKIP:
                continue
            full = os.path.join(dirpath, name)
            if not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                st = os.stat(full)
            except OSError:
                continue
            ext = os.path.splitext(name)[1].lower()
            out.append({
                "rel": rel,
                "name": name,
                "dir": posixpath.dirname(rel),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "ext": ext,
            })
    out.sort(key=lambda f: (-f["mtime"], f["rel"].lower()))
    return out


# --------------------------------------------------------------------------
# profiles: one password per shelf, stored in the environment
# --------------------------------------------------------------------------

PROFILE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
PASSWORD_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")

DEFAULT_EYEBROW = "tablinum · the record room"
DEFAULT_TITLE = "Documents"
DEFAULT_TAGLINE = "Everything kept in one place — notes, papers, reports and references."


class ConfigError(Exception):
    """Operator-facing config problem: printed to stderr, never a traceback."""


def write_auth(data: dict) -> None:
    """Write the credential file 0600, atomically — never world-readable."""
    tmp = AUTH_PATH + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_PATH)


def load_env(path: str) -> dict[str, str]:
    """Read KEY=VALUE pairs from a dotenv file. Missing file is not an error.

    Values are never echoed: a malformed line is reported by number only, because
    the most likely malformed line is the one holding a password.
    """
    out: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return out
    except OSError as exc:
        print(f"tablinum: cannot read {path}: {exc}", file=sys.stderr)
        return out

    for lineno, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        line = line.lstrip()
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            print(f"tablinum: {path}:{lineno}: ignoring a malformed line", file=sys.stderr)
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            print(f"tablinum: {path}:{lineno}: ignoring a malformed line", file=sys.stderr)
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        # the real environment wins, and a file's first spelling of a key wins
        if key in os.environ or key in out:
            continue
        out[key] = value
    return out


def environ_with_env_file() -> dict[str, str]:
    """os.environ, with .env filling in only the variables it does not already have."""
    env = dict(os.environ)
    env.update(load_env(ENV_PATH))
    return env


def _compile_pattern(pattern: str) -> re.Pattern:
    """One include glob -> regex. `*` crosses `/`, so a folder glob is recursive."""
    pat = pattern.replace("\\", "/")
    while pat.startswith("./") or pat.startswith("/"):
        pat = pat[2:] if pat.startswith("./") else pat[1:]
    if not pat:
        raise ConfigError("profiles.json: an include pattern is empty")
    if pat.startswith("/") or os.path.isabs(pat):
        raise ConfigError(f"profiles.json: include pattern is absolute: {pattern!r}")
    if ".." in pat.split("/"):
        raise ConfigError(f"profiles.json: include pattern contains '..': {pattern!r}")
    rx = re.escape(pat).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(rx, re.IGNORECASE | re.DOTALL)


def matches(rel: str, patterns: Sequence[str]) -> bool:
    """True when rel (relative to files/, '/'-separated) matches any pattern."""
    rel = rel.replace("\\", "/")
    return any(_compile_pattern(pattern).fullmatch(rel) for pattern in patterns)


@dataclass(frozen=True)
class Profile:
    """One password, one slice of files/."""

    name: str
    include: tuple[str, ...]
    password_env: str
    password: str          # resolved value; "" means disabled
    title: str
    tagline: str
    eyebrow: str
    patterns: tuple[re.Pattern, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "patterns",
                           tuple(_compile_pattern(p) for p in self.include))

    @property
    def enabled(self) -> bool:
        return bool(self.password)

    def allows(self, rel: str) -> bool:
        rel = rel.replace("\\", "/")
        return any(rx.fullmatch(rel) for rx in self.patterns)

    def select(self, files: list[dict]) -> list[dict]:
        """Filter collect() output to this shelf, preserving its order."""
        return [f for f in files if self.allows(f["rel"])]


class ProfileBook:
    """Every profile in profiles.json, with passwords resolved from the environment."""

    def __init__(self, profiles: dict[str, Profile], default: Profile | None,
                 all_profiles: list[Profile] | None = None):
        self.profiles = profiles          # ENABLED only, config order
        self.default = default            # even when disabled
        self.all = all_profiles if all_profiles is not None else list(profiles.values())

    def __bool__(self) -> bool:
        return bool(self.profiles)

    def get(self, name: str) -> Profile | None:
        return self.profiles.get(name)

    def match(self, password: str) -> str | None:
        """The profile whose password this is, or None.

        Every enabled profile is compared, even after a hit, so the response time
        does not reveal which profile (or how many) exist.
        """
        if not password:
            return None
        supplied = password.encode("utf-8")
        found = None
        for name, profile in self.profiles.items():
            if hmac.compare_digest(supplied, profile.password.encode("utf-8")):
                found = name
        return found

    @classmethod
    def from_mapping(cls, data: dict, env: Mapping[str, str]) -> "ProfileBook":
        if not isinstance(data, dict):
            raise ConfigError("profiles.json must contain a JSON object")
        if "default" not in data:
            raise ConfigError("profiles.json: missing the 'default' profile")
        raw_default = data["default"]
        if not isinstance(raw_default, dict):
            raise ConfigError("profiles.json: 'default' must be an object")
        raw_list = data.get("profiles", [])
        if not isinstance(raw_list, list):
            raise ConfigError("profiles.json: 'profiles' must be a list")

        def opt_text(raw: dict, key: str, label: str) -> str | None:
            if key not in raw:
                return None
            value = raw[key]
            if not isinstance(value, str):
                raise ConfigError(f"profiles.json: {label} has a non-string {key!r}")
            return value

        def include_of(raw: dict, label: str) -> tuple[str, ...]:
            if "include" not in raw:
                raise ConfigError(f"profiles.json: {label} is missing 'include'")
            value = raw["include"]
            if not isinstance(value, list) or not value:
                raise ConfigError(f"profiles.json: {label} 'include' must be a non-empty list")
            out = []
            for item in value:
                if not isinstance(item, str) or not item.strip():
                    raise ConfigError(f"profiles.json: {label} has an empty include pattern")
                out.append(item.strip())
            for pattern in out:
                _compile_pattern(pattern)
            return tuple(out)

        def password_env_of(raw: dict, label: str) -> str:
            if "password_env" not in raw:
                raise ConfigError(f"profiles.json: {label} is missing 'password_env'")
            value = raw["password_env"]
            if not isinstance(value, str) or not PASSWORD_ENV_RE.match(value):
                raise ConfigError(f"profiles.json: {label} has an invalid 'password_env'")
            return value

        def make_profile(name: str, raw: dict, label: str,
                         d_title: str, d_tagline: str, d_eyebrow: str) -> Profile:
            password_env = password_env_of(raw, label)
            value = env.get(password_env, "") or ""
            return Profile(
                name=name,
                include=include_of(raw, label),
                password_env=password_env,
                password=str(value),
                title=opt_text(raw, "title", label) or d_title,
                tagline=opt_text(raw, "tagline", label) or d_tagline,
                eyebrow=opt_text(raw, "eyebrow", label) or d_eyebrow,
            )

        default = make_profile("default", raw_default, "the default profile",
                               DEFAULT_TITLE, DEFAULT_TAGLINE, DEFAULT_EYEBROW)
        all_profiles = [default]
        seen_names = {"default"}
        for index, raw in enumerate(raw_list):
            label = f"profiles[{index}]"
            if not isinstance(raw, dict):
                raise ConfigError(f"profiles.json: {label} must be an object")
            name = raw.get("name")
            if not isinstance(name, str) or not PROFILE_NAME_RE.match(name):
                raise ConfigError(f"profiles.json: {label} has an invalid 'name'")
            if name in seen_names:
                raise ConfigError(f"profiles.json: duplicate profile name {name!r}")
            seen_names.add(name)
            all_profiles.append(make_profile(
                name, raw, f"profile {name!r}",
                default.title, default.tagline, default.eyebrow,
            ))

        seen_passwords: dict[str, str] = {}
        for profile in all_profiles:
            if not profile.enabled:
                continue
            prior = seen_passwords.get(profile.password)
            if prior is not None:
                raise ConfigError(
                    f"profiles.json: {prior} and {profile.password_env} resolve to the "
                    "same password; every profile password must be unique")
            seen_passwords[profile.password] = profile.password_env

        enabled = {p.name: p for p in all_profiles if p.enabled}
        return cls(enabled, default, all_profiles)


def load_profiles(path: str, env: Mapping[str, str]) -> ProfileBook:
    """Read profiles.json and resolve every password from env."""
    if not os.path.exists(path):
        return ProfileBook({}, None, [])
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    return ProfileBook.from_mapping(data, env)


def load_secret() -> dict:
    """Return auth.json's session secret, creating or upgrading the file.

    Passwords no longer live here: auth.json holds only the HMAC key and the
    session lifetime. An old 2.x file is rewritten without its password_hash.
    """
    data: dict = {}
    if os.path.exists(AUTH_PATH):
        try:
            with open(AUTH_PATH, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError) as exc:
            print(f"tablinum: cannot read {AUTH_PATH}: {exc}", file=sys.stderr)

    secret = data.get("secret")
    valid_secret = isinstance(secret, str) and re.fullmatch(r"[0-9a-fA-F]{64}", secret) is not None
    env_secret = os.environ.get("TABLINUM_SECRET")
    env_ok = bool(env_secret and re.fullmatch(r"[0-9a-fA-F]{64}", env_secret))
    if env_secret and not env_ok:
        print("tablinum: ignoring TABLINUM_SECRET (want 64 hex characters)", file=sys.stderr)

    hours = data.get("session_hours", 12)
    if not isinstance(hours, (int, float)):
        hours = 12
    result = {
        "secret": env_secret if env_ok else (secret if valid_secret else secrets.token_hex(32)),
        "session_hours": hours,
        "updated": data.get("updated") if isinstance(data.get("updated"), int) else int(time.time()),
    }
    legacy_keys = [key for key in data if str(key).startswith("password")]
    if not env_ok and (not valid_secret or legacy_keys):
        result["updated"] = int(time.time())
        write_auth(result)
    return result


class Sessions:
    """HMAC-signed stateless session tokens: `<expiry>.<profile>.<nonce>.<sig>`."""

    def __init__(self, secret: str, hours: float = 12):
        self._key = bytes.fromhex(secret)
        self.ttl = int(float(hours) * 3600)

    def _sign(self, payload: str) -> str:
        return hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).hexdigest()

    def issue(self, profile: str) -> tuple[str, int]:
        exp = int(time.time()) + self.ttl
        payload = f"{exp}.{profile}.{secrets.token_hex(8)}"
        return f"{payload}.{self._sign(payload)}", self.ttl

    def valid(self, token: str | None) -> str | None:
        """The profile name carried by a valid token, or None for any failure."""
        if not token or token.count(".") != 3:
            return None
        exp_s, profile, nonce, sig = token.split(".")
        if not profile:
            return None
        try:
            expected = self._sign(f"{exp_s}.{profile}.{nonce}")
        except UnicodeEncodeError:
            return None
        if not hmac.compare_digest(sig, expected):
            return None
        try:
            if int(exp_s) <= int(time.time()):
                return None
        except ValueError:
            return None
        return profile


class RateLimiter:
    """Failed-login throttle: per-client backoff plus a global ceiling.

    In-memory on purpose. A password check is already slow; the throttle only has
    to hold for the life of the process, and losing counters on restart is a far
    smaller problem than a lockout that cannot be cleared.
    """

    def __init__(self, per_ip_limit: int = 5, global_limit: int = 60,
                 window: int = 600, max_delay: int = 900):
        self.per_ip_limit = per_ip_limit
        self.global_limit = global_limit
        self.window = window
        self.max_delay = max_delay
        self._fails: dict[str, list[float]] = {}
        self._global: list[float] = []

    def _recent(self, times: list[float], now: float) -> list[float]:
        return [t for t in times if now - t < self.window]

    def blocked_for(self, ip: str) -> int:
        """Seconds this client must still wait, or 0."""
        now = time.time()
        fails = self._recent(self._fails.get(ip, []), now)
        self._fails[ip] = fails
        if len(fails) >= self.per_ip_limit:
            over = len(fails) - self.per_ip_limit
            delay = min(2 ** over, self.max_delay)
            if now - fails[-1] < delay:
                return int(delay - (now - fails[-1])) + 1
        glob = self._recent(self._global, now)
        self._global = glob
        if len(glob) >= self.global_limit and now - glob[-1] < self.max_delay:
            return int(self.max_delay - (now - glob[-1])) + 1
        return 0

    def record_failure(self, ip: str) -> None:
        now = time.time()
        self._fails.setdefault(ip, []).append(now)
        self._global.append(now)
        if len(self._fails) > 4096:  # keep the table bounded
            for k in [k for k, v in self._fails.items() if not self._recent(v, now)][:2048]:
                self._fails.pop(k, None)

    def reset(self, ip: str) -> None:
        self._fails.pop(ip, None)


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

THEME = """
  :root {
    --panel: #1a1d1f;
    --panel-edge: #0c0e0f;
    --silk: #d5dade;
    --silk-dim: #79838b;
    --hair: #2b3135;
    --socket: #111416;
    --amber: #d9a441;
    --up: #3fd07a;
    --down: #b4402f;
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust: 100%; }
  body {
    margin: 0;
    display: flex; flex-direction: column; min-height: 100vh;
    padding: clamp(22px, 5vw, 56px) clamp(16px, 4vw, 40px) 40px;
    background: var(--panel-edge);
    color: var(--silk);
    font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  main { max-width: 940px; margin: 0 auto; width: 100%; display: flex; flex-direction: column; flex: 1; }
  header { margin-bottom: 26px; }
  .eyebrow {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 0.7rem; letter-spacing: 0.22em; text-transform: uppercase;
    color: var(--amber); margin-bottom: 10px;
  }
  h1 {
    font-size: clamp(2rem, 6vw, 3rem); line-height: 1.02;
    letter-spacing: -0.035em; font-weight: 500; margin: 0 0 10px;
  }
  .tagline { color: var(--silk-dim); margin: 0; max-width: 58ch; line-height: 1.6; font-size: 0.95rem; }
  .stats {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 0.74rem; color: var(--silk-dim); margin-top: 14px;
    display: flex; gap: 16px; flex-wrap: wrap;
  }
  .stats b { color: var(--amber); font-weight: 500; }
  .search {
    display: flex; align-items: center; gap: 10px;
    background: var(--socket); border: 1px solid var(--hair); border-radius: 3px;
    padding: 10px 14px; margin: 22px 0 8px;
  }
  .search svg { flex: none; opacity: 0.45; }
  .search input {
    flex: 1; min-width: 0; background: none; border: 0; outline: 0; color: var(--silk);
    font-size: 0.92rem; font-family: inherit; padding: 0;
  }
  .search input::placeholder { color: #5c666d; }
  .search:focus-within { border-color: #3a4247; }
  h2.folder {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 0.7rem; font-weight: 500; letter-spacing: 0.16em; text-transform: uppercase;
    color: #8d979e; margin: 30px 0 8px; padding-bottom: 7px;
    border-bottom: 1px solid var(--hair);
    display: flex; gap: 10px; align-items: center;
  }
  h2.folder .path { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  h2.folder .count {
    letter-spacing: 0; text-transform: none; color: var(--silk-dim);
    border: 1px solid var(--hair); border-radius: 2px; padding: 1px 6px; font-size: 0.64rem;
  }
  ul.panel { list-style: none; margin: 0; padding: 0; border: 1px solid var(--hair); border-radius: 3px; overflow: hidden; }
  ul.panel li + li { border-top: 1px solid var(--hair); }
  a.row {
    display: grid; grid-template-columns: 56px minmax(0, 1fr) auto 96px;
    align-items: center; gap: 14px; padding: 13px 16px;
    background: var(--panel); text-decoration: none; color: inherit;
    transition: background 120ms ease;
  }
  a.row:hover { background: #202427; }
  a.row:focus-visible { outline: 2px solid var(--amber); outline-offset: -2px; }
  .chip {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 0.62rem; letter-spacing: 0.06em; text-align: center;
    width: 52px; justify-self: start;
    padding: 3px 0; border-radius: 2px; border: 1px solid var(--hair); color: var(--silk-dim);
  }
  .chip.web  { color: #6fb6d8; border-color: #274652; }
  .chip.doc, .chip.note { color: #d99a7a; border-color: #4a352a; }
  .chip.img  { color: #9ecf7d; border-color: #35462b; }
  .chip.data { color: #cfa8d9; border-color: #42304a; }
  .chip.vid, .chip.aud { color: #d9a441; border-color: #4a3d24; }
  .chip.bin  { color: var(--silk-dim); }
  .fname {
    font-size: 0.95rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .fname .stem { color: #eef1f3; }
  .fsize, .fdate {
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 0.72rem; color: var(--silk-dim); white-space: nowrap;
  }
  .fsize { text-align: right; }
  .fdate { text-align: right; }
  .empty { color: var(--silk-dim); padding: 26px 4px; font-size: 0.92rem; }
  .empty code {
    font-family: ui-monospace, Menlo, monospace; color: var(--amber);
    background: var(--socket); padding: 2px 6px; border-radius: 2px;
  }
  footer {
    margin-top: auto; padding-top: 38px;
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 0.71rem; color: #97a1a8;
    display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap;
    align-items: center;
  }
  footer a { color: var(--silk-dim); text-decoration: none; border-bottom: 1px solid #3a4247; }
  footer a:hover { color: var(--silk); }
  footer form { display: inline; }
  footer button {
    background: none; border: 0; padding: 0; margin: 0; cursor: pointer;
    color: var(--silk-dim); font: inherit; border-bottom: 1px solid #3a4247;
  }
  footer button:hover { color: var(--silk); }
  .whoami {
    display: flex; justify-content: flex-end; align-items: center; gap: 12px;
    margin-bottom: 18px;
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    font-size: 0.71rem; color: var(--silk-dim);
  }
  .whoami b { color: var(--amber); font-weight: 500; }
  .whoami form { display: inline; margin: 0; }
  .whoami button {
    background: var(--socket); border: 1px solid var(--hair); border-radius: 3px;
    padding: 4px 10px; cursor: pointer; color: var(--silk-dim); font: inherit;
  }
  .whoami button:hover { color: var(--amber); }
  @media (max-width: 560px) {
    a.row { grid-template-columns: 44px minmax(0, 1fr) auto; gap: 10px; padding: 12px 13px; }
    .fdate { display: none; }
  }
  @media (prefers-reduced-motion: reduce) { a.row { transition: none; } }
"""

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<meta name="description" content="__TAGLINE__">
<meta name="robots" content="noindex, nofollow">
<style>__THEME__</style>
</head>
<body>
<main>
  <header>
    __WHOAMI__
    <div class="eyebrow">__EYEBROW__</div>
    <h1>__TITLE__</h1>
    <p class="tagline">__TAGLINE__</p>
    <div class="stats">
      <span><b>__COUNT__</b> __NOUN__</span>
      <span><b>__SIZE__</b> total</span>
      <span>newest first</span>
      <span>__STATE__</span>
    </div>
  </header>
  __SEARCH__
  __GROUPS__
  <footer>
    <span>__FOOTER_LEFT__</span>
    <span>__FOOTER_RIGHT__</span>
  </footer>
</main>
__SCRIPT__
</body>
</html>
"""

LOGIN_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — __TITLE__</title>
<meta name="robots" content="noindex, nofollow">
<style>__THEME__
  .gate { flex: 1; display: flex; align-items: center; justify-content: center; min-height: 100%; }
  .card { width: 100%; max-width: 372px; }
  .card h1 { font-size: clamp(1.9rem, 6vw, 2.3rem); margin-bottom: 6px; }
  form { margin-top: 26px; }
  label {
    display: block; font-size: 0.7rem; letter-spacing: 0.12em; text-transform: uppercase;
    color: var(--silk-dim); margin-bottom: 8px;
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  input[type=password] {
    width: 100%; padding: 13px 14px; background: var(--socket); color: var(--silk);
    border: 1px solid var(--hair); border-radius: 3px; font-size: 1rem;
    font-family: inherit; outline: none;
  }
  input[type=password]:focus { border-color: #3a4247; }
  button[type=submit] {
    width: 100%; margin-top: 14px; padding: 13px 16px; cursor: pointer;
    background: var(--amber); color: #16181a; border: 0; border-radius: 3px;
    font-size: 0.9rem; font-weight: 600; letter-spacing: 0.02em; font-family: inherit;
  }
  button[type=submit]:hover { background: #e5b355; }
  .err {
    margin-top: 14px; padding: 10px 13px; border-radius: 3px; font-size: 0.85rem;
    color: #e9b6a8; background: rgba(180, 64, 47, 0.14); border: 1px solid #553027;
  }
  .hint {
    color: #8d979e; font-size: 0.74rem; margin-top: 24px; line-height: 1.6;
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
</style>
</head>
<body>
<main>
  <div class="gate">
    <div class="card">
      <div class="eyebrow">__EYEBROW__</div>
      <h1>__TITLE__</h1>
      <p class="tagline">__TAGLINE__</p>
      <form method="post" action="/login" autocomplete="off">
        <input type="hidden" name="csrf" value="__CSRF__">
        <label for="pw">Password</label>
        <input id="pw" name="password" type="password" required autofocus
               maxlength="1024" autocomplete="current-password">
        <button type="submit">Unlock</button>
        __ERROR__
      </form>
      <p class="hint">__HINT__</p>
    </div>
  </div>
</main>
</body>
</html>
"""

SEARCH = """<label class="search">
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
    <input id="q" type="search" placeholder="Filter by name" autocomplete="off" spellcheck="false" aria-label="Filter files">
  </label>"""

ROW = """      <li data-name="{needle}"><a class="row" href="{href}">
        <span class="chip {hue}">{label}</span>
        <span class="fname"><span class="stem">{name}</span></span>
        <span class="fsize">{size}</span>
        <span class="fdate">{date}</span>
      </a></li>"""

SCRIPT = """<script nonce="__NONCE__">
(function () {
  var q = document.getElementById('q');
  if (!q) return;
  var rows = Array.prototype.slice.call(document.querySelectorAll('ul.panel li'));
  var groups = Array.prototype.slice.call(document.querySelectorAll('h2.folder'));
  var panels = Array.prototype.slice.call(document.querySelectorAll('ul.panel'));
  q.addEventListener('input', function () {
    var term = q.value.trim().toLowerCase();
    rows.forEach(function (li) {
      var hit = !term || li.getAttribute('data-name').indexOf(term) !== -1;
      li.style.display = hit ? '' : 'none';
    });
    panels.forEach(function (ul) {
      var any = ul.querySelector('li:not([style*="display: none"])');
      ul.style.display = any ? '' : 'none';
    });
    groups.forEach(function (h) {
      var ul = h.nextElementSibling;
      if (ul && ul.classList.contains('panel')) h.style.display = ul.style.display;
    });
  });
})();
</script>"""

LOGOUT_FORM = """<form method="post" action="/logout"><button type="submit" title="End this session">sign out</button></form>"""


def link_for(rel: str) -> str:
    # Pages serves /x.html as /x, and the local server accepts both, so link the
    # extensionless form: no redirect hop on the public site, identical URL on the LAN.
    if rel.lower().endswith(".html"):
        rel = rel[:-5]
    return MOUNT + "/" + quote(rel)


def render(files: list[dict], *, eyebrow: str, title: str, tagline: str,
           footer_left: str, footer_right: str = "tablinum",
           footer_url: str = "https://github.com/ayaanngandhi/tablinum",
           nonce: str = "", locked: bool = True,
           profile_name: str | None = None) -> str:
    total = sum(f["size"] for f in files)

    groups: dict[str, list[dict]] = {}
    for f in files:
        groups.setdefault(f["dir"], []).append(f)

    blocks = []
    if not files:
        blocks.append('<p class="empty">Nothing here yet. Drop a file into '
                      '<code>files/</code> and reload.</p>')
    for folder in sorted(groups, key=lambda d: (d != "", d.lower())):
        if folder:
            n = len(groups[folder])
            blocks.append(f'  <h2 class="folder"><span class="path">files/{html.escape(folder)}</span>'
                          f'<span class="count">{n} file{"" if n == 1 else "s"}</span></h2>')
        rows = []
        for f in groups[folder]:
            label, hue = BADGES.get(f["ext"], (f["ext"].lstrip(".").upper()[:4] or "FILE", "bin"))
            rows.append(ROW.format(
                needle=html.escape(f["rel"].lower()),
                href=html.escape(link_for(f["rel"])),
                hue=hue, label=html.escape(label),
                name=html.escape(f["name"]),
                size=human_size(f["size"]),
                date=time.strftime("%d %b %Y", time.localtime(f["mtime"])),
            ))
        blocks.append('  <ul class="panel">\n' + "\n".join(rows) + "\n  </ul>")

    right = f'<a href="{html.escape(footer_url)}">{html.escape(footer_right)}</a>'
    if locked:
        right += " &nbsp;·&nbsp; " + LOGOUT_FORM

    whoami = ""
    if locked and profile_name:
        whoami = ('<div class="whoami"><span>signed in as <b>'
                  + html.escape(profile_name)
                  + '</b></span>' + LOGOUT_FORM + '</div>')
        state = f"private · signed in as {html.escape(profile_name)}"
    else:
        state = "private · signed in" if locked else "public shelf"

    return (PAGE
            .replace("__THEME__", THEME)
            .replace("__WHOAMI__", whoami)
            .replace("__EYEBROW__", html.escape(eyebrow))
            .replace("__TITLE__", html.escape(title))
            .replace("__TAGLINE__", html.escape(tagline))
            .replace("__COUNT__", str(len(files)))
            .replace("__NOUN__", "file" if len(files) == 1 else "files")
            .replace("__SIZE__", human_size(total))
            .replace("__STATE__", state)
            .replace("__SEARCH__", SEARCH if files else "")
            .replace("__GROUPS__", "\n".join(blocks))
            .replace("__FOOTER_LEFT__", html.escape(footer_left))
            .replace("__FOOTER_RIGHT__", right)
            .replace("__SCRIPT__", SCRIPT.replace("__NONCE__", nonce) if files else ""))


def issue_csrf(secret: str, ttl: int = CSRF_TTL) -> str:
    """A CSRF token that proves itself, so it cannot go stale behind a cookie.

    Double-submit (form token must equal a cookie) breaks the moment the browser
    and the server disagree about which token is current: a prefetch, a duplicated
    GET, a restored tab, or an edge cache rotating one and not the other. The
    person then retypes a correct password and is told the form expired. Signing
    the timestamp instead removes the round-trip entirely — the token is valid for
    CSRF_TTL no matter how many times the page is fetched.
    """
    ts = str(int(time.time()))
    mac = hmac.new(bytes.fromhex(secret), f"csrf:{ts}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"{ts}.{mac}"


def csrf_ok(secret: str, token: str, ttl: int = CSRF_TTL) -> bool:
    if not secret or not token or "." not in token:
        return False
    ts, _, mac = token.partition(".")
    if not ts.isdigit() or not mac:
        return False
    age = int(time.time()) - int(ts)
    if age < -60 or age > ttl:          # not from the future, not older than ttl
        return False
    want = hmac.new(bytes.fromhex(secret), f"csrf:{ts}".encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(mac, want)


def render_login(cfg: dict, error: str = "", csrf: str = "", wait: int = 0) -> str:
    if wait:
        error = f"Too many attempts. Try again in {wait} second{'' if wait == 1 else 's'}."
    err_html = f'<div class="err" role="alert">{html.escape(error)}</div>' if error else ""
    return (LOGIN_PAGE
            .replace("__THEME__", THEME)
            .replace("__EYEBROW__", html.escape(cfg.get("eyebrow", DEFAULT_EYEBROW)))
            .replace("__TITLE__", html.escape(cfg.get("title", DEFAULT_TITLE)))
            .replace("__TAGLINE__", "One password, and the door opens.")
            .replace("__CSRF__", html.escape(csrf))
            .replace("__ERROR__", err_html)
            .replace("__HINT__", html.escape(cfg.get(
                "login_hint",
                "password only · one shelf per person · rate limited"))))


def load_site_config(root: str) -> dict:
    """Optional tablinum.json next to the files/ directory."""
    path = os.path.join(os.path.dirname(os.path.abspath(root)), "tablinum.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError) as exc:
        print(f"tablinum: ignoring bad {path}: {exc}", file=sys.stderr)
        return {}


def page_for(root: str, cfg: dict, profile: Profile | None = None,
             nonce: str = "", locked: bool = True,
             profile_name: str | None = None) -> str:
    files = collect(root)
    if profile is not None:
        files = profile.select(files)
        eyebrow, title, tagline = profile.eyebrow, profile.title, profile.tagline
    else:
        eyebrow = cfg.get("eyebrow", DEFAULT_EYEBROW)
        title = cfg.get("title", DEFAULT_TITLE)
        tagline = cfg.get("tagline", DEFAULT_TAGLINE)
    return render(
        files,
        eyebrow=eyebrow,
        title=title,
        tagline=tagline,
        footer_left=cfg.get("footer_left", f"{len(files)} file{'' if len(files) == 1 else 's'} in files/"),
        footer_right=cfg.get("footer_right", "tablinum on github"),
        footer_url=cfg.get("footer_url", "https://github.com/ayaanngandhi/tablinum"),
        nonce=nonce, locked=locked, profile_name=profile_name,
    )


# --------------------------------------------------------------------------
# serving
# --------------------------------------------------------------------------

def resolve(root: str, url_path: str) -> str | None:
    """Map a /files/... URL to a real path inside root, or None if unsafe."""
    rel = unquote(url_path)
    rel = rel.replace("\\", "/").lstrip("/")
    if not rel.startswith(MOUNT.lstrip("/")):
        return None
    rel = rel[len(MOUNT.lstrip("/")):].lstrip("/")
    if not rel:
        return None
    target = os.path.realpath(os.path.join(root, rel))
    root_real = os.path.realpath(root)
    if target != root_real and not target.startswith(root_real + os.sep):
        return None
    if not os.path.isfile(target):
        # Cloudflare Pages serves /x.html as /x (it 308-redirects the .html away),
        # so accept the extensionless form too and both modes behave identically.
        if not os.path.splitext(target)[1]:
            alt = target + ".html"
            if os.path.isfile(alt):
                return alt
        return None
    return target


def rel_to(root: str, target: str) -> str:
    """A served file's path relative to root, after alias resolution."""
    return os.path.relpath(target, os.path.realpath(root)).replace(os.sep, "/")


def clean_text(value: str | None, limit: int = MAX_PASSWORD_LEN) -> str | None:
    """Sanitise a submitted string: no NULs, no control bytes, bounded length.

    A password is compared byte-for-byte afterwards, so the only edits allowed are
    ones that could never be part of a typed password. Whitespace is preserved —
    silently trimming it would lock out anyone whose password ends in a space.
    """
    if value is None or len(value) > limit:
        return None
    if "\x00" in value:
        return None
    if any(ord(c) < 0x20 for c in value):
        return None
    return value


def make_handler(root: str, cfg: dict, book: ProfileBook | None, verbose: bool):
    secret = load_secret() if book else {}
    sessions = Sessions(secret["secret"], secret.get("session_hours", 12)) if book else None
    session_secret = secret["secret"] if book else ""
    login_cfg = dict(cfg)
    if book and book.default:
        login_cfg["eyebrow"] = book.default.eyebrow
        login_cfg["title"] = book.default.title
    limiter = RateLimiter()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = f"Tablinum/{__version__}"
        sys_version = ""

        def log_message(self, fmt, *args):
            if verbose:
                sys.stderr.write("%s  %s\n" % (self.log_date_time_string(), fmt % args))

        # ---- helpers ---------------------------------------------------
        def _https(self) -> bool:
            proto = (self.headers.get("X-Forwarded-Proto") or "").lower()
            return proto == "https"

        def _ip(self) -> str:
            fwd = self.headers.get("CF-Connecting-IP") or self.headers.get("X-Forwarded-For")
            if fwd:
                return fwd.split(",")[0].strip()[:64]
            return (self.client_address[0] if self.client_address else "?")[:64]

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self._emit(extra)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _redirect(self, where: str, extra: dict | None = None):
            self.send_response(303)
            self.send_header("Location", where)
            self.send_header("Content-Length", "0")
            for k, v in SECURITY_HEADERS.items():
                self.send_header(k, v)
            self._emit(extra)
            self.end_headers()

        def _emit(self, extra: dict | None):
            """Send extra headers; a list value becomes one header per item.

            Set-Cookie is the reason this exists: two cookies must be two headers.
            Joining them with a comma silently loses the second one in real
            browsers, even though a naive client accepts it.
            """
            for k, v in (extra or {}).items():
                if isinstance(v, (list, tuple)):
                    for item in v:
                        self.send_header(k, item)
                else:
                    self.send_header(k, v)

        def _cookies(self) -> dict:
            out = {}
            for part in (self.headers.get("Cookie") or "").split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    out[k.strip()] = v.strip()
            return out

        def _current(self) -> tuple[str | None, Profile | None]:
            """The live profile for this request; (None, None) under --no-auth."""
            if not sessions:
                return None, None
            name = sessions.valid(self._cookies().get(COOKIE))
            profile = book.get(name) if name else None
            return (name, profile) if profile is not None else (None, None)

        def _cookie(self, name: str, value: str, max_age: int) -> str:
            bits = [f"{name}={value}", "Path=/", f"Max-Age={max_age}",
                    "HttpOnly", "SameSite=Lax"]
            if self._https():
                bits.append("Secure")
            return "; ".join(bits)

        def _html_headers(self, nonce: str, extra: dict | None = None) -> dict:
            head = {
                "Cache-Control": "no-store",
                "Content-Security-Policy": (
                    "default-src 'none'; style-src 'unsafe-inline'; "
                    f"script-src 'nonce-{nonce}'; img-src 'self' data:; "
                    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
                ),
            }
            head.update(extra or {})
            return head

        def _login_response(self, status: int = 200, error: str = "", wait: int = 0,
                            retry_after: int | None = None, extra: dict | None = None):
            """Render the login page and ALWAYS pair it with a matching CSRF cookie.

            Minting a new token for the form without updating the cookie is what
            makes someone retype a perfectly correct password and still be told
            their session expired: the form holds token B, the browser holds A.
            """
            csrf = issue_csrf(session_secret)
            page = render_login(login_cfg, error=error, csrf=csrf, wait=wait).encode("utf-8")
            head = {"Retry-After": str(retry_after)} if retry_after else {}
            head.update(extra or {})
            return self._send(status, page, "text/html; charset=utf-8",
                              self._html_headers("", head))

        def _not_found(self):
            body = (b"<!doctype html><meta charset=utf-8><title>Not found</title>"
                    b"<body style=\"background:#0c0e0f;color:#d5dade;font-family:Helvetica,Arial,sans-serif;"
                    b"padding:48px\"><h1 style=\"font-weight:500;letter-spacing:-.02em\">Not found</h1>"
                    b"<p style=\"color:#79838b\">No such file on this shelf. "
                    b"<a style=\"color:#d9a441\" href=\"/\">Back to the index</a>.</p>")
            self._send(404, body, "text/html; charset=utf-8", {"Cache-Control": "no-store"})

        # ---- verbs -----------------------------------------------------
        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = unquote(urlsplit(self.path).path)

            if path == "/healthz":
                return self._send(200, b"ok\n", "text/plain; charset=utf-8",
                                  {"Cache-Control": "no-store"})

            name, profile = self._current()
            if sessions and profile is None:
                # a deletion or a disabled profile makes an otherwise valid
                # signature useless: a session is not authorisation by itself
                clear = {"Set-Cookie": self._cookie(COOKIE, "", 0)}
                if path == "/login":
                    return self._login_response(extra=clear)
                return self._redirect("/login", {
                    **clear, "Cache-Control": "no-store",
                })

            if path in ("/", "/index.html"):
                nonce = secrets.token_urlsafe(16)
                page = page_for(root, cfg, profile=profile, nonce=nonce,
                                locked=bool(sessions), profile_name=name).encode("utf-8")
                return self._send(200, page, "text/html; charset=utf-8",
                                  self._html_headers(nonce))

            if path in ("/login", "/logout"):
                # GET never mutates state; the sign-out control posts.
                return self._redirect("/")

            if path.startswith(MOUNT + "/"):
                target = resolve(root, path)
                if not target:
                    return self._not_found()
                if profile is not None and not profile.allows(rel_to(root, target)):
                    # 404, not 403: never confirm that a file exists off-shelf
                    return self._not_found()
                ext = os.path.splitext(target)[1].lower()
                ctype = CONTENT_TYPES.get(ext, "application/octet-stream")
                try:
                    with open(target, "rb") as fh:
                        body = fh.read()
                except OSError:
                    return self._not_found()
                return self._send(200, body, ctype, {
                    "Cache-Control": "private, no-cache",
                    "Content-Disposition": "inline",
                })
            return self._not_found()

        def do_POST(self):
            path = unquote(urlsplit(self.path).path)
            if path not in ("/login", "/logout"):
                return self._send(405, b"method not allowed\n", "text/plain; charset=utf-8")

            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                return self._send(400, b"bad request\n", "text/plain; charset=utf-8")
            if length < 0 or length > MAX_BODY:
                return self._send(413, b"payload too large\n", "text/plain; charset=utf-8")
            ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ctype != "application/x-www-form-urlencoded":
                return self._send(415, b"unsupported media type\n", "text/plain; charset=utf-8")

            raw = self.rfile.read(length) if length else b""
            try:
                text = raw.decode("utf-8", "strict")
            except UnicodeDecodeError:
                return self._send(400, b"bad request\n", "text/plain; charset=utf-8")

            form: dict[str, str] = {}
            for pair in text.split("&"):
                if not pair:
                    continue
                k, _, v = pair.partition("=")
                key = unquote(k.replace("+", " "))
                if key and key not in form:
                    form[key] = unquote(v.replace("+", " "))

            if path == "/logout":
                return self._redirect("/login", {
                    "Set-Cookie": self._cookie(COOKIE, "", 0),
                    "Cache-Control": "no-store",
                })

            if not sessions:  # auth disabled: nothing to log into
                return self._redirect("/")

            ip = self._ip()
            supplied = clean_text(form.get("csrf", ""), 128) or ""
            if not csrf_ok(session_secret, supplied):
                print(f"tablinum: rejected a bad/expired csrf token from {ip}", file=sys.stderr)
                # NOT a password attempt: a stale tab must never burn someone's
                # attempts and lock them out of their own shelf
                return self._login_response(400, "That form expired. Reload and try again.")

            wait = limiter.blocked_for(ip)
            if wait:
                return self._login_response(429, wait=wait, retry_after=wait)

            password = clean_text(form.get("password", ""))
            name = book.match(password) if password else None
            if not name:
                limiter.record_failure(ip)
                return self._login_response(401, "That password is not right.")

            limiter.reset(ip)
            token, ttl = sessions.issue(name)
            return self._redirect("/", {
                "Set-Cookie": self._cookie(COOKIE, token, ttl),
                "Cache-Control": "no-store",
            })

    return Handler


def serve(root: str, host: str, port: int, verbose: bool, open_mode: bool):
    if not os.path.isdir(root):
        print(f"tablinum: no such directory: {root}", file=sys.stderr)
        return 2
    try:
        book = load_profiles(PROFILES_PATH, environ_with_env_file())
    except ConfigError as exc:
        print(f"tablinum: {exc}", file=sys.stderr)
        return 4
    if not book and not open_mode:
        print("tablinum: no profile has a password, so the shelf will not be served.\n"
              f"  Put at least one password in {ENV_PATH} (copy .env.example and edit it).\n"
              "  Or serve it openly on purpose with --no-auth", file=sys.stderr)
        return 3
    cfg = load_site_config(root)
    active_book = None if open_mode else book
    httpd = ThreadingHTTPServer((host, port),
                                make_handler(root, cfg, active_book, verbose))
    httpd.daemon_threads = True
    files = collect(root)
    if open_mode:
        print(f"Tablinum {__version__} — {len(files)} files from {root} — OPEN · no password")
    else:
        print(f"Tablinum {__version__} — {len(files)} files from {root} — "
              f"locked · {len(book.profiles)} profile{'' if len(book.profiles) == 1 else 's'}")
        for profile in book.profiles.values():
            count = len(profile.select(files))
            print(f"  {profile.name:<9} {count:>4} files   password from {profile.password_env}")
    print(f"  http://{host}:{port}/")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\ntablinum: stopped")
    return 0


# --------------------------------------------------------------------------
# static export
# --------------------------------------------------------------------------

def build(root: str, out: str, allow_public: bool) -> int:
    if not os.path.isdir(root):
        print(f"tablinum: no such directory: {root}", file=sys.stderr)
        return 2
    try:
        book = load_profiles(PROFILES_PATH, environ_with_env_file())
    except ConfigError as exc:
        print(f"tablinum: {exc}", file=sys.stderr)
        return 4
    if book and not allow_public:
        print("tablinum: this shelf has profiles, and a static export cannot check them.\n"
              "  Building would put every file in the clear. If that is really what you\n"
              "  want, re-run with --public.", file=sys.stderr)
        return 4
    if os.path.abspath(out) in (os.path.abspath(root), os.path.dirname(os.path.abspath(root))):
        print("tablinum: refusing to write the export inside itself", file=sys.stderr)
        return 2
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    choice = book.default if book else None
    files = collect(root)
    if choice is not None:
        files = choice.select(files)

    dest = os.path.join(out, MOUNT.lstrip("/"))
    os.makedirs(dest, exist_ok=True)
    for f in files:
        target = os.path.join(dest, *f["rel"].split("/"))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        shutil.copy2(os.path.join(root, *f["rel"].split("/")), target)

    cfg = load_site_config(root)
    index = page_for(root, cfg, profile=choice, locked=False)
    for name in ("index.html", "404.html"):
        with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
            fh.write(index)
    with open(os.path.join(out, "_headers"), "w", encoding="utf-8") as fh:
        fh.write("/files/*\n  Cache-Control: public, max-age=3600\n"
                 "/\n  Cache-Control: public, max-age=60\n"
                 "/*\n  X-Robots-Tag: noindex\n")
    with open(os.path.join(out, ".nojekyll"), "w", encoding="utf-8") as fh:
        fh.write("")

    print(f"tablinum: exported {len(files)} files → {out}/")
    print("tablinum: WARNING — a static export is unprotected. Anyone with the URL can read it.")
    return 0


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def print_rows(files: list[dict]) -> None:
    if not files:
        print("(empty)")
    for f in files:
        print(f"{human_size(f['size']):>9}  "
              f"{time.strftime('%d %b %Y', time.localtime(f['mtime']))}  {f['rel']}")


def cmd_list(args) -> int:
    files = collect(os.path.abspath(args.dir))
    if args.profile:
        try:
            book = load_profiles(PROFILES_PATH, environ_with_env_file())
        except ConfigError as exc:
            print(f"tablinum: {exc}", file=sys.stderr)
            return 4
        profile = book.get(args.profile)
        if profile is None:
            print(f"tablinum: no enabled profile named {args.profile!r}", file=sys.stderr)
            return 2
        files = profile.select(files)
    print_rows(files)
    return 0


def cmd_status(args) -> int:
    try:
        book = load_profiles(PROFILES_PATH, environ_with_env_file())
    except ConfigError as exc:
        print(f"tablinum: {exc}", file=sys.stderr)
        return 4
    files = collect(os.path.abspath(args.dir))
    folder = os.path.basename(os.path.normpath(os.path.abspath(args.dir))) + "/"
    if not book.all:
        print(f"profiles.json not found · 0 profiles · {len(files)} files under {folder}")
        return 0
    enabled = sum(1 for p in book.all if p.enabled)
    print(f"profiles.json · {enabled} of {len(book.all)} profiles enabled · "
          f"{len(files)} files under {folder}")
    for profile in book.all:
        count = len(profile.select(files))
        state = "enabled" if profile.enabled else "disabled"
        note = (f"password from {profile.password_env}" if profile.enabled
                else f"password from {profile.password_env} (unset)")
        print(f"  {profile.name:<9} {state:<9} {count:>4} files   {note}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tablinum",
                                 description="A small document shelf with a lock on the door.")
    ap.add_argument("--version", action="version", version=f"tablinum {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("serve", help="serve files/ over HTTP behind a login")
    s.add_argument("--dir", default=DEFAULT_ROOT, help="directory to publish (default: ./files)")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=6320)
    s.add_argument("--no-auth", action="store_true", help="serve without a password")
    s.add_argument("-v", "--verbose", action="store_true")

    b = sub.add_parser("build", help="export a static copy for Pages/S3/any host")
    b.add_argument("--dir", default=DEFAULT_ROOT, help="directory to publish (default: ./files)")
    b.add_argument("--out", default="dist", help="output directory (default: ./dist)")
    b.add_argument("--public", action="store_true",
                   help="allow an unprotected export even though profiles are set")

    c = sub.add_parser("list", help="print the index as plain text")
    c.add_argument("--dir", default=DEFAULT_ROOT)
    c.add_argument("--profile", help="only rows visible to this profile")

    st = sub.add_parser("status", help="show profiles, files and sessions")
    st.add_argument("--dir", default=DEFAULT_ROOT)

    args = ap.parse_args(argv)
    if args.cmd == "serve":
        return serve(os.path.abspath(args.dir), args.host, args.port, args.verbose, args.no_auth)
    if args.cmd == "build":
        return build(os.path.abspath(args.dir), os.path.abspath(args.out), args.public)
    if args.cmd == "list":
        return cmd_list(args)
    if args.cmd == "status":
        return cmd_status(args)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
