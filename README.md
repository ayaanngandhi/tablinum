# Tablinum

**A small document shelf with a lock on the door.** Drop files in a folder; get a clean, readable index of them — behind a password per shelf, on your LAN and on the public web, from the same directory.

In a Roman house the *tablinum* was the record room opening off the atrium: the place the family's papers were kept. This is that room, for files.

```
   files/                      tablinum                →  http://localhost:6320
     circles-class10.html                                →  https://docs.example.com
     unit-test.pdf
     notes/
```

No database, no user accounts, no build step to serve. Standard library only — no dependencies.

---

## Why

Static file hosting is easy; *finding* things is not. Tablinum is the minimum honest answer: a directory is the database, the listing is generated on every request, and one Python file serves both a LAN shelf and a password-gated public shelf.

It is deliberately small enough to read in one sitting and to leave running for years.

## Install

```bash
git clone https://github.com/ayaanngandhi/tablinum.git
cd tablinum
python3 -m venv .venv
cp .env.example .env                      # then put a unique password on each line
.venv/bin/python tablinum.py status
.venv/bin/python tablinum.py serve --port 6320
```

There is nothing to `pip install`: `tablinum.py` uses the standard library only. `./install.sh` creates the venv and registers a systemd user unit.

## Profiles

A profile is a name, one password, and a list of glob patterns over `files/`. The login asks for a password only: the password you type identifies the profile, so each password must be unique. You see the files that profile may see, and nothing else.

`profiles.json` describes the shelves and holds no secrets. The first key, `default`, is both a real login-able profile and the fallback for every other profile's presentation:

```json
{
  "default": {
    "eyebrow": "tablinum · the record room",
    "title": "Documents",
    "tagline": "Everything kept in one place — notes, papers, reports and references.",
    "include": ["*"],
    "password_env": "TABLINUM_PASSWORD"
  },
  "profiles": [
    {
      "name": "shared",
      "title": "Shared documents",
      "tagline": "The current working notes and one-off papers.",
      "include": ["short-term/*"],
      "password_env": "TABLINUM_PASSWORD_SHARED"
    }
  ]
}
```

- `include` is required and never inherited. Each pattern is matched against the file's path relative to `files/`, with `/` separators.
- `*` matches **any run of characters, including `/`**, so `short-term/*` includes `short-term/deep/img.png`. A bare `*` includes everything. `?` matches exactly one character. Matching is case-insensitive; a leading `./` or `/` is ignored. There is no negation, no `**`, and a `..` segment is rejected.
- `password_env` is required, never inherited, and must name an uppercase environment variable.
- `title`, `tagline` and `eyebrow` are optional; each falls back to the `default` profile, then to the built-in text.
- `name` is required for entries in `profiles`, and must match `^[a-z0-9][a-z0-9_-]{0,31}$`.

Passwords live in `.env`, which is gitignored. Copy the committed example and edit it:

```bash
cp .env.example .env
```

```
# One password per profile. Every value here MUST be unique.
TABLINUM_PASSWORD=change-me-default
TABLINUM_PASSWORD_SHARED=change-me-shared
```

Uniqueness is not cosmetic: with no username field, the password alone decides which profile opens, so two identical passwords would be ambiguous. `serve` refuses to start (exit 4) and names both environment variables — never the values.

A profile whose `password_env` variable is unset or empty is **disabled**: it is skipped at startup and listed as disabled by `status`. If no profile is enabled, `serve` refuses to start (exit 3) and points at `.env`; `--no-auth` serves every file openly instead, with no login and no sign-out. Any other malformed config is an error (exit 4), printed without a traceback.

### Upgrading from 2.x

The old single-password world is gone. Passwords in an old `auth.json` are ignored and the file is rewritten to hold only the session secret; put passwords in `.env` instead. Old sessions use the 2-field token and are rejected once, so everyone signs in again. The `passwd` subcommand has been removed.

### How the login is built

- **The password selects the profile.** `ProfileBook.match` compares the submitted value against every enabled profile with `hmac.compare_digest` and only then decides, so neither the response nor its timing reveals which profiles exist. A miss returns the same generic `That password is not right.` page.
- **Sessions are signed, not stored.** The cookie is `<expiry>.<profile>.<nonce>.<HMAC-SHA256>` keyed by the secret in `auth.json`; tampering with any field fails `hmac.compare_digest`. A valid signature is not enough on its own: the profile must still exist and be enabled, or the cookie is cleared and the request goes back to `/login`.
- **Cookies are `HttpOnly`, `SameSite=Lax`, `Path=/`,** and add `Secure` automatically whenever the request arrived over HTTPS (`X-Forwarded-Proto`), so a Cloudflare Tunnel gets hardened cookies while a bare LAN IP still works.
- **CSRF tokens sign themselves.** The login form carries a timestamped, HMAC-signed token; a stale form cannot burn a login attempt, and a GET can never end your session because logout is POST-only.
- **Throttling:** 5 failed attempts from one address start an exponential lockout (30 s, 60 s, … capped at 15 min), and a global ceiling stops distributed guessing. A correct password is *also* refused while a lockout is active.
- **Input is sanitised before comparison:** bodies are capped at 4 KB, must be `application/x-www-form-urlencoded`, must decode as strict UTF-8, and the password is rejected if it contains NUL or control bytes. Whitespace is preserved — silently trimming it would lock out anyone whose password ends in a space.
- **Authorisation happens per file.** After the traversal-safe `realpath` check and the extensionless `.html` alias, the final relative path must match the session profile's patterns. A file outside the shelf returns the same **404** as a missing file, so its existence is never confirmed.
- **Security headers on every response:** `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, and a nonce-based CSP (`default-src 'none'`) so injected markup cannot run.
- **No index, ever:** pages carry `noindex, nofollow`, and the listing is `Cache-Control: no-store` — the shelf never sits in a shared cache.

## Use

Put files in `./files` (or any directory you point it at):

```bash
cp ~/report.pdf files/
# reload the page — it is already listed
```

| Command | What it does |
| --- | --- |
| `tablinum.py serve --port 6320` | Live server behind the login. Newest first, filter box, nested folders grouped. |
| `tablinum.py status` | Profiles (enabled and disabled), file counts, session length. |
| `tablinum.py build --out dist` | Static export: `dist/index.html` + `dist/files/**`. Refuses while any profile is enabled; `--public` exports the default profile's shelf. |
| `tablinum.py list [--profile NAME]` | Print the index as plain text, optionally for one profile. |
| `./publish.sh <file>` | Copy onto the shelf, then deploy the public mirror. |

Flags: `--dir` selects what gets published (default `./files`), `--host` binds the interface (default `0.0.0.0`), `--no-auth` serves openly, `-v` logs every request.

### URL scheme

Deliberately boring:

- `/` — the index
- `/files/<relative path>` — a file, e.g. `/files/notes.pdf`
- `/login`, `/logout` — the door
- `/healthz` — `ok`, never gated (so uptime checks and routers work)

Files always live under `/files/`, so a file called `index.html` can never collide with the generated listing. `/files/report.html` and `/files/report` both resolve.

### Site text

Optional `tablinum.json` next to the published directory:

```json
{
  "eyebrow": "tablinum · the record room",
  "title": "Documents",
  "tagline": "Everything kept in one place.",
  "footer_left": "home server",
  "footer_right": "tablinum on github",
  "footer_url": "https://github.com/ayaanngandhi/tablinum"
}
```

Every key is optional. Bad JSON is ignored with a warning rather than crashing the server.

## Deploy

### LAN / home server

```bash
./install.sh
```

Creates the venv, checks for `.env`, and installs a *user* unit `tablinum.service` on `:6320`, enabled at boot with linger so it survives logout and reboot.

```bash
systemctl --user status tablinum
journalctl --user -u tablinum -f
```

### Internet, with profiles

A server that checks passwords needs a server. Put it behind a tunnel rather than a static host:

```bash
cloudflared tunnel route dns <tunnel> docs.example.com
# then add an ingress rule: docs.example.com → http://localhost:6320
```

Cloudflare terminates TLS and forwards; Tablinum sees `X-Forwarded-Proto: https`, marks the cookie `Secure`, and the login stands in front of every file. Nothing else is exposed.

### Static hosting — deliberately awkward

A static export cannot check profile passwords, so `build` **refuses to run while any profile is enabled**:

```
tablinum: this shelf has profiles, and a static export cannot check them.
  Building would put every file in the clear.
```

For a shelf that is *meant* to be public, pass `--public` explicitly; it exports the `default` profile's selection (everything when there is no config). That is what `deploy.sh` does, behind a confirmation prompt. `dist/` is an ordinary website — Pages, S3, nginx, a USB stick.

### Behind a router or reverse proxy

Tablinum serves at `/`, so a proxy just forwards to `127.0.0.1:6320`. No path rewriting, no trailing-slash ambiguity. To link it from an index page elsewhere, `href="/tablinum"` is enough if your router maps that slug.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

61 tests covering profile config and uniqueness, glob matching (including `*` crossing `/`), dotenv loading, session token forgery/expiry/profile tampering, per-profile file authorisation (404 off-shelf), CSRF rejection, throttling, path traversal (six encodings), the build guard, and that the session-secret file lands at 0600. `bash check.sh` also runs `tests/gate.py`, an end-to-end two-profile flow.

## Design notes

- **The filesystem is the source of truth.** No manifest, no sync, no state to get stale. Delete a file and it is gone from the index on the next request.
- **`no-store` on the listing, `private, no-cache` on files** — a shelf you can trust to show what is actually there.
- **Path traversal is blocked by realpath containment,** not string inspection; symlinks are resolved before the check.
- **Dotfiles are not published.** Nor is anything in `.git`, `.venv` or `__pycache__`.
- **Accessibility and degradation:** the search box filters already-rendered rows with a few lines of vanilla JS; with JS off the page is a complete, readable list. Rows are real links, focus-visible, and respect `prefers-reduced-motion`.
- **No upload, no delete, no account management.** Profiles are read-only shelves; passwords are edited in `.env`.

## Limits (on purpose)

- Profiles are coarse: each one sees a set of glob patterns, with no per-file grants or roles. It is a shelf for a household or a small team, not a multi-tenant app.
- Rate-limit counters live in memory: a restart clears them. That is acceptable for a small shelf and far better than a lockout that cannot be cleared.
- No search *inside* documents, no previews, no tagging. It indexes filenames, which is what a shelf needs.
- Files are read into memory per request; excellent for documents, wrong for multi-gigabyte media.
- No range requests, so video scrubbing is not supported.

## License

MIT © Ayaan Gandhi
