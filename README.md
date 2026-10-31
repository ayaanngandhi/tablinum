# Tablinum

**A small document shelf with a lock on the door.** Drop files in a folder; get a clean, readable index of them — behind one password, on your LAN and on the public web, from the same directory.

In a Roman house the *tablinum* was the record room opening off the atrium: the place the family's papers were kept. This is that room, for files.

```
   files/                      tablinum                →  http://localhost:6320
     circles-class10.html                                →  https://docs.example.com
     unit-test.pdf
     notes/
```

No database, no user accounts, no build step to serve. One dependency: `bcrypt`.

---

## Why

Static file hosting is easy; *finding* things is not. Tablinum is the minimum honest answer: a directory is the database, the listing is generated on every request, and one Python file serves both a LAN shelf and a password-gated public shelf.

It is deliberately small enough to read in one sitting and to leave running for years.

## Install

```bash
git clone https://github.com/ayaanngandhi/tablinum.git
cd tablinum
python3 -m venv .venv && .venv/bin/pip install bcrypt
.venv/bin/python tablinum.py passwd          # set the one password (prompted twice)
.venv/bin/python tablinum.py serve --port 6320
```

Open <http://localhost:6320> and sign in. `./install.sh` does all of the above and registers a systemd user unit.

## The password

There is exactly one, and it is never stored — only its **bcrypt** hash, at cost 12, in `auth.json`:

```json
{
  "password_hash": "$2b$12$…",
  "secret": "…64 hex chars, signs session cookies…",
  "session_hours": 12
}
```

`auth.json` is written **0600** and is gitignored. Set or change it:

```bash
tablinum.py passwd                    # prompted twice, nothing echoed
tablinum.py passwd --keep-sessions    # change the password, keep people signed in
tablinum.py status                    # is a password set? how many files?
```

Changing the password **rotates the signing secret by default**, which signs out every existing session. That is the behaviour you want after a password leaks.

**No password means no service.** If `auth.json` is missing, `serve` refuses to start rather than defaulting to open:

```
tablinum: no password is set, so the shelf will not be served.
  Set one first:  python3 tablinum.py passwd
  Or serve it openly on purpose with --no-auth
```

### How the login is built

- **bcrypt, cost 12** — `bcrypt.checkpw`, no plaintext, no reversible storage. A wrong password costs the same ~0.25 s as a right one, so the login is not a timing oracle.
- **Sessions are signed, not stored.** The cookie is `<expiry>.<nonce>.<HMAC-SHA256>` keyed by the secret in `auth.json`; tampering with the expiry or the signature fails `hmac.compare_digest`.
- **Cookies are `HttpOnly`, `SameSite=Lax`, `Path=/`,** and add `Secure` automatically whenever the request arrived over HTTPS (`X-Forwarded-Proto`), so a Cloudflare Tunnel gets hardened cookies while a bare LAN IP still works.
- **CSRF is double-submit:** the login form carries a token that must match the `tablinum_csrf` cookie, compared in constant time. Logout is POST-only — a GET can never end your session.
- **Throttling:** 5 failed attempts from one address start an exponential lockout (30 s, 60 s, … capped at 15 min), and a global ceiling stops distributed guessing. A correct password is *also* refused while a lockout is active.
- **Input is sanitised before comparison:** bodies are capped at 4 KB, must be `application/x-www-form-urlencoded`, must decode as strict UTF-8, and the password is rejected if it contains NUL or control bytes. Whitespace is preserved — silently trimming it would lock out anyone whose password ends in a space.
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
| `tablinum.py passwd` | Set or change the single password. |
| `tablinum.py status` | Whether a password is set, file count, session length. |
| `tablinum.py build --out dist` | Static export: `dist/index.html` + `dist/files/**`. Refuses while a password is set. |
| `tablinum.py list` | Print the index as plain text. |
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

Creates the venv, offers to set the password, and installs a *user* unit `tablinum.service` on `:6320`, enabled at boot with linger so it survives logout and reboot.

```bash
systemctl --user status tablinum
journalctl --user -u tablinum -f
```

### Internet, with the password

A server that checks a password needs a server. Put it behind a tunnel rather than a static host:

```bash
cloudflared tunnel route dns <tunnel> docs.example.com
# then add an ingress rule: docs.example.com → http://localhost:6320
```

Cloudflare terminates TLS and forwards; Tablinum sees `X-Forwarded-Proto: https`, marks the cookie `Secure`, and the login stands in front of every file. Nothing else is exposed.

### Static hosting — deliberately awkward

A static export cannot check a password, so `build` **refuses to run while `auth.json` exists**:

```
tablinum: this shelf has a password, and a static export cannot check it.
  Building would put every file in the clear.
```

For a shelf that is *meant* to be public, pass `--public` explicitly (that is what `deploy.sh` does, behind a confirmation prompt). `dist/` is an ordinary website — Pages, S3, nginx, a USB stick.

### Behind a router or reverse proxy

Tablinum serves at `/`, so a proxy just forwards to `127.0.0.1:6320`. No path rewriting, no trailing-slash ambiguity. To link it from an index page elsewhere, `href="/tablinum"` is enough if your router maps that slug.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

29 tests covering password round-trip (including that the plaintext never appears in the hash), session token forgery and expiry, CSRF rejection, throttling, path traversal (six encodings), the build guard, and that the credential file lands at 0600.

## Design notes

- **The filesystem is the source of truth.** No manifest, no sync, no state to get stale. Delete a file and it is gone from the index on the next request.
- **`no-store` on the listing, `private, no-cache` on files** — a shelf you can trust to show what is actually there.
- **Path traversal is blocked by realpath containment,** not string inspection; symlinks are resolved before the check.
- **Dotfiles are not published.** Nor is anything in `.git`, `.venv` or `__pycache__`.
- **Accessibility and degradation:** the search box filters already-rendered rows with a few lines of vanilla JS; with JS off the page is a complete, readable list. Rows are real links, focus-visible, and respect `prefers-reduced-motion`.
- **No upload, no delete, no per-user accounts.** One password, read-only shelf.

## Limits (on purpose)

- One password, so one level of access. It is a shelf for a household, not a multi-tenant app.
- Rate-limit counters live in memory: a restart clears them. With bcrypt at cost 12 that is a rounding error next to the actual guessing cost.
- No search *inside* documents, no previews, no tagging. It indexes filenames, which is what a shelf needs.
- Files are read into memory per request; excellent for documents, wrong for multi-gigabyte media.
- No range requests, so video scrubbing is not supported.

## License

MIT © Ayaan Gandhi
