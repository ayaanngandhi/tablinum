# Tablinum

**A small, dependency-free document shelf.** Drop files in a folder; get a clean, readable index of them — on your LAN and on the public web, from the same directory.

In a Roman house the *tablinum* was the record room opening off the atrium: the place the family's papers were kept. This is that room, for files.

```
   files/                      tablinum                →  http://localhost:6320
     circles-class10.html                                →  https://docs.example.com
     unit-test.pdf
     notes/
```

No database. No build step to serve. Nothing outside the Python standard library.

---

## Why

Static file hosting is easy; *finding* things is not. Tablinum is the minimum honest answer: a directory is the database, the listing is generated on every request, and the same Python file can export a static mirror for Cloudflare Pages, S3, or any dumb host.

It is deliberately small enough to read in one sitting (~600 lines, one file) and to leave running for years.

## Install

```bash
git clone https://github.com/ayaanngandhi/tablinum.git
cd tablinum
python3 tablinum.py serve --port 6320
```

Open <http://localhost:6320>. Requires Python 3.9+. That is the whole install.

## Use

Put files in `./files` (or any directory you point it at):

```bash
cp ~/report.pdf files/
# reload the page — it is already listed
```

| Command | What it does |
| --- | --- |
| `tablinum.py serve --port 6320` | Live server. Newest file first, filter box, nested folders grouped. |
| `tablinum.py build --out dist` | Static export: `dist/index.html` + `dist/files/**`, ready for Pages/S3/nginx. |
| `tablinum.py list` | Print the index as plain text (handy in a terminal or a cron mail). |

Flags: `--dir` selects what gets published (default `./files`), `--host` binds the interface (default `0.0.0.0`), `-v` logs every request.

### URL scheme

Deliberately boring and identical in both modes:

- `/` — the index
- `/files/<relative path>` — a file
- `/healthz` — `ok`

Files always live under `/files/`, so a file called `index.html` can never collide with the generated listing.

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
sudo ./install.sh
```

installs a *user* unit, `tablinum.service`, listening on `:6320` and enabled at boot. Then:

```bash
systemctl --user status tablinum
journalctl --user -u tablinum -f
```

`install.sh` also enables linger, so the unit survives logout and reboot.

### Cloudflare Pages

```bash
./deploy.sh                 # builds ./dist and pushes it to the Pages project
```

Set `PROJECT` and `BRANCH` in `deploy.sh` if you want different names, then attach your domain in the Pages dashboard. Because the export is plain static files, any host works the same way — `dist/` is a website.

### Behind a router or reverse proxy

Tablinum serves at `/`, so a proxy just forwards to `127.0.0.1:6320`. There is no path rewriting and no trailing-slash ambiguity. To link it from an index page elsewhere, `href="/tablinum"` is enough if your router maps that slug.

## Design notes

- **The filesystem is the source of truth.** No manifest, no sync, no state to get stale. Delete a file and it is gone from the index on the next request.
- **`Cache-Control: no-store` on the index, `no-cache` on files** when serving — a shelf you can trust to show what is actually there, which matters more than shaving milliseconds off a LAN page.
- **Path traversal is blocked by realpath containment,** not by string inspection; symlinks are resolved before the check.
- **Dotfiles are not published.** Nor is anything in `.git` or `__pycache__`.
- **The listing is honest about size and time.** Every row shows bytes and last-modified, formatted locally.
- **Accessibility and degradation:** the search box filters already-rendered rows with a few lines of vanilla JS; with JS off the page is a complete, readable list. Rows are real links, focus-visible, and respect `prefers-reduced-motion`.
- **No upload, no delete, no auth.** Read-only by design — it publishes a directory you already control. Put a proxy in front if you need access control.

## Limits (on purpose)

- No search *inside* documents, no previews, no tagging. It indexes filenames, which is what a shelf needs.
- Files are read into memory per request; excellent for documents, wrong for multi-gigabyte media. Use a real file server for that.
- No range requests, so video scrubbing is not supported.

## License

MIT © Ayaan Gandhi
