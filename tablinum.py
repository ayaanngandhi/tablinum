#!/usr/bin/env python3
"""
Tablinum — a small, dependency-free document shelf.

In a Roman house the tablinum was the record room opening off the atrium: the
place the family's papers were kept. This is that room, for files.

Two modes, one codebase:

    python3 tablinum.py serve --port 6320        # live LAN server, lists files/ as it is right now
    python3 tablinum.py build --out dist         # static export for Cloudflare Pages / any host

Drop any file into ./files and it appears in the listing. No database, no build
step needed to serve, no dependencies outside the Python standard library.

MIT licensed. https://github.com/ayaanngandhi/tablinum
"""

from __future__ import annotations

import argparse
import html
import json
import os
import posixpath
import shutil
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, unquote, urlsplit

__version__ = "1.0.0"

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.join(HERE, "files")
MOUNT = "/files"  # files are always served under this prefix, in both modes

SKIP = {".DS_Store", "Thumbs.db", ".git", "__pycache__"}

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
# rendering
# --------------------------------------------------------------------------

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<meta name="description" content="__TAGLINE__">
<style>
  :root {
    --panel: #1a1d1f;
    --panel-edge: #0c0e0f;
    --silk: #d5dade;
    --silk-dim: #79838b;
    --hair: #2b3135;
    --socket: #111416;
    --amber: #d9a441;
    --up: #3fd07a;
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
    flex: 1; background: none; border: 0; outline: 0; color: var(--silk);
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
  }
  footer a { color: var(--silk-dim); text-decoration: none; border-bottom: 1px solid #3a4247; }
  footer a:hover { color: var(--silk); }

  @media (max-width: 560px) {
    a.row { grid-template-columns: 44px minmax(0, 1fr) auto; gap: 10px; padding: 12px 13px; }
    .fdate { display: none; }
  }
  @media (prefers-reduced-motion: reduce) { a.row { transition: none; } }
</style>
</head>
<body>
<main>
  <header>
    <div class="eyebrow">__EYEBROW__</div>
    <h1>__TITLE__</h1>
    <p class="tagline">__TAGLINE__</p>
    <div class="stats">
      <span><b>__COUNT__</b> __NOUN__</span>
      <span><b>__SIZE__</b> total</span>
      <span>newest first</span>
    </div>
  </header>
  __SEARCH__
  __GROUPS__
  <footer>
    <span>__FOOTER_LEFT__</span>
    <span><a href="__FOOTER_URL__">__FOOTER_RIGHT__</a></span>
  </footer>
</main>
__SCRIPT__
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

SCRIPT = """<script>
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


def link_for(rel: str) -> str:
    return MOUNT + "/" + quote(rel)


def render(files: list[dict], *, eyebrow: str, title: str, tagline: str,
           footer_left: str, footer_right: str = "tablinum",
           footer_url: str = "https://github.com/ayaanngandhi/tablinum") -> str:
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

    return (PAGE
            .replace("__EYEBROW__", html.escape(eyebrow))
            .replace("__TITLE__", html.escape(title))
            .replace("__TAGLINE__", html.escape(tagline))
            .replace("__COUNT__", str(len(files)))
            .replace("__NOUN__", "file" if len(files) == 1 else "files")
            .replace("__SIZE__", human_size(total))
            .replace("__SEARCH__", SEARCH if files else "")
            .replace("__GROUPS__", "\n".join(blocks))
            .replace("__FOOTER_LEFT__", html.escape(footer_left))
            .replace("__FOOTER_RIGHT__", html.escape(footer_right))
            .replace("__FOOTER_URL__", html.escape(footer_url))
            .replace("__SCRIPT__", SCRIPT if files else ""))


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


def page_for(root: str, cfg: dict) -> str:
    files = collect(root)
    return render(
        files,
        eyebrow=cfg.get("eyebrow", "tablinum · the record room"),
        title=cfg.get("title", "Documents"),
        tagline=cfg.get("tagline", "Everything kept in one place — notes, papers, reports and references."),
        footer_left=cfg.get("footer_left", f"{len(files)} file{'' if len(files) == 1 else 's'} in files/"),
        footer_right=cfg.get("footer_right", "tablinum on github"),
        footer_url=cfg.get("footer_url", "https://github.com/ayaanngandhi/tablinum"),
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
        return None
    return target


def make_handler(root: str, cfg: dict, verbose: bool):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = f"Tablinum/{__version__}"
        sys_version = ""

        def log_message(self, fmt, *args):
            if verbose:
                sys.stderr.write("%s  %s\n" % (self.log_date_time_string(), fmt % args))

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _not_found(self):
            body = (b"<!doctype html><meta charset=utf-8><title>Not found</title>"
                    b"<body style=\"background:#0c0e0f;color:#d5dade;font-family:Helvetica,Arial,sans-serif;"
                    b"padding:48px\"><h1 style=\"font-weight:500;letter-spacing:-.02em\">Not found</h1>"
                    b"<p style=\"color:#79838b\">No such file on this shelf. "
                    b"<a style=\"color:#d9a441\" href=\"/\">Back to the index</a>.</p>")
            self._send(404, body, "text/html; charset=utf-8")

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            path = urlsplit(self.path).path
            if path in ("/", "/index.html"):
                page = page_for(root, cfg).encode("utf-8")
                return self._send(200, page, "text/html; charset=utf-8",
                                  {"Cache-Control": "no-store"})
            if path == "/healthz":
                return self._send(200, b"ok\n", "text/plain; charset=utf-8",
                                  {"Cache-Control": "no-store"})
            if path.startswith(MOUNT + "/"):
                target = resolve(root, path)
                if not target:
                    return self._not_found()
                ext = os.path.splitext(target)[1].lower()
                ctype = CONTENT_TYPES.get(ext, "application/octet-stream")
                try:
                    with open(target, "rb") as fh:
                        body = fh.read()
                except OSError:
                    return self._not_found()
                return self._send(200, body, ctype, {"Cache-Control": "no-cache"})
            return self._not_found()

    return Handler


def serve(root: str, host: str, port: int, verbose: bool):
    if not os.path.isdir(root):
        print(f"tablinum: no such directory: {root}", file=sys.stderr)
        return 2
    cfg = load_site_config(root)
    httpd = ThreadingHTTPServer((host, port), make_handler(root, cfg, verbose))
    httpd.daemon_threads = True
    count = len(collect(root))
    print(f"Tablinum {__version__} — {count} files from {root}")
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

def build(root: str, out: str) -> int:
    if not os.path.isdir(root):
        print(f"tablinum: no such directory: {root}", file=sys.stderr)
        return 2
    if os.path.abspath(out) in (os.path.abspath(root), os.path.dirname(os.path.abspath(root))):
        print("tablinum: refusing to write the export inside itself", file=sys.stderr)
        return 2
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)

    dest = os.path.join(out, MOUNT.lstrip("/"))
    shutil.copytree(root, dest, ignore=shutil.ignore_patterns(".DS_Store", "__pycache__", ".git"))

    cfg = load_site_config(root)
    index = page_for(root, cfg)
    with open(os.path.join(out, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(index)
    with open(os.path.join(out, "404.html"), "w", encoding="utf-8") as fh:
        fh.write(index)
    with open(os.path.join(out, "_headers"), "w", encoding="utf-8") as fh:
        fh.write("/files/*\n  Cache-Control: public, max-age=3600\n"
                 "/\n  Cache-Control: public, max-age=60\n")

    files = collect(root)
    print(f"tablinum: exported {len(files)} files → {out}/")
    return 0


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tablinum", description="A small, dependency-free document shelf.")
    ap.add_argument("--version", action="version", version=f"tablinum {__version__}")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("serve", help="serve files/ over HTTP with a live listing")
    s.add_argument("--dir", default=DEFAULT_ROOT, help="directory to publish (default: ./files)")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=6320)
    s.add_argument("-v", "--verbose", action="store_true")

    b = sub.add_parser("build", help="export a static copy for Pages/S3/any host")
    b.add_argument("--dir", default=DEFAULT_ROOT, help="directory to publish (default: ./files)")
    b.add_argument("--out", default="dist", help="output directory (default: ./dist)")

    c = sub.add_parser("list", help="print the index as plain text")
    c.add_argument("--dir", default=DEFAULT_ROOT)

    args = ap.parse_args(argv)
    if args.cmd == "serve":
        return serve(os.path.abspath(args.dir), args.host, args.port, args.verbose)
    if args.cmd == "build":
        return build(os.path.abspath(args.dir), os.path.abspath(args.out))
    if args.cmd == "list":
        files = collect(os.path.abspath(args.dir))
        if not files:
            print("(empty)")
        for f in files:
            print(f"{human_size(f['size']):>9}  "
                  f"{time.strftime('%d %b %Y', time.localtime(f['mtime']))}  {f['rel']}")
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
