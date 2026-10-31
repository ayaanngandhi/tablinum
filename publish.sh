#!/usr/bin/env bash
# Publish one or more files: copy them onto the shelf, then push the public mirror.
#   ./publish.sh ~/Downloads/notes.pdf
# The LAN server picks them up on the next request; the public site needs the deploy below.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $# -lt 1 ]; then
  echo "usage: ./publish.sh <file> [more files...]" >&2
  exit 1
fi

for f in "$@"; do
  if [ ! -f "$f" ]; then
    echo "not a file: $f" >&2
    exit 1
  fi
  cp "$f" "$DIR/files/"
  echo "added  $(basename "$f")"
done

"$DIR/deploy.sh"
