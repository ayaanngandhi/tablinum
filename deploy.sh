#!/usr/bin/env bash
# Build the static export and publish it to Cloudflare Pages.
#
# NOTE: a static export cannot check a password. This is for shelves that are
# MEANT to be public; it passes --public deliberately.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="${PROJECT:-tablinum}"
BRANCH="${BRANCH:-main}"

cd "$DIR"

python3 tablinum.py build --out dist --public

echo
read -r -p "Publish these files to the open internet at $PROJECT.pages.dev? [y/N] " yn
case "$yn" in
  [Yy]*) ;;
  *) echo "Stopped. Nothing was deployed."; exit 1 ;;
esac

wrangler pages deploy dist \
  --project-name "$PROJECT" \
  --branch "$BRANCH" \
  --commit-dirty=true

echo
echo "Deployed → https://$PROJECT.pages.dev"
