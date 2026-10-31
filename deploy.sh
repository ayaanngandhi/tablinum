#!/usr/bin/env bash
# Build the static export and publish it to Cloudflare Pages.
#   PROJECT / BRANCH can be overridden in the environment.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="${PROJECT:-tablinum}"
BRANCH="${BRANCH:-main}"

cd "$DIR"

python3 tablinum.py build --out dist

wrangler pages deploy dist \
  --project-name "$PROJECT" \
  --branch "$BRANCH" \
  --commit-dirty=true

echo
echo "Deployed → https://$PROJECT.pages.dev"
