#!/usr/bin/env bash
# Builds the release package for "Deploy to Azure": code + production dependencies, ready to run.
#   ./tools/build-package.sh   ->  dist/abr-approvals-bot.zip   (attach it to a GitHub release)
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
cp -R "$HERE/package.json" "$HERE/package-lock.json" "$HERE/src" "$HERE/public" "$TMP/"
(cd "$TMP" && npm ci --omit=dev --no-audit --no-fund --loglevel=error)
mkdir -p "$HERE/dist"
rm -f "$HERE/dist/abr-approvals-bot.zip"
(cd "$TMP" && zip -qr "$HERE/dist/abr-approvals-bot.zip" .)
rm -rf "$TMP"
ls -la "$HERE/dist/abr-approvals-bot.zip"
