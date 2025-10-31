#!/bin/bash

SCRIPT_PATH="$(realpath "$0")"
SCRIPT_NAME="$(basename "$SCRIPT_PATH")"

cd "$(dirname "$SCRIPT_PATH")" || exit 1

git fetch origin main >/dev/null 2>&1

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "🔄 New commit detected. Updating repository..."
    git reset --hard origin/main

    chmod +x "$SCRIPT_NAME"

    npm install --silent
    pm2 restart KeyloSite
else
    echo "✅ Already up to date."
fi
