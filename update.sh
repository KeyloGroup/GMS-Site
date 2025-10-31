#!/bin/bash

# Always ensure script is executable, even after a git reset
SCRIPT_PATH="$(realpath "$0")"
SCRIPT_NAME="$(basename "$SCRIPT_PATH")"

# Go to the repo root (this script is inside the repo)
cd "$(dirname "$SCRIPT_PATH")" || exit 1

# Make sure Git doesn't prompt for username/password
git config --local credential.helper store

# Fetch latest changes
git fetch origin main >/dev/null 2>&1

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "🔄 New commit detected. Updating repository..."
    git reset --hard origin/main

    # Restore execute permissions for this script
    chmod +x "$SCRIPT_NAME"

    # Install dependencies silently
    npm install --silent

    # Restart PM2 process
    pm2 restart KeyloSite
else
    echo "✅ Already up to date."
fi
