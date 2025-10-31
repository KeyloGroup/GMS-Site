#!/bin/bash

PM2_APP_NAME="KeyloSite"

git fetch origin main

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "New commit detected. Pulling updates..."
    git reset --hard origin/main

    if git diff --name-only HEAD~1 HEAD | grep -qE 'package\.json|package-lock\.json'; then
        echo "Dependencies changed. Installing..."
        npm install
    fi

    if [ -n "$(git diff --name-only HEAD~1 HEAD)" ]; then
        echo "Changes detected. Restarting PM2 app..."
        pm2 restart "$PM2_APP_NAME"
    fi
else
    echo "No new commits. Nothing to do."
fi
