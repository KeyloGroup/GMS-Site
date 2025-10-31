#!/bin/bash
cd /Keylo
git fetch origin main
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ $LOCAL != $REMOTE ]; then
    echo "New commit detected. Pulling updates..."
    git reset --hard origin/main
    npm install 
    pm2 restart KeyloSite
fi
