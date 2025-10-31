#!/bin/bash

set -e

cd "$(dirname "$(realpath "$0")")"

while true; do
  git fetch --depth=1 origin main --quiet
  LOCAL_COMMIT=$(git rev-parse HEAD)
  REMOTE_COMMIT=$(git rev-parse origin/main)
  if [ "$LOCAL_COMMIT" != "$REMOTE_COMMIT" ]; then
      echo "🔄 Fast update in progress..."
      git reset --hard origin/main --quiet
      if ! cmp -s package-lock.json .package-lock.last 2>/dev/null; then
          npm install --silent
          cp package-lock.json .package-lock.last
      fi
      pm2 restart KeyloSite
      echo "✅ Update complete."
  else
      echo "✅ Already up to date."
  fi
  sleep 10
done
