#!/usr/bin/env bash
# Development launcher: sets up a virtualenv, installs deps, starts the app.
# For production use gunicorn (see README) instead.
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d venv ]; then
  echo "Creating virtualenv..."
  python3 -m venv venv
fi

# shellcheck source=/dev/null
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

if [ ! -f .env ] && [ -f .env.example ]; then
  cp .env.example .env
  echo "Created .env from .env.example. Edit it if you need a server-side key."
fi

# gunicorn.conf.py loads .env itself, so no shell export dance is needed.
echo "Starting. Settings come from .env; default is http://0.0.0.0:8000"
exec gunicorn -c gunicorn.conf.py wsgi:application
