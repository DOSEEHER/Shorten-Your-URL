#!/bin/sh
set -eu
python -c "from app import init_db_and_admin; init_db_and_admin()"
exec gunicorn --bind 0.0.0.0:5000 --workers "${WEB_WORKERS:-2}" --threads "${WEB_THREADS:-2}" --timeout 30 --access-logfile - --error-logfile - app:app
