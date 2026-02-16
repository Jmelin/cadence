# Cadence

Cadence is a lightweight Flask app for tracking recurring tasks, grouped by category, with completion history and simple backup/restore controls.

## What it does

- Create task groups (for example: Health, Home, Work)
- Add tasks into groups
- Mark tasks complete and store full completion history
- Show human-friendly "last completed" timing
- Provide a hidden admin route for task deletion, full wipe, and restore from JSON backups
- Persist data in SQLite

## Tech stack

- Python
- Flask
- SQLite
- Gunicorn (for container runtime)
- Docker / Docker Compose (optional)

## Requirements

- Python 3.10+ (3.12 recommended)
- `pip`
- Docker + Docker Compose plugin (optional, for containerized run)

## Quick start (local Python)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create an environment file:

```bash
cp .env.example .env
```

Then edit `.env` and set at least:

- `ADMIN_SLUG` (long random slug)
- `SECRET_KEY` (recommended: 64 hex chars)
- `USER_TIMEZONE` (IANA timezone like `America/New_York` or `UTC`)

Generate a strong `SECRET_KEY` if needed:

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

Run:

```bash
python app.py
```

Open: `http://127.0.0.1:5000`

Notes:

- `ADMIN_SLUG` is optional, but without it all `/admin/...` routes return `404`.
- If `SECRET_KEY` is not set, the app generates one at startup (sessions are then invalidated on restart).

## Quick start (Docker Compose)

Create and configure your env file:

```bash
cp .env.example .env
```

Then update `ADMIN_SLUG`, `SECRET_KEY`, and `USER_TIMEZONE` in `.env`.

Start:

```bash
docker compose up --build -d
```

View logs:

```bash
docker compose logs -f cadence
```

Stop:

```bash
docker compose down
```

Open: `http://127.0.0.1:5000`

## Configuration

Environment variables used by the app:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADMIN_SLUG` | unset | Secret slug for admin route (`/admin/<slug>`). If unset, admin route is disabled (404). |
| `SECRET_KEY` | random at process start | Flask session and CSRF signing key. Set this explicitly in real deployments. |
| `USER_TIMEZONE` | `UTC` | Timezone used for displayed completion times (IANA format, e.g. `America/Chicago`). Invalid values fall back to `UTC`. |
| `DATABASE_PATH` | `./tasks.db` | SQLite database file path. |
| `BACKUP_DIR` | `./backups` | Directory for JSON backups. |
| `MAX_NAME_LENGTH` | `120` | Maximum length for group/task names. |
| `SESSION_COOKIE_SECURE` | `false` | Set to `true` when serving over HTTPS. |
| `FLASK_DEBUG` | `false` | Enables Flask debug mode when running `python app.py`. |

## Data storage

### Local run

- Database: `tasks.db`
- Backups: `backups/backup-YYYYMMDD-HHMMSS.json`

### Docker Compose run

- In container: database at `/data/tasks.db`, backups at `/data/backups`
- Persisted via named volume: `cadence_data`

## Admin route

Admin URL format:

- `http://127.0.0.1:5000/admin/<your-admin-slug>`

Available admin actions:

- Delete a task (also removes its completion history)
- Full wipe
  - Creates a backup first
  - Removes all groups, tasks, completions
  - Re-creates default `General` group
- Restore from an existing backup file in the backup directory

## Security behavior

- All `POST` forms require CSRF token validation
- Admin slug checks use constant-time comparison
- Response headers include:
  - `Content-Security-Policy`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
- Session cookies are `HttpOnly` and `SameSite=Lax`

## Project layout

- `app.py`: Flask app and SQLite logic
- `templates/index.html`: main task UI
- `templates/admin.html`: admin UI
- `docker-compose.yml`: local container orchestration
- `Dockerfile`: production-style app image
- `.env.example`: example environment file for local and Compose runs

## Troubleshooting

- `docker compose` fails with `set ADMIN_SLUG` or `set SECRET_KEY`:
  - Ensure `.env` exists (`cp .env.example .env`) and contains both values.
- Admin page returns `404`:
  - Ensure `ADMIN_SLUG` is set and URL slug matches exactly.
- Data appears reset after container restart:
  - Confirm the container uses the `cadence_data` volume and you did not remove volumes.
