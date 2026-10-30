# Cadence

Cadence is a Flask application for recurring tasks. Tasks belong to groups. The application stores completion history in SQLite.

## Features

- Create task groups, such as Health, Home, and Work.
- Add tasks to a group.
- Complete a task with an optional note of 500 characters or fewer.
- Open each task's history to see completion times, notes, and intervals between completions.
- Filter the Activity page by task, area, and date range.
- Set a task cadence, due-soon lead time, pause state, and reminder state.
- Use an admin page to delete tasks, erase data, and restore JSON backups.
- Store data in SQLite.

## Task dashboard

The dashboard shows each task's due status and time since its last completion. Status counts update after each change.

- Select a status count to filter the tasks.
- Use the search field to find a task or area.
- Select **View history** on a task card to see its completions and notes.
- Open **Details** to add a completion note or change schedule settings.
- Select **Complete** to record a completion. Use **Complete with note** inside Details to include a note.

Tasks appear by area, sorted by name A–Z within each area. Search, filters, and updates without a page reload require JavaScript.
Task forms and expandable details also work without JavaScript.

### Profiles

Each task can have one profile. Tasks without a profile are global.

- Open `/` to see all tasks.
- Open a profile URL, such as `/jordan`, to see that profile's tasks and all global tasks.
- Select a profile above the dashboard to switch views. Search and status filters apply within that view.
- Open **Create a profile** to add a name and URL slug. Leave the slug empty to generate it from the name.
- New tasks default to the current profile. In **All profiles**, new tasks default to **Global**.
- To change a task's profile, open **Details**, then **Schedule & reminders**. Select a profile or **Global** and save.

Global tasks share one schedule and completion history. Completing a global task updates it for everyone.
Profiles filter tasks. They are not accounts and do not restrict access.
The Activity page and reminder emails still include all profiles. Profiles do not change reminder recipients.

Profile URLs use lowercase letters, numbers, and single hyphens. Each slug starts with a letter and has at most 80 characters.
Slugs must be unique. Application paths, such as `activity`, `tasks`, and `admin`, are reserved. Unknown profile URLs return 404.

To delete a profile, open its dashboard and expand **Delete this profile**. Confirm that its tasks will become global.
Deleting a profile keeps its tasks and completion history.

Existing tasks become global when the database upgrades. Backups include profiles and task assignments.
Restoring an older backup without profiles makes its tasks global. A full wipe also deletes profiles.

### Completion history

Each task card shows the exact last completion time, the time since that completion, and a history link with the completion count.
The task history page shows its last completion, total completions, and next due date above a dated timeline.
Each timeline entry includes the completion time, an optional note, and the elapsed interval since the previous completion.

Select **Activity** to see completions across all tasks. Select a task name in the timeline to open its history.
Use the task and area filters to narrow the Activity timeline. Both timelines support **From** and **Through** date filters.
The date range includes both selected dates in `USER_TIMEZONE`, including daylight saving time changes.
Intervals use elapsed time, while **Today**, **Yesterday**, and days-ago labels use local calendar dates.

Each page shows up to 50 completions, newest first. Select **Older completions** to continue or **Newest completions** to return.
Pagination keeps the selected filters. You can bookmark or share a filtered URL.
History pages and filters work without JavaScript. History is read-only; logging past completions and correcting entries are not supported.

### Repeat intervals

Automatic scheduling is the default. Cadence uses the median interval between completions after at least three completions with distinct times.

To set a manual interval, enter a value in **Repeat every, in days** when you add a task.
For an existing task, open **Details**, then **Schedule & reminders**.
For example, `7` means weekly and `14` means every two weeks.

A manual interval calculates the next due time from the last completion. A new task needs one completion before its schedule starts.
Each completion starts the next interval. Reminder emails use this schedule when enabled.

To return to automatic scheduling, clear the repeat interval and select **Save settings**. Cadence keeps the completion history.

### Seasonal tasks

Open **Details**, then **Schedule & reminders**. Under **Active months**, select the months when you do the task. Select **Save settings**.

For a summer task, select June, July, and August. Select all months for a year-round task. At least one month must remain selected.

Outside its active months, a task shows **Off season**. It is not due soon or overdue. It sends no individual reminders and does not appear in reminder digests.

Month changes use `USER_TIMEZONE`. During active months, the normal schedule resumes from the last completion. A task can become overdue when its season starts.

You can still complete a task outside its active months. Existing tasks and older backups default to all months. Backups include each task's active months.

## Requirements

- Python 3.10 or later.
- `pip`
- Docker with the Docker Compose plugin for a container run.

## Run Locally

Create and activate a virtual environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the Python packages.

```bash
pip install -r requirements.txt
```

Create the environment file.

```bash
cp .env.example .env
```

Set these values in `.env`:

- `ADMIN_SLUG`: A long random string.
- `SECRET_KEY`: A random 64-character hexadecimal string.
- `USER_TIMEZONE`: An IANA time zone, such as `America/New_York` or `UTC`.

Generate a `SECRET_KEY`.

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

Start the application.

```bash
python app.py
```

Open `http://127.0.0.1:5000`.

## Run With Docker Compose

Create the environment file.

```bash
cp .env.example .env
```

Set `ADMIN_SLUG`, `SECRET_KEY`, and `USER_TIMEZONE` in `.env`.

Start the services.

```bash
docker compose up --build -d
```

Open `http://127.0.0.1:5000`.

Read the application log.

```bash
docker compose logs -f cadence
```

Stop the services.

```bash
docker compose down
```

## Configuration

The application reads the following environment variables.

| Variable | Default | Description |
| --- | --- | --- |
| `ADMIN_SLUG` | unset | Secret value in the admin URL. The admin page returns `404` if this value is unset. |
| `SECRET_KEY` | random at process start | Key for Flask sessions and CSRF tokens. Set this value for deployments. |
| `USER_TIMEZONE` | `UTC` | Time zone for completion times. Invalid values use `UTC`. |
| `DATABASE_PATH` | `./tasks.db` | SQLite database path. |
| `BACKUP_DIR` | `./backups` | Directory for JSON backups. |
| `MAX_NAME_LENGTH` | `120` | Maximum length for group and task names. |
| `SESSION_COOKIE_SECURE` | `false` | Set to `true` for HTTPS. |
| `FLASK_DEBUG` | `false` | Enables Flask debug mode for `python app.py`. |
| `PUBLIC_BASE_URL` | unset | Public HTTPS URL for reminder links. |
| `SMTP_HOST` | unset | SMTP server host. |
| `SMTP_PORT` | `587` | SMTP server port. |
| `SMTP_USERNAME` | unset | SMTP user name. |
| `SMTP_PASSWORD` | unset | SMTP password. |
| `SMTP_FROM` | unset | Sender address for reminders. |
| `SMTP_USE_TLS` | `true` | Starts TLS before SMTP authentication and mail delivery. |
| `REMINDER_RECIPIENT` | unset | Recipient address for reminders. |
| `REMINDER_DIGEST_HOUR` | `8` | Local hour from 0 through 23 for the daily digest. |
| `EMAIL_ACTION_SECRET` | unset | Secret for expiring reminder links. |
| `EMAIL_ACTION_TTL_HOURS` | `72` | Valid time for a reminder link, in hours. |
| `REMINDER_WORKER_INTERVAL_SECONDS` | `60` | Time between worker scans, in seconds. |
| `REMINDER_MAX_ATTEMPTS` | `3` | Maximum deliveries for one reminder. |
| `REMINDER_RETRY_DELAY_MINUTES` | `15` | Time before a retry, in minutes. |
| `DEFAULT_DUE_SOON_LEAD_DAYS` | `0` | Global due-soon lead time. `0` uses automatic proportional timing. |

## Email Reminders

Docker Compose starts a `reminder-worker` service. The service uses the same SQLite data as the web application.

The worker sends no mail until all required reminder values are set. The required values are `PUBLIC_BASE_URL`, `SMTP_HOST`, `SMTP_FROM`, `REMINDER_RECIPIENT`, and `EMAIL_ACTION_SECRET`.

The worker sends one reminder for each overdue due time. After the local digest hour, it sends a daily digest for due-soon and overdue tasks.

Delivery records prevent duplicate mail. Failed or stale deliveries retry until they reach `REMINDER_MAX_ATTEMPTS`.

Reminder links open a confirmation page. Only the CSRF-protected confirmation `POST` completes a task. Links use HMAC authentication, expire, and work once.

## Data Storage

### Local Run

- Database: `tasks.db`
- Backups: `backups/backup-YYYYMMDD-HHMMSS.json`

### Docker Compose Run

- Database: `/data/tasks.db`
- Backups: `/data/backups`
- Persistent volume: `cadence_data`

## Admin Page

Open `http://127.0.0.1:5000/admin/<your-admin-slug>`.

The admin page can delete a task and its completion history. It can erase all data after it creates a backup.

An erase creates the `General` group after it deletes all groups, tasks, and completions. The admin page can also restore a backup from the backup directory.

## Security

- All `POST` forms require a CSRF token.
- Admin slug comparisons use constant-time comparison.
- The application sends `Content-Security-Policy` response headers.
- The application sends `X-Frame-Options: DENY` response headers.
- The application sends `X-Content-Type-Options: nosniff` response headers.
- The application sends `Referrer-Policy: no-referrer` response headers.
- Session cookies use `HttpOnly` and `SameSite=Lax`.

## Project Files

- `app.py`: Flask application and SQLite functions.
- `reminder_worker.py`: Email reminder worker.
- `templates/index.html`: Main task page.
- `templates/activity.html`: Activity and task history timelines.
- `templates/admin.html`: Admin page.
- `docker-compose.yml`: Container service configuration.
- `Dockerfile`: Application image definition.
- `.env.example`: Example environment configuration.

## Troubleshooting

If `docker compose` reports `set ADMIN_SLUG` or `set SECRET_KEY`, create `.env`. Then set both values.

If Docker shows completion times in UTC, set `USER_TIMEZONE` in `.env`. Then rebuild the services.

```bash
docker compose up --build -d
```

If the admin page returns `404`, make sure that `ADMIN_SLUG` is set. Make sure that the URL has the same slug.

If data disappears after a container restart, make sure that the service uses the `cadence_data` volume. Do not remove volumes.
