import os
import json
import hmac
import hashlib
import secrets
import sqlite3
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from html import escape
from math import ceil
from pathlib import Path
from statistics import median
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Flask, abort, g, jsonify, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "tasks.db"
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", str(BASE_DIR / "backups")))
MIN_COMPLETIONS_FOR_CADENCE = 3
MAX_CADENCE_INTERVAL_DAYS = 3650
MAX_DUE_SOON_LEAD_DAYS = 365
MAX_COMPLETION_NOTE_LENGTH = 500


def load_env_file(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue

        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


load_env_file(BASE_DIR / ".env")


def resolve_display_timezone(value: str):
    timezone_name = value.strip() if value else ""
    if not timezone_name:
        timezone_name = "UTC"
    try:
        return ZoneInfo(timezone_name), timezone_name
    except ZoneInfoNotFoundError:
        return timezone.utc, "UTC"


app = Flask(__name__)
app.config["DATABASE"] = os.getenv("DATABASE_PATH", str(DB_PATH))
app.config["ADMIN_SLUG"] = os.getenv("ADMIN_SLUG", "").strip() or None
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_NAME_LENGTH"] = int(os.getenv("MAX_NAME_LENGTH", "120"))
display_timezone, timezone_name = resolve_display_timezone(os.getenv("USER_TIMEZONE", "UTC"))
app.config["DISPLAY_TIMEZONE"] = display_timezone
app.config["USER_TIMEZONE"] = timezone_name
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("SESSION_COOKIE_SECURE", "").lower() in {"1", "true", "yes"}
)
app.config["PUBLIC_BASE_URL"] = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
app.config["SMTP_HOST"] = os.getenv("SMTP_HOST", "").strip()
app.config["SMTP_PORT"] = int(os.getenv("SMTP_PORT", "587"))
app.config["SMTP_USERNAME"] = os.getenv("SMTP_USERNAME", "")
app.config["SMTP_PASSWORD"] = os.getenv("SMTP_PASSWORD", "")
app.config["SMTP_FROM"] = os.getenv("SMTP_FROM", "")
app.config["SMTP_USE_TLS"] = os.getenv("SMTP_USE_TLS", "true").lower() in {"1", "true", "yes"}
app.config["REMINDER_RECIPIENT"] = os.getenv("REMINDER_RECIPIENT", "").strip()
app.config["REMINDER_DIGEST_HOUR"] = int(os.getenv("REMINDER_DIGEST_HOUR", "8"))
app.config["EMAIL_ACTION_SECRET"] = os.getenv("EMAIL_ACTION_SECRET", "")
app.config["EMAIL_ACTION_TTL_HOURS"] = int(os.getenv("EMAIL_ACTION_TTL_HOURS", "72"))
app.config["REMINDER_WORKER_INTERVAL_SECONDS"] = int(
    os.getenv("REMINDER_WORKER_INTERVAL_SECONDS", "60")
)
app.config["REMINDER_MAX_ATTEMPTS"] = int(os.getenv("REMINDER_MAX_ATTEMPTS", "3"))
app.config["REMINDER_RETRY_DELAY_MINUTES"] = int(
    os.getenv("REMINDER_RETRY_DELAY_MINUTES", "15")
)
app.config["DEFAULT_DUE_SOON_LEAD_DAYS"] = int(
    os.getenv("DEFAULT_DUE_SOON_LEAD_DAYS", "0")
)


def parse_iso_utc(timestamp: Optional[str]) -> Optional[datetime]:
    if not timestamp:
        return None
    return datetime.fromisoformat(timestamp)


def format_local_datetime(timestamp: Optional[str]) -> str:
    completed_at = parse_iso_utc(timestamp)
    if not completed_at:
        return "Never"
    local_time = completed_at.astimezone(app.config["DISPLAY_TIMEZONE"])
    return local_time.strftime("%b %d, %Y at %I:%M %p").replace(" 0", " ")


def completed_ago(timestamp: Optional[str]) -> str:
    completed_at = parse_iso_utc(timestamp)
    if not completed_at:
        return "Not completed yet"

    elapsed_days = (datetime.now(timezone.utc) - completed_at).days
    if elapsed_days <= 0:
        return "Completed today"
    if elapsed_days == 1:
        return "Completed 1 day ago"
    if elapsed_days < 30:
        return f"Completed {elapsed_days} days ago"

    months = elapsed_days // 30
    if months == 1:
        return "Completed 1 month ago"
    return f"Completed {months} months ago"


def format_interval_days(interval_days: float) -> str:
    rounded_days = float(round(interval_days, 1))
    if rounded_days == 1:
        return "1 day"
    if rounded_days.is_integer():
        return f"{int(rounded_days)} days"
    return f"{rounded_days} days"


def cadence_insight(
    history: list[str],
    manual_interval_days: Optional[float] = None,
    due_soon_lead_days: Optional[int] = None,
    is_paused: bool = False,
    now: Optional[datetime] = None,
) -> dict:
    insight = {
        "status": None,
        "interval_days": None,
        "due_at": None,
        "due_display": None,
        "message": None,
        "source": None,
    }
    if is_paused:
        insight["message"] = "Paused"
        return insight
    if manual_interval_days is not None:
        if not history:
            insight["source"] = "manual"
            insight["interval_days"] = manual_interval_days
            insight["message"] = (
                f"Manual cadence: every {format_interval_days(manual_interval_days)}. "
                "Complete it once to start scheduling."
            )
            return insight
        interval_days = manual_interval_days
        source = "manual"
    else:
        source = "learned"
        if len(history) < MIN_COMPLETIONS_FOR_CADENCE:
            if history:
                remaining = MIN_COMPLETIONS_FOR_CADENCE - len(history)
                completion_word = "completion" if remaining == 1 else "completions"
                insight["message"] = f"{remaining} more {completion_word} to learn its cadence"
            return insight

        completion_times = [parse_iso_utc(timestamp) for timestamp in history]
        if any(timestamp is None for timestamp in completion_times):
            return insight
        gaps = [
            (completion_times[index] - completion_times[index + 1]).total_seconds() / 86400
            for index in range(len(completion_times) - 1)
            if completion_times[index] > completion_times[index + 1]
        ]
        if len(gaps) < MIN_COMPLETIONS_FOR_CADENCE - 1:
            insight["message"] = "Needs more distinct completion days to learn its cadence"
            return insight
        interval_days = float(median(gaps))

    completion_times = [parse_iso_utc(timestamp) for timestamp in history]
    if any(timestamp is None for timestamp in completion_times):
        return insight
    due_at = completion_times[0] + timedelta(days=interval_days)
    now = now or datetime.now(timezone.utc)
    lead_days = (
        due_soon_lead_days
        or app.config["DEFAULT_DUE_SOON_LEAD_DAYS"]
        or min(7, max(1, ceil(interval_days * 0.2)))
    )
    insight.update(
        {
            "interval_days": round(interval_days, 1),
            "due_at": due_at.isoformat(),
            "due_display": format_local_datetime(due_at.isoformat()),
            "source": source,
        }
    )
    cadence_label = "Manual cadence" if source == "manual" else "Typical cadence"
    cadence_text = f"{cadence_label}: every {format_interval_days(interval_days)}"
    if now >= due_at:
        insight["status"] = "overdue"
        insight["message"] = f"{cadence_text}. Expected {insight['due_display']}"
    elif due_at - now <= timedelta(days=lead_days):
        insight["status"] = "due_soon"
        insight["message"] = f"{cadence_text}. Due {insight['due_display']}"
    else:
        insight["message"] = f"{cadence_text}. Next due {insight['due_display']}"
    return insight


def completion_timestamp(completion) -> str:
    return completion["completed_at"] if isinstance(completion, (dict, sqlite3.Row)) else completion


def completion_note(completion) -> Optional[str]:
    if isinstance(completion, (dict, sqlite3.Row)):
        return completion["note"]
    return None


def enrich_task(task: dict, history: list, now: Optional[datetime] = None) -> dict:
    timestamps = [completion_timestamp(completion) for completion in history]
    task["last_completed_display"] = format_local_datetime(task["last_completed_at"])
    task["completed_ago"] = completed_ago(task["last_completed_at"])
    task["completion_count"] = len(history)
    history_entries = []
    for index, item in enumerate(history):
        timestamp = completion_timestamp(item)
        entry = {
            "display": format_local_datetime(timestamp),
            "days_since_previous": None,
            "note": completion_note(item),
        }
        if index < len(history) - 1:
            current = parse_iso_utc(timestamp)
            previous = parse_iso_utc(completion_timestamp(history[index + 1]))
            if current and previous:
                entry["days_since_previous"] = max((current - previous).days, 0)
        history_entries.append(entry)
    task["completion_history"] = history_entries
    task["group_name"] = task["group_name"] or "Ungrouped"
    task["is_paused"] = bool(task["is_paused"])
    task["reminders_enabled"] = bool(task["reminders_enabled"])
    task["cadence"] = cadence_insight(
        timestamps,
        manual_interval_days=task["manual_interval_days"],
        due_soon_lead_days=task["due_soon_lead_days"],
        is_paused=task["is_paused"],
        now=now,
    )
    cadence = task["cadence"]
    task["dashboard_status"] = (
        "paused" if task["is_paused"] else cadence["status"]
        or ("scheduled" if cadence["due_at"] else "learning")
    )
    if cadence["due_at"]:
        today = (now or datetime.now(timezone.utc)).astimezone(app.config["DISPLAY_TIMEZONE"]).date()
        due_date = parse_iso_utc(cadence["due_at"]).astimezone(app.config["DISPLAY_TIMEZONE"]).date()
        days = (due_date - today).days
        task["due_summary"] = (
            f"{abs(days)} days overdue" if days < -1 else
            "1 day overdue" if days == -1 else
            "Due today" if days == 0 else
            "Due tomorrow" if days == 1 else f"Due in {days} days"
        )
    else:
        task["due_summary"] = (
            "Paused" if task["is_paused"] else
            "Complete once to start" if task["manual_interval_days"] else "Learning your routine"
        )
    task["schedule_summary"] = (
        f"Every {format_interval_days(task['manual_interval_days'])} · Manual"
        if task["manual_interval_days"] else "Automatic schedule"
    )
    return task


def wants_json_response() -> bool:
    return request.accept_mimetypes.best == "application/json"


def mutation_error(message: str, status: int = 400):
    if wants_json_response():
        return jsonify({"error": message}), status
    return redirect(url_for("index"))


def task_payload(db: sqlite3.Connection, task_id: int) -> Optional[dict]:
    row = db.execute(
        """
        SELECT tasks.id, tasks.name, tasks.created_at, tasks.last_completed_at,
               tasks.group_id, tasks.manual_interval_days, tasks.due_soon_lead_days,
               tasks.is_paused, tasks.reminders_enabled, groups.name AS group_name
        FROM tasks
        LEFT JOIN groups ON groups.id = tasks.group_id
        WHERE tasks.id = ?
        """,
        (task_id,),
    ).fetchone()
    if not row:
        return None

    task = dict(row)
    completion_rows = db.execute(
        """
        SELECT completed_at, note
        FROM task_completions
        WHERE task_id = ?
        ORDER BY completed_at DESC
        """,
        (task_id,),
    ).fetchall()
    history = [dict(row) for row in completion_rows]
    return enrich_task(task, history)


def reminder_configuration_error() -> Optional[str]:
    required = {
        "PUBLIC_BASE_URL": app.config["PUBLIC_BASE_URL"],
        "SMTP_HOST": app.config["SMTP_HOST"],
        "SMTP_FROM": app.config["SMTP_FROM"],
        "REMINDER_RECIPIENT": app.config["REMINDER_RECIPIENT"],
        "EMAIL_ACTION_SECRET": app.config["EMAIL_ACTION_SECRET"],
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        return f"Missing reminder configuration: {', '.join(missing)}"
    return None


def reminder_tasks(db: sqlite3.Connection, now: datetime) -> list[dict]:
    rows = db.execute(
        """
        SELECT tasks.id, tasks.name, tasks.created_at, tasks.last_completed_at,
               tasks.group_id, tasks.manual_interval_days, tasks.due_soon_lead_days,
               tasks.is_paused, tasks.reminders_enabled, groups.name AS group_name
        FROM tasks
        LEFT JOIN groups ON groups.id = tasks.group_id
        WHERE tasks.reminders_enabled = 1 AND tasks.is_paused = 0
        """
    ).fetchall()
    completion_rows = db.execute(
        """
        SELECT task_id, completed_at
        FROM task_completions
        ORDER BY completed_at DESC
        """
    ).fetchall()
    histories = {}
    for row in completion_rows:
        histories.setdefault(int(row["task_id"]), []).append(row["completed_at"])
    return [
        enrich_task(dict(row), histories.get(int(row["id"]), []), now=now)
        for row in rows
    ]


def claim_reminder(
    db: sqlite3.Connection,
    dedupe_key: str,
    reminder_type: str,
    recipient: str,
    now: datetime,
    task_id: Optional[int] = None,
    due_at: Optional[str] = None,
) -> Optional[int]:
    try:
        cursor = db.execute(
            """
            INSERT INTO reminder_deliveries (
                dedupe_key, reminder_type, task_id, due_at, recipient, status, attempted_at
            ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
            """,
            (dedupe_key, reminder_type, task_id, due_at, recipient, now.isoformat()),
        )
        db.commit()
        return int(cursor.lastrowid)
    except sqlite3.IntegrityError:
        db.rollback()
        existing = db.execute(
            """
            SELECT id, status, attempt_count, attempted_at, next_attempt_at
            FROM reminder_deliveries
            WHERE dedupe_key = ?
            """,
            (dedupe_key,),
        ).fetchone()
        if not existing or int(existing["attempt_count"]) >= app.config["REMINDER_MAX_ATTEMPTS"]:
            return None
        if existing["status"] not in {"failed", "pending"}:
            return None
        retry_after = parse_iso_utc(existing["next_attempt_at"])
        if existing["status"] == "failed" and retry_after and retry_after > now:
            return None
        claimed_at = parse_iso_utc(existing["attempted_at"])
        if existing["status"] == "pending" and claimed_at and claimed_at > now - timedelta(
            minutes=app.config["REMINDER_RETRY_DELAY_MINUTES"]
        ):
            return None
        cursor = db.execute(
            """
            UPDATE reminder_deliveries
            SET status = 'pending', attempted_at = ?, attempt_count = attempt_count + 1,
                next_attempt_at = NULL, error_message = NULL
            WHERE id = ? AND status IN ('failed', 'pending') AND attempt_count < ?
            """,
            (now.isoformat(), existing["id"], app.config["REMINDER_MAX_ATTEMPTS"]),
        )
        db.commit()
        return int(existing["id"]) if cursor.rowcount == 1 else None


def complete_reminder_delivery(
    db: sqlite3.Connection,
    delivery_id: int,
    error_message: Optional[str] = None,
    now: Optional[datetime] = None,
) -> None:
    now = now or datetime.now(timezone.utc)
    if error_message:
        retry_at = now + timedelta(
            minutes=app.config["REMINDER_RETRY_DELAY_MINUTES"]
        )
        db.execute(
            """
            UPDATE reminder_deliveries
            SET status = 'failed', error_message = ?, next_attempt_at = ?
            WHERE id = ?
            """,
            (error_message[:1000], retry_at.isoformat(), delivery_id),
        )
    else:
        db.execute(
            "UPDATE reminder_deliveries SET status = 'sent', sent_at = ? WHERE id = ?",
            (now.isoformat(), delivery_id),
        )
    db.commit()


def create_email_action_token(db: sqlite3.Connection, task_id: int, now: datetime) -> str:
    nonce = secrets.token_urlsafe(32)
    signature = hmac.new(
        app.config["EMAIL_ACTION_SECRET"].encode("utf-8"),
        nonce.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token = f"{nonce}.{signature}"
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = now + timedelta(hours=app.config["EMAIL_ACTION_TTL_HOURS"])
    db.execute(
        """
        INSERT INTO email_action_tokens (token_hash, task_id, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (token_hash, task_id, now.isoformat(), expires_at.isoformat()),
    )
    db.commit()
    return token


def email_action_url(token: str) -> str:
    return f"{app.config['PUBLIC_BASE_URL']}/email-actions/{token}"


def send_email(subject: str, text: str, html: str) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = app.config["SMTP_FROM"]
    message["To"] = app.config["REMINDER_RECIPIENT"]
    message.set_content(text)
    message.add_alternative(html, subtype="html")
    with smtplib.SMTP(app.config["SMTP_HOST"], app.config["SMTP_PORT"], timeout=30) as smtp:
        if app.config["SMTP_USE_TLS"]:
            smtp.starttls()
        if app.config["SMTP_USERNAME"]:
            smtp.login(app.config["SMTP_USERNAME"], app.config["SMTP_PASSWORD"])
        smtp.send_message(message)


def task_reminder_message(task: dict, action_url: str) -> tuple[str, str, str]:
    name = task["name"]
    message = task["cadence"]["message"]
    subject = f"Cadence reminder: {name}"
    text = f"{name}\n{message}\n\nMark complete: {action_url}"
    html = (
        f"<p><strong>{escape(name)}</strong></p><p>{escape(message)}</p>"
        f'<p><a href="{escape(action_url, quote=True)}">Mark complete</a></p>'
    )
    return subject, text, html


def send_due_reminders(db: sqlite3.Connection, now: datetime) -> int:
    sent_count = 0
    recipient = app.config["REMINDER_RECIPIENT"]
    for task in reminder_tasks(db, now):
        if task["cadence"]["status"] != "overdue":
            continue
        due_at = task["cadence"]["due_at"]
        delivery_id = claim_reminder(
            db,
            f"task:{task['id']}:individual:{due_at}",
            "individual",
            recipient,
            now,
            task_id=task["id"],
            due_at=due_at,
        )
        if delivery_id is None:
            continue
        try:
            token = create_email_action_token(db, task["id"], now)
            send_email(*task_reminder_message(task, email_action_url(token)))
        except (OSError, smtplib.SMTPException) as error:
            complete_reminder_delivery(db, delivery_id, str(error), now)
        else:
            complete_reminder_delivery(db, delivery_id, now=now)
            sent_count += 1
    return sent_count


def send_daily_digest(db: sqlite3.Connection, now: datetime) -> int:
    local_now = now.astimezone(app.config["DISPLAY_TIMEZONE"])
    if local_now.hour < app.config["REMINDER_DIGEST_HOUR"]:
        return 0
    tasks = [task for task in reminder_tasks(db, now) if task["cadence"]["status"]]
    if not tasks:
        return 0
    date_key = local_now.date().isoformat()
    delivery_id = claim_reminder(
        db,
        f"digest:{date_key}",
        "digest",
        app.config["REMINDER_RECIPIENT"],
        now,
    )
    if delivery_id is None:
        return 0
    try:
        lines = []
        html_items = []
        for task in tasks:
            token = create_email_action_token(db, task["id"], now)
            action_url = email_action_url(token)
            lines.append(f"{task['name']}: {task['cadence']['message']}\nMark complete: {action_url}")
            html_items.append(
                f"<li><strong>{escape(task['name'])}</strong>: {escape(task['cadence']['message'])} "
                f'<a href="{escape(action_url, quote=True)}">Mark complete</a></li>'
            )
        send_email(
            "Cadence daily reminder",
            "\n\n".join(lines),
            f"<p>Tasks needing attention:</p><ul>{''.join(html_items)}</ul>",
        )
    except (OSError, smtplib.SMTPException) as error:
        complete_reminder_delivery(db, delivery_id, str(error), now)
        return 0
    complete_reminder_delivery(db, delivery_id, now=now)
    return 1


def run_reminders_once(now: Optional[datetime] = None) -> dict:
    configuration_error = reminder_configuration_error()
    if configuration_error:
        return {"status": "disabled", "reason": configuration_error}
    now = now or datetime.now(timezone.utc)
    init_db()
    db = get_db()
    return {
        "status": "ok",
        "individual_sent": send_due_reminders(db, now),
        "digest_sent": send_daily_digest(db, now),
    }


def get_default_group_id(db: sqlite3.Connection) -> int:
    row = db.execute(
        "SELECT id FROM groups WHERE name = ?",
        ("General",),
    ).fetchone()
    if row:
        return int(row["id"])

    db.execute("INSERT INTO groups (name) VALUES (?)", ("General",))
    db.commit()
    return int(
        db.execute("SELECT id FROM groups WHERE name = ?", ("General",)).fetchone()["id"]
    )


def get_valid_group_id(db: sqlite3.Connection, group_id_raw: str) -> Optional[int]:
    if not group_id_raw:
        return None
    try:
        group_id = int(group_id_raw)
    except ValueError:
        return None

    group = db.execute("SELECT id FROM groups WHERE id = ?", (group_id,)).fetchone()
    if not group:
        return None
    return int(group["id"])


def normalize_name(value: str) -> Optional[str]:
    name = value.strip()
    if not name:
        return None
    if len(name) > app.config["MAX_NAME_LENGTH"]:
        return None
    return name


def normalize_completion_note(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    note = value.strip()
    if len(note) > MAX_COMPLETION_NOTE_LENGTH:
        return None
    return note or None


def parse_optional_interval(value: str) -> Optional[float]:
    if not value.strip():
        return None
    try:
        interval = float(value)
    except ValueError:
        return None
    if not 0 < interval <= MAX_CADENCE_INTERVAL_DAYS:
        return None
    return interval


def parse_optional_lead_days(value: str) -> Optional[int]:
    if not value.strip():
        return None
    try:
        lead_days = int(value)
    except ValueError:
        return None
    if not 1 <= lead_days <= MAX_DUE_SOON_LEAD_DAYS:
        return None
    return lead_days


def require_admin_slug(slug: str) -> None:
    configured_slug = app.config.get("ADMIN_SLUG")
    if not configured_slug or not hmac.compare_digest(slug, configured_slug):
        abort(404)


def get_csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token() -> None:
    expected = session.get("_csrf_token", "")
    received = request.form.get("_csrf_token", "")
    if not expected or not received or not hmac.compare_digest(expected, received):
        abort(400)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def ensure_backup_dir() -> Path:
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        BACKUP_DIR.chmod(0o700)
    except OSError:
        pass
    return BACKUP_DIR


def export_snapshot(db: sqlite3.Connection) -> dict:
    groups = [
        dict(row)
        for row in db.execute(
            "SELECT id, name FROM groups ORDER BY id ASC"
        ).fetchall()
    ]
    tasks = [
        dict(row)
        for row in db.execute(
            """
            SELECT id, name, created_at, last_completed_at, group_id,
                   manual_interval_days, due_soon_lead_days, is_paused, reminders_enabled
            FROM tasks
            ORDER BY id ASC
            """
        ).fetchall()
    ]
    task_completions = [
        dict(row)
        for row in db.execute(
            """
            SELECT id, task_id, completed_at, note
            FROM task_completions
            ORDER BY id ASC
            """
        ).fetchall()
    ]
    reminder_deliveries = [
        dict(row)
        for row in db.execute(
            """
            SELECT id, dedupe_key, reminder_type, task_id, due_at, recipient, status,
                   attempted_at, sent_at, error_message, attempt_count, next_attempt_at
            FROM reminder_deliveries
            ORDER BY id ASC
            """
        ).fetchall()
    ]
    email_action_tokens = [
        dict(row)
        for row in db.execute(
            """
            SELECT id, token_hash, task_id, created_at, expires_at, consumed_at
            FROM email_action_tokens
            ORDER BY id ASC
            """
        ).fetchall()
    ]
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "groups": groups,
        "tasks": tasks,
        "task_completions": task_completions,
        "reminder_deliveries": reminder_deliveries,
        "email_action_tokens": email_action_tokens,
    }


def create_backup(db: sqlite3.Connection) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = ensure_backup_dir() / f"backup-{timestamp}.json"
    with backup_path.open("w", encoding="utf-8") as handle:
        json.dump(export_snapshot(db), handle, indent=2)
    try:
        backup_path.chmod(0o600)
    except OSError:
        pass
    return backup_path


def list_backups() -> list[str]:
    if not BACKUP_DIR.exists():
        return []
    return sorted(
        [path.name for path in BACKUP_DIR.glob("backup-*.json") if path.is_file()],
        reverse=True,
    )


def resolve_backup_path(filename: str) -> Optional[Path]:
    if not filename:
        return None
    safe_name = Path(filename).name
    if safe_name != filename or not safe_name.endswith(".json"):
        return None

    backup_dir = ensure_backup_dir().resolve()
    candidate = (backup_dir / safe_name).resolve()
    if candidate.parent != backup_dir or not candidate.exists():
        return None
    return candidate


def restore_snapshot(db: sqlite3.Connection, snapshot: dict) -> bool:
    required_keys = {"groups", "tasks", "task_completions"}
    if not required_keys.issubset(snapshot.keys()):
        return False

    groups = snapshot.get("groups")
    tasks = snapshot.get("tasks")
    task_completions = snapshot.get("task_completions")
    reminder_deliveries = snapshot.get("reminder_deliveries", [])
    email_action_tokens = snapshot.get("email_action_tokens", [])
    if (
        not isinstance(groups, list)
        or not isinstance(tasks, list)
        or not isinstance(task_completions, list)
        or not isinstance(reminder_deliveries, list)
        or not isinstance(email_action_tokens, list)
    ):
        return False

    try:
        db.execute("BEGIN")
        db.execute("DELETE FROM email_action_tokens")
        db.execute("DELETE FROM reminder_deliveries")
        db.execute("DELETE FROM task_completions")
        db.execute("DELETE FROM tasks")
        db.execute("DELETE FROM groups")

        for group in groups:
            if not isinstance(group, dict):
                raise ValueError("Invalid group row")
            group_name = group.get("name")
            if not isinstance(group_name, str):
                raise ValueError("Invalid group name")
            db.execute(
                "INSERT INTO groups (id, name) VALUES (?, ?)",
                (group.get("id"), normalize_name(group_name)),
            )
        for task in tasks:
            if not isinstance(task, dict):
                raise ValueError("Invalid task row")
            task_name = task.get("name")
            if not isinstance(task_name, str):
                raise ValueError("Invalid task name")
            db.execute(
                """
                INSERT INTO tasks (
                    id, name, created_at, last_completed_at, group_id,
                    manual_interval_days, due_soon_lead_days, is_paused, reminders_enabled
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.get("id"),
                    normalize_name(task_name),
                    task.get("created_at"),
                    task.get("last_completed_at"),
                    task.get("group_id"),
                    task.get("manual_interval_days"),
                    task.get("due_soon_lead_days"),
                    int(bool(task.get("is_paused", False))),
                    int(bool(task.get("reminders_enabled", False))),
                ),
            )
        for completion in task_completions:
            if not isinstance(completion, dict):
                raise ValueError("Invalid completion row")
            db.execute(
                """
                INSERT INTO task_completions (id, task_id, completed_at, note)
                VALUES (?, ?, ?, ?)
                """,
                (
                    completion.get("id"),
                    completion.get("task_id"),
                    completion.get("completed_at"),
                    normalize_completion_note(completion.get("note", ""))
                ),
            )
        for delivery in reminder_deliveries:
            if not isinstance(delivery, dict):
                raise ValueError("Invalid reminder delivery row")
            db.execute(
                """
                INSERT INTO reminder_deliveries (
                    id, dedupe_key, reminder_type, task_id, due_at, recipient, status,
                    attempted_at, sent_at, error_message, attempt_count, next_attempt_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    delivery.get("id"),
                    delivery.get("dedupe_key"),
                    delivery.get("reminder_type"),
                    delivery.get("task_id"),
                    delivery.get("due_at"),
                    delivery.get("recipient"),
                    delivery.get("status"),
                    delivery.get("attempted_at"),
                    delivery.get("sent_at"),
                    delivery.get("error_message"),
                    delivery.get("attempt_count", 1),
                    delivery.get("next_attempt_at"),
                ),
            )
        for token in email_action_tokens:
            if not isinstance(token, dict):
                raise ValueError("Invalid email action token row")
            db.execute(
                """
                INSERT INTO email_action_tokens (
                    id, token_hash, task_id, created_at, expires_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    token.get("id"),
                    token.get("token_hash"),
                    token.get("task_id"),
                    token.get("created_at"),
                    token.get("expires_at"),
                    token.get("consumed_at"),
                ),
            )

        if not groups:
            db.execute("INSERT INTO groups (name) VALUES (?)", ("General",))
        db.commit()
        return True
    except (sqlite3.DatabaseError, ValueError, TypeError):
        db.rollback()
        return False


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token}


@app.teardown_appcontext
def close_db(_error: Optional[Exception]) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
        """
    )
    db.execute("INSERT OR IGNORE INTO groups (name) VALUES (?)", ("General",))
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            last_completed_at TEXT,
            group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
            manual_interval_days REAL,
            due_soon_lead_days INTEGER,
            is_paused INTEGER NOT NULL DEFAULT 0,
            reminders_enabled INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS task_completions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            completed_at TEXT NOT NULL,
            note TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS reminder_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            dedupe_key TEXT NOT NULL UNIQUE,
            reminder_type TEXT NOT NULL,
            task_id INTEGER REFERENCES tasks(id) ON DELETE CASCADE,
            due_at TEXT,
            recipient TEXT NOT NULL,
            status TEXT NOT NULL,
            attempted_at TEXT NOT NULL,
            sent_at TEXT,
            error_message TEXT,
            attempt_count INTEGER NOT NULL DEFAULT 1,
            next_attempt_at TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS email_action_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            consumed_at TEXT
        )
        """
    )
    columns = {row["name"] for row in db.execute("PRAGMA table_info(tasks)").fetchall()}
    if "group_id" not in columns:
        db.execute("ALTER TABLE tasks ADD COLUMN group_id INTEGER")
    if "manual_interval_days" not in columns:
        db.execute("ALTER TABLE tasks ADD COLUMN manual_interval_days REAL")
    if "due_soon_lead_days" not in columns:
        db.execute("ALTER TABLE tasks ADD COLUMN due_soon_lead_days INTEGER")
    if "is_paused" not in columns:
        db.execute("ALTER TABLE tasks ADD COLUMN is_paused INTEGER NOT NULL DEFAULT 0")
    if "reminders_enabled" not in columns:
        db.execute("ALTER TABLE tasks ADD COLUMN reminders_enabled INTEGER NOT NULL DEFAULT 0")
    completion_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(task_completions)").fetchall()
    }
    if "note" not in completion_columns:
        db.execute("ALTER TABLE task_completions ADD COLUMN note TEXT")
    delivery_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(reminder_deliveries)").fetchall()
    }
    if "attempt_count" not in delivery_columns:
        db.execute(
            "ALTER TABLE reminder_deliveries ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 1"
        )
    if "next_attempt_at" not in delivery_columns:
        db.execute("ALTER TABLE reminder_deliveries ADD COLUMN next_attempt_at TEXT")

    default_group_id = get_default_group_id(db)
    db.execute(
        "UPDATE tasks SET group_id = ? WHERE group_id IS NULL",
        (default_group_id,),
    )
    db.commit()


@app.before_request
def ensure_schema() -> None:
    init_db()
    if request.method == "POST":
        validate_csrf_token()


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'"
    )
    return response


@app.get("/")
def index():
    db = get_db()
    group_rows = db.execute(
        """
        SELECT id, name
        FROM groups
        ORDER BY groups.name COLLATE NOCASE
        """
    ).fetchall()
    groups = [dict(row) for row in group_rows]
    task_rows = db.execute(
        """
        SELECT tasks.id, tasks.name, tasks.created_at, tasks.last_completed_at,
               tasks.group_id, tasks.manual_interval_days, tasks.due_soon_lead_days,
               tasks.is_paused, tasks.reminders_enabled, groups.name AS group_name
        FROM tasks
        LEFT JOIN groups ON groups.id = tasks.group_id
        ORDER BY groups.name COLLATE NOCASE, tasks.name COLLATE NOCASE
        """
    ).fetchall()
    completion_rows = db.execute(
        """
        SELECT task_id, completed_at, note
        FROM task_completions
        ORDER BY completed_at DESC
        """
    ).fetchall()
    completions_by_task = {}
    for row in completion_rows:
        task_id = int(row["task_id"])
        completions_by_task.setdefault(task_id, []).append(dict(row))

    tasks_by_group = {group["id"]: [] for group in groups}
    ungrouped_tasks = []
    overdue_tasks = []
    due_soon_tasks = []
    for row in task_rows:
        task = dict(row)
        history = completions_by_task.get(task["id"], [])
        task = enrich_task(task, history)
        if task["cadence"]["status"] == "overdue":
            overdue_tasks.append(task)
        elif task["cadence"]["status"] == "due_soon":
            due_soon_tasks.append(task)
        group_id = task["group_id"]
        if group_id in tasks_by_group:
            tasks_by_group[group_id].append(task)
        else:
            ungrouped_tasks.append(task)

    grouped_tasks = []
    for group in groups:
        group_tasks = tasks_by_group[group["id"]]
        if group_tasks:
            grouped_tasks.append(
                {"id": group["id"], "name": group["name"], "tasks": group_tasks}
            )
    if ungrouped_tasks:
        grouped_tasks.append({"id": None, "name": "Ungrouped", "tasks": ungrouped_tasks})

    overdue_tasks.sort(key=lambda task: task["cadence"]["due_at"])
    due_soon_tasks.sort(key=lambda task: task["cadence"]["due_at"])
    return render_template(
        "index.html",
        grouped_tasks=grouped_tasks,
        groups=groups,
        overdue_tasks=overdue_tasks,
        due_soon_tasks=due_soon_tasks,
    )


@app.post("/tasks")
def create_task():
    name = normalize_name(request.form.get("name", ""))
    if not name:
        return mutation_error("Enter a task name.")

    manual_interval_raw = request.form.get("manual_interval_days", "")
    manual_interval_days = parse_optional_interval(manual_interval_raw)
    if manual_interval_raw.strip() and manual_interval_days is None:
        return mutation_error(
            f"Manual cadence must be greater than 0 and at most {MAX_CADENCE_INTERVAL_DAYS} days."
        )

    db = get_db()
    group_id_raw = request.form.get("group_id", "")
    group_id = get_valid_group_id(db, group_id_raw) or get_default_group_id(db)
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        """
        INSERT OR IGNORE INTO tasks (name, created_at, last_completed_at, group_id, manual_interval_days)
        VALUES (?, ?, NULL, ?, ?)
        """,
        (name, now, group_id, manual_interval_days),
    )
    db.commit()
    if wants_json_response():
        task = db.execute("SELECT id FROM tasks WHERE name = ?", (name,)).fetchone()
        return jsonify(
            {
                "task": task_payload(db, int(task["id"])),
                "created": cursor.rowcount == 1,
            }
        )
    return redirect(url_for("index"))


@app.post("/groups")
def create_group():
    name = normalize_name(request.form.get("name", ""))
    if not name:
        return mutation_error("Enter a group name.")

    db = get_db()
    cursor = db.execute("INSERT OR IGNORE INTO groups (name) VALUES (?)", (name,))
    db.commit()
    if wants_json_response():
        group = db.execute("SELECT id, name FROM groups WHERE name = ?", (name,)).fetchone()
        return jsonify({"group": dict(group), "created": cursor.rowcount == 1})
    return redirect(url_for("index"))


@app.post("/tasks/<int:task_id>/complete")
def complete_task(task_id: int):
    db = get_db()
    task = db.execute("SELECT id FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if not task:
        abort(404)

    note = normalize_completion_note(request.form.get("note", ""))
    if request.form.get("note", "").strip() and note is None:
        return mutation_error(f"Completion notes must be {MAX_COMPLETION_NOTE_LENGTH} characters or fewer.")

    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT INTO task_completions (task_id, completed_at, note)
        VALUES (?, ?, ?)
        """,
        (task_id, now, note),
    )
    db.execute(
        "UPDATE tasks SET last_completed_at = ? WHERE id = ?",
        (now, task_id),
    )
    db.commit()
    if wants_json_response():
        return jsonify({"task": task_payload(db, task_id)})
    return redirect(url_for("index"))


@app.post("/tasks/<int:task_id>/move")
def move_task(task_id: int):
    db = get_db()
    task = db.execute("SELECT id FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if not task:
        abort(404)

    group_id = get_valid_group_id(db, request.form.get("group_id", ""))
    if group_id is None:
        return mutation_error("Choose a valid group.")

    db.execute(
        "UPDATE tasks SET group_id = ? WHERE id = ?",
        (group_id, task_id),
    )
    db.commit()
    if wants_json_response():
        return jsonify({"task": task_payload(db, task_id)})
    return redirect(url_for("index"))


@app.post("/tasks/<int:task_id>/settings")
def update_task_settings(task_id: int):
    db = get_db()
    task = db.execute("SELECT id FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if not task:
        abort(404)

    manual_interval_raw = request.form.get("manual_interval_days", "")
    manual_interval_days = parse_optional_interval(manual_interval_raw)
    if manual_interval_raw.strip() and manual_interval_days is None:
        return mutation_error(
            f"Manual cadence must be between 0 and {MAX_CADENCE_INTERVAL_DAYS} days."
        )

    lead_days_raw = request.form.get("due_soon_lead_days", "")
    due_soon_lead_days = parse_optional_lead_days(lead_days_raw)
    if lead_days_raw.strip() and due_soon_lead_days is None:
        return mutation_error(
            f"Due-soon lead time must be between 1 and {MAX_DUE_SOON_LEAD_DAYS} days."
        )

    db.execute(
        """
        UPDATE tasks
        SET manual_interval_days = ?, due_soon_lead_days = ?, is_paused = ?,
            reminders_enabled = ?
        WHERE id = ?
        """,
        (
            manual_interval_days,
            due_soon_lead_days,
            int(request.form.get("is_paused") == "1"),
            int(request.form.get("reminders_enabled") == "1"),
            task_id,
        ),
    )
    db.commit()
    if wants_json_response():
        return jsonify({"task": task_payload(db, task_id)})
    return redirect(url_for("index"))


def get_email_action_token(db: sqlite3.Connection, token: str) -> Optional[sqlite3.Row]:
    try:
        nonce, signature = token.rsplit(".", 1)
    except ValueError:
        return None
    expected_signature = hmac.new(
        app.config["EMAIL_ACTION_SECRET"].encode("utf-8"),
        nonce.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return None
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = db.execute(
        """
        SELECT email_action_tokens.id, email_action_tokens.task_id,
               email_action_tokens.expires_at, email_action_tokens.consumed_at, tasks.name
        FROM email_action_tokens
        JOIN tasks ON tasks.id = email_action_tokens.task_id
        WHERE email_action_tokens.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()
    if not row or row["consumed_at"]:
        return None
    expires_at = parse_iso_utc(row["expires_at"])
    if not expires_at or expires_at <= datetime.now(timezone.utc):
        return None
    return row


@app.get("/email-actions/<token>")
def confirm_email_action(token: str):
    action = get_email_action_token(get_db(), token)
    if not action:
        abort(404)
    return render_template("email_confirm.html", token=token, task_name=action["name"])


@app.post("/email-actions/<token>")
def complete_from_email_action(token: str):
    db = get_db()
    action = get_email_action_token(db, token)
    if not action:
        abort(404)

    now = datetime.now(timezone.utc).isoformat()
    try:
        db.execute("BEGIN")
        consumed = db.execute(
            """
            UPDATE email_action_tokens
            SET consumed_at = ?
            WHERE id = ? AND consumed_at IS NULL
            """,
            (now, action["id"]),
        )
        if consumed.rowcount != 1:
            db.rollback()
            abort(404)
        db.execute(
            "INSERT INTO task_completions (task_id, completed_at) VALUES (?, ?)",
            (action["task_id"], now),
        )
        db.execute(
            "UPDATE tasks SET last_completed_at = ? WHERE id = ?",
            (now, action["task_id"]),
        )
        db.commit()
    except sqlite3.DatabaseError:
        db.rollback()
        abort(500)
    return render_template("email_confirm.html", task_name=action["name"], completed=True)


@app.get("/admin/<slug>")
def admin_panel(slug: str):
    require_admin_slug(slug)

    db = get_db()
    task_rows = db.execute(
        """
        SELECT tasks.id, tasks.name, groups.name AS group_name, tasks.last_completed_at
        FROM tasks
        LEFT JOIN groups ON groups.id = tasks.group_id
        ORDER BY tasks.name COLLATE NOCASE
        """
    ).fetchall()
    tasks = []
    for row in task_rows:
        task = dict(row)
        task["group_name"] = task["group_name"] or "Ungrouped"
        task["last_completed_display"] = format_local_datetime(task["last_completed_at"])
        tasks.append(task)
    reminder_deliveries = [
        dict(row)
        for row in db.execute(
            """
            SELECT reminder_deliveries.reminder_type, reminder_deliveries.status,
                   reminder_deliveries.attempt_count, reminder_deliveries.attempted_at,
                   reminder_deliveries.sent_at, reminder_deliveries.error_message,
                   tasks.name AS task_name
            FROM reminder_deliveries
            LEFT JOIN tasks ON tasks.id = reminder_deliveries.task_id
            ORDER BY reminder_deliveries.id DESC
            LIMIT 25
            """
        ).fetchall()
    ]

    return render_template(
        "admin.html",
        admin_slug=slug,
        tasks=tasks,
        backups=list_backups(),
        reminder_deliveries=reminder_deliveries,
    )


@app.post("/admin/<slug>/tasks/<int:task_id>/delete")
def admin_delete_task(slug: str, task_id: int):
    require_admin_slug(slug)

    db = get_db()
    db.execute("DELETE FROM task_completions WHERE task_id = ?", (task_id,))
    db.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
    db.commit()
    return redirect(url_for("admin_panel", slug=slug))


@app.post("/admin/<slug>/wipe")
def admin_wipe(slug: str):
    require_admin_slug(slug)

    db = get_db()
    create_backup(db)
    db.execute("DELETE FROM task_completions")
    db.execute("DELETE FROM tasks")
    db.execute("DELETE FROM groups")
    db.execute("INSERT INTO groups (name) VALUES (?)", ("General",))
    db.commit()
    return redirect(url_for("admin_panel", slug=slug))


@app.post("/admin/<slug>/restore")
def admin_restore(slug: str):
    require_admin_slug(slug)

    backup_filename = request.form.get("backup_file", "")
    backup_path = resolve_backup_path(backup_filename)
    if backup_path is None:
        return redirect(url_for("admin_panel", slug=slug))

    try:
        with backup_path.open("r", encoding="utf-8") as handle:
            snapshot = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return redirect(url_for("admin_panel", slug=slug))

    restored = restore_snapshot(get_db(), snapshot)
    if not restored:
        return redirect(url_for("admin_panel", slug=slug))
    return redirect(url_for("admin_panel", slug=slug))


if __name__ == "__main__":
    debug_enabled = os.getenv("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host="0.0.0.0", debug=debug_enabled)
