import os
import json
import hmac
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Flask, abort, g, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "tasks.db"
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", str(BASE_DIR / "backups")))


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

app = Flask(__name__)
app.config["DATABASE"] = os.getenv("DATABASE_PATH", str(DB_PATH))
app.config["ADMIN_SLUG"] = os.getenv("ADMIN_SLUG", "").strip() or None
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_NAME_LENGTH"] = int(os.getenv("MAX_NAME_LENGTH", "120"))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("SESSION_COOKIE_SECURE", "").lower() in {"1", "true", "yes"}
)


def parse_iso_utc(timestamp: Optional[str]) -> Optional[datetime]:
    if not timestamp:
        return None
    return datetime.fromisoformat(timestamp)


def format_local_datetime(timestamp: Optional[str]) -> str:
    completed_at = parse_iso_utc(timestamp)
    if not completed_at:
        return "Never"
    local_time = completed_at.astimezone()
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
            SELECT id, name, created_at, last_completed_at, group_id
            FROM tasks
            ORDER BY id ASC
            """
        ).fetchall()
    ]
    task_completions = [
        dict(row)
        for row in db.execute(
            """
            SELECT id, task_id, completed_at
            FROM task_completions
            ORDER BY id ASC
            """
        ).fetchall()
    ]
    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "groups": groups,
        "tasks": tasks,
        "task_completions": task_completions,
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
    if (
        not isinstance(groups, list)
        or not isinstance(tasks, list)
        or not isinstance(task_completions, list)
    ):
        return False

    try:
        db.execute("BEGIN")
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
                INSERT INTO tasks (id, name, created_at, last_completed_at, group_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    task.get("id"),
                    normalize_name(task_name),
                    task.get("created_at"),
                    task.get("last_completed_at"),
                    task.get("group_id"),
                ),
            )
        for completion in task_completions:
            if not isinstance(completion, dict):
                raise ValueError("Invalid completion row")
            db.execute(
                """
                INSERT INTO task_completions (id, task_id, completed_at)
                VALUES (?, ?, ?)
                """,
                (
                    completion.get("id"),
                    completion.get("task_id"),
                    completion.get("completed_at"),
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
            group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS task_completions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            completed_at TEXT NOT NULL
        )
        """
    )
    columns = {row["name"] for row in db.execute("PRAGMA table_info(tasks)").fetchall()}
    if "group_id" not in columns:
        db.execute("ALTER TABLE tasks ADD COLUMN group_id INTEGER")

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
        "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'"
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
               tasks.group_id, groups.name AS group_name
        FROM tasks
        LEFT JOIN groups ON groups.id = tasks.group_id
        ORDER BY groups.name COLLATE NOCASE, tasks.name COLLATE NOCASE
        """
    ).fetchall()
    completion_rows = db.execute(
        """
        SELECT task_id, completed_at
        FROM task_completions
        ORDER BY completed_at DESC
        """
    ).fetchall()
    completions_by_task = {}
    for row in completion_rows:
        task_id = int(row["task_id"])
        completions_by_task.setdefault(task_id, []).append(row["completed_at"])

    tasks_by_group = {group["id"]: [] for group in groups}
    ungrouped_tasks = []
    for row in task_rows:
        task = dict(row)
        task["last_completed_display"] = format_local_datetime(task["last_completed_at"])
        task["completed_ago"] = completed_ago(task["last_completed_at"])
        history = completions_by_task.get(task["id"], [])
        task["completion_count"] = len(history)
        history_entries = []
        for i, item in enumerate(history):
            entry = {"display": format_local_datetime(item), "days_since_previous": None}
            if i < len(history) - 1:
                current = parse_iso_utc(item)
                previous = parse_iso_utc(history[i + 1])
                if current and previous:
                    elapsed_days = (current - previous).days
                    entry["days_since_previous"] = max(elapsed_days, 0)
            history_entries.append(entry)
        task["completion_history"] = history_entries
        task["group_name"] = task["group_name"] or "Ungrouped"
        group_id = task["group_id"]
        if group_id in tasks_by_group:
            tasks_by_group[group_id].append(task)
        else:
            ungrouped_tasks.append(task)

    grouped_tasks = []
    for group in groups:
        group_tasks = tasks_by_group[group["id"]]
        if group_tasks:
            grouped_tasks.append({"name": group["name"], "tasks": group_tasks})
    if ungrouped_tasks:
        grouped_tasks.append({"name": "Ungrouped", "tasks": ungrouped_tasks})

    return render_template("index.html", grouped_tasks=grouped_tasks, groups=groups)


@app.post("/tasks")
def create_task():
    name = normalize_name(request.form.get("name", ""))
    if not name:
        return redirect(url_for("index"))

    db = get_db()
    group_id_raw = request.form.get("group_id", "")
    group_id = get_valid_group_id(db, group_id_raw) or get_default_group_id(db)
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT OR IGNORE INTO tasks (name, created_at, last_completed_at, group_id)
        VALUES (?, ?, NULL, ?)
        """,
        (name, now, group_id),
    )
    db.commit()
    return redirect(url_for("index"))


@app.post("/groups")
def create_group():
    name = normalize_name(request.form.get("name", ""))
    if not name:
        return redirect(url_for("index"))

    db = get_db()
    db.execute("INSERT OR IGNORE INTO groups (name) VALUES (?)", (name,))
    db.commit()
    return redirect(url_for("index"))


@app.post("/tasks/<int:task_id>/complete")
def complete_task(task_id: int):
    db = get_db()
    task = db.execute("SELECT id FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if not task:
        abort(404)

    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        """
        INSERT INTO task_completions (task_id, completed_at)
        VALUES (?, ?)
        """,
        (task_id, now),
    )
    db.execute(
        "UPDATE tasks SET last_completed_at = ? WHERE id = ?",
        (now, task_id),
    )
    db.commit()
    return redirect(url_for("index"))


@app.post("/tasks/<int:task_id>/move")
def move_task(task_id: int):
    db = get_db()
    task = db.execute("SELECT id FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if not task:
        abort(404)

    group_id = get_valid_group_id(db, request.form.get("group_id", ""))
    if group_id is None:
        return redirect(url_for("index"))

    db.execute(
        "UPDATE tasks SET group_id = ? WHERE id = ?",
        (group_id, task_id),
    )
    db.commit()
    return redirect(url_for("index"))


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

    return render_template(
        "admin.html",
        admin_slug=slug,
        tasks=tasks,
        backups=list_backups(),
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
