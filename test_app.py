import tempfile
import unittest
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

from app import (
    app,
    cadence_insight,
    create_email_action_token,
    export_snapshot,
    format_local_datetime,
    get_db,
    init_db,
    restore_snapshot,
    run_reminders_once,
    send_daily_digest,
    task_payload,
)


class MutationApiTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.display_timezone = app.config["DISPLAY_TIMEZONE"]
        self.reminder_config = {
            key: app.config[key]
            for key in (
                "PUBLIC_BASE_URL",
                "SMTP_HOST",
                "SMTP_PORT",
                "SMTP_FROM",
                "REMINDER_RECIPIENT",
                "EMAIL_ACTION_SECRET",
                "REMINDER_DIGEST_HOUR",
                "REMINDER_MAX_ATTEMPTS",
                "REMINDER_RETRY_DELAY_MINUTES",
                "DEFAULT_DUE_SOON_LEAD_DAYS",
            )
        }
        app.config.update(
            TESTING=True,
            DATABASE=str(Path(self.temp_dir.name) / "tasks.db"),
            SECRET_KEY="test-secret",
            PUBLIC_BASE_URL="https://cadence.test",
            SMTP_HOST="smtp.test",
            SMTP_PORT=587,
            SMTP_FROM="Cadence <reminders@cadence.test>",
            REMINDER_RECIPIENT="user@cadence.test",
            EMAIL_ACTION_SECRET="test-email-action-secret",
            REMINDER_DIGEST_HOUR=8,
            REMINDER_MAX_ATTEMPTS=3,
            REMINDER_RETRY_DELAY_MINUTES=15,
            DEFAULT_DUE_SOON_LEAD_DAYS=0,
        )
        with app.app_context():
            init_db()
        self.client = app.test_client()
        with self.client.session_transaction() as session:
            session["_csrf_token"] = "test-csrf-token"

    def tearDown(self):
        app.config["DISPLAY_TIMEZONE"] = self.display_timezone
        app.config.update(self.reminder_config)
        self.temp_dir.cleanup()

    def post_json(self, path, data):
        data["_csrf_token"] = "test-csrf-token"
        return self.client.post(
            path,
            data=data,
            headers={"Accept": "application/json"},
        )

    def test_task_actions_return_updated_task_state(self):
        group_response = self.post_json("/groups", {"name": "Home"})
        self.assertEqual(group_response.status_code, 200)
        group = group_response.get_json()["group"]

        create_response = self.post_json(
            "/tasks", {"name": "Water plants", "group_id": group["id"]}
        )
        self.assertEqual(create_response.status_code, 200)
        created_task = create_response.get_json()["task"]
        self.assertTrue(create_response.get_json()["created"])
        self.assertEqual(created_task["group_name"], "Home")
        self.assertEqual(created_task["completion_count"], 0)

        complete_response = self.post_json(
            f"/tasks/{created_task['id']}/complete", {}
        )
        self.assertEqual(complete_response.status_code, 200)
        completed_task = complete_response.get_json()["task"]
        self.assertEqual(completed_task["completion_count"], 1)
        self.assertEqual(completed_task["completed_ago"], "Completed today")

        move_response = self.post_json(
            f"/tasks/{created_task['id']}/move", {"group_id": 1}
        )
        self.assertEqual(move_response.status_code, 200)
        self.assertEqual(move_response.get_json()["task"]["group_name"], "General")

    def test_duplicate_creation_reports_existing_record(self):
        first_response = self.post_json(
            "/tasks", {"name": "Water plants", "group_id": 1}
        )
        second_response = self.post_json(
            "/tasks", {"name": "Water plants", "group_id": 1}
        )

        self.assertTrue(first_response.get_json()["created"])
        self.assertFalse(second_response.get_json()["created"])
        self.assertEqual(
            first_response.get_json()["task"]["id"],
            second_response.get_json()["task"]["id"],
        )

    def test_json_actions_require_a_csrf_token(self):
        response = self.client.post(
            "/tasks",
            data={"name": "Water plants", "group_id": 1},
            headers={"Accept": "application/json"},
        )

        self.assertEqual(response.status_code, 400)

    def test_workspace_renders_progressive_enhancement_hooks(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'data-async-action="create-task"', response.data)
        self.assertIn(b'id="task-groups"', response.data)
        self.assertIn(b'src="/static/app.js"', response.data)
        self.assertIn(b"script-src 'self'", response.headers["Content-Security-Policy"].encode())

    def test_cadence_insight_uses_median_gap_and_due_boundaries(self):
        history = [
            "2026-01-21T00:00:00+00:00",
            "2026-01-11T00:00:00+00:00",
            "2026-01-01T00:00:00+00:00",
        ]
        not_due = cadence_insight(
            history, now=datetime(2026, 1, 22, tzinfo=timezone.utc)
        )
        due_soon = cadence_insight(
            history, now=datetime(2026, 1, 30, tzinfo=timezone.utc)
        )
        overdue = cadence_insight(
            history, now=datetime(2026, 2, 1, tzinfo=timezone.utc)
        )

        self.assertEqual(not_due["interval_days"], 10.0)
        self.assertIsNone(not_due["status"])
        self.assertEqual(due_soon["status"], "due_soon")
        self.assertEqual(overdue["status"], "overdue")

    def test_cadence_insight_needs_distinct_completion_gaps(self):
        insight = cadence_insight(
            [
                "2026-01-11T00:00:00+00:00",
                "2026-01-11T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ]
        )

        self.assertIsNone(insight["status"])
        self.assertIn("distinct completion days", insight["message"])

    def test_cadence_uses_median_to_resist_an_outlier_gap(self):
        insight = cadence_insight(
            [
                "2026-01-31T00:00:00+00:00",
                "2026-01-21T00:00:00+00:00",
                "2026-01-11T00:00:00+00:00",
                "2025-10-03T00:00:00+00:00",
            ],
            now=datetime(2026, 1, 31, tzinfo=timezone.utc),
        )

        self.assertEqual(insight["interval_days"], 10.0)
        self.assertIn("every 10 days", insight["message"])

    def test_global_due_soon_default_applies_without_task_override(self):
        app.config["DEFAULT_DUE_SOON_LEAD_DAYS"] = 5
        insight = cadence_insight(
            [
                "2026-01-21T00:00:00+00:00",
                "2026-01-11T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
            ],
            now=datetime(2026, 1, 27, tzinfo=timezone.utc),
        )

        self.assertEqual(insight["status"], "due_soon")

    def test_cadence_displays_due_times_in_the_user_timezone(self):
        app.config["DISPLAY_TIMEZONE"] = ZoneInfo("America/Chicago")
        insight = cadence_insight(
            ["2026-01-01T00:00:00+00:00"],
            manual_interval_days=1,
            now=datetime(2025, 12, 31, tzinfo=timezone.utc),
        )

        self.assertEqual(
            format_local_datetime("2026-01-02T00:00:00+00:00"),
            "Jan 1, 2026 at 6:00 PM",
        )
        self.assertEqual(insight["due_display"], "Jan 1, 2026 at 6:00 PM")

    def test_manual_cadence_and_pause_override_learned_history(self):
        history = ["2026-01-01T00:00:00+00:00"]
        manual = cadence_insight(
            history,
            manual_interval_days=7,
            due_soon_lead_days=2,
            now=datetime(2026, 1, 9, tzinfo=timezone.utc),
        )
        paused = cadence_insight(
            history,
            manual_interval_days=7,
            is_paused=True,
            now=datetime(2026, 1, 9, tzinfo=timezone.utc),
        )

        self.assertEqual(manual["source"], "manual")
        self.assertEqual(manual["status"], "overdue")
        self.assertEqual(paused["message"], "Paused")
        self.assertIsNone(paused["status"])

    def test_task_settings_are_saved_and_returned_as_json(self):
        create_response = self.post_json(
            "/tasks", {"name": "Replace filter", "group_id": 1}
        )
        task_id = create_response.get_json()["task"]["id"]

        settings_response = self.post_json(
            f"/tasks/{task_id}/settings",
            {
                "manual_interval_days": "30",
                "due_soon_lead_days": "5",
                "is_paused": "1",
                "reminders_enabled": "1",
            },
        )
        task = settings_response.get_json()["task"]

        self.assertEqual(settings_response.status_code, 200)
        self.assertEqual(task["manual_interval_days"], 30.0)
        self.assertEqual(task["due_soon_lead_days"], 5)
        self.assertTrue(task["is_paused"])
        self.assertTrue(task["reminders_enabled"])
        self.assertEqual(task["cadence"]["message"], "Paused")

    def test_task_settings_reject_invalid_cadence(self):
        create_response = self.post_json(
            "/tasks", {"name": "Replace filter", "group_id": 1}
        )
        task_id = create_response.get_json()["task"]["id"]

        response = self.post_json(
            f"/tasks/{task_id}/settings", {"manual_interval_days": "0"}
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("Manual cadence", response.get_json()["error"])

    def test_v2_snapshot_preserves_task_settings(self):
        create_response = self.post_json(
            "/tasks", {"name": "Replace filter", "group_id": 1}
        )
        task_id = create_response.get_json()["task"]["id"]
        self.post_json(
            f"/tasks/{task_id}/settings",
            {
                "manual_interval_days": "30",
                "due_soon_lead_days": "5",
                "is_paused": "1",
                "reminders_enabled": "1",
            },
        )
        with app.app_context():
            db = get_db()
            snapshot = export_snapshot(db)
            self.assertTrue(restore_snapshot(db, snapshot))
            task = task_payload(db, task_id)

        self.assertEqual(task["manual_interval_days"], 30.0)
        self.assertEqual(task["due_soon_lead_days"], 5)
        self.assertTrue(task["is_paused"])
        self.assertTrue(task["reminders_enabled"])

    def test_snapshot_preserves_reminder_delivery_history(self):
        self.create_overdue_reminder_task()
        app.config["REMINDER_DIGEST_HOUR"] = 23
        with app.app_context(), patch("app.send_email"):
            run_reminders_once(datetime(2026, 2, 2, 10, tzinfo=timezone.utc))
            db = get_db()
            snapshot = export_snapshot(db)
            self.assertTrue(restore_snapshot(db, snapshot))
            delivery = db.execute(
                "SELECT status, attempt_count FROM reminder_deliveries"
            ).fetchone()

        self.assertEqual(delivery["status"], "sent")
        self.assertEqual(delivery["attempt_count"], 1)

    def test_pre_v2_snapshot_restores_with_safe_settings_defaults(self):
        snapshot = {
            "groups": [{"id": 1, "name": "General"}],
            "tasks": [
                {
                    "id": 1,
                    "name": "Replace filter",
                    "created_at": "2026-01-01T00:00:00+00:00",
                    "last_completed_at": None,
                    "group_id": 1,
                }
            ],
            "task_completions": [],
        }
        with app.app_context():
            db = get_db()
            self.assertTrue(restore_snapshot(db, snapshot))
            task = task_payload(db, 1)

        self.assertIsNone(task["manual_interval_days"])
        self.assertIsNone(task["due_soon_lead_days"])
        self.assertFalse(task["is_paused"])
        self.assertFalse(task["reminders_enabled"])

    def test_enhanced_submission_serializes_before_disabling_controls(self):
        script = (Path(__file__).parent / "static" / "app.js").read_text()

        self.assertIn("event.preventDefault()", script)
        self.assertIn("body: formData", script)
        self.assertLess(
            script.index("const formData = new FormData(form);"),
            script.index("controls.forEach((control) => (control.disabled = true));"),
        )

    def create_overdue_reminder_task(self):
        response = self.post_json("/tasks", {"name": "Replace filter", "group_id": 1})
        task_id = response.get_json()["task"]["id"]
        with app.app_context():
            db = get_db()
            db.executemany(
                "INSERT INTO task_completions (task_id, completed_at) VALUES (?, ?)",
                [
                    (task_id, "2026-01-21T00:00:00+00:00"),
                    (task_id, "2026-01-11T00:00:00+00:00"),
                    (task_id, "2026-01-01T00:00:00+00:00"),
                ],
            )
            db.execute(
                """
                UPDATE tasks
                SET last_completed_at = ?, reminders_enabled = 1
                WHERE id = ?
                """,
                ("2026-01-21T00:00:00+00:00", task_id),
            )
            db.commit()
        return task_id

    def test_individual_reminder_sends_once_per_due_cycle(self):
        self.create_overdue_reminder_task()
        now = datetime(2026, 2, 2, 10, tzinfo=timezone.utc)
        app.config["REMINDER_DIGEST_HOUR"] = 23

        with app.app_context(), patch("app.send_email") as send_email:
            first = run_reminders_once(now)
            second = run_reminders_once(now)

        self.assertEqual(first["individual_sent"], 1)
        self.assertEqual(second["individual_sent"], 0)
        self.assertEqual(send_email.call_count, 1)

    def test_daily_digest_sends_once_per_local_day(self):
        self.create_overdue_reminder_task()
        now = datetime(2026, 2, 2, 20, tzinfo=timezone.utc)
        with app.app_context(), patch("app.send_email") as send_email:
            first = send_daily_digest(get_db(), now)
            second = send_daily_digest(get_db(), now)

        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        self.assertEqual(send_email.call_count, 1)

    def test_delivery_failure_is_recorded(self):
        self.create_overdue_reminder_task()
        app.config["REMINDER_DIGEST_HOUR"] = 23
        with app.app_context(), patch("app.send_email", side_effect=OSError("SMTP unavailable")):
            result = run_reminders_once(datetime(2026, 2, 2, 10, tzinfo=timezone.utc))
        with app.app_context():
            delivery = get_db().execute(
                "SELECT status, error_message FROM reminder_deliveries"
            ).fetchone()

        self.assertEqual(result["individual_sent"], 0)
        self.assertEqual(delivery["status"], "failed")
        self.assertIn("SMTP unavailable", delivery["error_message"])

    def test_failed_delivery_retries_after_the_configured_delay(self):
        self.create_overdue_reminder_task()
        app.config["REMINDER_DIGEST_HOUR"] = 23
        first_attempt = datetime(2026, 2, 2, 10, tzinfo=timezone.utc)
        with app.app_context(), patch("app.send_email", side_effect=OSError("SMTP unavailable")):
            run_reminders_once(first_attempt)
        with app.app_context(), patch("app.send_email") as send_email:
            result = run_reminders_once(first_attempt + timedelta(minutes=16))
            delivery = get_db().execute(
                "SELECT status, attempt_count FROM reminder_deliveries"
            ).fetchone()

        self.assertEqual(result["individual_sent"], 1)
        self.assertEqual(send_email.call_count, 1)
        self.assertEqual(delivery["status"], "sent")
        self.assertEqual(delivery["attempt_count"], 2)

    def test_email_action_requires_confirmation_and_is_single_use(self):
        task_id = self.create_overdue_reminder_task()
        with app.app_context():
            token = create_email_action_token(
                get_db(), task_id, datetime.now(timezone.utc)
            )

        page = self.client.get(f"/email-actions/{token}")
        complete = self.client.post(
            f"/email-actions/{token}", data={"_csrf_token": "test-csrf-token"}
        )
        repeated = self.client.post(
            f"/email-actions/{token}", data={"_csrf_token": "test-csrf-token"}
        )

        self.assertEqual(page.status_code, 200)
        self.assertEqual(complete.status_code, 200)
        self.assertEqual(repeated.status_code, 404)
        with app.app_context():
            self.assertEqual(task_payload(get_db(), task_id)["completion_count"], 4)

    def test_expired_or_altered_email_actions_are_rejected(self):
        task_id = self.create_overdue_reminder_task()
        with app.app_context():
            expired_token = create_email_action_token(
                get_db(), task_id, datetime.now(timezone.utc) - timedelta(hours=73)
            )

        self.assertEqual(self.client.get(f"/email-actions/{expired_token}").status_code, 404)
        self.assertEqual(self.client.get(f"/email-actions/{expired_token}x").status_code, 404)

    def test_schema_upgrade_preserves_existing_task_history(self):
        legacy_database = Path(self.temp_dir.name) / "legacy.db"
        legacy_db = sqlite3.connect(legacy_database)
        legacy_db.executescript(
            """
            CREATE TABLE groups (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);
            CREATE TABLE tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                last_completed_at TEXT,
                group_id INTEGER
            );
            CREATE TABLE task_completions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                completed_at TEXT NOT NULL
            );
            INSERT INTO groups (id, name) VALUES (1, 'General');
            INSERT INTO tasks (id, name, created_at, last_completed_at, group_id)
            VALUES (1, 'Replace filter', '2026-01-01T00:00:00+00:00', '2026-01-02T00:00:00+00:00', 1);
            INSERT INTO task_completions (task_id, completed_at)
            VALUES (1, '2026-01-02T00:00:00+00:00');
            """
        )
        legacy_db.commit()
        legacy_db.close()
        original_database = app.config["DATABASE"]
        app.config["DATABASE"] = str(legacy_database)
        try:
            with app.app_context():
                init_db()
                task = task_payload(get_db(), 1)
        finally:
            app.config["DATABASE"] = original_database

        self.assertEqual(task["name"], "Replace filter")
        self.assertEqual(task["completion_count"], 1)
        self.assertFalse(task["reminders_enabled"])


if __name__ == "__main__":
    unittest.main()
