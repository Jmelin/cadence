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

    def create_profile(self, name="Jordan", slug="jordan"):
        response = self.post_json("/profiles", {"name": name, "slug": slug})
        self.assertEqual(response.status_code, 200)
        return response.get_json()["profile"]

    def test_profile_views_include_own_and_global_tasks(self):
        jordan = self.create_profile()
        alex = self.create_profile("Alex", "alex")
        global_task = self.post_json("/tasks", {"name": "Shared chore"}).get_json()["task"]
        jordan_task = self.post_json("/tasks", {"name": "Jordan chore", "profile_id": jordan["id"]}).get_json()["task"]
        alex_task = self.post_json("/tasks", {"name": "Alex chore", "profile_id": alex["id"]}).get_json()["task"]
        for path, included, excluded in (
            ("/", [global_task, jordan_task, alex_task], []),
            ("/jordan", [global_task, jordan_task], [alex_task]),
            ("/alex", [global_task, alex_task], [jordan_task]),
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                html = response.get_data(as_text=True)
                for task in included:
                    self.assertIn(f'data-task-id="{task["id"]}"', html)
                for task in excluded:
                    self.assertNotIn(f'data-task-id="{task["id"]}"', html)
                self.assertIn('class="profile-badge">Global</span>', html)
        self.assertEqual(self.client.get("/unknown-profile").status_code, 404)
        self.assertEqual(self.client.get("/activity").status_code, 200)

    def test_profile_form_defaults_and_html_redirects(self):
        profile = self.create_profile()
        profile_html = self.client.get("/jordan").get_data(as_text=True)
        all_html = self.client.get("/").get_data(as_text=True)
        self.assertIn(f'<option value="{profile["id"]}" selected>Jordan</option>', profile_html)
        self.assertIn('<option value="" selected>Global</option>', all_html)
        response = self.client.post("/tasks", data={
            "_csrf_token": "test-csrf-token", "name": "New chore",
            "profile_id": profile["id"], "view_profile": "jordan",
        })
        self.assertEqual(response.location, "/jordan")
        with app.app_context():
            task_id = get_db().execute("SELECT id FROM tasks WHERE name = 'New chore'").fetchone()["id"]
        for action in ("complete", "move", "settings"):
            response = self.client.post(f"/tasks/{task_id}/{action}", data={
                "_csrf_token": "test-csrf-token", "view_profile": "jordan", "group_id": "1",
            })
            self.assertEqual(response.location, "/jordan")
        response = self.client.post("/groups", data={
            "_csrf_token": "test-csrf-token", "name": "Home", "view_profile": "https://evil.test",
        })
        self.assertEqual(response.location, "/")

    def test_profile_reassignment_preserves_completion_history(self):
        jordan = self.create_profile()
        alex = self.create_profile("Alex", "alex")
        task = self.post_json("/tasks", {"name": "Chore", "profile_id": jordan["id"]}).get_json()["task"]
        self.post_json(f'/tasks/{task["id"]}/complete', {"note": "Done once"})
        settings_path = f'/tasks/{task["id"]}/settings'
        unchanged = self.post_json(settings_path, {}).get_json()["task"]
        self.assertEqual(unchanged["profile_id"], jordan["id"])
        reassigned = self.post_json(settings_path, {"profile_id": alex["id"]}).get_json()["task"]
        self.assertEqual(reassigned["profile_name"], "Alex")
        self.assertEqual(reassigned["completion_count"], 1)
        self.assertNotIn(f'data-task-id="{task["id"]}"', self.client.get("/jordan").get_data(as_text=True))
        global_task = self.post_json(settings_path, {"profile_id": ""}).get_json()["task"]
        self.assertIsNone(global_task["profile_id"])
        self.assertIsNone(global_task["profile_name"])
        for path in ("/jordan", "/alex"):
            self.assertIn(f'data-task-id="{task["id"]}"', self.client.get(path).get_data(as_text=True))
        self.assertEqual(global_task["completion_history"][0]["note"], "Done once")

    def test_global_completion_is_shared_across_profile_views(self):
        self.create_profile()
        self.create_profile("Alex", "alex")
        task = self.post_json("/tasks", {"name": "Shared chore"}).get_json()["task"]
        for slug in ("jordan", "alex"):
            response = self.client.post(f'/tasks/{task["id"]}/complete', data={
                "_csrf_token": "test-csrf-token", "view_profile": slug, "note": f"Done by {slug}",
            }, follow_redirects=True)
            self.assertEqual(response.status_code, 200)
        for slug in ("jordan", "alex"):
            html = self.client.get(f"/{slug}").get_data(as_text=True)
            self.assertIn("History (2)", html)
            self.assertIn("Done by jordan", html)
            self.assertIn("Done by alex", html)
        with app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 1)

    def test_profile_validation_and_slug_generation(self):
        generated = self.post_json("/profiles", {"name": "Jordán Melin"})
        self.assertEqual(generated.get_json()["profile"]["slug"], "jordan-melin")
        self.assertEqual(generated.get_json()["profile"]["url"], "/jordan-melin")
        for slug in ("activity", "tasks", "groups", "profiles", "admin", "email-actions", "static", "global", "UPPER", "../bad", "two--hyphens", "-leading", "trailing-", "1start", "long" * 21):
            with self.subTest(slug=slug):
                self.assertEqual(self.post_json("/profiles", {"name": "Invalid", "slug": slug}).status_code, 400)
        self.assertEqual(self.post_json("/profiles", {"name": ""}).status_code, 400)
        self.assertEqual(self.post_json("/profiles", {"name": "Other", "slug": "jordan-melin"}).status_code, 409)
        response = self.client.post("/profiles", data={"name": "No CSRF"}, headers={"Accept": "application/json"})
        self.assertEqual(response.status_code, 400)

    def test_invalid_task_profiles_do_not_change_tasks(self):
        profile = self.create_profile()
        task = self.post_json("/tasks", {"name": "Chore", "profile_id": profile["id"]}).get_json()["task"]
        for value in ("999", "-1", "invalid", "1.0", "1 OR 1=1", "١"):
            with self.subTest(value=value):
                self.assertEqual(self.post_json("/tasks", {"name": "Invalid chore", "profile_id": value}).status_code, 400)
                self.assertEqual(self.post_json(f'/tasks/{task["id"]}/settings', {"profile_id": value}).status_code, 400)
        with app.app_context():
            self.assertEqual(task_payload(get_db(), task["id"])["profile_id"], profile["id"])
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 1)

    def test_delete_profile_requires_confirmation_and_makes_tasks_global(self):
        profile = self.create_profile()
        self.create_profile("Alex", "alex")
        task = self.post_json("/tasks", {"name": "Chore", "profile_id": profile["id"]}).get_json()["task"]
        self.post_json(f'/tasks/{task["id"]}/complete', {"note": "Keep this history"})
        path = f'/profiles/{profile["id"]}/delete'
        self.assertEqual(self.post_json(path, {}).status_code, 400)
        self.assertEqual(self.client.get("/jordan").status_code, 200)
        self.assertEqual(self.post_json(path, {"confirm_global": "1"}).location, "/")
        self.assertEqual(self.client.get("/jordan").status_code, 404)
        self.assertIn("Keep this history", self.client.get("/alex").get_data(as_text=True))
        with app.app_context():
            restored = task_payload(get_db(), task["id"])
            self.assertIsNone(restored["profile_id"])
            self.assertEqual(restored["completion_count"], 1)
        self.assertEqual(self.post_json(path, {"confirm_global": "1"}).status_code, 404)

    def test_snapshot_preserves_profiles_and_assignments(self):
        profile = self.create_profile()
        task = self.post_json("/tasks", {"name": "Chore", "profile_id": profile["id"]}).get_json()["task"]
        self.post_json(f'/tasks/{task["id"]}/complete', {"note": "Keep this history"})
        with app.app_context():
            db = get_db()
            snapshot = export_snapshot(db)
            self.assertEqual(snapshot["profiles"], [{"id": profile["id"], "name": "Jordan", "slug": "jordan"}])
            self.assertTrue(restore_snapshot(db, snapshot))
            self.assertEqual(task_payload(db, task["id"])["profile_id"], profile["id"])
            self.assertEqual(task_payload(db, task["id"])["completion_count"], 1)
            for invalid in (None, [{"id": 1, "name": "Invalid", "slug": "admin"}], []):
                with self.subTest(invalid=invalid):
                    self.assertFalse(restore_snapshot(db, {**snapshot, "profiles": invalid}))
                    self.assertEqual(task_payload(db, task["id"])["profile_id"], profile["id"])
            snapshot.pop("profiles")
            for saved_task in snapshot["tasks"]:
                saved_task.pop("profile_id")
            self.assertTrue(restore_snapshot(db, snapshot))
            self.assertIsNone(task_payload(db, task["id"])["profile_id"])
            self.assertEqual(db.execute("SELECT COUNT(*) FROM profiles").fetchone()[0], 0)

    def test_full_wipe_includes_profiles_in_backup_and_removes_them(self):
        profile = self.create_profile()
        self.post_json("/tasks", {"name": "Chore", "profile_id": profile["id"]})
        with patch.dict(app.config, {"ADMIN_SLUG": "test-admin"}), patch("app.create_backup") as backup:
            response = self.post_json("/admin/test-admin/wipe", {})
            self.assertEqual(response.status_code, 302)
            backup.assert_called_once()
        with app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM profiles").fetchone()[0], 0)
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 0)

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
            f"/tasks/{created_task['id']}/complete", {"note": "Watered the fern"}
        )
        self.assertEqual(complete_response.status_code, 200)
        completed_task = complete_response.get_json()["task"]
        self.assertEqual(completed_task["completion_count"], 1)
        self.assertEqual(completed_task["completed_ago"], "Completed today")
        self.assertEqual(completed_task["completion_history"][0]["note"], "Watered the fern")

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

    def test_create_with_repeat_interval_and_return_to_automatic(self):
        response = self.post_json(
            "/tasks", {"name": "Water plants", "manual_interval_days": "7"}
        )
        self.assertEqual(response.status_code, 200)
        task = response.get_json()["task"]
        self.assertEqual(task["manual_interval_days"], 7)
        self.assertEqual(task["cadence"]["source"], "manual")
        self.assertIsNone(task["cadence"]["due_at"])
        self.assertEqual(task["due_summary"], "Complete once to start")
        completed = self.post_json(f"/tasks/{task['id']}/complete", {}).get_json()["task"]
        due = datetime.fromisoformat(completed["cadence"]["due_at"])
        last = datetime.fromisoformat(completed["last_completed_at"])
        self.assertEqual(due - last, timedelta(days=7))
        self.assertEqual(completed["dashboard_status"], "scheduled")
        automatic = self.post_json(
            f"/tasks/{task['id']}/settings", {"manual_interval_days": ""}
        ).get_json()["task"]
        self.assertIsNone(automatic["manual_interval_days"])
        self.assertEqual(automatic["completion_count"], 1)
        self.assertEqual(automatic["dashboard_status"], "learning")

    def test_create_rejects_invalid_repeat_interval_without_saving(self):
        for value in ["0", "-7", "3651", "NaN", "inf", "weekly"]:
            with self.subTest(value=value):
                response = self.post_json(
                    "/tasks", {"name": "Invalid interval", "manual_interval_days": value}
                )
                self.assertEqual(response.status_code, 400)
        with app.app_context():
            self.assertEqual(get_db().execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 0)

    def test_dashboard_summary_uses_local_calendar_date(self):
        app.config["DISPLAY_TIMEZONE"] = ZoneInfo("America/Chicago")
        task_id = self.create_overdue_reminder_task()
        with app.app_context():
            db = get_db()
            db.execute("UPDATE tasks SET manual_interval_days = 1 WHERE id = ?", (task_id,))
            db.commit()
            with patch("app.datetime") as clock:
                clock.now.return_value = datetime(2026, 1, 22, 1, tzinfo=timezone.utc)
                clock.fromisoformat.side_effect = datetime.fromisoformat
                task = task_payload(db, task_id)
        self.assertEqual(task["dashboard_status"], "overdue")
        self.assertEqual(task["due_summary"], "Due today")

    def test_clearing_manual_interval_restores_learned_cadence(self):
        task_id = self.create_overdue_reminder_task()
        manual = self.post_json(
            f"/tasks/{task_id}/settings", {"manual_interval_days": "30"}
        ).get_json()["task"]
        automatic = self.post_json(
            f"/tasks/{task_id}/settings", {"manual_interval_days": ""}
        ).get_json()["task"]
        self.assertEqual(manual["cadence"]["interval_days"], 30)
        self.assertEqual(automatic["cadence"]["interval_days"], 10)
        self.assertEqual(automatic["cadence"]["source"], "learned")
        self.assertEqual(automatic["completion_count"], 3)

    def test_completion_note_is_preserved_by_backups(self):
        create_response = self.post_json(
            "/tasks", {"name": "Replace filter", "group_id": 1}
        )
        task_id = create_response.get_json()["task"]["id"]
        self.post_json(f"/tasks/{task_id}/complete", {"note": "Installed HEPA filter"})

        with app.app_context():
            db = get_db()
            snapshot = export_snapshot(db)
            self.assertTrue(restore_snapshot(db, snapshot))
            task = task_payload(db, task_id)

        self.assertEqual(task["completion_history"][0]["note"], "Installed HEPA filter")

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
        self.assertIn(b'href="/activity"', response.data)
        self.assertIn(b'data-async-action="create-task"', response.data)
        self.assertIn(b'id="task-groups"', response.data)
        self.assertIn(b'src="/static/app.js"', response.data)
        self.assertIn(b"script-src 'self'", response.headers["Content-Security-Policy"].encode())

    def test_activity_shows_completions_across_tasks_newest_first(self):
        app.config["DISPLAY_TIMEZONE"] = ZoneInfo("America/Chicago")
        first_id = self.post_json("/tasks", {"name": "Water plants"}).get_json()["task"]["id"]
        second_id = self.post_json("/tasks", {"name": "Replace filter"}).get_json()["task"]["id"]
        with app.app_context():
            db = get_db()
            db.executemany(
                "INSERT INTO task_completions (task_id, completed_at, note) VALUES (?, ?, ?)",
                [
                    (first_id, "2026-01-21T23:00:00+00:00", None),
                    (second_id, "2026-01-22T01:00:00+00:00", "New <filter>"),
                    (first_id, "2026-01-22T02:00:00+00:00", "Watered"),
                ],
            )
            db.commit()

        response = self.client.get("/activity")
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertLess(html.index("Watered"), html.index("New &lt;filter&gt;"))
        self.assertLess(html.index("New &lt;filter&gt;"), html.index("Jan 21, 2026 at 5:00 PM"))
        self.assertIn("Jan 21, 2026 at 8:00 PM", html)
        self.assertIn("Jan 21, 2026 at 7:00 PM", html)
        self.assertIn('datetime="2026-01-22T02:00:00+00:00"', html)
        self.assertIn('href="/"', html)

    def test_activity_has_empty_state(self):
        response = self.client.get("/activity")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No activity yet", response.data)

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
        self.assertIsNone(task["profile_id"])
        self.assertIsNone(task["profile_name"])

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
