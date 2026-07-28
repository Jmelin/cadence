import time

from app import app, run_reminders_once


def main() -> None:
    while True:
        try:
            with app.app_context():
                result = run_reminders_once()
            print(result, flush=True)
        except Exception as error:
            print({"status": "error", "reason": str(error)}, flush=True)
        time.sleep(app.config["REMINDER_WORKER_INTERVAL_SECONDS"])


if __name__ == "__main__":
    main()
