import random
import time
from datetime import datetime
from zoneinfo import ZoneInfo


LOG_FILE = "security_traffic.log"
LONDON_TZ = ZoneInfo("Europe/London")

INFO_EVENTS = [
    "INFO: User Login",
    "INFO: File Access",
]

CRITICAL_EVENTS = [
    "CRITICAL: SQL Injection Attempt",
    "CRITICAL: Brute Force Attack",
]


def choose_event() -> str:
    """Return an event string with an 80/20 INFO/CRITICAL split."""
    if random.random() < 0.8:
        return random.choice(INFO_EVENTS)
    return random.choice(CRITICAL_EVENTS)


def write_log_line() -> None:
    timestamp = datetime.now(LONDON_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")
    event = choose_event()
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(f"{timestamp} - {event}\n")


def main() -> None:
    print(f"Writing logs to '{LOG_FILE}' every 5 seconds. Press Ctrl+C to stop.")
    try:
        while True:
            write_log_line()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopped log generation.")


if __name__ == "__main__":
    main()
