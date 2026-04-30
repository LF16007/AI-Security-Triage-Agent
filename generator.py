#!/usr/bin/env python3
"""
Generate simulated security traffic logs.

Creates/updates `security_traffic.log` by appending one log line every 5 seconds.
Most entries are INFO logs, with occasional RED ALERT errors.
"""

from __future__ import annotations

import random
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


LOG_FILE = Path("security_traffic.log")
LONDON_TZ = ZoneInfo("Europe/London")
SLEEP_SECONDS = 5

INFO_EVENTS = [
    "User session validated",
    "Heartbeat check passed",
    "Firewall rule sync completed",
    "Request processed successfully",
    "Token refresh completed",
    "System health check nominal",
]

RED_ALERT_EVENTS = [
    "SQL Injection",
    "Unauthorized Access",
    "Credential Stuffing Attempt",
    "Privilege Escalation Attempt",
    "Suspicious Payload Detected",
]

# 85% INFO, 15% RED ALERT
LOG_LEVEL_WEIGHTS = [("INFO", 0.85), ("RED ALERT", 0.15)]


def current_london_time() -> str:
    """Return current timestamp in London time (ISO-like format)."""
    return datetime.now(LONDON_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")


def build_log_line() -> str:
    """Build one randomized log line."""
    level = random.choices(
        [choice[0] for choice in LOG_LEVEL_WEIGHTS],
        [choice[1] for choice in LOG_LEVEL_WEIGHTS],
        k=1,
    )[0]

    if level == "INFO":
        event = random.choice(INFO_EVENTS)
        source_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        return f"{current_london_time()} | {level} | {event} | src_ip={source_ip}"

    event = random.choice(RED_ALERT_EVENTS)
    source_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    return f"{current_london_time()} | {level} | {event} | src_ip={source_ip}"


def main() -> None:
    """Append a new log entry every few seconds forever."""
    print(f"Writing logs to: {LOG_FILE.resolve()}")
    print("Press Ctrl+C to stop.")

    while True:
        line = build_log_line()
        with LOG_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        print(line)
        time.sleep(SLEEP_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped log generator.")
