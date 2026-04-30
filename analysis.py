#!/usr/bin/env python3
"""
Real-time RED ALERT analyzer for security_traffic.log.

Whenever a RED ALERT line is appended to the log file, this script calls an
LLM API to generate a one-sentence explanation of why that specific attack is
a threat to a London business.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path


LOG_FILE = Path("security_traffic.log")
POLL_INTERVAL_SECONDS = 1.0

# OpenAI-compatible Chat Completions endpoint.
LLM_API_URL = os.getenv("LLM_API_URL", "https://api.openai.com/v1/chat/completions")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")


def extract_attack_type(log_line: str) -> str:
    """
    Extract attack type from a log line.
    Expected RED ALERT format:
      <timestamp> | RED ALERT | <attack type> | src_ip=...
    """
    parts = [part.strip() for part in log_line.split("|")]
    if len(parts) >= 3:
        return parts[2]
    return "Unknown attack"


def build_prompt(attack_type: str, log_line: str) -> str:
    """Create a focused prompt for one-sentence threat explanation."""
    return (
        "You are a cybersecurity analyst.\n"
        "In exactly one sentence, explain why this attack is a threat to a London business.\n"
        f"Attack type: {attack_type}\n"
        f"Log line: {log_line}\n"
        "Keep it practical and concise."
    )


def explain_threat_with_llm(attack_type: str, log_line: str) -> str:
    """Call the LLM API and return a one-sentence explanation."""
    if not LLM_API_KEY:
        return (
            "Missing LLM_API_KEY, so no model explanation was generated; "
            f"{attack_type} can still disrupt business operations and trust."
        )

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You explain cyber threats for business stakeholders in one sentence."
                ),
            },
            {"role": "user", "content": build_prompt(attack_type, log_line)},
        ],
        "temperature": 0.2,
        "max_tokens": 80,
    }

    request = urllib.request.Request(
        LLM_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {LLM_API_KEY}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response_data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        return f"LLM API HTTP error {exc.code}: {error_body}"
    except urllib.error.URLError as exc:
        return f"LLM API connection error: {exc.reason}"
    except TimeoutError:
        return "LLM API timeout error."

    try:
        message = response_data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return f"Unexpected LLM API response: {response_data}"

    return " ".join(message.strip().split())


def follow_file(path: Path):
    """
    Yield new lines appended to file, similar to `tail -f`.
    If file doesn't exist yet, wait until it appears.
    """
    while not path.exists():
        print(f"Waiting for log file: {path.resolve()}")
        time.sleep(POLL_INTERVAL_SECONDS)

    with path.open("r", encoding="utf-8") as handle:
        handle.seek(0, os.SEEK_END)  # Read only new incoming entries.
        while True:
            line = handle.readline()
            if not line:
                time.sleep(POLL_INTERVAL_SECONDS)
                continue
            yield line.rstrip("\n")


def main() -> None:
    print(f"Monitoring: {LOG_FILE.resolve()}")
    print(f"Using model: {LLM_MODEL}")
    print("Waiting for RED ALERT entries...\n")

    for line in follow_file(LOG_FILE):
        if "RED ALERT" not in line:
            continue

        attack_type = extract_attack_type(line)
        explanation = explain_threat_with_llm(attack_type, line)
        print(f"[RED ALERT] {attack_type}")
        print(f"Threat explanation: {explanation}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped analyzer.")
