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
from collections.abc import Iterator
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


def follow_log_tail(
    path: Path,
    *,
    poll_interval: float = POLL_INTERVAL_SECONDS,
    start_at_end: bool = True,
) -> Iterator[str]:
    """
    Continuously yield new lines appended to `path`, like Linux `tail -f`.

    Blocks forever on the open file: seeks to EOF (when ``start_at_end`` is
    True), then reads line-by-line, sleeping briefly when no data is ready.
    If the file does not exist yet, waits until it appears.
    """
    while not path.exists():
        print(f"Waiting for log file: {path.resolve()}")
        time.sleep(poll_interval)

    with path.open("r", encoding="utf-8") as handle:
        if start_at_end:
            handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if not line:
                time.sleep(poll_interval)
                continue
            yield line.rstrip("\n")


def follow_security_traffic_log(
    *,
    poll_interval: float = POLL_INTERVAL_SECONDS,
    start_at_end: bool = True,
) -> Iterator[str]:
    """
    Monitor ``security_traffic.log`` for new lines without exiting, ``tail -f`` style.

    Yields each complete line as it is appended. Runs until the process is
    interrupted (e.g. Ctrl+C).
    """
    yield from follow_log_tail(
        LOG_FILE,
        poll_interval=poll_interval,
        start_at_end=start_at_end,
    )


def main() -> None:
    import json

    print(f"Monitoring: {LOG_FILE.resolve()}")
    print(f"Using model: {LLM_MODEL}")
    print("Waiting for RED ALERT entries...\n")

    for line in follow_security_traffic_log():
        if "RED ALERT" not in line:
            continue

        attack_type = extract_attack_type(line)
        response = explain_threat_with_llm(attack_type, line)

        risk_level = "UNKNOWN"
        fintech_impact = "No impact assessment provided."

        if isinstance(response, dict):
            risk_level = response.get("risk_level", "UNKNOWN")
            fintech_impact = response.get("fintech_impact", "No impact assessment provided.")
        elif isinstance(response, str):
            try:
                parsed = json.loads(response)
                if isinstance(parsed, dict):
                    risk_level = parsed.get("risk_level", "UNKNOWN")
                    fintech_impact = parsed.get("fintech_impact", "No impact assessment provided.")
                else:
                    # Not a dict, treat as plain text
                    risk_level = "HIGH"
                    fintech_impact = response
            except Exception:
                # Failed to parse as JSON, treat as fintech_impact text
                risk_level = "HIGH"
                fintech_impact = response
        else:
            fintech_impact = str(response)
            risk_level = "HIGH"

        # Format output: bold blue (ANSI: \033[1;34m ... \033[0m)
        explanation = (
            f"\033[1;34mRisk Level: {risk_level}\033[0m\n"
            f"\033[1;34mFintech Impact: {fintech_impact}\033[0m"
        )
        print(f"[RED ALERT] {attack_type}")
        print(f"Threat explanation: {explanation}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped analyzer.")
