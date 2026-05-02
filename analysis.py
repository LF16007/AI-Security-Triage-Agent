#!/usr/bin/env python3
"""
Real-time RED ALERT analyzer for security_traffic.log.

Whenever a RED ALERT line is appended to the log file, this script creates a
local triage assessment and appends it to triage_report.json.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


LOG_FILE = Path("security_traffic.log")
REPORT_FILE = Path("triage_report.json")
POLL_INTERVAL_SECONDS = 1.0
LONDON_TZ = ZoneInfo("Europe/London")


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


def current_london_time() -> str:
    """Return current London timestamp."""
    return datetime.now(LONDON_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")


def determine_risk_level(attack_type: str) -> str:
    """Classify risk based on attack type and triage policy."""
    normalized = attack_type.lower()
    high_risk_keywords = (
        "sql injection",
        "unauthorized access",
        "privilege escalation",
        "suspicious payload",
    )
    medium_risk_keywords = ("credential stuffing", "brute force", "recon")

    if any(keyword in normalized for keyword in high_risk_keywords):
        return "HIGH"
    if any(keyword in normalized for keyword in medium_risk_keywords):
        return "MEDIUM"
    return "MEDIUM"


def build_fintech_impact(attack_type: str, risk_level: str) -> dict[str, str]:
    """Build detailed impact statements for London banking standards."""
    normalized = attack_type.lower()

    if "sql injection" in normalized:
        regulatory = (
            "Potential compromise of customer and transaction records can trigger FCA/PRA "
            "major incident assessment, expedited governance escalation, and formal breach "
            "documentation under UK financial-services control expectations."
        )
        operational = (
            "Tampered or exfiltrated database records may corrupt balances, payment states, "
            "and reconciliation flows, creating a material risk to real-time clearing, "
            "settlement, and end-of-day reporting continuity."
        )
        trust = (
            "Exposure of account or identity data can drive customer churn, complaints, and "
            "reputational loss, especially where London retail and SME clients expect "
            "high-integrity digital banking channels."
        )
    elif "unauthorized access" in normalized:
        regulatory = (
            "Unauthorized account or system entry indicates control failure across access "
            "management, requiring prompt FCA/PRA-impact evaluation, evidence retention, "
            "and board-level risk oversight updates."
        )
        operational = (
            "Compromised credentials can enable fraudulent transactions or malicious admin "
            "changes, disrupting core banking operations, incident response workloads, and "
            "service availability obligations."
        )
        trust = (
            "Customers interpret unauthorized access as direct failure of safeguarding duties, "
            "reducing confidence in secure custody of funds and personal data."
        )
    else:
        regulatory = (
            "This attack pattern suggests a material cyber threat that should be assessed "
            "against FCA/PRA incident thresholds, internal operational resilience controls, "
            "and mandatory audit-trace requirements."
        )
        operational = (
            "Unchecked malicious activity can degrade authentication, transaction integrity, "
            "or platform stability, impacting payment timeliness and critical business services."
        )
        trust = (
            "Repeated hostile activity increases perceived fragility of the bank's digital "
            "channels and may reduce customer willingness to transact online."
        )

    summary = (
        f"{attack_type} is a {risk_level} threat because it can create regulatory exposure "
        "under London financial oversight, disrupt transaction continuity, and undermine "
        "customer trust in secure banking operations."
    )

    return {
        "summary": summary,
        "regulatory_compliance": regulatory,
        "operational_continuity": operational,
        "customer_trust": trust,
    }


def write_report_entry(entry: dict[str, object], report_path: Path = REPORT_FILE) -> None:
    """Append one RED ALERT triage entry to a local JSON report file."""
    if report_path.exists():
        try:
            existing = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except json.JSONDecodeError:
            existing = []
    else:
        existing = []

    existing.append(entry)
    report_path.write_text(json.dumps(existing, indent=2), encoding="utf-8")


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
    print(f"Monitoring: {LOG_FILE.resolve()}")
    print(f"Writing report to: {REPORT_FILE.resolve()}")
    print("Waiting for RED ALERT entries...\n")

    for line in follow_security_traffic_log():
        if "RED ALERT" not in line:
            continue

        attack_type = extract_attack_type(line)
        risk_level = determine_risk_level(attack_type)
        fintech_impact = build_fintech_impact(attack_type, risk_level)

        entry: dict[str, object] = {
            "observed_at_london": current_london_time(),
            "attack_type": attack_type,
            "risk_level": risk_level,
            "raw_log": line,
            "fintech_impact": fintech_impact,
        }
        write_report_entry(entry)

        print(f"[RED ALERT] {attack_type}")
        print(f"Risk Level: {risk_level}")
        print(f"Fintech Impact: {fintech_impact['summary']}")
        print("Saved to triage_report.json\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped analyzer.")
