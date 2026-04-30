import os
import time


LOG_FILE = "security_traffic.log"
RED = "\033[91m"
RESET = "\033[0m"


def watch_log() -> None:
    """Watch the security log and alert on CRITICAL entries."""
    print(f"Watching '{LOG_FILE}' for threats... Press Ctrl+C to stop.")

    while not os.path.exists(LOG_FILE):
        time.sleep(1)

    with open(LOG_FILE, "r", encoding="utf-8") as log_file:
        # Start watching new entries only.
        log_file.seek(0, os.SEEK_END)

        while True:
            line = log_file.readline()
            if not line:
                time.sleep(0.5)
                continue

            if "CRITICAL" in line:
                # TODO: Integration with LLM for Ed Donner Video 3.
                entry = line.strip()
                print(f"{RED}THREAT DETECTED: {entry}{RESET}")


def main() -> None:
    try:
        watch_log()
    except KeyboardInterrupt:
        print("\nStopped threat monitoring.")


if __name__ == "__main__":
    main()
