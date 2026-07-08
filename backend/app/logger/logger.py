from app.logger.log_entry import LogEntry

LOG_FILE = "logs/waf.log"


def save_log(entry: LogEntry):
    with open(LOG_FILE, "a") as file:
        file.write("=" * 50 + "\n")
        file.write(f"Timestamp : {entry.timestamp}\n")
        file.write(f"IP        : {entry.ip}\n")
        file.write(f"Method    : {entry.method}\n")
        file.write(f"URL       : {entry.url}\n")
        file.write(f"Attack    : {entry.attack}\n")
        file.write(f"Decision  : {entry.decision}\n")
        file.write(f"Severity  : {entry.severity}\n")
        file.write("=" * 50 + "\n\n")
