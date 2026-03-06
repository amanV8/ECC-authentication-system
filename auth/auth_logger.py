import datetime
import os
from database import get_db

LOG_FILE = "logs/auth.log"


def log_event(username, status, reason, ip_address):

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")

    conn = get_db()

    conn.execute("""
        INSERT INTO login_logs (username, timestamp, status, reason, ip_address)
        VALUES (?, ?, ?, ?, ?)
    """, (username, timestamp, status, reason, ip_address))

    conn.commit()
    conn.close()

    # Ensure logs folder exists
    os.makedirs("logs", exist_ok=True)

    # Write log entry to file
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {username} | {status} | {reason} | {ip_address}\n")