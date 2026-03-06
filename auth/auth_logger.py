import datetime
import os
import pytz
from database import get_db

LOG_FILE = "logs/auth.log"

IST = pytz.timezone("Asia/Kolkata")


def log_event(username, status, reason, ip_address):

    # Force IST timezone
    timestamp = datetime.datetime.now(IST).strftime("%Y-%m-%d %I:%M:%S %p")

    conn = get_db()

    conn.execute("""
        INSERT INTO login_logs (username, timestamp, status, reason, ip_address)
        VALUES (?, ?, ?, ?, ?)
    """, (username, timestamp, status, reason, ip_address))

    conn.commit()
    conn.close()

    os.makedirs("logs", exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} | {username} | {status} | {reason} | {ip_address}\n")