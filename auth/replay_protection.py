import datetime
from database import get_db


def nonce_exists(username, nonce):
    conn = get_db()
    record = conn.execute(
        "SELECT * FROM nonces WHERE username = ? AND nonce = ?",
        (username, nonce.hex())
    ).fetchone()
    conn.close()
    return record is not None


def store_nonce(username, nonce):
    conn = get_db()
    conn.execute("""
        INSERT INTO nonces (username, nonce, used_at)
        VALUES (?, ?, ?)
    """, (username, nonce.hex(), datetime.datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()