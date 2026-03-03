import sqlite3

def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    conn = get_db()
    cursor = conn.cursor()

    # USERS TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password_hash TEXT,
            public_key TEXT,
            private_key TEXT
        )
    """)

    # SESSION TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            token TEXT,
            expiry TEXT,
            ip_address TEXT
        )
    """)

    # NONCE TABLE (Replay Protection)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            nonce TEXT,
            used_at TEXT
        )
    """)

    # LOGIN LOG TABLE
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            timestamp TEXT,
            status TEXT,
            reason TEXT,
            ip_address TEXT
        )
    """)

    conn.commit()
    conn.close()