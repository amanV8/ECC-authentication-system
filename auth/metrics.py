from database import get_db


def get_security_metrics():
    conn = get_db()

    total_attempts = conn.execute(
        "SELECT COUNT(*) FROM login_logs"
    ).fetchone()[0]

    success_count = conn.execute(
        "SELECT COUNT(*) FROM login_logs WHERE status = 'SUCCESS'"
    ).fetchone()[0]

    failure_count = conn.execute(
        "SELECT COUNT(*) FROM login_logs WHERE status = 'FAILURE'"
    ).fetchone()[0]

    replay_count = conn.execute(
        "SELECT COUNT(*) FROM login_logs WHERE reason = 'Replay Attack Detected'"
    ).fetchone()[0]

    signature_failures = conn.execute(
        "SELECT COUNT(*) FROM login_logs WHERE reason = 'Signature Verification Failed'"
    ).fetchone()[0]

    active_sessions = conn.execute(
        "SELECT COUNT(*) FROM sessions"
    ).fetchone()[0]

    conn.close()

    return {
        "total_attempts": total_attempts,
        "success": success_count,
        "failure": failure_count,
        "replay_attacks": replay_count,
        "signature_failures": signature_failures,
        "active_sessions": active_sessions
    }