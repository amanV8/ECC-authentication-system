from flask import Flask, render_template, request, redirect, session
import hashlib
import datetime
import os

# ECC utilities
from auth.ecc_utils import (
    generate_keypair,
    generate_nonce,
    sign_nonce,
    verify_signature,
    derive_session_key
)

# Security modules
from auth.replay_protection import nonce_exists, store_nonce
from auth.auth_logger import log_event
from auth.metrics import get_security_metrics

# Database layer
from database import get_db, create_tables


# =====================================
# APP INITIALIZATION
# =====================================

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Create tables on startup
create_tables()


# =====================================
# HOME
# =====================================

@app.route('/')
def home():
    return render_template("home.html")


# =====================================
# REGISTER
# =====================================

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Generate ECC key pair
        private_pem, public_pem = generate_keypair()

        conn = get_db()

        conn.execute("""
            INSERT INTO users (username, email, password_hash, public_key, private_key)
            VALUES (?, ?, ?, ?, ?)
        """, (username, email, password_hash, public_pem, private_pem))

        conn.commit()
        conn.close()

        return redirect('/login')

    return render_template("register.html")


# =====================================
# LOGIN
# =====================================

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db()

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        # STEP 1: PASSWORD VALIDATION
        if not user or user['password_hash'] != password_hash:
            log_event(username, "FAILURE", "Invalid Credentials", request.remote_addr)
            conn.close()
            return "Invalid Credentials"

        print("\n=== ECC AUTHENTICATION TRACE ===")

        # STEP 2: GENERATE NONCE
        nonce = generate_nonce()
       # nonce = bytes.fromhex("7e0d6caa9f3d269afabdf2d1ca19782a")

        # STEP 3: REPLAY PROTECTION
        if nonce_exists(username, nonce):
            log_event(username, "FAILURE", "Replay Attack Detected", request.remote_addr)
            conn.close()
            return "Replay Attack Detected - Connection Terminated"

        store_nonce(username, nonce)
        print("2. Nonce Stored for Replay Protection")

        # STEP 4: SIGN NONCE
        signature = sign_nonce(user['private_key'], nonce)
        print("3. Nonce Signed with Private Key")

        

        # STEP 5: VERIFY SIGNATURE
        try:
            verify_signature(user['public_key'], signature, nonce)
            print("4. Signature Verified Successfully")
        except Exception:
            log_event(username, "FAILURE", "Signature Verification Failed", request.remote_addr)
            conn.close()
            return "Authentication Failed"

        # STEP 6: DERIVE SESSION KEY
        session_key = derive_session_key(user['public_key'])
        print("5. Secure Session Key Established")

        # STEP 7: GENERATE TOKEN
        timestamp = datetime.datetime.now()
        expiry = timestamp + datetime.timedelta(minutes=5)

        token_raw = session_key + username + str(timestamp)
        token = hashlib.sha256(token_raw.encode()).hexdigest()

        print("6. Time-Bound Session Token Generated")
        print("7. Expiry Set to:", expiry)
        print("=== AUTHENTICATION SUCCESS ===\n")

        # STEP 8: STORE SESSION
        ip_address = request.remote_addr

        conn.execute("""
            INSERT INTO sessions (username, token, expiry, ip_address)
            VALUES (?, ?, ?, ?)
        """, (username, token, expiry.isoformat(), ip_address))

        conn.commit()
        conn.close()

        session['username'] = username
        session['token'] = token

        # STEP 9: LOG SUCCESS
        log_event(username, "SUCCESS", "Authentication Successful", ip_address)

        return redirect("/dashboard")

    return render_template("login.html")


# =====================================
# DASHBOARD
# =====================================

@app.route('/dashboard')
def dashboard():

    token = session.get('token')
    username = session.get('username')

    if not token:
        return redirect('/login')

    conn = get_db()

    record = conn.execute(
        "SELECT * FROM sessions WHERE token = ?",
        (token,)
    ).fetchone()

    if not record:
        conn.close()
        return "Invalid Session"

    # EXPIRY CHECK
    expiry = datetime.datetime.fromisoformat(record['expiry'])

    if datetime.datetime.now() > expiry:
        conn.close()
        return "Session Expired"

    # IP BINDING CHECK
    current_ip = request.remote_addr

    if record['ip_address'] != current_ip:
        conn.close()
        return "Session Hijacking Detected"

    conn.close()

    return render_template("dashboard.html", username=username)


# =====================================
# SECURITY METRICS
# =====================================

@app.route('/admin/security')
def security_dashboard():

    metrics = get_security_metrics()

    return render_template(
        "security_metrics.html",
        metrics=metrics
    )


# =====================================
# SECURITY LOGS
# =====================================

@app.route('/admin/logs')
def view_logs():

    conn = get_db()

    logs = conn.execute("""
        SELECT username, timestamp, status, reason, ip_address
        FROM login_logs
        ORDER BY timestamp DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    return render_template("security_logs.html", logs=logs)


# =====================================
# LOGOUT
# =====================================

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


# =====================================
# RUN SERVER
# =====================================

if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=8000)
