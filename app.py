from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import hashlib
import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"  # used for session security


# ---------------------------
# DATABASE CONNECTION
# ---------------------------

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------
# CREATE TABLES (RUN ON START)
# ---------------------------

def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            login_time TEXT,
            status TEXT,
            reason TEXT
        )
    """)

    conn.commit()
    conn.close()


create_tables()


# ---------------------------
# HOME
# ---------------------------

@app.route('/')
def home():
    return render_template("home.html")


# ---------------------------
# REGISTER
# ---------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        created_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db_connection()

        try:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (username, email, password_hash, created_at)
            )
            conn.commit()
            return redirect('/login')

        except Exception as e:
            return f"Error: {e}"

        finally:
            conn.close()

    return render_template("register.html")



# ---------------------------
# LOGIN
# ---------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form['username'].strip()
        password = request.form['password'].strip()

        password_hash = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db_connection()

        try:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if user and user['password_hash'] == password_hash:

                session['username'] = username
                return redirect('/dashboard')

            else:
                return "Invalid login!"

        finally:
            conn.close()

    return render_template("login.html")


# ---------------------------
# DASHBOARD
# ---------------------------

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template("dashboard.html", username=session['username'])
    else:
        return redirect('/login')


# ---------------------------
# LOGOUT
# ---------------------------

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/')

# ---------------------------
# PRODUCTION
# ---------------------------

if __name__ == "__main__":
    from waitress import serve
    print("=" * 60)
    print("🚀 Server starting on http://localhost:8000")
    print("=" * 60)
    serve(app, host='0.0.0.0', port=8000, threads=4)
