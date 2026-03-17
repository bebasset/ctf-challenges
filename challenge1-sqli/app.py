"""
CTF Challenge 1: "The Vault"
Category: Web - SQL Injection
Difficulty: Easy/Medium
"""

from flask import Flask, request, render_template_string, g
import sqlite3
import os

app = Flask(__name__)
DATABASE = "/tmp/vault.db"

FLAG = "SYR{sql_inj3ct10n_unl0cks_the_vault}"

# -- Database setup ----------------------------------------------------------

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            DROP TABLE IF EXISTS users;
            CREATE TABLE users (
                id       INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                role     TEXT NOT NULL DEFAULT 'user'
            );

            INSERT INTO users (username, password, role) VALUES
                ('alice',  'hunter2',        'user'),
                ('bob',    'ilovecats',      'user'),
                ('admin',  'sUp3rS3cr3tPw!', 'admin');

            DROP TABLE IF EXISTS secrets;
            CREATE TABLE secrets (
                id      INTEGER PRIMARY KEY,
                owner   TEXT NOT NULL,
                content TEXT NOT NULL
            );

            INSERT INTO secrets (owner, content) VALUES
                ('alice', 'My cat is named Whiskers.'),
                ('bob',   'I secretly like pineapple on pizza.'),
                ('admin', '""" + FLAG + """');
        """)
        db.commit()


# -- Routes ------------------------------------------------------------------

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>The Vault — Login</title>
  <style>
    body { font-family: monospace; background:#111; color:#0f0; display:flex;
           justify-content:center; align-items:center; height:100vh; margin:0; }
    .box { border:1px solid #0f0; padding:2rem; width:320px; }
    h2   { margin-top:0; }
    input { width:100%; background:#000; color:#0f0; border:1px solid #0f0;
            padding:.4rem; margin:.3rem 0 .8rem; box-sizing:border-box; }
    button { width:100%; background:#0f0; color:#000; border:none;
             padding:.5rem; cursor:pointer; font-weight:bold; }
    .err { color:#f44; margin-top:.5rem; }
    .hint { color:#555; font-size:.8rem; margin-top:1rem; }
  </style>
</head>
<body>
<div class="box">
  <h2>&#128274; The Vault</h2>
  <p>Only authorized personnel may access the vault contents.</p>
  <form method="POST" action="/login">
    <label>Username</label>
    <input name="username" autocomplete="off" />
    <label>Password</label>
    <input name="password" type="password" />
    <button type="submit">LOGIN</button>
  </form>
  {% if error %}<p class="err">{{ error }}</p>{% endif %}
  <p class="hint">Hint: the vault keeper never patches their software.</p>
</div>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>The Vault — Dashboard</title>
  <style>
    body { font-family: monospace; background:#111; color:#0f0; margin:2rem; }
    table { border-collapse:collapse; width:100%; }
    th,td { border:1px solid #0f0; padding:.4rem .8rem; text-align:left; }
    th { background:#001a00; }
    .flag { color:#ff0; font-weight:bold; }
    a { color:#0f0; }
  </style>
</head>
<body>
  <h2>&#128274; Welcome, {{ username }}!</h2>
  <p>Your role: <strong>{{ role }}</strong></p>
  <h3>Vault Secrets</h3>
  <table>
    <tr><th>#</th><th>Owner</th><th>Secret</th></tr>
    {% for row in secrets %}
    <tr>
      <td>{{ row[0] }}</td>
      <td>{{ row[1] }}</td>
      <td {% if 'SYR{' in row[2] %}class="flag"{% endif %}>{{ row[2] }}</td>
    </tr>
    {% endfor %}
  </table>
  <br><a href="/logout">Logout</a>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(LOGIN_PAGE, error=None)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABILITY: raw string interpolation into SQL — classic SQLi
    query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"

    db = get_db()
    try:
        cursor = db.execute(query)
        row = cursor.fetchone()
    except sqlite3.OperationalError as e:
        return render_template_string(LOGIN_PAGE, error=f"DB error: {e}")

    if row is None:
        return render_template_string(LOGIN_PAGE, error="Invalid credentials.")

    user_id, uname, role = row
    secrets = db.execute("SELECT id, owner, content FROM secrets").fetchall()
    return render_template_string(DASHBOARD_PAGE, username=uname, role=role, secrets=secrets)

@app.route("/logout")
def logout():
    return render_template_string(LOGIN_PAGE, error=None)


if __name__ == "__main__":
    init_db()
    print("[*] Vault initialized. Running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
