"""
CTF Challenge 1: "The Vault"
Category: Web - SQL Injection
Difficulty: Easy/Medium
"""

from flask import Flask, request, render_template_string, g, jsonify
import sqlite3

app = Flask(__name__)
DATABASE = "/tmp/vault.db"

FLAG = "cusectf{sql_inj3ct10n_unl0cks_the_vault}"

HINTS = [
    "The login form sends your input directly to a database query. What happens when you add unusual characters?",
    "SQL has special characters that change how a query is interpreted — try a single quote <code>'</code> in the username field and watch for errors.",
    "SQL comments (<code>--</code>) tell the database to ignore everything after them. What if the password check just... disappeared?",
]

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


# -- Pages -------------------------------------------------------------------

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>The Vault &mdash; SYR InfoSec CTF</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Courier New', monospace;
      background: #0d0d0d;
      color: #00ff41;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
    }

    /* ── top banner ── */
    .banner {
      position: fixed; top: 0; width: 100%;
      background: #0d0d0d;
      border-bottom: 1px solid #003300;
      padding: .6rem 1.5rem;
      display: flex; align-items: center; gap: 1rem;
      z-index: 10;
    }
    .banner .logo { color: #ff6600; font-weight: bold; font-size: 1rem; letter-spacing:.05em; }
    .banner .sep  { color: #333; }
    .banner .chname { font-size: .9rem; color: #aaa; }
    .banner .diff { margin-left:auto; font-size:.75rem;
                    border:1px solid #ff6600; color:#ff6600; padding:.1rem .5rem; }

    /* ── card ── */
    .card {
      background: #111;
      border: 1px solid #00ff41;
      padding: 2.5rem 2rem;
      width: 360px;
      box-shadow: 0 0 30px rgba(0,255,65,.08);
    }
    .card h2 { font-size: 1.3rem; margin-bottom: .4rem; }
    .card .subtitle { color: #555; font-size: .8rem; margin-bottom: 1.6rem; }

    label { display:block; font-size:.8rem; color:#aaa; margin-bottom:.25rem; }
    input {
      width: 100%; background: #000; color: #00ff41;
      border: 1px solid #003300; padding: .5rem;
      margin-bottom: 1rem; font-family: inherit; font-size: .9rem;
      transition: border-color .2s;
    }
    input:focus { outline: none; border-color: #00ff41; }
    button[type=submit] {
      width: 100%; background: #00ff41; color: #000;
      border: none; padding: .6rem; font-family: inherit;
      font-weight: bold; font-size: .95rem; cursor: pointer;
      transition: background .2s;
    }
    button[type=submit]:hover { background: #00cc33; }

    .err { color: #ff4444; font-size: .85rem; margin-top: .8rem; }

    /* ── hints panel ── */
    .hints-wrap { margin-top: 1.5rem; border-top: 1px solid #1a1a1a; padding-top: 1rem; }
    .hints-toggle {
      background: none; border: 1px solid #333; color: #555;
      font-family: inherit; font-size: .78rem; padding: .3rem .7rem;
      cursor: pointer; width: 100%; text-align: left;
      transition: border-color .2s, color .2s;
    }
    .hints-toggle:hover { border-color: #00ff41; color: #00ff41; }
    .hints-list { display: none; margin-top: .8rem; }
    .hints-list.open { display: block; }
    .hint-item {
      background: #0a0a0a; border-left: 2px solid #ff6600;
      padding: .5rem .75rem; margin-bottom: .5rem;
      font-size: .8rem; color: #ccc; line-height: 1.5;
    }
    .hint-item .num { color: #ff6600; font-weight: bold; margin-right: .4rem; }
    .hint-item.locked { border-left-color: #333; color: #444; font-style: italic; }
    .reveal-btn {
      background: none; border: none; color: #ff6600;
      font-family: inherit; font-size: .78rem; cursor: pointer;
      padding: 0; text-decoration: underline;
    }
  </style>
</head>
<body>

<div class="banner">
  <span class="logo">SYR InfoSec CTF</span>
  <span class="sep">|</span>
  <span class="chname">Challenge 1 &mdash; The Vault</span>
  <span class="diff">Easy / Medium</span>
</div>

<div class="card">
  <h2>&#128274; The Vault</h2>
  <p class="subtitle">Restricted access. Authorized personnel only.</p>

  <form method="POST" action="/login">
    <label>Username</label>
    <input name="username" autocomplete="off" spellcheck="false" />
    <label>Password</label>
    <input name="password" type="password" />
    <button type="submit">LOGIN</button>
  </form>

  {% if error %}<p class="err">&#9888; {{ error }}</p>{% endif %}

  <div class="hints-wrap">
    <button class="hints-toggle" onclick="toggleHints()">&#128161; Hints (click to expand)</button>
    <div class="hints-list" id="hintsList">
      <div class="hint-item" id="h1">
        <span class="num">H1</span> The login form sends your input directly to a database query. What happens when you add unusual characters?
      </div>
      <div class="hint-item locked" id="h2">
        <span class="num">H2</span>
        <span id="h2-text">&#128274; Locked &mdash; <button class="reveal-btn" onclick="reveal('h2')">reveal</button></span>
      </div>
      <div class="hint-item locked" id="h3">
        <span class="num">H3</span>
        <span id="h3-text">&#128274; Locked &mdash; <button class="reveal-btn" onclick="reveal('h3')">reveal</button></span>
      </div>
    </div>
  </div>
</div>

<script>
  const hintData = {
    h2: "SQL has special characters that change how a query is interpreted &mdash; try a single quote <code>'</code> in the username field and watch for errors.",
    h3: "SQL comments (<code>--</code>) tell the database to ignore everything after them. What if the password check just&hellip; disappeared?"
  };
  function toggleHints() {
    document.getElementById('hintsList').classList.toggle('open');
  }
  function reveal(id) {
    const el = document.getElementById(id);
    el.classList.remove('locked');
    document.getElementById(id + '-text').innerHTML =
      '<span class="num">' + id.toUpperCase().replace('H','H') + '</span>' + hintData[id];
  }
</script>
</body>
</html>
"""

DASHBOARD_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>The Vault &mdash; Dashboard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Courier New', monospace; background: #0d0d0d;
           color: #00ff41; padding: 5rem 2rem 2rem; }
    .banner {
      position: fixed; top: 0; width: 100%;
      background: #0d0d0d; border-bottom: 1px solid #003300;
      padding: .6rem 1.5rem; display: flex; align-items: center; gap: 1rem; z-index: 10;
    }
    .banner .logo  { color: #ff6600; font-weight: bold; }
    .banner .sep   { color: #333; }
    .banner .chname { font-size: .9rem; color: #aaa; }
    .banner a { margin-left: auto; font-size: .8rem; color: #555;
                text-decoration: none; border: 1px solid #333; padding: .2rem .6rem; }
    .banner a:hover { border-color: #00ff41; color: #00ff41; }
    .welcome { margin-bottom: 1.5rem; }
    .welcome h2 { font-size: 1.2rem; }
    .role { color: #ff6600; font-size: .85rem; margin-top: .3rem; }
    table { border-collapse: collapse; width: 100%; max-width: 800px; }
    th, td { border: 1px solid #1a3a1a; padding: .5rem 1rem; text-align: left; }
    th { background: #0a1a0a; color: #aaa; font-size: .8rem; text-transform: uppercase; }
    tr:hover td { background: #0a1a0a; }
    .flag { color: #ffff00; font-weight: bold; letter-spacing: .05em; }
    .section-title { font-size: .8rem; color: #aaa; text-transform: uppercase;
                     letter-spacing: .1em; margin: 1.5rem 0 .5rem; }
  </style>
</head>
<body>

<div class="banner">
  <span class="logo">SYR InfoSec CTF</span>
  <span class="sep">|</span>
  <span class="chname">The Vault &mdash; Dashboard</span>
  <a href="/logout">Logout</a>
</div>

<div class="welcome">
  <h2>&#128513; Access granted &mdash; welcome, {{ username }}</h2>
  <p class="role">Role: {{ role }}</p>
</div>

<p class="section-title">&#128196; Vault Contents</p>
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
    print("[*] The Vault running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
