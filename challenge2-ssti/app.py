"""
CTF Challenge 2: "The Report Engine"
Category: Web - Server-Side Template Injection (SSTI)
Difficulty: Medium
"""

from flask import Flask, request, render_template_string

app = Flask(__name__)

FLAG = "cusectf{j1nj4_t3mpl4t3s_4r3_n0t_a_sandbox}"

FLAG_PATH = "/tmp/flag.txt"
with open(FLAG_PATH, "w") as f:
    f.write(FLAG + "\n")

# -- Pages -------------------------------------------------------------------

HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>ReportEngine v1.0 &mdash; SYR InfoSec CTF</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Courier New', monospace;
      background: #0d0d12;
      color: #e0e0e0;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 4rem 1rem;
    }

    /* ── banner ── */
    .banner {
      position: fixed; top: 0; width: 100%;
      background: #0d0d12; border-bottom: 1px solid #1a1a2e;
      padding: .6rem 1.5rem;
      display: flex; align-items: center; gap: 1rem; z-index: 10;
    }
    .banner .logo  { color: #ff6600; font-weight: bold; font-size: 1rem; }
    .banner .sep   { color: #333; }
    .banner .chname { font-size: .9rem; color: #aaa; }
    .banner .diff  { margin-left: auto; font-size: .75rem;
                     border: 1px solid #e94560; color: #e94560; padding: .1rem .5rem; }

    /* ── card ── */
    .card {
      background: #13131f;
      border: 1px solid #e94560;
      padding: 2.5rem 2rem;
      width: 520px;
      max-width: 95vw;
      box-shadow: 0 0 40px rgba(233,69,96,.07);
    }
    .card h1 { font-size: 1.3rem; color: #e94560; margin-bottom: .3rem; }
    .card .subtitle { color: #555; font-size: .82rem; margin-bottom: 1.6rem; line-height: 1.5; }

    .input-row { display: flex; gap: .5rem; margin-bottom: .5rem; }
    input[type=text] {
      flex: 1; background: #0d0d12; color: #e0e0e0;
      border: 1px solid #2a2a3e; padding: .5rem;
      font-family: inherit; font-size: .9rem;
      transition: border-color .2s;
    }
    input[type=text]:focus { outline: none; border-color: #e94560; }
    button[type=submit] {
      background: #e94560; color: #fff; border: none;
      padding: .5rem 1.1rem; font-family: inherit;
      font-size: .9rem; cursor: pointer; transition: background .2s;
    }
    button[type=submit]:hover { background: #c73652; }

    .note { color: #555; font-size: .78rem; margin-bottom: 1.5rem; }
    .note code { color: #e94560; }

    /* ── hints ── */
    .hints-wrap { border-top: 1px solid #1a1a2e; padding-top: 1rem; }
    .hints-toggle {
      background: none; border: 1px solid #2a2a3e; color: #555;
      font-family: inherit; font-size: .78rem; padding: .3rem .7rem;
      cursor: pointer; width: 100%; text-align: left;
      transition: border-color .2s, color .2s;
    }
    .hints-toggle:hover { border-color: #e94560; color: #e0e0e0; }
    .hints-list { display: none; margin-top: .8rem; }
    .hints-list.open { display: block; }
    .hint-item {
      background: #0a0a14; border-left: 2px solid #ff6600;
      padding: .5rem .75rem; margin-bottom: .5rem;
      font-size: .8rem; color: #ccc; line-height: 1.5;
    }
    .hint-item .num { color: #ff6600; font-weight: bold; margin-right: .4rem; }
    .hint-item.locked { border-left-color: #2a2a3e; color: #444; font-style: italic; }
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
  <span class="chname">Challenge 2 &mdash; The Report Engine</span>
  <span class="diff">Medium</span>
</div>

<div class="card">
  <h1>&#128202; ReportEngine v1.0</h1>
  <p class="subtitle">Enter your name and the system will generate a personalized status report. Fast, dynamic, and fully customizable.</p>

  <form method="GET" action="/report">
    <div class="input-row">
      <input type="text" name="name" placeholder="Your name..." spellcheck="false" />
      <button type="submit">Generate</button>
    </div>
  </form>
  <p class="note">Try entering <code>Alice</code> to see a sample report.</p>

  <div class="hints-wrap">
    <button class="hints-toggle" onclick="toggleHints()">&#128161; Hints (click to expand)</button>
    <div class="hints-list" id="hintsList">
      <div class="hint-item" id="h1">
        <span class="num">H1</span> The app takes your name and puts it directly into a page. What if your "name" contained something the server shouldn't evaluate?
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
    h2: "Try submitting <code>{{7*7}}</code> as your name. If the page shows <strong>49</strong>, the server is evaluating your input as code.",
    h3: "Jinja2 templates have access to Python internals. Look into <code>lipsum.__globals__</code> &mdash; it might open some doors."
  };
  function toggleHints() {
    document.getElementById('hintsList').classList.toggle('open');
  }
  function reveal(id) {
    const el = document.getElementById(id);
    el.classList.remove('locked');
    document.getElementById(id + '-text').innerHTML = hintData[id];
  }
</script>
</body>
</html>
"""

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Report &mdash; SYR InfoSec CTF</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Courier New', monospace; background: #0d0d12; color: #e0e0e0;
      padding: 5rem 2rem 2rem;
    }
    .banner {
      position: fixed; top: 0; width: 100%;
      background: #0d0d12; border-bottom: 1px solid #1a1a2e;
      padding: .6rem 1.5rem; display: flex; align-items: center; gap: 1rem; z-index: 10;
    }
    .banner .logo  { color: #ff6600; font-weight: bold; }
    .banner .sep   { color: #333; }
    .banner .chname { font-size: .9rem; color: #aaa; }
    .banner a { margin-left: auto; font-size: .8rem; color: #555;
                text-decoration: none; border: 1px solid #2a2a3e; padding: .2rem .6rem; }
    .banner a:hover { border-color: #e94560; color: #e0e0e0; }
    .card {
      background: #13131f; border: 1px solid #2a2a3e;
      padding: 1.5rem; max-width: 600px; margin-bottom: 1rem;
    }
    .card .field { margin-bottom: .5rem; font-size: .9rem; }
    .card .label { color: #555; font-size: .75rem; text-transform: uppercase;
                   letter-spacing: .08em; margin-bottom: .1rem; }
    .card .value { color: #e0e0e0; }
    h2 { color: #e94560; font-size: 1.2rem; margin-bottom: 1.2rem; }
  </style>
</head>
<body>

<div class="banner">
  <span class="logo">SYR InfoSec CTF</span>
  <span class="sep">|</span>
  <span class="chname">The Report Engine</span>
  <a href="/">&#8592; Back</a>
</div>

<h2>&#128202; Status Report</h2>
<div class="card">
  <div class="field"><div class="label">Recipient</div><div class="value">""" + "{{ name }}" + """</div></div>
  <div class="field"><div class="label">Status</div><div class="value">Active</div></div>
  <div class="field"><div class="label">Clearance</div><div class="value">Level 1</div></div>
  <div class="field"><div class="label">Generated</div><div class="value">2026-03-17</div></div>
</div>

</body>
</html>
"""

@app.route("/")
def index():
    prefill = request.args.get("name", "")
    return render_template_string(HOME_PAGE, prefill=prefill)

@app.route("/report")
def report():
    name = request.args.get("name", "Anonymous")
    # VULNERABILITY: name is placed directly into the template string before rendering
    template = REPORT_TEMPLATE.replace("{{ name }}", name)
    return render_template_string(template)


if __name__ == "__main__":
    print("[*] ReportEngine running on http://0.0.0.0:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
