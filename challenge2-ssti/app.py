"""
CTF Challenge 2: "The Report Engine"
Category: Web - Server-Side Template Injection (SSTI)
Difficulty: Medium
"""

from flask import Flask, request, render_template_string
import subprocess, os

app = Flask(__name__)

FLAG = "SYR{j1nj4_t3mpl4t3s_4r3_n0t_a_sandbox}"

# Write flag to a file that the SSTI payload can read
FLAG_PATH = "/tmp/flag.txt"
with open(FLAG_PATH, "w") as f:
    f.write(FLAG + "\n")

# -- Pages -------------------------------------------------------------------

HOME_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>ReportEngine v1.0</title>
  <style>
    body  { font-family: monospace; background:#1a1a2e; color:#eee; margin:2rem auto;
            max-width:700px; }
    h1    { color:#e94560; }
    input[type=text] { width:80%; background:#16213e; color:#eee; border:1px solid #e94560;
                        padding:.5rem; font-family:monospace; }
    button { background:#e94560; color:#fff; border:none; padding:.5rem 1rem;
             cursor:pointer; font-family:monospace; }
    .output { background:#0f3460; padding:1rem; margin-top:1rem; min-height:2rem;
              white-space:pre-wrap; word-break:break-all; }
    .note   { color:#aaa; font-size:.85rem; margin-top:.5rem; }
  </style>
</head>
<body>
  <h1>&#128202; ReportEngine v1.0</h1>
  <p>Enter a name below and we'll generate a personalized status report for you.</p>
  <form method="GET" action="/report">
    <input type="text" name="name" placeholder="Your name..." value="{{ prefill }}" />
    <button type="submit">Generate Report</button>
  </form>
  <p class="note">Example: try entering <code>Alice</code> to see your report.</p>
</body>
</html>
"""

# VULNERABILITY: user-supplied `name` is injected directly into a Jinja2 template string
REPORT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
  <title>Report for """ + "{{ name }}" + """</title>
  <style>
    body  { font-family: monospace; background:#1a1a2e; color:#eee; margin:2rem auto;
            max-width:700px; }
    h1    { color:#e94560; }
    .card { background:#16213e; border:1px solid #0f3460; padding:1rem; margin:.5rem 0; }
    .output { background:#0f3460; padding:1rem; margin-top:1rem; white-space:pre-wrap;
              word-break:break-all; }
    a { color:#e94560; }
  </style>
</head>
<body>
  <h1>&#128202; Status Report</h1>
  <div class="card">
    <strong>Recipient:</strong> """ + "{{ name }}" + """<br>
    <strong>Status:</strong> Active<br>
    <strong>Clearance:</strong> Level 1<br>
    <strong>Generated:</strong> 2026-03-17
  </div>
  <p><a href="/">&#8592; Generate another report</a></p>
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
    # An attacker can inject Jinja2 expressions like {{ 7*7 }} or config/class chains
    template = REPORT_TEMPLATE.replace("{{ name }}", name)
    return render_template_string(template)


if __name__ == "__main__":
    print("[*] ReportEngine running on http://0.0.0.0:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
