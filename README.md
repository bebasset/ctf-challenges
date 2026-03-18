# SYR InfoSec CTF — Web Challenges

Two self-contained web application CTF challenges built for the **Syracuse University Information Security Club**.

| # | Name | Vulnerability | Difficulty | Port |
|---|------|--------------|------------|------|
| 1 | The Vault | SQL Injection | Easy/Medium | 5000 |
| 2 | The Report Engine | Server-Side Template Injection (SSTI) | Medium | 5001 |

---

## Hosting with Docker (recommended)

### Requirements
- Docker
- Docker Compose

### Run both challenges

```bash
git clone https://github.com/bebasset/ctf-challenges.git
cd ctf-challenges
docker compose up --build
```

| Challenge | URL |
|-----------|-----|
| The Vault (SQLi) | http://localhost:5000 |
| The Report Engine (SSTI) | http://localhost:5001 |

### Run a single challenge

```bash
docker compose up --build the-vault        # Challenge 1 only
docker compose up --build report-engine    # Challenge 2 only
```

### Stop everything

```bash
docker compose down
```

---

## Running without Docker

```bash
pip install flask

# Challenge 1
cd challenge1-sqli && python app.py

# Challenge 2
cd challenge2-ssti && python app.py
```

---

## Challenge Summaries

### Challenge 1 — The Vault (SQL Injection)
A corporate login portal where the SQL query is built via raw string interpolation. Players must bypass authentication and retrieve the admin's secret from the database.

### Challenge 2 — The Report Engine (SSTI)
A Flask report generator that inserts user input directly into a Jinja2 template string before rendering. Players must identify the injection point and leverage Python's object model to read the flag from the server.

---

## For Challenge Authors

Each challenge directory contains a `README.md` with the full solution, payload walkthrough, and learning objectives.

---

*Syracuse University Information Security Club*
