# Digital Evidence Chain-of-Custody System

SWE 401 – Software Engineering, Fall 2026 · Abu Dhabi University
Instructor: Dr. Murad Al-Rajab

## Team members

| Name | Student ID | Main responsibility |
|---|---|---|
| Mohammed AlHammadi | 1094614 | Back end: authentication, hashing, audit log, database |

## Problem

Digital evidence (documents, images, logs, disk images) can be copied or changed without leaving obvious signs.
Many teams still keep evidence on shared drives and track custody in spreadsheets or paper forms, so they cannot
easily prove that a file is unchanged, that the custody record itself was not edited, or who handled the file and when.

## Key features

- **Role-based accounts** – Admin, Supervisor, Investigator, Auditor; account lock after 5 failed logins.
- **Case management** – create, search, filter and close cases (closed cases become read-only).
- **Evidence upload with SHA-256** – files are hashed in 64 KB chunks while they are saved; stored files are read-only.
- **Activity tracking** – every login, upload, view, download, transfer, verification and report export is logged.
- **Tamper-evident audit log** – each log entry stores the hash of the previous entry; “Verify whole chain” finds any edited or deleted entry.
- **Two-step custody transfer** – custody only changes when the receiving user accepts.
- **Integrity verification** – on demand and on a schedule (default every 60 minutes); a mismatch raises a High alert.
- **Unusual-activity alerts** – after-hours access, bulk downloads, failed integrity checks, repeated failed logins.
- **PDF chain-of-custody report** – evidence details, original hash, full custody history and chain status.

## Technologies

Python 3.11+ · Flask 3 · Flask-SQLAlchemy · Flask-Login · SQLite (default) or PostgreSQL ·
Jinja2 + Bootstrap 5 · hashlib (SHA-256) · ReportLab (PDF) · pytest

## Prerequisites

- Python 3.11 or newer and `pip`
- Git
- (Optional) PostgreSQL 14+ if you do not want to use the default SQLite file

## Installation

```bash
git clone https://github.com/mkalhammadi/swe401-evidence-chain-of-custody.git
cd swe401-evidence-chain-of-custody
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

Copy `.env.example` to `.env` (or export the variables in your shell). All values have safe defaults for local use.

| Variable | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | `change-me-in-production` | Flask session key – **change it** |
| `DATABASE_URL` | SQLite file in `instance/coc.db` | e.g. `postgresql+psycopg2://coc:coc@localhost:5432/coc` |
| `EVIDENCE_STORE` | `instance/evidence_store` | Folder for stored evidence files |
| `MAX_UPLOAD_MB` | `200` | Largest file allowed |
| `INTEGRITY_CHECK_INTERVAL_MIN` | `60` | Scheduled integrity check; `0` turns it off |
| `LOCAL_UTC_OFFSET_HOURS` | `4` | Local time zone for the after-hours rule (UAE = +4) |
| `WORK_HOURS_START` / `WORK_HOURS_END` | `7` / `19` | Working hours for the after-hours rule |
| `BULK_DOWNLOAD_LIMIT` / `BULK_DOWNLOAD_WINDOW_MIN` | `5` / `10` | Bulk-download rule |
| `FAILED_LOGIN_LIMIT` / `LOCKOUT_MINUTES` | `5` / `15` | Account lockout |

For PostgreSQL also run `pip install psycopg2-binary`.

## How to run

```bash
flask --app run init-db        # create tables
flask --app run seed-demo      # optional: demo users, 2 cases, 5 evidence files
flask --app run run            # open http://127.0.0.1:5000
```

Demo accounts (password for all: `Demo@12345`): `admin`, `supervisor`, `investigator`, `investigator2`, `auditor`.
To create a real admin instead: `flask --app run create-admin`.

Other commands:

```bash
flask --app run verify-all     # check every evidence file now
flask --app run verify-chain   # check the audit log hash chain
```

## How to test

```bash
pytest -v
```

24 automated tests (TC-01 … TC-24) cover login and lockout, role access, cases, upload hashing, activity logging,
integrity checks, tamper detection, transfers, audit-chain tampering, anomaly alerts, the PDF report and basic
performance. Each test name starts with the test-case ID used in the project report.

## Project structure

```
app/
  __init__.py          application factory, CSRF check, filters
  models.py            entity classes: User, Case, Evidence, CustodyEvent, Transfer, Alert
  routes/              boundary layer (Flask blueprints)
  services/            control layer: hashing, audit, evidence, integrity, transfer, anomaly, report
  templates/           Jinja2 pages
  static/css/          Bootstrap 5 + app styles
  cli.py, seed.py      command-line tools and demo data
tests/                 pytest suite
config.py              settings (environment variables)
run.py                 entry point
```

## Notes and limits

- The system shows that evidence and its history have not changed; it does not by itself make evidence legally admissible.
- Alerts are warnings for a person to review; the system never blocks users automatically (except login lockout).
- Use HTTPS (e.g. behind Nginx) and a strong `SECRET_KEY` for any real deployment.
