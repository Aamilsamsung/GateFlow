# GateFlow — Hostel Leave & Gate Pass Platform

> **Prototype only — NOT safe for production or real student data.** This repository contains an early FastAPI backend with intentionally insecure demo-only identity headers. Do not deploy it to a public endpoint or use it for actual gate access.

GateFlow aims to support students, verified guardians, wardens, security staff and hostel administrators through an auditable digital leave process.

## Current scope

- Student submits a leave request
- Assigned parent account decides
- Warden approves where hostel policy requires it
- Security records exit and return with a demo token
- Audit records and tenant-filtered leave queries

**Important:** Parent-only approval is a *proposed policy* and must never bypass an institution's required warden approval without official authorization.

## Local development

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
# Set a long random local development secret:
# Linux/macOS: export GATEFLOW_DEMO_SECRET="change-me"
# Windows PowerShell: $env:GATEFLOW_DEMO_SECRET="change-me"
uvicorn app.main:app --reload --host 127.0.0.1
```

Visit http://127.0.0.1:8000/docs.

Demo authentication header: `X-Demo-Auth: pes:student:student1:<secret>`, where `<secret>` is the `GATEFLOW_DEMO_SECRET` environment variable. Roles: `student`, `parent`, `warden`, `security`, `admin`. This is **not real authentication** and must not be exposed publicly.

## Main API

| Method | Endpoint | Role |
| --- | --- | --- |
| GET | /health | Everyone |
| POST | /leaves | Student |
| GET | /leaves | Authenticated role (filtered by role/tenant) |
| POST | /leaves/{id}/parent-decision | Parent |
| POST | /leaves/{id}/warden-decision | Warden |
| GET | /leaves/{id}/pass | Student owner |
| POST | /gate/scan | Security |
| GET | /audit | Warden, admin |
| PUT | /policy | Admin (in-memory demo setting) |

## Before any pilot

Replace demo authentication with verified guardian enrollment, secure sessions and staff MFA. Implement persistent tenant policies, database migrations, transactional gate scans, expiring QR codes, privacy/retention controls, alerts, frontend, and a full automated security regression suite. Use dedicated PostgreSQL with verified tenant isolation. Get written hostel approval for deployment and leave policies.

PES is a **proposed** pilot, not an approved partner.
