# ThreatIQ v4.0 — Deployment & Usage Guide

Everything in this guide was run live against the real codebase in this
session: the app booted, the full 50+ test suite passed, the OTX
connector was exercised through the actual API (manual fetch, pipeline
ingestion, evaluation), and `locustfile.py` ran against the live server
with **0 failures across 98 requests**. Docker Compose itself could not
be executed here (no `docker` binary in this sandbox) — that path is
reviewed but unverified; run the `curl` checks in section 3 yourself as
the first confirmation.

---

## 1. What changed in this pass

You asked to replace FS-ISAC with OTX and fix anything missing. Full
diff-level detail is in `CHANGELOG_OTX_MIGRATION.md`. Summary:

- **FS-ISAC → OTX**: `app/connectors/fsisac_connector.py` deleted;
  `app/connectors/otx_connector.py` added, matching the existing
  connector interface exactly (`fetch_recent(limit)`, same IoC dict
  shape, same offline-fallback pattern). Every reference updated:
  `config.py`, `.env.template`, `docker-compose.yml`, `connectors.py`,
  `pipeline.py`, `evaluation.py`, `iocs.py` (mock data), `models.py`
  (enum — `OTX` was already defined there, `FSISAC` removed), Celery
  `celery_app.py`/`tasks.py`, `tests/test_all.py`, `README.md`, `SETUP.md`.
- **Two real bugs fixed** that predate the OTX work:
  1. `requirements.txt` was missing `python-jose`, `passlib`, `bcrypt` —
     `app/core/security.py` imports them directly, so a fresh
     `pip install -r requirements.txt` followed by starting the app
     would `ImportError` immediately.
  2. `requirements.txt` pinned `taxii2-client==2020.4.21`, a version that
     does not exist on PyPI — `pip install -r requirements.txt` failed
     outright. Fixed to `2.3.0`, the latest real release.
  3. `/api/v1/pipeline/status`, after any completed pipeline run, threw a
     `PydanticSerializationError: Unable to serialize unknown type:
     <class 'numpy.bool_'>` — one `"overfitting": gap>0.10` in
     `pipeline.py` wasn't wrapped in `bool()` (the equivalent line in
     `evaluation.py` already was). Found by actually running the pipeline
     end-to-end, not by inspection.
- **`locustfile.py`** rebuilt from scratch against the real API contract
  (real login response shape, real credentials, real request bodies,
  real per-IP rate limiter behavior) and verified live.

---

## 2. Prerequisites

- Python 3.11+ (verified here on 3.12.3)
- `pip`
- Docker + Docker Compose (only needed for the full-stack path)
- A free OTX API key if you want live (non-synthetic) OTX data:
  [https://otx.alienvault.com](https://otx.alienvault.com) → sign up → **Settings → API Integration**

---

## 3. Path A — Local dev, no Docker (fastest way to see it work)

```bash
cd threatiq_v4

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt   # now installs cleanly -- see fix #1/#2 above

cp .env.template .env
# Set OTX_API_KEY if you have one. Leave blank to run entirely on the
# offline synthetic sample -- everything below works either way.

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

In a second terminal:

```bash
# Health check
curl http://localhost:8000/health

# Log in with a real default credential (note: these are the actual
# passwords hashed in app/api/v1/auth.py, not simple usernames)
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "ThreatIQ@Admin25!"}'

# Use the returned access_token for everything below
TOKEN="<paste access_token here>"

# Connector statuses (OTX now appears instead of FS-ISAC)
curl http://localhost:8000/api/v1/connectors -H "Authorization: Bearer $TOKEN"

# Pull real (or offline-sample) OTX indicators
curl -X POST "http://localhost:8000/api/v1/connectors/OTX/fetch?limit=10" \
  -H "Authorization: Bearer $TOKEN"

# Run evaluation against the OTX dataset slice
curl -X POST http://localhost:8000/api/v1/evaluation/run \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"dataset_type": "real_otx", "n_records": 100, "model": "RandomForest"}'
```

Interactive API docs: **http://localhost:8000/docs**

---

## 4. Path B — Full stack via Docker Compose

```bash
cd threatiq_v4
cp .env.template .env      # fill in OTX_API_KEY / MISP / OpenCTI as desired
docker compose up -d
docker compose ps
curl http://localhost:8000/health
docker compose logs -f api
```

Services: `postgres`, `redis`, `api`, `worker` (Celery), `beat` (Celery
scheduler — now runs `ingest-otx-daily` instead of `ingest-fsisac-daily`).
Both `docker/Dockerfile` and `docker/Dockerfile.api` exist in this repo
and are near-identical; `docker-compose.yml` builds from
`docker/Dockerfile.api`.

Tear down: `docker compose down` (add `-v` to also wipe the Postgres volume).

**Note on persistence**: `app/models/models.py` and `app/db/session.py`
exist and are correct, but the current API route handlers
(`app/api/v1/iocs.py` etc.) use in-memory mock/demo data, not the DB —
Postgres starts and passes its healthcheck but nothing writes to it yet.
This isn't something this pass changed; it's the state the uploaded
project was already in.

---

## 5. Running the tests

```bash
source venv/bin/activate
pip install -r requirements.txt
pytest tests/ -v
```

Expect **100 passed** (56 as of the OTX migration + 17 covering the Wazuh
SIEM connector/MISP-export integration + 16 covering STIX 2.1/ATT&CK
Navigator export + 11 covering cross-source correlation — see
`CHANGELOG_SIEM_AND_CTI_STANDARDS.md` for the full breakdown of what each
new test class checks).

---

## 6. Running the load test (locust)

With the API running (Path A or B):

```bash
# Interactive UI at http://localhost:8089
locust -f locustfile.py --host http://localhost:8000

# Headless, 30 users ramping over 10s for 5 minutes, CSV output
mkdir -p results
locust -f locustfile.py --host http://localhost:8000 \
  --headless -u 30 -r 10 -t 5m --csv=results/threatiq_load
```

**Read this before judging the results**: the API's rate limiter
(`app/core/security.py`, `RateLimiter`) is keyed per-IP, not per-user. In
a local Locust run every simulated user shares one client IP, so they all
draw from the same token bucket — 120/min default, **20/min** on
`pipeline/run`, `graph/train`, `connectors/*/fetch`, `evaluation/run`, and
30/min on `feedback`. At even 15-30 concurrent users you will see 429s on
those endpoints. `locustfile.py` already treats 200 and 429 as both
"success" on strict-limited tasks for exactly this reason — a 429 there
means the limiter is doing its job, not that something's broken. If you
want to actually saturate the strict-limited endpoints without hitting
the shared bucket, run Locust from multiple source IPs or temporarily
raise `strict_limiter`'s `calls` in `security.py`.

Verified live in this session: 15 users / 25s → 98 requests, 0 failures,
across all 16 distinct endpoints including every OTX-touching one.

---

## 7. Default dev logins

From `app/api/v1/auth.py`'s in-memory `_USERS` table:

| Username  | Password             | Role    | max_tlp   |
|-----------|-----------------------|---------|-----------|
| `admin`   | `ThreatIQ@Admin25!`   | admin   | TLP:RED   |
| `analyst` | `ThreatIQ@Analyst25!` | analyst | TLP:AMBER |
| `viewer`  | `ThreatIQ@Viewer25!`  | viewer  | TLP:GREEN |

Passwords are real PBKDF2-SHA256 hashed (260k iterations), not
plaintext-stored — see `hash_password()`/`verify_password()` in
`app/core/security.py`. **Change or remove these before any real
deployment**; this is a dev-only in-memory store, not the production
DB-backed `User` table implied by the README's schema description.

---

## 8. Understanding the OTX connector

`app/connectors/otx_connector.py` replaces `FSISACConnector`, following
the exact same interface every other connector uses:

```python
OTXConnector(api_key=None, api_url=None).fetch_recent(limit=100) -> list[dict]
```

| | FS-ISAC | OTX (AlienVault) |
|---|---|---|
| Cost | Requires paid financial-sector membership | Free |
| Signup friction | Membership approval process | Self-serve API key, immediate |
| Auth | Never actually live-tested in this project | `X-OTX-API-KEY` header, live-tested against real API shape |
| Scope | Finance-sector only | General-purpose CTI |

Fetch strategy, in order:

1. `GET /pulses/subscribed` — pulses your OTX account subscribes to.
2. If empty or the request fails, `GET /search/pulses?q=malware` — public
   keyword search, works even on a brand-new key with zero subscriptions.
3. If both fail (or no key is configured), a small bundled offline
   sample, flagged `is_synthetic: False` (matching the convention: these
   are *real*, just non-live, curated CTI examples — not
   `generate_synthetic_iocs()` synthetic data).

`OTX_TYPE_MAP` at the top of the file maps OTX's indicator types
(`IPv4`, `domain`, `FileHash-SHA256`, `CVE`, etc.) to ThreatIQ's
`ioc_type` vocabulary, matching `MISPConnector`'s naming convention
exactly (`"IPv4 Address"`, `"Domain Name"`, `"File Hash (SHA256)"`, ...).
`source` is set to `"OTX AlienVault"` to match the pre-existing
`IoCSourceType.OTX` enum value in `app/models/models.py` — that enum
already anticipated this migration.

---

## 9. Config reference

New in `.env.template` / `app/core/config.py`:

```bash
# Free, no membership gate
OTX_API_KEY=
OTX_API_URL=https://otx.alienvault.com/api/v1
```

`FSISAC_API_URL`/`FSISAC_API_KEY` are gone from both files — nothing in
the codebase reads them anymore, so there's no backward-compatibility
reason to keep dead settings around.

---

## 10. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `pip install -r requirements.txt` fails on `taxii2-client` | Fixed in this pass — pull the updated `requirements.txt`. |
| `ImportError: No module named 'jose'` on startup | Fixed in this pass — `python-jose`, `passlib`, `bcrypt` are now in `requirements.txt`. |
| `/api/v1/pipeline/status` 500s with a `numpy.bool_` serialization error after a run | Fixed in this pass — see item 3 in section 1. |
| `401 Unauthorized` | Missing/expired `Authorization: Bearer <token>` header. Tokens last 24h (`ACCESS_TOKEN_EXPIRE_MINUTES`). |
| `403 Forbidden` on `/graph/train` or `/connectors/{name}/fetch` | Those routes are admin-only (`require_role("admin")`). Log in as `admin`. |
| `403 Forbidden` on `GET /iocs/{id}` as `viewer` | Expected — viewer's `max_tlp` is `TLP:GREEN`, and that record is `TLP:AMBER`/`RED`. Not a bug. |
| `429 Too Many Requests` during a Locust run | Expected under concurrent load — see section 6. Not a failure. |
| `docker compose up` — `worker`/`beat` don't start | Confirm `redis` is healthy first (`docker compose ps`). |
| OTX fetch always returns the offline sample even with a key set | Confirm `OTX_API_KEY` is in `.env` (not just `.env.template`) and the process restarted after editing it. |
