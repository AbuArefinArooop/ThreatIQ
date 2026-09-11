# ThreatIQ v4.1 — Getting Started

**Start here.** This is the one document you need to deploy and run the whole project. Everything else in the repo (`README.md`, `SETUP.md`, `DEPLOYMENT.md`, the `CHANGELOG_*.md` files, and `docs/`) is reference material this guide links out to when you need more depth — you shouldn't need to read them front-to-back just to get the platform running.

---

## 1. What you have

A CTI aggregation platform (FastAPI + Celery + PostgreSQL + Redis) that:

- Ingests from **MISP, CIRCL, OTX/AlienVault, and Wazuh SIEM** through one uniform connector interface
- Classifies indicators with four ML models (Random Forest / Gradient Boosting / Logistic Regression / Decision Tree) behind an overfitting gate
- Predicts adversary→technique relationships with a pure-NumPy Graph Attention Network trained on MITRE ATT&CK
- Publishes its own output back out as **MISP events**, **STIX 2.1 bundles**, and **MITRE ATT&CK Navigator layers**
- Boosts confidence when the same indicator is independently confirmed by multiple sources
- Ships with 100 passing automated tests and a defense-in-depth security layer (JWT, RBAC, rate limiting, TLP-aware access control)

```
ThreatIQ/
├── GETTING_STARTED.md          ← you are here
├── README.md                    Full architecture reference, API table
├── SETUP.md                     Detailed manual (non-Docker) setup
├── DEPLOYMENT.md                Detailed Docker deployment + troubleshooting
├── CHANGELOG_OTX_MIGRATION.md   History: FS-ISAC → OTX migration
├── CHANGELOG_BUGFIX_PASS.md     History: dependency/bugfix pass
├── CHANGELOG_SIEM_AND_CTI_STANDARDS.md   History: this pass (SIEM, STIX, Navigator, correlation)
├── docs/
│   ├── ThreatIQ_v4_Research_Paper_IEEE.tex/.pdf   The research paper (compiles clean)
│   ├── ThreatIQ_v4.1_SIEM_CTI_Extension.pptx      Presentation deck for this pass
│   └── DEMO_SCRIPT.md                              Timed live-demo walkthrough
├── app/                          Application source
├── tests/test_all.py             100 tests
├── docker-compose.yml             Core stack: postgres + redis + api + worker + beat
├── docker-compose.wazuh.yml       Optional: Wazuh SIEM stack (manager+indexer+dashboard)
└── requirements.txt
```

---

## 2. Prerequisites

| Need | Why |
|---|---|
| Docker + Docker Compose | Runs the whole stack without touching your host Python |
| Python 3.11+ (only if running without Docker) | See §6 |
| A free OTX API key *(optional)* | For live (non-synthetic) OTX data — https://otx.alienvault.com |
| A MISP instance *(optional)* | For live MISP pull, and for the MISP-export/SIEM-loop features |
| A Wazuh deployment *(optional)* | For live SIEM alert ingestion — see §5 |

**None of the optional items are required to run the platform.** Every connector has an offline-fallback mode with curated sample data, so the full pipeline — classification, GAT training, STIX/Navigator export, correlation — works out of the box with zero credentials.

---

## 3. Fastest path: Docker Compose (recommended)

```bash
cd ThreatIQ
cp .env.template .env        # edit if you have real credentials; safe to leave blank
docker compose up -d
```

Wait ~15 seconds for the Postgres/Redis healthchecks, then confirm:

```bash
curl http://localhost:8000/health
# {"status":"healthy","version":"4.0.0"}
```

Open **http://localhost:8000** in a browser — the full SPA (dashboard, IoC library, pipeline, attack graph, connectors, evaluation) is served there.

**Default logins** (dev only — see §8 before any real deployment):

| Username | Password | Role |
|---|---|---|
| `admin` | `ThreatIQ@Admin25!` | admin |
| `analyst` | `ThreatIQ@Analyst25!` | analyst |
| `viewer` | `ThreatIQ@Viewer25!` | viewer |

Tear down: `docker compose down` (add `-v` to also wipe the Postgres volume).

---

## 4. Verify it's actually working

```bash
# Log in
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ThreatIQ@Admin25!"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# Connector status — MISP/CIRCL/OTX/WAZUH/OpenCTI should all list, most "offline" until configured
curl -s http://localhost:8000/api/v1/connectors -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Run the full 4-stage pipeline (ingestion → classification → anomaly detection → GAT)
curl -s -X POST http://localhost:8000/api/v1/pipeline/run \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"n_records": 500, "sources": ["MISP","CIRCL","OTX","WAZUH","Synthetic"], "run_gat_training": true, "gat_epochs": 10}'

# Poll status until it reports "Done"
curl -s http://localhost:8000/api/v1/pipeline/status -H "Authorization: Bearer $TOKEN"
```

If all of that returns sensible JSON with no 500s, the platform is fully operational.

Run the automated test suite the same way it's verified in CI:

```bash
docker compose exec api pytest tests/ -v
# Expect: 100 passed
```

---

## 5. Adding the SIEM stack (optional)

Wazuh's stack (manager + indexer + dashboard) is heavier than everything else combined, so it's a separate compose overlay rather than bundled into the core stack:

```bash
# One-time: generate Wazuh's indexer certs (required before first boot)
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node && docker compose -f generate-indexer-certs.yml run --rm generator
cd ../..
cp -r wazuh-docker/single-node/config ThreatIQ/wazuh-config
cp -r wazuh-docker/single-node/config/wazuh_indexer_ssl_certs ThreatIQ/wazuh-config/

# Bring up both stacks together
cd ThreatIQ
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d
```

Wazuh dashboard: `https://localhost:8443` (default creds `admin` / whatever you set in `.env` for `WAZUH_API_PASSWORD`).

Without this step, `WAZUH_INDEXER_URL` stays unset in `.env` and the Wazuh connector runs in offline mode — the platform is fully usable either way.

---

## 6. Manual setup (no Docker)

```bash
cd ThreatIQ
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.template .env
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

PostgreSQL and Redis still need to be reachable (either via `docker compose up postgres redis -d` or your own local install) — see `SETUP.md` for the full non-Docker walkthrough including Alembic migrations.

---

## 7. Configuration reference

All settings live in `.env` (copy from `.env.template`). Every block below is optional — leave blank to use offline sample data for that source.

```bash
# CTI feed connectors
MISP_URL=                          MISP_API_KEY=
CIRCL_USERNAME=                    CIRCL_PASSWORD=       # public endpoints work with no auth at all
OTX_API_KEY=                       OTX_API_URL=https://otx.alienvault.com/api/v1

# SIEM integration (pull: Wazuh alerts in / push: reuses MISP_URL+MISP_API_KEY above)
WAZUH_INDEXER_URL=                 WAZUH_API_USERNAME=
WAZUH_API_PASSWORD=                WAZUH_VERIFY_SSL=true

# OpenCTI enrichment
OPENCTI_URL=                       OPENCTI_TOKEN=

# Core app
SECRET_KEY=                        # generate a real random string before any non-local use
POSTGRES_PASSWORD=                 # change from the default before any non-local use
```

---

## 8. Using the platform — a guided tour of every capability

All examples assume `$TOKEN` from §4.

| Capability | Call | Notes |
|---|---|---|
| Run the full pipeline | `POST /api/v1/pipeline/run` | 4 stages, admin/analyst |
| Manually pull one connector | `POST /api/v1/connectors/{name}/fetch` | `name` ∈ MISP / CIRCL / OTX / WAZUH; admin only |
| Cross-source correlation | `POST /api/v1/connectors/correlate` | Fetches all connectors, boosts confidence on matches; admin/analyst |
| Publish to MISP | `POST /api/v1/connectors/misp/export` | Pushes high-confidence IoCs out; admin only |
| Export IoCs as STIX 2.1 | `GET /api/v1/iocs/export/stix` | Any role, TLP-filtered |
| Export GAT predictions as ATT&CK Navigator layer | `GET /api/v1/graph/navigator-layer` | Any role — open the file at mitre-attack.github.io/attack-navigator |
| Retrain the GAT | `POST /api/v1/graph/train` | Admin only — **overwrites `model_artifacts/gat_weights.npz`** |
| Evaluate on real or synthetic data | `POST /api/v1/evaluation/run` | `dataset_type` ∈ synthetic / real_misp / real_circl / real_otx / real_wazuh / mixed |

Full endpoint reference with request/response shapes: `README.md` → *API Reference*.

**⚠️ Before you retrain the GAT:** doing so overwrites `model_artifacts/gat_weights.npz`. If you need to preserve a specific trained state (e.g. to match numbers reported in `docs/ThreatIQ_v4_Research_Paper_IEEE.pdf`), back that file up first, or restore it afterward with `git checkout -- model_artifacts/gat_weights.npz` if you're working from the included git history.

For a full narrated walkthrough of the SIEM/STIX/Navigator/correlation features specifically, see `docs/DEMO_SCRIPT.md`.

---

## 9. Before any real (non-local, non-demo) deployment

1. **Rotate credentials.** The default dev logins (§3) and `.env.template`'s placeholder `SECRET_KEY`/`POSTGRES_PASSWORD` are for local demo only.
2. **Check for stale secrets.** A prior version of this codebase shipped a live-looking API key hardcoded as a config default (see `CHANGELOG_SIEM_AND_CTI_STANDARDS.md` §0) — it's fixed in this package, but if you're merging this with a fork that predates the fix, re-run `grep -rnE "(api_key|password|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}" app/` before deploying.
3. **Wire up persistence.** The API route handlers currently use in-memory demo data; PostgreSQL and the SQLAlchemy schema exist and start successfully but aren't yet wired into the routes (see `README.md` → *Known Remaining Limitations*).
4. **Review TLP defaults and RBAC roles** in `app/core/security.py` against your organization's actual data-handling policy before exposing this beyond a local demo.

---

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| `pip install` fails | Make sure you're on the trimmed `requirements.txt` in this package — `torch`/`torch-geometric` were removed as confirmed-unused dead weight |
| `401 Unauthorized` | Missing/expired Bearer token — tokens last 24h |
| `403 Forbidden` | You're hitting an admin-only or admin/analyst-only route on a lower-privileged token — see the role column in §8's table |
| Wazuh containers won't start | You skipped the one-time cert-generation step in §5 |
| `WAZUH`/`MISP` correlate shows 0 corroborated observables | Expected in fully offline mode — each connector's sample data was authored independently, so no genuine overlaps exist until at least two sources are live against real infrastructure |
| ATT&CK Navigator layer comes back with 0 techniques | Expected with the small offline MITRE relationship sample the GAT ships trained on — see `README.md`'s Future Work section |

Full troubleshooting table (pre-dating this pass, still valid): `DEPLOYMENT.md` §10.

---

## 11. Where everything else lives

- **Deep architecture / full API reference** → `README.md`
- **Manual setup, migrations, load testing** → `SETUP.md`
- **Docker deployment details, live-verification results** → `DEPLOYMENT.md`
- **What changed and why, pass by pass** → the three `CHANGELOG_*.md` files, oldest to newest
- **The research paper** (compiles cleanly with `pdflatex`) → `docs/ThreatIQ_v4_Research_Paper_IEEE.tex` / `.pdf`
- **Presentation deck for this pass** → `docs/ThreatIQ_v4.1_SIEM_CTI_Extension.pptx`
- **Live demo script** → `docs/DEMO_SCRIPT.md`
