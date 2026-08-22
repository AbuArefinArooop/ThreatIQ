# ThreatIQ v4.0 -- Complete Setup Guide

## Quick Start (Development -- no credentials needed)

```bash
# 1. Clone and enter the project
cd threatiq_v4

# 2. Create virtual environment
python -m venv venv && source venv/bin/activate  # Windows: venv\\Scripts\\activate

# 3. Install dependencies
pip install fastapi uvicorn sqlalchemy asyncpg psycopg2-binary redis celery \
    alembic pydantic-settings scikit-learn numpy pandas networkx httpx

# 4. Copy env template
cp .env.template .env
# Edit .env to add credentials (optional -- works offline without them)

# 5. Start PostgreSQL + Redis (Docker)
docker compose up postgres redis -d

# 6. Run DB migrations
alembic upgrade head

# 7. Start the API server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 8. Open API docs
http://localhost:8000/docs
```

## Full Production Stack

```bash
docker compose --profile migrate up  # runs migrations first
docker compose up -d                 # starts all services
```

## Connecting Real CTI Feeds

### MISP
1. Sign up / set up a MISP instance: https://www.misp-project.org
2. Generate an API key: Administration > List Auth Keys
3. Add to .env: MISP_URL=https://your-misp.example.com  MISP_API_KEY=xxx

### CIRCL (Free, no registration for basic endpoints)
- No credentials needed for CVE lookup
- For authenticated feeds: register at https://www.circl.lu/services/misp/

### OTX / AlienVault (Free — no membership approval needed)
- Register at https://otx.alienvault.com (free account)
- Get your API key from https://otx.alienvault.com/api
- Add to .env: OTX_API_KEY=...  (OTX_API_URL defaults to the public API, no need to set it)

### OpenCTI Enrichment Connector
1. Install OpenCTI: https://docs.opencti.io
2. Create an API token in OpenCTI settings
3. Add to .env: OPENCTI_URL=http://localhost:8080  OPENCTI_TOKEN=xxx
4. ThreatIQ auto-registers as an enrichment connector

## Downloading MITRE ATT&CK STIX Bundle (for trained GAT)

```bash
mkdir -p data/mitre_attack
curl -L https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json \
  -o data/mitre_attack/enterprise-attack.json
```
Then set: MITRE_ATTACK_DATA_PATH=./data/mitre_attack/enterprise-attack.json

## Running the Trained GAT

```bash
# Via API (POST triggers background training):
curl -X POST http://localhost:8000/api/v1/graph/train?epochs=200

# Or directly:
python -c "
from app.ml.gat import GATTrainer
trainer = GATTrainer('./data/mitre_attack/enterprise-attack.json')
metrics = trainer.train(epochs=200)
trainer.save()
print(metrics)
"
```

## API Endpoints Summary

| Method | URL | Description |
|--------|-----|-------------|
| GET | /health | Health check |
| GET | /docs | Interactive API docs |
| GET | /api/v1/iocs | List/search IoCs |
| POST | /api/v1/pipeline/run | Run full 4-stage pipeline |
| GET | /api/v1/pipeline/status | Pipeline status |
| GET | /api/v1/graph | Graph stats + GAT predictions |
| POST | /api/v1/graph/train | Retrain GAT on MITRE ATT&CK |
| POST | /api/v1/feedback | Submit analyst RL correction |
| GET | /api/v1/connectors | Connector statuses |
| POST | /api/v1/connectors/{name}/fetch | Manual feed fetch |
| POST | /api/v1/connectors/opencti/enrich | OpenCTI enrichment test |
| POST | /api/v1/evaluation/run | Evaluate on real/synthetic data |
| GET | /api/v1/evaluation/gat | GAT link-prediction accuracy vs MITRE |

## Load Testing

`locustfile.py` at the project root covers every endpoint above with a
realistic, role-weighted traffic mix and is rate-limit-aware (the API's
token-bucket limiter is per-IP, so a local Locust run shares one bucket
across all simulated users — 429s under load are expected, not failures).

```bash
pip install locust   # already in requirements.txt

# Interactive UI at http://localhost:8089
locust -f locustfile.py --host http://localhost:8000

# Headless, 30 users ramping over 10s for 5 minutes, CSV output
mkdir -p results
locust -f locustfile.py --host http://localhost:8000 \
  --headless -u 30 -r 10 -t 5m --csv=results/threatiq_load
```

See `DEPLOYMENT.md` for the full guide, including expected output and
troubleshooting.
