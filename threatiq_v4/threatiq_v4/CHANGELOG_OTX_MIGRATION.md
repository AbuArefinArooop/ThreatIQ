# Changelog — FS-ISAC → OTX Migration + Bug Fixes

Applied directly to the real codebase you uploaded (`threatiq_v4.zip`).
Every change below was verified: full test suite run (56/56 passing),
live server boot, live curl checks against every touched endpoint, and a
live Locust run (98 requests, 0 failures).

## Files added

- `app/connectors/otx_connector.py` — new `OTXConnector` class, same
  interface as `MISPConnector`/`CIRCLConnector`
  (`fetch_recent(limit) -> list[dict]`, same IoC dict shape: `external_id`,
  `text`, `label`, `severity`, `severity_label`, `confidence`, `source`,
  `source_trust`, `ioc_value`, `ioc_type`, `tlp`, `is_synthetic`,
  `raw_payload`). Offline fallback + live fetch (subscribed pulses, then
  public pulse search) implemented and tested.
- `locustfile.py` — full load test covering every `/api/v1/*` endpoint,
  rebuilt from scratch against this repo's actual API contract.
- `DEPLOYMENT.md` — deploy/run/test guide.
- `CHANGELOG_OTX_MIGRATION.md` — this file.

## Files removed

- `app/connectors/fsisac_connector.py` — retired, replaced by
  `otx_connector.py`.

## Files modified

| File | Change |
|---|---|
| `app/core/config.py` | Removed `FSISAC_API_URL`/`FSISAC_API_KEY`; added `OTX_API_KEY`/`OTX_API_URL`. |
| `.env.template` | Same swap, plus a comment pointing at the free OTX signup URL. |
| `docker-compose.yml` | `api` and `worker` service env blocks: `FSISAC_API_URL`/`FSISAC_API_KEY` → `OTX_API_KEY`/`OTX_API_URL`. |
| `app/api/v1/connectors.py` | Status list: `"FS-ISAC"` entry → `"OTX"`. Manual-fetch dispatch: `elif name == "FS-ISAC"` branch → `elif name == "OTX"`, now instantiating `OTXConnector`. |
| `app/api/v1/pipeline.py` | Default `sources` list and the `allowed` validator set: `"FS-ISAC"` → `"OTX"`. Stage-1 ingestion block now calls `OTXConnector(settings.OTX_API_KEY, settings.OTX_API_URL)`. **Also fixed**: `"overfitting": gap>0.10` → `"overfitting": bool(gap>0.10)` (pre-existing bug, see below). |
| `app/api/v1/evaluation.py` | Allowed `dataset_type` set: `"real_fsisac"` → `"real_otx"`. Branch now instantiates `OTXConnector`. |
| `app/api/v1/iocs.py` | Mock/demo `source` rotation: `"FS-ISAC"` → `"OTX AlienVault"`. |
| `app/models/models.py` | Removed `FSISAC = "FS-ISAC"` from `IoCSourceType`. **Not added**: `OTX = "OTX AlienVault"` was already present in this enum before this session — the schema had already anticipated this migration. |
| `app/workers/celery_app.py` | Docstring + beat schedule: `ingest-fsisac-daily` / `app.workers.tasks.ingest_fsisac` → `ingest-otx-daily` / `app.workers.tasks.ingest_otx`. |
| `app/workers/tasks.py` | `ingest_fsisac` task → `ingest_otx` task, same retry/backoff shape, now calling `OTXConnector`. |
| `tests/test_all.py` | `TestFSISACConnector` (2 tests) → `TestOTXConnector` (7 tests), matching the file's existing per-connector test style. |
| `requirements.txt` | **Bug fix**: added `python-jose[cryptography]`, `passlib[bcrypt]`, `bcrypt` — `app/core/security.py` imports these directly and there was no working install path without them. **Bug fix**: `taxii2-client==2020.4.21` (nonexistent version, `pip install` failed outright) → `taxii2-client==2.3.0` (latest real release). Also added `respx`, `locust` for testing/load-testing. |
| `README.md` | Quick-start comment, gap-closure table, architecture tree, and known-limitations section: FS-ISAC references → OTX. Load-testing limitation note updated to reflect the new `locustfile.py` and what it has/hasn't validated. |
| `SETUP.md` | FS-ISAC credentials section → OTX (free signup, no membership approval). Added a "Load Testing" section. |

## Bugs found and fixed that predate the OTX work

These were caught by actually running the app end-to-end, not by static
review — they'd affect the codebase regardless of the FS-ISAC/OTX swap.

1. **`requirements.txt` missing auth dependencies.** `app/core/security.py`
   does `from jose import JWTError, jwt` and
   `from passlib.context import CryptContext` at module level. Neither
   `python-jose` nor `passlib` (nor `bcrypt`, which `passlib[bcrypt]`
   needs) were in `requirements.txt`. A fresh
   `pip install -r requirements.txt && uvicorn app.main:app` would
   `ImportError` before the app even started.

2. **`taxii2-client==2020.4.21` does not exist on PyPI.** The actual
   published versions top out at `2.3.0` (confirmed via `pip install`
   against the real index). This made `pip install -r requirements.txt`
   fail outright, not just at import time — nothing else in the file
   would install either, since pip aborts the whole batch. Fixed to `2.3.0`.

3. **`/api/v1/pipeline/status` crashed after any completed pipeline run.**
   `app/api/v1/pipeline.py`'s classification stage computed
   `"overfitting": gap>0.10` where `gap` is a `numpy.float64` (from
   `sklearn.metrics.f1_score`), so the comparison produces a
   `numpy.bool_` — a type Pydantic can't serialize. Every call to
   `GET /pipeline/status` after a run completed would 500 with
   `PydanticSerializationError: Unable to serialize unknown type:
   <class 'numpy.bool_'>`. The equivalent line in `evaluation.py` already
   correctly wraps this in `bool(...)`; `pipeline.py` didn't. Fixed to
   match. Verified by running a full pipeline (`MISP`, `CIRCL`, `OTX`,
   `Synthetic` sources, GAT training included) and polling status to
   completion with no errors.

## What was deliberately left alone

- `app/core/synthetic_data.py`'s `SOURCES`/`SOURCE_TRUST` lists still
  include both `"FS-ISAC"` and `"OTX AlienVault"` as flavor labels for
  *synthetic* (fake, `is_synthetic=True`) data generation. This is
  cosmetic variety for training data, unrelated to the real connectors,
  and changing it isn't part of "replace the FS-ISAC connector" — left
  untouched to avoid an unrequested behavior change to the synthetic
  data generator's label distribution.
- `app/db/session.py`, `app/models/models.py`'s table definitions,
  Alembic migrations, and DB-backed persistence generally — not part of
  this pass's scope, and not touched.
- `docker/Dockerfile` vs `docker/Dockerfile.api` — both exist, both look
  correct, `docker-compose.yml` already correctly points at `.api`. Left
  as-is.
