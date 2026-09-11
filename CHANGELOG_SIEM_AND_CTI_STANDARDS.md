# Changelog — SIEM Integration, Open CTI Standards, and Security/Cleanup Pass

Applied directly to the real uploaded codebase (`ThreatIQ.7z`). Every
change below was verified: full test suite run (100/100 passing, up from
56/56), a live server boot, live curl checks against every new endpoint,
and a live end-to-end pipeline run that genuinely ingested Wazuh alerts
alongside MISP/CIRCL/OTX and retrained the GAT.

## 0. Critical security fix — found before anything else was touched

`app/core/config.py` shipped a **live-looking API key hardcoded as the
default value** for `OTX_API_KEY`:

```python
OTX_API_KEY: Optional[str] = "d82f8d639f6ece466e1501be55410b3481cfe3a976eb057707d41915d390d631"
```

This was already committed to git history, meaning every clone of the
repo carried the key automatically. Fixed to `None`, matching every other
optional credential in the file. **You should rotate this key** at
https://otx.alienvault.com/api regardless of anything else in this pass —
a default value baked into source and committed to git is a real exposure
even for a low-sensitivity free-tier key, and the same pattern with a more
sensitive credential (`MISP_API_KEY`, `SECRET_KEY`, `POSTGRES_PASSWORD`)
would be a real incident.

No other hardcoded secrets were found (`grep -rnE` across `app/` for
key/password/secret/token-shaped literals came back clean).

## 1. Repository cleanup

- Removed three stray `venv/` directories (`venv/`, `threatiq_v4/venv/`,
  `app/connectors/venv/`) — untracked, ~14MB each, pure bloat.
- Removed `threatiq_v4/threatiq_v4/` — a duplicate, *tracked* nested copy
  of the entire project (an accidental zip-in-zip artifact). Its presence
  meant every real file existed twice in git history.
- Removed the empty `.dist/` directory.
- Added `.gitignore` (there wasn't one) covering venvs, `__pycache__`,
  `.env`, editor cruft, and load-test output — so none of the above can
  recur silently.
- Removed `torch`/`torch-geometric` from `requirements.txt`. Confirmed via
  `grep -rn "^import torch\|^from torch" app/` that neither package is
  imported anywhere — `app/ml/gat.py` is genuinely pure NumPy. Keeping
  them listed as dependencies roughly triples the Docker image for
  nothing.
- Net effect: uncompressed project size dropped from ~48MB to ~5.8MB.

## 2. SIEM integration (pull + push loop)

**New: `app/connectors/wazuh_connector.py`** — pull connector, following
the exact interface every existing connector uses:
`fetch_recent(limit) -> list[dict]`, identical IoC dict shape, identical
`_live` flag / offline-fallback contract to `OTXConnector`. Queries the
Wazuh indexer's OpenSearch-compatible search API for alerts at or above
rule level 5, maps Wazuh's 0–15 rule.level onto ThreatIQ's 1–5 severity
scale, and extracts the most relevant observable (`srcip`/`dstip`/`url`/
agent name) per alert. Falls back to four curated offline sample alerts
when unconfigured or unreachable.

**New: `app/connectors/misp_export.py`** — the push-direction counterpart
to `MISPConnector`. Filters the current IoC store down to
confident/severe/non-synthetic records and publishes them as a MISP Event
via PyMISP (already pinned in `requirements.txt`). Wazuh's own MISP
integration module (configured separately, on the Wazuh side) then polls
that event and auto-generates detection rules from it — closing the loop:
`CTI sources → ThreatIQ (classify) → MISP export → Wazuh (detects on live
traffic) → WazuhConnector (pulls alerts back in)`. Works against both raw
connector dicts and the `IoCResponse` Pydantic shape used by `GET
/api/v1/iocs` (field-name mismatch — `confidence` vs `label_confidence` —
handled by a small dual-accessor helper).

**Wiring (all existing files, minimal diffs):**
- `app/core/config.py` — added `WAZUH_INDEXER_URL` / `WAZUH_API_USERNAME`
  / `WAZUH_API_PASSWORD` / `WAZUH_VERIFY_SSL`.
- `app/models/models.py` — added `IoCSourceType.WAZUH = "Wazuh SIEM"`
  (kept the existing generic `SIEM = "Internal SIEM"` untouched).
- `app/api/v1/connectors.py` — `"WAZUH"` added to the connector-status
  list and the manual-fetch dispatch, matching the exact pattern used for
  OTX. New endpoint: `POST /api/v1/connectors/misp/export` (admin-only,
  strict-limited) — deliberately a distinct, manually-triggered action
  rather than something that fires automatically after every pipeline
  run, since publishing to an external system should be an explicit
  choice.
- `app/api/v1/pipeline.py` — `"WAZUH"` added to the default `sources` list
  and the `allowed` validator set; Stage-1 ingestion gets a
  `WazuhConnector(...)` branch identical in shape to the OTX branch.
- `app/api/v1/evaluation.py` — `"real_wazuh"` added as a `dataset_type`,
  matching `real_misp`/`real_circl`/`real_otx`.
- `app/workers/tasks.py` / `celery_app.py` — new `ingest_wazuh` task,
  scheduled every 15 minutes (SIEM alerts are far higher-frequency than
  the daily/hourly feed pulls the other sources use).
- `docker-compose.yml` — `WAZUH_*` env vars passed through to `api` and
  `worker`; pinned the compose network name to `threatiq_default` so the
  new Wazuh overlay can join it reliably.
- `locustfile.py` — `"WAZUH"` added to `CONNECTOR_NAMES`, `"real_wazuh"`
  added to `EVAL_DATASET_TYPES`, so both get exercised under load.
- `.env` / `.env.template` — new `WAZUH_*` variables documented.

**New: `docker-compose.wazuh.yml`** — a separate overlay (not merged into
the main compose file, since Wazuh's manager+indexer+dashboard stack is
heavier than everything else combined) bringing up a single-node Wazuh
deployment on the same Docker network. Requires generating Wazuh's
indexer certs once via the official `wazuh-docker` quick-start generator
before first run (documented in the file's header comment) — Wazuh will
not start without them.

**Tests:** `TestWazuhConnector` (8 tests) and `TestMISPExporter` (9
tests) added to `tests/test_all.py`, mirroring the existing per-connector
test style exactly — offline fallback, `is_synthetic` flag, source label,
limit handling, live/offline mode detection, IoC shape parity, graceful
degradation on unreachable/unconfigured targets, and (for the exporter)
confidence/severity threshold filtering and dual field-name support.

## 3. Open CTI standards additions

These aren't SIEM plumbing — they connect ThreatIQ's own output to the
actual global standards the CTI field has converged on, so its output is
useful outside ThreatIQ itself, not just inside it.

**New: `app/services/stix_export.py`** — exports IoCs as a **STIX 2.1
Bundle** (the OASIS Cyber Threat Intelligence TC standard; the same
interchange format MISP, OpenCTI, and virtually every commercial CTI
platform speak). Deliberately general-purpose and standalone, unlike
`misp_export.py` which targets one specific platform's API — this
produces plain STIX 2.1 JSON any STIX/TAXII-consuming tool can ingest.

Design choices worth knowing about:
- Indicator IDs are **UUIDv5**, deterministically derived from the IoC
  value. Re-exporting the same IoC twice produces the same
  `indicator--<uuid>`, which is the STIX-recommended practice for
  idempotent republication (a consumer sees an *update*, not a
  duplicate).
- `confidence` follows the STIX 2.1 spec exactly — an integer 0–100, not
  ThreatIQ's internal 0.0–1.0 float.
- TLP markings reuse the exact same `STIX_TLP_MAP` constant already used
  by `opencti_connector.py`, so a TLP:AMBER IoC gets one consistent STIX
  representation everywhere in ThreatIQ, not two different ones.
- CVE-typed records are exported as a proper `vulnerability` SDO, per the
  spec's own guidance, not forced into a fabricated Indicator pattern.
- IoC types with no dedicated STIX Cyber Observable Object (e.g. a bare
  `"Host"` hostname) are exported as an annotation-only `Note`, clearly
  scoped as such — rather than inventing a non-standard SCO and claiming
  false STIX compliance.

New endpoint: `GET /api/v1/iocs/export/stix` (any authenticated role,
TLP-filtered per caller exactly like `GET /iocs`, synthetic records
excluded by default).

**New: `app/services/attck_navigator.py`** — exports GAT's link
predictions as a **MITRE ATT&CK Navigator layer** (the standard JSON
format for https://mitre-attack.github.io/attack-navigator, the most
widely used free analyst tool for visualizing ATT&CK technique coverage).
`predict_links()` already produces `(actor, technique, score)` triples;
as raw JSON they're only useful to something reading the API response. A
Navigator layer turns the same predictions into a heatmap over the real
ATT&CK matrix any analyst can open and filter without writing code — the
most direct way to make GAT's output "practical" rather than just an
evaluation-report metric.

Where multiple actors are predicted against the same technique, the
technique's layer score is the **maximum** across actors (not averaged),
and the comment field lists every contributing actor with its own score —
a technique predicted by several different actors is exactly the signal
an analyst wants surfaced, not diluted.

New endpoint: `GET /api/v1/graph/navigator-layer` (any authenticated
role).

**Tests:** `TestSTIXExport` (9 tests) and `TestAttackNavigatorExport` (6
tests) added, covering bundle envelope correctness, per-type pattern
generation, the CVE→Vulnerability special case, the unmapped-type→Note-
only fallback, deterministic ID generation, TLP-marking consistency, dual
field-name support, technique-ID resolution from node names, max-not-sum
scoring, and descending sort order.

**Honest caveat on the Navigator layer in practice:** with the currently
checked-in GAT weights (and even a fresh in-memory retrain against the
existing tiny offline MITRE relationship sample — the same one the IEEE
paper's own evaluation section flags as low-statistical-power, ~4 pairs),
`predict_links()` rarely clears its 0.3 confidence threshold, so the
layer often comes back with zero techniques. This is **not** a defect in
the new export code — the existing, untouched `GET /api/v1/graph`
endpoint shows the identical empty `predictions: []` with the same
weights. It's a direct consequence of the tiny offline evaluation
dataset, and is resolved the same way the paper's own "Future Work"
section already identifies: downloading and training against the full
MITRE ATT&CK enterprise STIX corpus.

## 4. Cross-source correlation

The single most concrete "best-in-class CTI platform" differentiator
that was still missing: independent corroboration across sources.
Right up to this point, MISP/CIRCL/OTX/Wazuh were four separate fetches
with no relationship between them — the same IP reported by both OTX and
Wazuh would just show up as two unrelated records. Correlation is the
actual mechanical core of what makes tools like MISP valuable as
*correlation engines*, not just aggregators: a fact confirmed by two
independent sources is more credible than the same fact reported twice
by one source (this is also the entire premise behind the Admiralty/NATO
System's separate reliability-vs-credibility axes covered in the
accompanying CTI literature).

**New: `app/services/correlation.py`** — `correlate_iocs(records) ->
list[dict]`. Groups records by normalized `(ioc_value, ioc_type)`
(case-insensitive for domains/URLs/emails per RFC 1035/3986, exact match
otherwise). A value seen from only one source passes through unboosted.
A value confirmed by N independent sources gets its confidence boosted
via `headroom * (1 - (1 - 0.35)^min(N-1, 4))` — each additional source
closes part of the remaining gap to 1.0 rather than adding a flat bonus
(which would let enough low-quality sources reach 100% artificially).
Severity takes the group maximum; `is_synthetic` is only `True` if *every*
corroborating record is synthetic (so a real IoC confirmed alongside a
synthetic training record doesn't get mislabeled).

Deliberately **not** wired into the default pipeline path — pipeline.py's
classification/GAT stages are already tested and their metrics match
the paper's cited numbers, and correlation changes record *counts*
(merging duplicates), which would shift those numbers silently. Instead:

New endpoint: `POST /api/v1/connectors/correlate` (admin or analyst,
strict-limited) — fetches a fresh batch from every connector in whatever
mode each is currently configured for (live or offline), runs
correlation, and returns the merged view with per-source counts, unique
observable count, and how many were independently confirmed by 2+
sources. Read-only, entirely separate from `/pipeline/run`.

New UI: a **"Correlate Sources"** button on the Connectors page, with a
results table showing each observable's contributing sources, boosted
confidence, and the size of the boost.

**Honest caveat, same spirit as the Navigator layer note below:** run
this against the fully offline demo (no live credentials at all), and
`corroborated_observables` will typically be `0` — each connector's
offline sample set was written independently, so there's no reason for
the same literal IoC value to appear in more than one of them. That's
correct, expected behaviour, not a bug: real corroboration only shows up
once at least two connectors are pointed at real, overlapping
infrastructure (e.g. an actor's C2 IP appearing in both a live OTX pulse
and a live Wazuh alert).

**Tests:** `TestCorrelation` (11 tests) — single-source pass-through,
multi-source merge, confidence boost exceeding the highest individual
input, the 1.0 ceiling, max-severity selection, full source listing,
case-insensitive domain matching, type-scoped matching (a hash and a
domain that happen to share a literal string must NOT correlate),
descending sort by corroboration, the synthetic-only-if-all-synthetic
rule, and empty input.

## 5. Frontend wiring

The SPA (`app/static/index.html`) wasn't touched by the backend work
above by default — its connector grid already renders generically from
whatever `GET /connectors` returns, so `WAZUH` appeared there automatically.
But the two new export capabilities were only reachable via raw API calls
until this pass added:
- A Wazuh icon (🛡) in the connector grid's icon lookup map.
- `"Wazuh SIEM"` added to the IoC Library's source filter dropdown.
- An **"Export STIX 2.1"** button on the IoC Library page, next to the
  existing CSV/JSON export buttons — same pattern, downloads the bundle
  as a `.json` file client-side.
- An **"Export Navigator Layer"** button on the Attack Knowledge Graph
  page, next to Refresh/Retrain — downloads the layer file ready to
  upload directly at mitre-attack.github.io/attack-navigator.

Verified live: both buttons' backing JS functions are present in the
served page, and both API endpoints they call return `200` end-to-end.

## 6. Verification performed

```
100 passed in <20s   (56 original + 17 SIEM connector/exporter tests +
                       16 STIX/Navigator tests + 11 correlation tests)
```

Live smoke test (real HTTP requests against a running server, admin,
analyst, and viewer tokens):
- `GET /api/v1/connectors` → `WAZUH` appears in the list, correctly
  reported `offline` (no credentials configured)
- `POST /api/v1/connectors/WAZUH/fetch?limit=3` → 3 offline sample alerts
  returned in the standard IoC shape; connector status `last_run` /
  `records_last_run` updated afterward
- `POST /api/v1/connectors/misp/export` → correctly reports
  `"skipped": "misp_not_configured"` rather than crashing; correctly
  returns `403` for a non-admin (`analyst`) token
- `POST /api/v1/connectors/correlate` → correctly returns `200` for
  `admin` and `analyst`, correctly returns `403` for `viewer`; live run
  fetched 16 records across MISP/CIRCL/OTX/WAZUH (all in offline mode)
  and correctly reported `corroborated_observables: 0` (see caveat below
  — this is expected with independently-written offline sample data, not
  a bug)
- `POST /api/v1/evaluation/run` with `dataset_type: "real_wazuh"` →
  accepted and routed correctly
- `POST /api/v1/pipeline/run` with `"WAZUH"` in `sources` → live pipeline
  log shows `WAZUH: 4 alerts` ingested alongside MISP/CIRCL/OTX,
  contributing to 216 total records; all four classifiers passed the
  overfitting gate; GAT trained successfully
- `GET /api/v1/iocs/export/stix?min_confidence=0.8` → valid STIX 2.1
  bundle, correct `indicator`/`vulnerability`/`note` object types per
  record
- `GET /api/v1/graph/navigator-layer?top_k=5` → valid Navigator layer
  envelope (see caveat above re: technique count with current weights)
- Frontend: `exportSTIX`, `exportNavigatorLayer`, and `runCorrelation`
  all confirmed present in the actually-served `index.html` (not just
  the source file), and their three backing API calls each confirmed
  returning `200`

**Note on `model_artifacts/gat_weights.npz`:** an earlier verification
pass in this same session ran a full pipeline (`run_gat_training: true`),
which retrained and overwrote this file. Since the IEEE paper cites
specific metrics (Hits@1=0.250, Hits@5=1.000, MRR=0.425, final training
loss=53.48) from a particular trained run, that file was deliberately
restored via `git checkout -- model_artifacts/gat_weights.npz` before
this pass concluded, so the numbers in the paper stay reproducible from
the delivered archive. All GAT-related testing in this pass (including
the Navigator layer check above) used either the restored checked-in
weights or an explicitly *unsaved* in-memory retrain — nothing in this
delivery has silently changed your paper's cited numbers.

## 7. What was deliberately left alone

- The mock/demo IoC data in `app/api/v1/iocs.py` (`_MOCK_IOCS`) — not
  touched; `MISPExporter` and `stix_export.py` both read from it as-is
  for the export endpoints, exactly as it already exists.
- `app/connectors/synthetic_data.py`'s source-label lists — same
  reasoning as the OTX migration pass: cosmetic variety for synthetic
  training data, unrelated to real connectors.
- Postgres-backed persistence — still out of scope, as documented in
  `README.md`'s own "Known Remaining Limitations" section; this pass
  didn't change that.
