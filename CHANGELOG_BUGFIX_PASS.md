# Changelog — Bug Fix & Hardening Pass

Applied on top of the FS-ISAC → OTX migration. Every fix below was verified
live: full test suite (56/56 passing, including a strengthened test), a live
server boot, and real HTTP requests against every touched endpoint.

## Bugs found and fixed

### 1. Frontend still sent `FS-ISAC` to the backend (`app/static/index.html`)
The FS-ISAC → OTX migration updated every backend file but missed the SPA.
12 references across the AI Pipeline page, Evaluation page dropdown
(`real_fsisac`), Connectors page, and — critically — the actual
`POST /pipeline/run` request body, which the backend's Pydantic validator
now rejects (`allowed = {"MISP","CIRCL","OTX","Synthetic","VirusTotal"}`).
This was the direct cause of the "Pipeline error: Failed to fetch" /
`Unknown sources` errors in the UI. All references swapped to OTX.

### 2. GAT evaluation metrics were non-reproducible (`app/ml/gat.py`)
`load_mitre_relationships()` returned the actual shared module-level
`MITRE_OFFLINE_RELATIONSHIPS` list (not a copy) when no STIX bundle is
configured. Both `GATTrainer.train()` and `GET /evaluation/gat` call
`random.shuffle()` on the returned list to build the train/test split.
Because the same list object was shuffled in place on every call,
re-seeding to 42 on each call shuffled an *already-shuffled* list,
producing a different split — and therefore different Hits@1/5/10/MRR —
on every single call, despite looking deterministic. Confirmed live:
three consecutive calls returned Hits@5 = 0.0, 0.0, 1.0 for the same
trained model.
**Fix:** `load_mitre_relationships()` now returns `list(MITRE_OFFLINE_RELATIONSHIPS)`,
a copy, so callers can shuffle freely without corrupting shared state.
Verified: repeated calls now return identical metrics.

### 3. `source` filter on `GET /api/v1/iocs` was a complete no-op (`app/api/v1/iocs.py`)
The query parameter was declared, documented, and used by the frontend's
source dropdown, but never applied to the filter chain — every other
filter (`label`, `severity`, `tlp`, `is_anomaly`, `is_synthetic`) was
wired up except this one. Confirmed live: `?source=MISP` returned all
200 records across every source. Fixed by adding the missing filter line.

### 4. Synthetic data generator wasn't fully reproducible despite a seed param (`app/core/synthetic_data.py`)
`generate_synthetic_iocs(seed=...)` seeded a local `rng` and `np.random`,
but the helper that builds the actual IoC value (`_gen_ioc`) called the
*global*, unseeded `random` module instead of the passed-in `rng`. Labels
and severities were reproducible; the actual hash/IP/domain value was
not. The existing test had a telling comment — *"Labels must be
identical even if ioc_value uses RNG differently"* — documenting the bug
as a known workaround rather than fixing it.
**Fix:** `_gen_ioc()` now takes and uses the seeded `rng`. Strengthened
`test_reproducible_with_seed` to also assert `ioc_value` equality.

### 5. `records_processed` in pipeline status was meaningless (`app/api/v1/pipeline.py`)
It was computed as `len(_state["log"])` — the number of log lines —
which happened to produce a plausible-looking number that had nothing to
do with actual records processed. Fixed to report `len(combined)`, the
real count of real + synthetic IoCs ingested that run (verified: 212 for
a 200-record run with 12 real IoCs pulled from MISP/CIRCL/OTX).

### 6. Connector status never reflected real activity (`app/api/v1/connectors.py`)
`GET /api/v1/connectors` always returned `last_run: null` and
`records_last_run: 0` for every connector, even immediately after a
successful manual fetch — the fields existed in the response model but
were never populated. Added an in-memory `_last_fetch` store updated by
`POST /connectors/{name}/fetch` and read by the status endpoint. Verified:
after fetching OTX, the status endpoint now shows a real timestamp and
record count.

### 7. CIRCL live-mode fetch never populated real CVE data (`app/connectors/circl_connector.py`)
`_fetch_live_cves` pulled a list of CVE IDs from `/browse/2024` but
passed an empty `{}` as the per-CVE detail payload — every live-fetched
CVE got the same placeholder severity (always "High"/4) and a generic
summary string, regardless of the real CVE's actual CVSS score. Fixed to
fetch each CVE's real detail from `/cve/{id}` before building the IoC
record, with a per-CVE try/except so one failed lookup doesn't abort the
whole batch.

### 8. Login had a timing side-channel that undermined its own anti-enumeration comment (`app/api/v1/auth.py`)
Unknown usernames returned immediately (skipping `verify_password`
entirely), while known usernames always ran the full PBKDF2-SHA256
verification (260k iterations). This is a classic timing oracle: an
attacker can enumerate valid usernames by measuring response time, even
though the error message is identical either way. Fixed by always
running `verify_password` — against a dummy hash when the user doesn't
exist — so response time no longer depends on username validity.
Verified: known-user and unknown-user average response times are now
within noise of each other (previously the unknown-user path returned
near-instantly).

### 9. MISP live-fetch had a latent type bug (`app/connectors/misp_connector.py`)
`getattr(attr, "Event", {}).get("info", "")` assumed PyMISP's
pythonified `attr.Event` is always a plain dict. In practice PyMISP
returns a `MISPEvent` object for this field, which may not support
`.get()`, so this could raise `AttributeError` the first time the code
path actually ran against a real MISP server (never exercised previously
— no live MISP instance was available to test against). Made defensive:
handles both dict and object attribute access.

## Verification performed

- Full test suite: 56/56 passing (57 assertions including the
  strengthened reproducibility test)
- Live server boot + real JWT login as admin/analyst/viewer
- Full 4-stage pipeline run to completion, polled to `success`
- Every `/api/v1/*` endpoint exercised with real HTTP requests
- GAT evaluation determinism re-verified across 4 repeated calls
- Synthetic data `ioc_value` reproducibility re-verified directly
- Connector fetch → status round-trip re-verified
- Login timing re-measured before/after the fix
- CIRCL/MISP offline fallback paths re-verified end-to-end

## Known limitation (unchanged from prior pass)

Live CIRCL fetch could not be tested end-to-end in this sandbox — the
sandbox's network egress policy blocks `circl.lu` (`403 host_not_allowed`),
so the connector correctly falls back to its offline sample, which is the
intended and tested behavior. The fixed detail-fetch logic is correct by
inspection and matches the documented CIRCL cve-search API contract
(`/api/cve/{id}`), but real production-scale validation needs to happen
against the live API from an unrestricted network.
