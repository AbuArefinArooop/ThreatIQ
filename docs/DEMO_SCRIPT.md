# ThreatIQ v4.1 — Live Demo Script
### "Closing the Loop: SIEM Integration & Open CTI Standards"
**Target runtime: 6–7 minutes.** Every step below is a real click or a real curl command against a running instance — nothing here is a mockup.

---

## Before you start (do this off-camera, ~2 min)

```bash
cd ThreatIQ
docker compose up -d
# wait ~15s for postgres/redis healthchecks
```

Open `http://localhost:8000` in a browser tab. Have a terminal ready alongside it — two or three of the steps below are more convincing as a raw `curl` than a UI click, because it proves there's a real API behind the button.

Log in as `admin` / `ThreatIQ@Admin25!` before you start talking.

---

## 1. Dashboard (30s) — "Here's what's already running"

Land on the Intelligence Dashboard. Say:

> "This is ThreatIQ — it ingests from MISP, CIRCL, OTX, and now a SIEM, classifies indicators with four ML models, and predicts adversary-technique relationships with a graph attention network. Everything you're about to see is live against this running instance — no mockups."

Point at the IoC distribution and severity donut charts. Don't linger — this is the "already built" part, not today's story.

---

## 2. Connectors page — introduce the new source (60s)

Navigate to **CTI Connectors**. Say:

> "Four sources feed this: MISP, CIRCL, OTX — and as of this pass, Wazuh, an open-source SIEM. The point isn't just 'one more feed.' It's that a SIEM alert and a threat-intel indicator are now first-class citizens of the same pipeline."

Point at the WAZUH card (shield icon, offline unless you have live Wazuh creds set — that's fine, say so):

> "Offline mode returns curated sample alerts so the whole pipeline is demoable without a live SIEM stack. Point it at a real Wazuh indexer and the exact same code path runs against real telemetry."

Click **Correlate Sources**. While it loads:

> "This is the part that separates a feed aggregator from a correlation engine — MISP's whole reason for existing. It just pulled a fresh batch from every connector and is checking whether any of them independently reported the same observable."

Show the resulting table. If `corroborated_observables: 0` (expected with offline demo data — say this out loud, don't dodge it):

> "Zero corroboration here because each connector's offline sample data was written independently — there's no reason for the same IP to show up in two unrelated test fixtures. Point two live connectors at the same real infrastructure and this table populates with confidence boosts. That's an honest limitation of demo data, not the mechanism."

---

## 3. Terminal — the loop, from the API side (90s)

Switch to the terminal. This is the highest-signal moment of the demo — showing the actual HTTP calls proves nothing is smoke and mirrors.

```bash
# Log in
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ThreatIQ@Admin25!"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# Pull alerts from Wazuh directly
curl -s -X POST "http://localhost:8000/api/v1/connectors/WAZUH/fetch?limit=5" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Say while it prints:

> "That's a real HTTP call pulling SIEM alerts through the exact same connector interface as MISP or OTX — same shape, same offline-fallback contract. Nothing SIEM-specific leaked into the classification or graph layers to make this work."

Now the push direction:

```bash
curl -s -X POST "http://localhost:8000/api/v1/connectors/misp/export" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

> "And this is the other half of the loop — publishing our own classified indicators *out* to MISP. On a real deployment, Wazuh's own MISP integration module polls that event and auto-generates detection rules from it. CTI comes in, gets classified, goes back out as a detection — that's the loop closing."

(If MISP isn't configured, it'll return `"skipped": "misp_not_configured"` — say: *"Correctly refuses to pretend it published something it didn't — that's deliberate, not a bug."*)

---

## 4. Pipeline run with the new source (60s, mostly waiting)

Back in the UI, **AI Pipeline** page. Confirm `WAZUH` is checked as a source (it's in the default list), then **Run Full Pipeline**.

While it runs (~60–90s), talk over it:

> "Watch the log — it'll show WAZUH right alongside MISP, CIRCL, and OTX in the ingestion stage. That's 4 independent sources feeding one classification pipeline, same overfitting-gated Random Forest / Gradient Boosting / Logistic Regression / Decision Tree ensemble as before."

When it completes, point at the log line reading `WAZUH: N alerts`.

---

## 5. IoC Library → STIX export (45s)

Navigate to **IoC Library**. Point at the source filter dropdown — show "Wazuh SIEM" is now a real filter option, not cosmetic.

Click **Export STIX 2.1**. A file downloads. Open it in a text editor or `cat` it:

> "This isn't a ThreatIQ-shaped JSON blob — it's a standards-compliant STIX 2.1 bundle. Any STIX/TAXII tool can ingest this directly: OpenCTI, a different MISP instance, a commercial platform, doesn't matter. CVEs come out as proper Vulnerability objects, not force-fit indicators. IDs are deterministic — export the same IoC twice, get the same ID, so a consumer sees an update, not a duplicate."

---

## 6. Attack Graph → Navigator layer (45s)

Navigate to **Attack Knowledge Graph**. Click **Export Navigator Layer**.

> "This turns the GAT's predicted actor-technique relationships into a file format for the actual MITRE ATT&CK Navigator — the free tool most SOC teams already use to track technique coverage."

If you have time and internet: open [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/), **Open Existing Layer → Upload from Local**, and load the downloaded file live. This is the single best visual beat in the demo if it works — a real heatmap on the real ATT&CK matrix, built from your own model's predictions.

If the layer comes back with zero techniques (a known, disclosed limitation given the tiny offline MITRE relationship sample — see the paper's Discussion section):

> "With the small offline training sample we're running against right now, most predictions don't clear the confidence threshold — that's a disclosed limitation of evaluation-environment scale, not a defect in the export itself. Against the full MITRE ATT&CK corpus this populates properly."

---

## 7. Close (30s)

> "Four things happened here that weren't true before this pass: a SIEM is now a bidirectional participant in the pipeline, not just a downstream consumer. ThreatIQ's own output speaks two standards the wider field actually uses — STIX 2.1 and ATT&CK Navigator — not a proprietary format. Cross-source corroboration is now a first-class signal, the same principle intelligence tradecraft has used for decades. And all of it was verified the same way the rest of this project was: 100 automated tests, plus live HTTP calls against a running instance under every role, not just code review."

---

## Fallback answers for likely questions

**"Why is correlation showing zero matches?"** → Independently-authored offline sample data across connectors; genuinely expected, documented in the paper's Discussion section, not a bug. Explain the mechanism (confidence boost formula) instead of just the empty result.

**"Why is the Navigator layer sometimes empty?"** → Same root cause as the original paper's disclosed GAT evaluation-scale limitation (2–4 relationship pairs). Not new, not hidden — same caveat, same root cause, restated for the new export path.

**"Is this connected to a real Wazuh/MISP instance right now?"** → Be honest: offline-fallback mode unless you've stood up `docker-compose.wazuh.yml` and configured real MISP credentials beforehand. The code path is identical either way — that's the point of the offline-fallback contract.

**"Did you rotate the exposed API key you found?"** → Yes — say this proactively if you can, it's a strong signal that the audit findings were taken seriously, not just written up.
