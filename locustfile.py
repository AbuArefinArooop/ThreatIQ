"""
Locust load test — ThreatIQ v4.0
=================================
Covers every endpoint in the real app/api/v1 routers, weighted to
resemble real analyst/dashboard traffic: heavy reads (`iocs`, `graph`,
`connectors` status), occasional writes (`feedback`), and rare expensive
operations (`pipeline/run`, `graph/train`, `evaluation/run`, connector
manual-fetch) gated to the admin/analyst roles that actually hold them.

IMPORTANT — rate limiting is per-IP, not per-user (see app/core/security.py
RateLimiter, keyed on request.client.host). Every simulated Locust user in
a local run shares one client IP, so they all draw from the *same* token
bucket: 120/min default, 20/min strict (pipeline/run, graph/train,
connectors/*/fetch, evaluation/run), 30/min feedback. At even moderate
concurrency you WILL see 429s on the strict-limited endpoints — that's
the rate limiter doing its job, not a bug. This file treats 200 and 429
as both "success" on strict-limited tasks so a 429-heavy run doesn't look
like a failed load test; watch the results CSV's status-code breakdown to
see the real ratio.

Run:
    locust -f locustfile.py --host http://localhost:8000

Headless, e.g. 30 users ramping over 10s for 5 minutes:
    locust -f locustfile.py --host http://localhost:8000 \\
        --headless -u 30 -r 10 -t 5m --csv=results/threatiq_load
"""

from __future__ import annotations

import random

from locust import HttpUser, between, tag, task

# Real dev credentials from app/api/v1/auth.py's in-memory _USERS table.
# Weighted so read-heavy roles (viewer/analyst) dominate, like a real SOC.
CREDENTIALS = [
    ("admin", "ThreatIQ@Admin25!", 1),
    ("analyst", "ThreatIQ@Analyst25!", 3),
    ("viewer", "ThreatIQ@Viewer25!", 4),
]

# Wired into POST /connectors/{name}/fetch's dispatch (app/api/v1/connectors.py);
# name must be uppercase, matching ^[A-Z0-9_-]{2,20}$.
CONNECTOR_NAMES = ["MISP", "CIRCL", "OTX", "WAZUH"]

EVAL_DATASET_TYPES = ["synthetic", "real_misp", "real_circl", "real_otx", "real_wazuh", "mixed"]

IOC_CLASSES = [
    "Malware", "Phishing", "Ransomware", "DDoS", "APT",
    "SQL Injection", "Zero-Day", "Credential Stuffing", "Insider Threat",
]


def _weighted_credentials() -> tuple[str, str]:
    idx = random.choices(range(len(CREDENTIALS)), weights=[c[2] for c in CREDENTIALS], k=1)[0]
    return CREDENTIALS[idx][0], CREDENTIALS[idx][1]


def _ok_or_rate_limited(resp) -> None:
    """For strict-limited endpoints: 200 and 429 both count as success --
    a 429 under load means the limiter is correctly protecting the
    endpoint, not that the endpoint is broken."""
    if resp.status_code in (200, 201, 202, 429):
        resp.success()
    else:
        resp.failure(f"unexpected status {resp.status_code}: {resp.text[:200]}")


class ThreatIQUser(HttpUser):
    """Simulates a logged-in analyst/viewer/admin browsing ThreatIQ."""

    wait_time = between(1, 4)
    weight = 9

    def on_start(self) -> None:
        self.username, self.password = _weighted_credentials()
        self.token: str | None = None
        self.role: str | None = None
        self._login()

    def _login(self) -> None:
        with self.client.post(
            "/api/v1/auth/login",
            json={"username": self.username, "password": self.password},
            name="/api/v1/auth/login",
            catch_response=True,
        ) as resp:
            if resp.status_code != 200:
                resp.failure(f"login failed: {resp.status_code} {resp.text}")
                return
            data = resp.json()
            self.token = data.get("access_token")
            self.role = data.get("role")
            resp.success()

    @property
    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    # ── Health / smoke (no auth) ────────────────────────────────
    @tag("health")
    @task(2)
    def health(self) -> None:
        self.client.get("/health", name="/health")

    @tag("health")
    @task(1)
    def ready(self) -> None:
        self.client.get("/ready", name="/ready")

    # ── Auth: who am I ───────────────────────────────────────────
    @tag("auth")
    @task(2)
    def whoami(self) -> None:
        self.client.get(
            "/api/v1/auth/me", headers=self._auth_headers, name="/api/v1/auth/me"
        )

    # ── IoCs (most common analyst action) ───────────────────────
    @tag("iocs")
    @task(10)
    def list_iocs(self) -> None:
        params = {"page": random.randint(1, 3), "per_page": 20}
        if random.random() < 0.3:
            params["q"] = "185.220"
        if random.random() < 0.2:
            params["label"] = random.choice(["Malware", "Ransomware", "APT"])
        self.client.get(
            "/api/v1/iocs", params=params, headers=self._auth_headers, name="/api/v1/iocs"
        )

    @tag("iocs")
    @task(4)
    def get_single_ioc(self) -> None:
        ioc_id = f"ioc-{random.randint(1, 200):05d}"
        with self.client.get(
            f"/api/v1/iocs/{ioc_id}",
            headers=self._auth_headers,
            name="/api/v1/iocs/[id]",
            catch_response=True,
        ) as resp:
            # 403 is expected here: viewers (max_tlp=TLP:GREEN) will
            # legitimately get blocked from TLP:AMBER/RED records.
            if resp.status_code in (200, 403, 404):
                resp.success()
            else:
                resp.failure(f"unexpected status {resp.status_code}")

    # ── Graph stats (dashboard widget, polled often) ────────────
    @tag("graph")
    @task(8)
    def graph_stats(self) -> None:
        self.client.get(
            "/api/v1/graph", headers=self._auth_headers, name="/api/v1/graph"
        )

    # ── Connector health panel ───────────────────────────────────
    @tag("connectors")
    @task(6)
    def connector_statuses(self) -> None:
        self.client.get(
            "/api/v1/connectors", headers=self._auth_headers, name="/api/v1/connectors"
        )

    # ── Pipeline status polling ──────────────────────────────────
    @tag("pipeline")
    @task(5)
    def pipeline_status(self) -> None:
        self.client.get(
            "/api/v1/pipeline/status",
            headers=self._auth_headers,
            name="/api/v1/pipeline/status",
        )

    # ── RL agent status ──────────────────────────────────────────
    @tag("feedback")
    @task(3)
    def rl_status(self) -> None:
        self.client.get(
            "/api/v1/feedback/status",
            headers=self._auth_headers,
            name="/api/v1/feedback/status",
        )

    # ── GAT evaluation vs MITRE ground truth (read-only) ─────────
    @tag("evaluation")
    @task(3)
    def evaluation_gat(self) -> None:
        self.client.get(
            "/api/v1/evaluation/gat",
            headers=self._auth_headers,
            name="/api/v1/evaluation/gat",
        )

    # ── Feedback submission (analyst/admin only, 30/min limiter) ─
    @tag("feedback")
    @task(3)
    def submit_feedback(self) -> None:
        if self.role not in ("admin", "analyst"):
            return
        predicted = random.choice(IOC_CLASSES)
        true_class = random.choice(IOC_CLASSES)
        with self.client.post(
            "/api/v1/feedback",
            json={
                "ioc_id": f"ioc-{random.randint(1, 200):05d}",
                "predicted_class": predicted,
                "true_class": true_class,
                "is_correct": predicted == true_class,
                "analyst_confidence": round(random.uniform(0.5, 1.0), 2),
            },
            headers=self._auth_headers,
            name="/api/v1/feedback",
            catch_response=True,
        ) as resp:
            _ok_or_rate_limited(resp)

    # ── Manual connector fetch, incl. the new OTX connector ───────
    # admin only, 20/min strict limiter shared across all simulated users
    @tag("connectors", "otx", "expensive")
    @task(2)
    def connector_fetch(self) -> None:
        if self.role != "admin":
            return
        name = random.choice(CONNECTOR_NAMES)
        with self.client.post(
            f"/api/v1/connectors/{name}/fetch",
            params={"limit": 25},
            headers=self._auth_headers,
            name="/api/v1/connectors/[name]/fetch",
            catch_response=True,
        ) as resp:
            _ok_or_rate_limited(resp)

    # ── OpenCTI enrichment test (admin only, rare) ────────────────
    @tag("connectors", "opencti", "expensive")
    @task(1)
    def opencti_enrich(self) -> None:
        if self.role != "admin":
            return
        with self.client.post(
            "/api/v1/connectors/opencti/enrich",
            headers=self._auth_headers,
            name="/api/v1/connectors/opencti/enrich",
            catch_response=True,
        ) as resp:
            _ok_or_rate_limited(resp)

    # ── Evaluation run across each dataset slice, incl. real_otx ──
    @tag("evaluation", "otx", "expensive")
    @task(1)
    def evaluation_run(self) -> None:
        if self.role not in ("admin", "analyst"):
            return
        dataset_type = random.choice(EVAL_DATASET_TYPES)
        with self.client.post(
            "/api/v1/evaluation/run",
            json={"dataset_type": dataset_type, "n_records": 100, "model": "RandomForest"},
            headers=self._auth_headers,
            name="/api/v1/evaluation/run",
            catch_response=True,
        ) as resp:
            _ok_or_rate_limited(resp)

    # ── Expensive: full 4-stage pipeline run, incl. OTX ingestion ─
    @tag("pipeline", "otx", "expensive")
    @task(1)
    def pipeline_run(self) -> None:
        if self.role not in ("admin", "analyst"):
            return
        with self.client.post(
            "/api/v1/pipeline/run",
            json={
                "n_records": 500,
                "sources": ["MISP", "CIRCL", "OTX", "Synthetic"],
                "run_gat_training": True,
                "gat_epochs": 10,
            },
            headers=self._auth_headers,
            name="/api/v1/pipeline/run",
            catch_response=True,
        ) as resp:
            # 409 = pipeline already running -- also expected under load
            if resp.status_code in (200, 409, 429):
                resp.success()
            else:
                resp.failure(f"unexpected status {resp.status_code}")

    # ── Expensive: GAT retrain (admin only, rarest) ───────────────
    @tag("graph", "expensive")
    @task(1)
    def graph_train(self) -> None:
        if self.role != "admin":
            return
        with self.client.post(
            "/api/v1/graph/train",
            params={"epochs": 10},
            headers=self._auth_headers,
            name="/api/v1/graph/train",
            catch_response=True,
        ) as resp:
            _ok_or_rate_limited(resp)


class UnauthenticatedUser(HttpUser):
    """
    Small weight of traffic that never logs in — checks that protected
    routes correctly return 401 under load rather than silently degrading.
    """

    wait_time = between(2, 6)
    weight = 1

    @task
    def hit_protected_route_without_token(self) -> None:
        with self.client.get(
            "/api/v1/iocs", name="/api/v1/iocs [no-auth]", catch_response=True
        ) as resp:
            if resp.status_code == 401:
                resp.success()
            else:
                resp.failure(f"expected 401, got {resp.status_code}")
