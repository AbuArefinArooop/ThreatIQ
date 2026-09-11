"""
ThreatIQ v4.0 -- MISP Export Module (push direction)

Push-direction counterpart to MISPConnector (which pulls external CTI in).
This module publishes ThreatIQ's own output -- high-confidence classified
IoCs and flagged anomalies -- back to a MISP instance as MISP Events.
Wazuh's stock MISP integration module (var/ossec/integrations/misp.py)
then polls that same MISP instance and auto-generates detection rules
from whatever ThreatIQ publishes, closing the loop:

    CTI sources -> ThreatIQ (classify/score) -> MISP export -> Wazuh
    (detects on live traffic) -> WazuhConnector (pulls alerts back in)

Accepts records in either shape ThreatIQ uses internally:
  - raw connector dicts (external_id/text/label/severity/confidence/...),
    as returned by fetch_recent() on any connector, or
  - the app.api.v1.iocs IoCResponse model (label_confidence instead of
    confidence, plus is_anomaly), as served by GET /api/v1/iocs
so the same exporter works whether it's fed live pipeline output or the
current in-memory IoC store.

Requires: pymisp (already pinned in requirements.txt at pymisp==2.4.196).
Publishing is a no-op (returns None, logs a warning) if MISP_URL /
MISP_API_KEY aren't configured -- it never raises just because export
wasn't set up, matching the other connectors' graceful-degradation style.
"""
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Maps ThreatIQ's ioc_type vocabulary to MISP attribute types -- the
# inverse of MISPConnector's type_map.
_IOC_TYPE_TO_MISP_TYPE = {
    "IPv4 Address": "ip-dst",
    "IPv6 Address": "ip-dst",
    "Domain Name": "domain",
    "URL": "url",
    "File Hash (SHA256)": "sha256",
    "File Hash (SHA1)": "sha1",
    "File Hash (MD5)": "md5",
    "Email Address": "email-src",
    "CVE Identifier": "vulnerability",
    "Host": "hostname",
}

# Export thresholds -- only push IoCs worth turning into detection rules.
DEFAULT_MIN_CONFIDENCE = 0.75
DEFAULT_MIN_SEVERITY = 3


def _field(record: Any, *names: str, default=None):
    """Reads a field from either a raw connector dict or a Pydantic
    IoCResponse instance, trying each candidate name in turn -- lets the
    same exporter accept both record shapes ThreatIQ uses internally."""
    for name in names:
        if isinstance(record, dict):
            if name in record:
                return record[name]
        elif hasattr(record, name):
            return getattr(record, name)
    return default


def _confidence(record: Any) -> float:
    return float(_field(record, "confidence", "label_confidence", default=0.0) or 0.0)


class MISPExporter:
    """Publishes ThreatIQ-generated intelligence to a MISP instance as
    MISP Events, so MISP-consuming tools (Wazuh, OpenCTI, other ThreatIQ
    deployments) can act on ThreatIQ's classification output, not just
    the raw feeds it ingested."""

    def __init__(self, misp_url: str | None = None, misp_api_key: str | None = None, verify_ssl: bool = True):
        self.misp_url = misp_url
        self.misp_api_key = misp_api_key
        self.verify_ssl = verify_ssl
        self._live = bool(misp_url and misp_api_key)
        self._client = None
        if self._live:
            try:
                from pymisp import PyMISP
                self._client = PyMISP(misp_url, misp_api_key, verify_ssl)
                logger.info("MISP export target configured at %s", misp_url)
            except Exception as exc:
                logger.warning("MISP export client init failed (%s) -- export will no-op", exc)
                self._live = False

    def select_candidates(
        self,
        records: list[Any],
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        min_severity: int = DEFAULT_MIN_SEVERITY,
    ) -> list[Any]:
        """Filters records down to those worth exporting: confident,
        severe, and not synthetic training data."""
        return [
            r for r in records
            if _confidence(r) >= min_confidence
            and int(_field(r, "severity", default=0) or 0) >= min_severity
            and not bool(_field(r, "is_synthetic", default=False))
        ]

    def publish_iocs(
        self,
        records: list[Any],
        event_info: str = "ThreatIQ high-confidence IoCs",
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        min_severity: int = DEFAULT_MIN_SEVERITY,
    ) -> dict | None:
        """Publishes qualifying IoCs as attributes on a single new MISP
        event. Returns {"event_id", "attributes_published", "skipped"}
        summarising what happened; never raises on a missing/unreachable
        MISP target -- it logs and returns a "skipped" result instead,
        matching the other connectors' offline-graceful-degradation style."""
        candidates = self.select_candidates(records, min_confidence, min_severity)
        if not candidates:
            logger.info("MISP export: no records met confidence>=%.2f/severity>=%d", min_confidence, min_severity)
            return {"event_id": None, "attributes_published": 0, "skipped": "no_candidates"}

        if not self._live:
            logger.warning("MISP export skipped: MISP_URL/MISP_API_KEY not configured")
            return {"event_id": None, "attributes_published": 0, "skipped": "misp_not_configured"}

        from pymisp import MISPAttribute, MISPEvent

        event = MISPEvent()
        event.info = f"{event_info} ({datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC)"
        event.distribution = 0  # organisation only
        event.threat_level_id = self._max_threat_level(candidates)
        event.analysis = 2  # completed -- ThreatIQ already classified these

        added = 0
        for record in candidates:
            ioc_type = _field(record, "ioc_type", default="")
            misp_type = _IOC_TYPE_TO_MISP_TYPE.get(ioc_type, "text")
            attr = MISPAttribute()
            attr.type = misp_type
            attr.value = _field(record, "ioc_value", default="")
            attr.category = "Network activity" if misp_type in ("ip-dst", "domain", "url") else "Payload delivery"
            attr.to_ids = True
            attr.comment = (
                f"ThreatIQ: {_field(record, 'label', default='unclassified')} "
                f"(confidence={_confidence(record):.2f}, "
                f"severity={_field(record, 'severity_label', default='?')}, "
                f"source={_field(record, 'source', default='?')})"
            )
            try:
                event.add_attribute(**attr)
                added += 1
            except Exception as exc:
                logger.warning("MISP export: skipped one attribute (%s)", exc)

        try:
            result = self._client.add_event(event, pythonify=True)
        except Exception as exc:
            logger.error("MISP export failed: %s", exc)
            return {"event_id": None, "attributes_published": 0, "skipped": f"misp_error: {exc}"}

        event_id = getattr(result, "id", None)
        logger.info("MISP export: published %d attributes in event %s", added, event_id)
        return {"event_id": event_id, "attributes_published": added, "skipped": None}

    @staticmethod
    def _max_threat_level(records: list[Any]) -> int:
        """MISP threat_level_id: 1=High, 2=Medium, 3=Low, 4=Undefined
        (inverted vs ThreatIQ's own severity scale). Maps the highest
        ThreatIQ severity in the batch onto MISP's scale."""
        max_severity = max((int(_field(r, "severity", default=1) or 1) for r in records), default=1)
        if max_severity >= 5:
            return 1
        if max_severity >= 3:
            return 2
        return 3
