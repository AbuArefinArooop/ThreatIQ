"""
ThreatIQ v4.0 -- Wazuh SIEM Connector (pull direction)

Treats Wazuh alerts as another CTI source, following the exact same
interface every other connector uses: fetch_recent(limit) -> list[dict].
This is the "SIEM" half of the ThreatIQ <-> SIEM integration loop; the
other half is misp_export.py, which pushes ThreatIQ's own classified
IoCs out to MISP for Wazuh's own MISP integration module to consume.

Why Wazuh specifically: it's free, open-source, Docker-friendly, and
ships a REST-queryable indexer (OpenSearch-compatible) plus a built-in
MISP integration module -- no bespoke glue code needed on the Wazuh side.

Offline mode returns realistic sample alerts (mirrors the offline-fallback
contract of MISPConnector / CIRCLConnector / OTXConnector) so the rest of
the pipeline (classification, GAT, evaluation) can be exercised without a
live Wazuh stack running.

Setup: Set WAZUH_INDEXER_URL / WAZUH_API_USERNAME / WAZUH_API_PASSWORD in .env
Auth:  HTTP basic auth against the Wazuh indexer's OpenSearch-compatible API
API:   https://documentation.wazuh.com/current/user-manual/api/reference.html
"""
import logging

logger = logging.getLogger(__name__)

SEVERITY_LABELS = {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}

# Wazuh's rule.level runs 0-15. Mapped onto ThreatIQ's 1-5 ordinal scale,
# same style as OTX's vote-count mapping and MISP's threat_level_id mapping.
_LEVEL_THRESHOLDS = [(12, 5), (9, 4), (6, 3), (3, 2)]

# Below this rule.level, alerts are typically noise (successful logins,
# routine syscheck diffs) and would just dilute the classifier's training
# pool rather than add signal.
_MIN_RULE_LEVEL = 5

WAZUH_OFFLINE_SAMPLES = [
    {"id": "WAZUH-OFFLINE-001", "label": "Credential Stuffing",
     "text": "Wazuh alert: multiple authentication failures followed by a success from the same source",
     "ioc_value": "198.51.100.23", "ioc_type": "IPv4 Address", "severity": 4,
     "groups": ["authentication_failed", "pci_dss_10.2.4"]},
    {"id": "WAZUH-OFFLINE-002", "label": "Malware",
     "text": "Wazuh alert: file integrity monitoring detected unauthorized modification of a system binary",
     "ioc_value": "web-app-03", "ioc_type": "Host", "severity": 5,
     "groups": ["syscheck", "rootcheck"]},
    {"id": "WAZUH-OFFLINE-003", "label": "APT",
     "text": "Wazuh alert: outbound connection matched against known command-and-control infrastructure",
     "ioc_value": "203.0.113.77", "ioc_type": "IPv4 Address", "severity": 5,
     "groups": ["intrusion_detection", "threat_intel_match"]},
    {"id": "WAZUH-OFFLINE-004", "label": "DDoS",
     "text": "Wazuh alert: abnormal spike in inbound connection rate consistent with a SYN flood",
     "ioc_value": "192.0.2.15", "ioc_type": "IPv4 Address", "severity": 3,
     "groups": ["network_ids", "flood_detected"]},
]


def _label_from_groups(groups: list[str], description: str) -> str:
    haystack = f"{' '.join(groups)} {description}".lower()
    if "ransom" in haystack:
        return "Ransomware"
    if "phish" in haystack:
        return "Phishing"
    if "threat_intel_match" in haystack or "apt" in haystack:
        return "APT"
    if "flood" in haystack or "ddos" in haystack:
        return "DDoS"
    if "authentication_fail" in haystack or "brute" in haystack:
        return "Credential Stuffing"
    if "syscheck" in haystack or "rootcheck" in haystack:
        return "Malware"
    return "Malware"


def _severity_from_level(level: int) -> int:
    for threshold, severity in _LEVEL_THRESHOLDS:
        if level >= threshold:
            return severity
    return 1


def _confidence_from_level(level: int) -> float:
    return round(min(0.5 + level / 30, 0.95), 2)


def _extract_ioc(alert_data: dict, agent_name: str) -> tuple[str, str]:
    """Best-effort extraction of the most relevant observable from a Wazuh
    alert document, falling back through the fields Wazuh most commonly
    populates, in order of specificity."""
    if alert_data.get("srcip"):
        return alert_data["srcip"], "IPv4 Address"
    if alert_data.get("dstip"):
        return alert_data["dstip"], "IPv4 Address"
    if alert_data.get("url"):
        return alert_data["url"], "URL"
    if agent_name:
        return agent_name, "Host"
    return "unknown", "Host"


class WazuhConnector:
    """
    Wazuh SIEM connector (pull). Live mode queries the Wazuh indexer's
    OpenSearch-compatible search API for recent high-severity alerts.
    Offline mode returns curated sample alerts.
    """

    SOURCE_NAME = "Wazuh SIEM"

    def __init__(
        self,
        indexer_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
    ):
        self.indexer_url = (indexer_url or "").rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self._live = bool(indexer_url and username and password)
        if self._live:
            logger.info("Wazuh live mode configured at %s", self.indexer_url)
        else:
            logger.info("Wazuh offline mode -- using curated sample alerts")

    def fetch_recent(self, limit: int = 100) -> list[dict]:
        if self._live:
            return self._fetch_live(limit)
        return self._enrich_offline(limit)

    def _fetch_live(self, limit: int) -> list[dict]:
        """Live Wazuh fetch: queries the indexer for alerts at or above
        the minimum rule level, sorted newest first. Falls back to the
        offline sample if the indexer is unreachable, mirroring OTX's
        fall-through-to-offline behaviour on any live-fetch error."""
        import httpx
        query = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"range": {"rule.level": {"gte": _MIN_RULE_LEVEL}}},
        }
        try:
            with httpx.Client(
                auth=(self.username, self.password),
                verify=self.verify_ssl,
                timeout=10.0,
            ) as client:
                resp = client.post(f"{self.indexer_url}/wazuh-alerts-*/_search", json=query)
                if resp.status_code == 200:
                    hits = resp.json().get("hits", {}).get("hits", [])
                    if hits:
                        return self._parse_hits(hits, limit)
                    logger.info("Wazuh indexer returned zero matching alerts")
                else:
                    logger.warning("Wazuh indexer returned %d", resp.status_code)
        except Exception as exc:
            logger.error("Wazuh live fetch error: %s", exc)
        return self._enrich_offline(limit)

    def _parse_hits(self, hits: list[dict], limit: int) -> list[dict]:
        iocs = []
        for hit in hits:
            alert = hit.get("_source", {})
            rule = alert.get("rule", {}) or {}
            level = int(rule.get("level", 0))
            severity = _severity_from_level(level)
            data = alert.get("data", {}) or {}
            agent = (alert.get("agent", {}) or {}).get("name", "")
            ioc_value, ioc_type = _extract_ioc(data, agent)
            description = rule.get("description", "Wazuh alert")
            groups = rule.get("groups", [])
            iocs.append({
                "external_id": hit.get("_id", f"wazuh-{level}-{ioc_value}"),
                "text": description,
                "label": _label_from_groups(groups, description),
                "severity": severity,
                "severity_label": SEVERITY_LABELS[severity],
                "confidence": _confidence_from_level(level),
                "source": self.SOURCE_NAME,
                "source_trust": 0.90,
                "ioc_value": ioc_value,
                "ioc_type": ioc_type,
                "tlp": "TLP:AMBER",  # internal telemetry, not for public sharing
                "is_synthetic": False,
                "raw_payload": alert,
            })
            if len(iocs) >= limit:
                break
        return iocs

    def _enrich_offline(self, limit: int = 100) -> list[dict]:
        return [{
            "external_id": s["id"],
            "text": s["text"],
            "label": s["label"],
            "severity": s["severity"],
            "severity_label": SEVERITY_LABELS[s["severity"]],
            "confidence": 0.80,
            "source": self.SOURCE_NAME,
            "source_trust": 0.90,
            "ioc_value": s["ioc_value"],
            "ioc_type": s["ioc_type"],
            "tlp": "TLP:AMBER",
            "is_synthetic": False,
            "raw_payload": s,
        } for s in WAZUH_OFFLINE_SAMPLES[:limit]]
