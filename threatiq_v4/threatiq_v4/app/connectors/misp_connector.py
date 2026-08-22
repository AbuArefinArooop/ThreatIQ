"""
ThreatIQ v4.0 -- MISP Connector
Fetches real IoC events from a MISP instance via PyMISP.
Falls back to realistic offline test data when credentials are absent.
Setup:  Set MISP_URL and MISP_API_KEY in .env
"""
import logging
from datetime import datetime, timedelta
from typing import Any

logger = logging.getLogger(__name__)

MISP_THREAT_CATEGORIES = {
    "malware": "Malware", "ransomware": "Ransomware", "phishing": "Phishing",
    "apt": "APT", "ddos": "DDoS", "intrusion": "APT",
    "vulnerability": "Zero-Day", "fraud": "Credential Stuffing",
    "network activity": "DDoS", "payload delivery": "Malware",
}

OFFLINE_SAMPLE_EVENTS = [
    {"id": "MISP-OFFLINE-001", "info": "Emotet botnet C2 IPs observed in EU financial sector",
     "threat_level_id": "1", "distribution": "1", "timestamp": "1704067200",
     "Attribute": [
         {"type": "ip-dst", "value": "185.220.101.47", "category": "Network activity",
          "comment": "Emotet C2 server", "to_ids": True},
         {"type": "domain", "value": "evil-update.net", "category": "Network activity",
          "comment": "Emotet loader domain", "to_ids": True},
     ]},
    {"id": "MISP-OFFLINE-002", "info": "LockBit 3.0 ransomware sample -- healthcare sector targeting",
     "threat_level_id": "1", "distribution": "1", "timestamp": "1704153600",
     "Attribute": [
         {"type": "sha256", "value": "a3f4e2b1c8d9e7f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5a6b7",
          "category": "Payload delivery", "comment": "LockBit 3.0 encryptor", "to_ids": True},
     ]},
    {"id": "MISP-OFFLINE-003", "info": "APT29 spear-phishing campaign against government entities",
     "threat_level_id": "1", "distribution": "1", "timestamp": "1704240000",
     "Attribute": [
         {"type": "domain", "value": "secure-update-portal.com", "category": "Network activity",
          "comment": "APT29 phishing domain", "to_ids": True},
         {"type": "email-src", "value": "noreply@secure-update-portal.com",
          "category": "Payload delivery", "comment": "Phishing sender", "to_ids": True},
     ]},
]


def _map_misp_attribute_to_ioc(attr: dict, event: dict) -> dict | None:
    """Convert a single MISP attribute to a ThreatIQ IoC dict."""
    attr_type = attr.get("type", "")
    value = attr.get("value", "")
    if not value or not attr.get("to_ids", False):
        return None

    type_map = {
        "ip-dst": "IPv4 Address", "ip-src": "IPv4 Address",
        "domain": "Domain Name", "hostname": "Domain Name",
        "url": "URL", "sha256": "File Hash (SHA256)",
        "sha1": "File Hash (SHA1)", "md5": "File Hash (MD5)",
        "email-src": "Email Address", "vulnerability": "CVE Identifier",
        "filename|sha256": "File Hash (SHA256)",
    }
    ioc_type = type_map.get(attr_type)
    if not ioc_type:
        return None

    category = attr.get("category", "").lower()
    info = event.get("info", "")
    threat_level = int(event.get("threat_level_id", 2))
    severity = max(1, 5 - threat_level)  # MISP: 1=High -> severity 4, 4=Undefined -> 1
    label = MISP_THREAT_CATEGORIES.get(category, "Malware")
    if "ransom" in info.lower():
        label = "Ransomware"
    elif "phish" in info.lower():
        label = "Phishing"
    elif "apt" in info.lower() or "apt29" in info.lower():
        label = "APT"
    elif "ddos" in info.lower():
        label = "DDoS"

    return {
        "external_id": f"{event['id']}-{attr.get('uuid', attr_type)}",
        "text": f"{info} -- {attr.get('comment', '')} [{attr_type}: {value}]",
        "label": label,
        "severity": severity,
        "severity_label": {1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}[severity],
        "confidence": 0.85,
        "source": "MISP",
        "source_trust": 0.90,
        "ioc_value": value,
        "ioc_type": ioc_type,
        "tlp": "TLP:AMBER",
        "is_synthetic": False,
        "raw_payload": {"event_id": event["id"], "attribute": attr},
    }


class MISPConnector:
    """
    Real MISP connector.  When MISP_URL / MISP_API_KEY are set, fetches live data.
    Otherwise returns OFFLINE_SAMPLE_EVENTS for development / testing.
    """

    def __init__(self, url: str | None = None, api_key: str | None = None, verify_ssl: bool = True):
        self.url = url
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self._client = None
        self._live = bool(url and api_key)
        if self._live:
            try:
                from pymisp import PyMISP
                self._client = PyMISP(url, api_key, verify_ssl)
                logger.info("MISP live connection established at %s", url)
            except Exception as exc:
                logger.warning("MISP connection failed (%s) -- falling back to offline data", exc)
                self._live = False

    def fetch_recent(self, days_back: int = 7, limit: int = 500) -> list[dict]:
        """Fetch IoCs published in the last `days_back` days."""
        if self._live:
            return self._fetch_live(days_back, limit)
        logger.info("MISP offline mode -- returning %d sample events", len(OFFLINE_SAMPLE_EVENTS))
        return self._parse_events(OFFLINE_SAMPLE_EVENTS)

    def _fetch_live(self, days_back: int, limit: int) -> list[dict]:
        since = (datetime.utcnow() - timedelta(days=days_back)).strftime("%Y-%m-%d")
        try:
            result = self._client.search(
                controller="attributes", published=True,
                date_from=since, to_ids=True, limit=limit,
                includeEventTags=True, pythonify=True
            )
            logger.info("MISP returned %d attributes", len(result))
            iocs = []
            for attr in result:
                event_data = {
                    "id": str(attr.event_id),
                    "info": getattr(attr, "Event", {}).get("info", ""),
                    "threat_level_id": getattr(attr, "Event", {}).get("threat_level_id", "2"),
                    "distribution": "1",
                    "timestamp": str(attr.timestamp.timestamp()) if hasattr(attr, "timestamp") else "0",
                }
                attr_dict = {
                    "type": attr.type, "value": attr.value,
                    "category": attr.category, "comment": attr.comment or "",
                    "to_ids": attr.to_ids, "uuid": attr.uuid,
                }
                ioc = _map_misp_attribute_to_ioc(attr_dict, event_data)
                if ioc:
                    iocs.append(ioc)
            return iocs
        except Exception as exc:
            logger.error("MISP live fetch error: %s", exc)
            return []

    def _parse_events(self, events: list[dict]) -> list[dict]:
        iocs = []
        for event in events:
            for attr in event.get("Attribute", []):
                ioc = _map_misp_attribute_to_ioc(attr, event)
                if ioc:
                    iocs.append(ioc)
        return iocs
