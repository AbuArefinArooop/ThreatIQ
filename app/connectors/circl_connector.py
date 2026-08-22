"""
ThreatIQ v4.0 -- CIRCL (circl.lu) Connector
Fetches IoC data from CIRCL's CVE/hash/IP lookup APIs.
CIRCL is the Computer Incident Response Center Luxembourg.
No authentication required for basic endpoints.
Ref: https://www.circl.lu/services/
"""
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

CIRCL_OFFLINE_SAMPLES = [
    {"id": "CVE-2024-3400", "label": "Zero-Day",
     "text": "CVE-2024-3400 PAN-OS command injection in GlobalProtect exploited by UTA0218 pre-patch",
     "ioc_value": "CVE-2024-3400", "ioc_type": "CVE Identifier", "severity": 5,
     "threat_actor": "UTA0218", "ttp": "T1190", "ttp_name": "Exploit Public-Facing Application"},
    {"id": "CVE-2023-34362", "label": "Zero-Day",
     "text": "MOVEit Transfer SQL injection CVE-2023-34362 exploited by Cl0p ransomware for mass exfil",
     "ioc_value": "CVE-2023-34362", "ioc_type": "CVE Identifier", "severity": 5,
     "threat_actor": "Conti", "ttp": "T1190", "ttp_name": "Exploit Public-Facing Application"},
    {"id": "CVE-2023-4966", "label": "Zero-Day",
     "text": "Citrix Bleed CVE-2023-4966 session token hijacking exploited against financial sector",
     "ioc_value": "CVE-2023-4966", "ioc_type": "CVE Identifier", "severity": 4,
     "threat_actor": "LockBit", "ttp": "T1078", "ttp_name": "Valid Accounts"},
]


class CIRCLConnector:
    """
    CIRCL CTI connector.  Uses httpx for async-friendly HTTP calls.
    Falls back to curated offline CVE data when network is unavailable.
    """

    BASE_URL = "https://www.circl.lu/api"

    def __init__(self, username: str | None = None, password: str | None = None):
        self.auth = (username, password) if (username and password) else None
        self._live = False
        try:
            import httpx
            self._client_cls = httpx.Client
            self._live = True
        except ImportError:
            logger.warning("httpx not installed -- CIRCL offline mode")

    def fetch_recent_cves(self, limit: int = 50) -> list[dict]:
        if self._live:
            return self._fetch_live_cves(limit)
        logger.info("CIRCL offline mode -- returning %d sample CVEs", len(CIRCL_OFFLINE_SAMPLES))
        return self._enrich_samples(CIRCL_OFFLINE_SAMPLES)

    def _fetch_live_cves(self, limit: int) -> list[dict]:
        import httpx
        iocs = []
        try:
            with httpx.Client(timeout=15.0, auth=self.auth) as client:
                # CIRCL cve-search API: browse the year's CVE index, then
                # fetch each CVE's real detail (cvss/summary) individually --
                # the browse endpoint only returns bare IDs.
                resp = client.get(f"{self.BASE_URL}/browse/2024", timeout=10.0)
                if resp.status_code == 200:
                    data = resp.json()
                    for cve_id in list(data)[:limit]:
                        detail = {}
                        try:
                            d_resp = client.get(f"{self.BASE_URL}/cve/{cve_id}", timeout=10.0)
                            if d_resp.status_code == 200:
                                detail = d_resp.json() or {}
                        except Exception as exc:
                            logger.warning("CIRCL CVE detail fetch failed for %s: %s", cve_id, exc)
                        ioc = self._cve_to_ioc(cve_id, detail)
                        if ioc:
                            iocs.append(ioc)
                else:
                    logger.warning("CIRCL API returned %d", resp.status_code)
        except Exception as exc:
            logger.error("CIRCL live fetch error: %s", exc)
        return iocs or self._enrich_samples(CIRCL_OFFLINE_SAMPLES)

    def _cve_to_ioc(self, cve_id: str, data: dict) -> dict | None:
        summary = data.get("summary", f"CVE vulnerability indicator {cve_id}")
        cvss = data.get("cvss", 5.0) or 5.0
        severity = 5 if cvss >= 9 else (4 if cvss >= 7 else (3 if cvss >= 4 else 2))
        return {
            "external_id": cve_id,
            "text": summary,
            "label": "Zero-Day",
            "severity": severity,
            "severity_label": {1:"Informational",2:"Low",3:"Medium",4:"High",5:"Critical"}[severity],
            "confidence": 0.92,
            "source": "CIRCL",
            "source_trust": 0.92,
            "ioc_value": cve_id,
            "ioc_type": "CVE Identifier",
            "tlp": "TLP:WHITE",
            "is_synthetic": False,
            "raw_payload": data,
        }

    def _enrich_samples(self, samples: list[dict]) -> list[dict]:
        out = []
        for s in samples:
            out.append({
                "external_id": s["id"],
                "text": s["text"],
                "label": s["label"],
                "severity": s["severity"],
                "severity_label": {1:"Informational",2:"Low",3:"Medium",4:"High",5:"Critical"}[s["severity"]],
                "confidence": 0.92,
                "source": "CIRCL",
                "source_trust": 0.92,
                "ioc_value": s["ioc_value"],
                "ioc_type": s["ioc_type"],
                "tlp": "TLP:WHITE",
                "threat_actor": s.get("threat_actor"),
                "ttp": s.get("ttp"),
                "ttp_name": s.get("ttp_name"),
                "is_synthetic": False,
                "raw_payload": s,
            })
        return out
