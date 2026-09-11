"""CTI connector status and manual fetch -- admin only for writes."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from app.core.security import get_current_user, CurrentUser, require_role, default_limiter, strict_limiter, rate_limit, audit_log

router = APIRouter()

class ConnectorStatus(BaseModel):
    name: str; live_mode: bool; status: str
    last_run: str | None = None; records_last_run: int = 0

# In-memory record of the last manual fetch per connector (dev store --
# production would persist this on the connectors/runs table).
_last_fetch: dict[str, dict] = {}

@router.get("", response_model=list[ConnectorStatus], summary="List connector statuses")
async def list_connectors(
    user: CurrentUser = Depends(get_current_user),
    _rl=Depends(rate_limit(default_limiter)),
):
    from app.core.config import settings
    defs = [
        ("MISP",    bool(settings.MISP_URL)),
        ("CIRCL",   True),
        ("OTX",     bool(settings.OTX_API_KEY)),
        ("WAZUH",   bool(settings.WAZUH_INDEXER_URL and settings.WAZUH_API_USERNAME)),
        ("OpenCTI", bool(settings.OPENCTI_URL)),
    ]
    out = []
    for name, live in defs:
        last = _last_fetch.get(name, {})
        out.append(ConnectorStatus(
            name=name, live_mode=live, status="live" if live else "offline",
            last_run=last.get("at"), records_last_run=last.get("count", 0),
        ))
    return out

@router.post("/{connector_name}/fetch", summary="Trigger manual fetch (admin only)")
async def manual_fetch(
    request: Request,
    connector_name: str,
    limit: int = 100,
    user: CurrentUser = Depends(require_role("admin")),
    _rl=Depends(rate_limit(strict_limiter)),
):
    import re
    if not re.match(r"^[A-Z0-9_-]{2,20}$", connector_name):
        raise HTTPException(400, "Invalid connector name")
    if not 1 <= limit <= 1000:
        raise HTTPException(400, "limit must be 1-1000")
    from app.core.config import settings
    name = connector_name.upper()
    if name == "MISP":
        from app.connectors.misp_connector import MISPConnector
        iocs = MISPConnector(settings.MISP_URL, settings.MISP_API_KEY).fetch_recent(limit=limit)
    elif name == "CIRCL":
        from app.connectors.circl_connector import CIRCLConnector
        iocs = CIRCLConnector(settings.CIRCL_USERNAME, settings.CIRCL_PASSWORD).fetch_recent_cves(limit=limit)
    elif name == "OTX":
        from app.connectors.otx_connector import OTXConnector
        iocs = OTXConnector(settings.OTX_API_KEY, settings.OTX_API_URL).fetch_recent(limit=limit)
    elif name == "WAZUH":
        from app.connectors.wazuh_connector import WazuhConnector
        iocs = WazuhConnector(
            settings.WAZUH_INDEXER_URL, settings.WAZUH_API_USERNAME,
            settings.WAZUH_API_PASSWORD, settings.WAZUH_VERIFY_SSL,
        ).fetch_recent(limit=limit)
    else:
        raise HTTPException(404, f"Unknown connector: {connector_name}")
    _last_fetch[name] = {
        "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "count": len(iocs),
    }
    audit_log.log(user.user_id, user.tenant_id, "manual_fetch", "connectors",
                  details={"connector":connector_name,"fetched":len(iocs)})
    return {"connector":connector_name,"fetched":len(iocs),"sample":iocs[:2]}

@router.post("/correlate", summary="Fetch from all configured connectors and correlate overlapping IoCs")
async def correlate_connectors(
    request: Request,
    limit_per_source: int = 50,
    user: CurrentUser = Depends(require_role("admin", "analyst")),
    _rl=Depends(rate_limit(strict_limiter)),
):
    """
    Pulls a fresh batch from every connector (MISP, CIRCL, OTX, WAZUH --
    each in whatever mode it's currently configured for, live or offline),
    then runs cross-source correlation: the same observable reported by
    multiple independent sources gets its confidence boosted rather than
    just appearing as separate duplicate records. This is the core
    mechanic that makes a correlation engine like MISP's genuinely more
    useful than a plain aggregator -- corroboration across sources is
    itself evidence, on top of whatever each individual source reported.

    Read-only: does not feed into classification/GAT (that path stays on
    POST /pipeline/run, whose reported metrics match the numbers cited in
    the accompanying research paper and shouldn't shift silently). This
    endpoint exists to make correlation visible and inspectable on its
    own, not to alter the tested pipeline's behaviour.
    """
    from app.connectors.misp_connector import MISPConnector
    from app.connectors.circl_connector import CIRCLConnector
    from app.connectors.otx_connector import OTXConnector
    from app.connectors.wazuh_connector import WazuhConnector
    from app.services.correlation import correlate_iocs
    from app.core.config import settings

    fetched: list[dict] = []
    per_source_counts: dict[str, int] = {}

    fetchers = [
        ("MISP", lambda: MISPConnector(settings.MISP_URL, settings.MISP_API_KEY, settings.MISP_VERIFY_SSL).fetch_recent(limit=limit_per_source)),
        ("CIRCL", lambda: CIRCLConnector(settings.CIRCL_USERNAME, settings.CIRCL_PASSWORD).fetch_recent_cves(limit=limit_per_source)),
        ("OTX", lambda: OTXConnector(settings.OTX_API_KEY, settings.OTX_API_URL).fetch_recent(limit=limit_per_source)),
        ("WAZUH", lambda: WazuhConnector(settings.WAZUH_INDEXER_URL, settings.WAZUH_API_USERNAME,
                                          settings.WAZUH_API_PASSWORD, settings.WAZUH_VERIFY_SSL).fetch_recent(limit=limit_per_source)),
    ]
    for name, fetch in fetchers:
        try:
            iocs = fetch()
            fetched.extend(iocs)
            per_source_counts[name] = len(iocs)
        except Exception as exc:
            per_source_counts[name] = 0
            fetched_error = str(exc)  # noqa: F841 -- surfaced via per_source_counts=0, not raised

    correlated = correlate_iocs(fetched)
    multi_source = [r for r in correlated if r["source_count"] > 1]

    result = {
        "fetched_total": len(fetched),
        "per_source_counts": per_source_counts,
        "unique_observables": len(correlated),
        "corroborated_observables": len(multi_source),
        "correlated": correlated,
    }
    audit_log.log(user.user_id, user.tenant_id, "correlate_connectors", "connectors",
                  details={"fetched_total": len(fetched), "corroborated": len(multi_source)})
    return result


@router.post("/misp/export", summary="Export high-confidence IoCs to MISP (admin only)")
async def export_to_misp(
    request: Request,
    min_confidence: float = 0.75,
    min_severity: int = 3,
    user: CurrentUser = Depends(require_role("admin")),
    _rl=Depends(rate_limit(strict_limiter)),
):
    """
    Push side of the SIEM integration loop: filters the current IoC store
    down to records that are confident, severe, and not synthetic training
    data, then publishes them as a MISP event via MISPExporter. Wazuh's own
    MISP integration module (configured separately, on the Wazuh side)
    polls that event and auto-generates detection rules from it.

    Deliberately a distinct, admin-only, manually-triggered action rather
    than something that fires automatically after every pipeline run --
    publishing to an external system should be an explicit choice, not a
    side effect.
    """
    if not 0.0 <= min_confidence <= 1.0:
        raise HTTPException(400, "min_confidence must be between 0.0 and 1.0")
    if not 1 <= min_severity <= 5:
        raise HTTPException(400, "min_severity must be between 1 and 5")

    from app.connectors.misp_export import MISPExporter
    from app.api.v1.iocs import _MOCK_IOCS
    from app.core.config import settings

    exporter = MISPExporter(settings.MISP_URL, settings.MISP_API_KEY, settings.MISP_VERIFY_SSL)
    result = exporter.publish_iocs(
        _MOCK_IOCS,
        event_info="ThreatIQ high-confidence IoCs",
        min_confidence=min_confidence,
        min_severity=min_severity,
    )
    audit_log.log(user.user_id, user.tenant_id, "misp_export", "connectors",
                  details={"min_confidence": min_confidence, "min_severity": min_severity, **result})
    return result


@router.post("/opencti/enrich", summary="Test OpenCTI enrichment (admin only)")
async def enrich_test(
    request: Request,
    user: CurrentUser = Depends(require_role("admin")),
    _rl=Depends(rate_limit(strict_limiter)),
):
    from app.connectors.opencti_connector import ThreatIQOpenCTIConnector
    from app.core.config import settings
    connector = ThreatIQOpenCTIConnector(settings)
    result = connector.test_enrichment_offline()
    audit_log.log(user.user_id, user.tenant_id, "opencti_enrich_test", "connectors")
    return result
