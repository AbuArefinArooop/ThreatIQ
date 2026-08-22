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
    else:
        raise HTTPException(404, f"Unknown connector: {connector_name}")
    _last_fetch[name] = {
        "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "count": len(iocs),
    }
    audit_log.log(user.user_id, user.tenant_id, "manual_fetch", "connectors",
                  details={"connector":connector_name,"fetched":len(iocs)})
    return {"connector":connector_name,"fetched":len(iocs),"sample":iocs[:2]}

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
