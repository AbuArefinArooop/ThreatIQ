"""
IoC endpoints -- fully secured and validated.
"""
import math
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, field_validator
from app.core.security import (
    get_current_user, CurrentUser, filter_by_tlp,
    sanitise_query_param, default_limiter, rate_limit,
    audit_log, require_role
)

router = APIRouter()


class IoCResponse(BaseModel):
    id: str
    text: str
    label: str
    label_confidence: float
    severity: int
    severity_label: str
    source: str
    ioc_value: str
    ioc_type: str
    tlp: str
    is_anomaly: bool
    anomaly_score: float
    is_synthetic: bool
    threat_actor: str | None = None
    ttp: str | None = None
    model_config = {"from_attributes": True}


class IoCListResponse(BaseModel):
    total: int
    page: int
    per_page: int
    pages: int
    data: list[IoCResponse]


_MOCK_IOCS = [
    IoCResponse(
        id=f"ioc-{i:05d}",
        text=["Emotet C2 beacon over HTTPS to 185.220.101.x","LockBit 3.0 encryptor SHA256 sample",
              "APT29 spear-phishing domain registered 2024-11","Cl0p MOVEit data exfil IP",
              "AsyncRAT C2 server in bulletproof hosting"][i%5],
        label=["Malware","Ransomware","APT","Ransomware","Malware"][i%5],
        label_confidence=round(0.82+0.01*(i%10),3),
        severity=(i%5)+1,
        severity_label=["Informational","Low","Medium","High","Critical"][i%5],
        source=["MISP","CIRCL","OTX AlienVault","Internal SIEM","VirusTotal"][i%5],
        ioc_value=[f"185.220.{i%200+10}.{i%254+1}",
                   f"a3f4e{i:04x}b1c8d9e7f0a1b2c3d4e5f6{i:08x}",
                   f"secure-update-{i:04d}.net",
                   f"198.51.{i%200}.{i%254+1}",
                   f"3b4c5d{i:04x}a7b8c9d0e1f2a3b4c5d6e7"][i%5],
        ioc_type=["IPv4 Address","File Hash (SHA256)","Domain Name","IPv4 Address","File Hash (SHA256)"][i%5],
        tlp=["TLP:AMBER","TLP:RED","TLP:AMBER","TLP:GREEN","TLP:WHITE"][i%5],
        is_anomaly=(i%20==0),
        anomaly_score=round(0.05+0.04*(i%20),3),
        is_synthetic=False,
        threat_actor=["None","LockBit","APT29","Cl0p","Lazarus"][i%5].replace("None","") or None,
        ttp=["T1071","T1486","T1566","T1190","T1059"][i%5],
    )
    for i in range(1, 201)
]


@router.get("", response_model=IoCListResponse, summary="List and search IoCs")
async def list_iocs(
    request: Request,
    q: str | None = Query(None, max_length=256),
    label: str | None = Query(None, max_length=64),
    severity: int | None = Query(None, ge=1, le=5),
    source: str | None = Query(None, max_length=64),
    tlp: str | None = Query(None, pattern="^TLP:(WHITE|GREEN|AMBER|RED)$"),
    is_anomaly: bool | None = Query(None),
    is_synthetic: bool | None = Query(None),
    page: int = Query(1, ge=1, le=10000),
    per_page: int = Query(50, ge=1, le=500),
    user: CurrentUser = Depends(get_current_user),
    _rl=Depends(rate_limit(default_limiter)),
):
    # Sanitise free-text query
    if q:
        try: q = sanitise_query_param(q)
        except ValueError as e:
            raise HTTPException(400, f"Invalid query: {e}")

    records = _MOCK_IOCS
    # TLP access control
    records = [r for r in records
               if {"TLP:WHITE":0,"TLP:GREEN":1,"TLP:AMBER":2,"TLP:RED":3}.get(r.tlp,0)
               <= {"TLP:WHITE":0,"TLP:GREEN":1,"TLP:AMBER":2,"TLP:RED":3}.get(user.max_tlp,0)]

    if label:   records = [r for r in records if r.label == label]
    if severity: records = [r for r in records if r.severity == severity]
    if source:  records = [r for r in records if r.source == source]
    if tlp:     records = [r for r in records if r.tlp == tlp]
    if is_anomaly is not None:   records = [r for r in records if r.is_anomaly == is_anomaly]
    if is_synthetic is not None: records = [r for r in records if r.is_synthetic == is_synthetic]
    if q:
        ql = q.lower()
        records = [r for r in records if ql in r.ioc_value.lower()
                   or ql in r.label.lower() or ql in r.source.lower()
                   or ql in r.text.lower()]

    total  = len(records)
    start  = (page-1)*per_page
    audit_log.log(user.user_id, user.tenant_id, "list_iocs", "iocs",
                  details={"total":total,"filters":{"q":q,"label":label}})
    return IoCListResponse(
        total=total, page=page, per_page=per_page,
        pages=math.ceil(total/per_page) if total else 1,
        data=records[start:start+per_page],
    )


@router.get("/{ioc_id}", response_model=IoCResponse, summary="Get single IoC")
async def get_ioc(
    request: Request,
    ioc_id: str,
    user: CurrentUser = Depends(get_current_user),
    _rl=Depends(rate_limit(default_limiter)),
):
    # Validate ioc_id format to prevent path traversal / injection
    import re
    if not re.match(r"^ioc-[0-9]{5}$", ioc_id):
        raise HTTPException(400, "Invalid IoC ID format")
    idx = int(ioc_id.split("-")[1])
    if idx < 1 or idx > len(_MOCK_IOCS):
        raise HTTPException(404, "IoC not found")
    ioc = _MOCK_IOCS[idx-1]
    # TLP check
    if {"TLP:WHITE":0,"TLP:GREEN":1,"TLP:AMBER":2,"TLP:RED":3}.get(ioc.tlp,0) >        {"TLP:WHITE":0,"TLP:GREEN":1,"TLP:AMBER":2,"TLP:RED":3}.get(user.max_tlp,0):
        raise HTTPException(403, "Insufficient TLP clearance for this record")
    return ioc
