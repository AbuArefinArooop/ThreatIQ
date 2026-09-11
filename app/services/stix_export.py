"""
ThreatIQ v4.0 -- STIX 2.1 Export Service

Exports ThreatIQ IoC records as a standards-compliant STIX 2.1 Bundle
(OASIS Cyber Threat Intelligence TC standard -- the same interchange
format MISP, OpenCTI, and virtually every commercial CTI platform speak).
This is deliberately *general purpose*: MISPExporter (misp_export.py)
targets one specific platform's API; this module produces plain STIX 2.1
JSON that any STIX/TAXII-consuming tool can ingest, not just MISP.

Design notes:
  - Indicator IDs are UUIDv5, derived deterministically from the IoC value
    (namespaced under a fixed ThreatIQ UUID). Re-exporting the same IoC
    twice produces the same indicator--<uuid>, which is the STIX-recommended
    practice for idempotent re-publication (a consumer sees an update to
    the same object, not a duplicate).
  - `confidence` follows the STIX 2.1 spec exactly: an integer 0-100, not
    ThreatIQ's internal 0.0-1.0 float.
  - TLP markings and severity-to-score mapping reuse the exact same
    STIX_TLP_MAP / STIX_SEVERITY_SCORE constants already used by
    opencti_connector.py, so a TLP:AMBER IoC gets the same marking-definition
    ID everywhere in ThreatIQ, not two different STIX representations of
    the same real-world thing.
  - Ambiguous/non-standard observable types (e.g. "Host", a bare hostname
    with no dedicated STIX Cyber Observable type) are NOT force-fit into
    a fabricated SCO. They're exported as an annotation-only Note, clearly
    marked as such, rather than claiming false STIX compliance.
"""
import uuid
from datetime import datetime, timezone
from typing import Any

from app.connectors.opencti_connector import STIX_TLP_MAP, STIX_SEVERITY_SCORE

# Fixed namespace UUID for deriving deterministic indicator IDs -- any
# valid UUID works here, it just needs to stay constant across runs.
_THREATIQ_NAMESPACE = uuid.UUID("6f6e0c6a-7b1e-4f0a-9c3d-2e6a7c9f1b0a")

# ioc_type -> STIX 2.1 pattern template. Deliberately mirrors the inverse
# of _IOC_TYPE_TO_MISP_TYPE in misp_export.py so the two exporters agree
# on what ThreatIQ's ioc_type vocabulary means in each target format.
_STIX_PATTERN_TEMPLATES = {
    "IPv4 Address": "[ipv4-addr:value = '{value}']",
    "IPv6 Address": "[ipv6-addr:value = '{value}']",
    "Domain Name": "[domain-name:value = '{value}']",
    "URL": "[url:value = '{value}']",
    "File Hash (SHA256)": "[file:hashes.'SHA-256' = '{value}']",
    "File Hash (SHA1)": "[file:hashes.'SHA-1' = '{value}']",
    "File Hash (MD5)": "[file:hashes.MD5 = '{value}']",
    "Email Address": "[email-addr:value = '{value}']",
}

# Types handled as a Vulnerability SDO rather than an Indicator, per the
# STIX 2.1 spec's own recommendation (vulnerabilities are not observables).
_CVE_TYPES = {"CVE Identifier", "CVE"}


def _field(record: Any, *names: str, default=None):
    """Reads a field from either a raw connector dict or a Pydantic
    IoCResponse instance -- identical accessor to misp_export.py's, kept
    duplicated (not imported) so this module has zero dependency on the
    push-export module and can be used completely standalone."""
    for name in names:
        if isinstance(record, dict):
            if name in record:
                return record[name]
        elif hasattr(record, name):
            return getattr(record, name)
    return default


def _confidence_pct(record: Any) -> int:
    raw = float(_field(record, "confidence", "label_confidence", default=0.0) or 0.0)
    return max(0, min(100, round(raw * 100)))


def _indicator_id(ioc_value: str) -> str:
    return f"indicator--{uuid.uuid5(_THREATIQ_NAMESPACE, ioc_value)}"


def _note_id(ioc_value: str) -> str:
    return f"note--{uuid.uuid5(_THREATIQ_NAMESPACE, 'note:' + ioc_value)}"


def _vulnerability_id(cve_id: str) -> str:
    return f"vulnerability--{uuid.uuid5(_THREATIQ_NAMESPACE, cve_id)}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _marking_refs(tlp: str) -> list[str]:
    ref = STIX_TLP_MAP.get(tlp or "TLP:AMBER", STIX_TLP_MAP["TLP:AMBER"])
    return [ref]


def _threatiq_note(record: Any, refs: list[str]) -> dict:
    """A STIX Note carrying ThreatIQ's own analysis, linked to whatever
    SDO(s) it explains via object_refs -- keeps ThreatIQ's classification
    output attached to the indicator without inventing custom SDO fields
    that other tools wouldn't understand."""
    ioc_value = _field(record, "ioc_value", default="")
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": _note_id(ioc_value),
        "created": _now_iso(),
        "modified": _now_iso(),
        "abstract": f"ThreatIQ classification: {_field(record, 'label', default='unclassified')}",
        "content": (
            f"Source: {_field(record, 'source', default='unknown')} | "
            f"Severity: {_field(record, 'severity_label', default='?')} | "
            f"Confidence: {_confidence_pct(record)}% | "
            f"Synthetic: {bool(_field(record, 'is_synthetic', default=False))}"
        ),
        "object_refs": refs,
        "object_marking_refs": _marking_refs(_field(record, "tlp", default="TLP:AMBER")),
    }


def record_to_stix_objects(record: Any) -> list[dict]:
    """Converts a single ThreatIQ IoC record into one or more STIX 2.1
    SDOs: an Indicator (or Vulnerability for CVEs) plus an accompanying
    Note carrying ThreatIQ's classification metadata. Returns an empty
    indicator list (Note only) for ioc_types with no clean STIX Cyber
    Observable Object mapping, rather than fabricating one."""
    ioc_type = _field(record, "ioc_type", default="")
    ioc_value = _field(record, "ioc_value", default="")
    severity_label = _field(record, "severity_label", default="Medium")
    tlp = _field(record, "tlp", default="TLP:AMBER")
    marking = _marking_refs(tlp)

    if ioc_type in _CVE_TYPES:
        vuln = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": _vulnerability_id(ioc_value),
            "created": _now_iso(),
            "modified": _now_iso(),
            "name": ioc_value,
            "external_references": [{"source_name": "cve", "external_id": ioc_value}],
            "object_marking_refs": marking,
        }
        return [vuln, _threatiq_note(record, [vuln["id"]])]

    template = _STIX_PATTERN_TEMPLATES.get(ioc_type)
    if template is None:
        # No standard SCO for this type (e.g. bare "Host") -- annotate only,
        # don't claim a fabricated observable pattern.
        return [_threatiq_note(record, [])]

    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _indicator_id(ioc_value),
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": _field(record, "text", default=ioc_value)[:250],
        "description": _field(record, "text", default=""),
        "indicator_types": ["malicious-activity"],
        "pattern": template.format(value=ioc_value),
        "pattern_type": "stix",
        "valid_from": _now_iso(),
        "confidence": _confidence_pct(record),
        "labels": [_field(record, "label", default="unclassified")],
        "object_marking_refs": marking,
        "x_threatiq_severity_score": STIX_SEVERITY_SCORE.get(severity_label, 50),
    }
    return [indicator, _threatiq_note(record, [indicator["id"]])]


def build_ioc_bundle(records: list[Any], exclude_synthetic: bool = True) -> dict:
    """Builds a single STIX 2.1 Bundle from a list of ThreatIQ IoC records.

    exclude_synthetic=True (the default) drops records flagged
    is_synthetic -- training data shouldn't be exported as if it were
    real threat intelligence; this mirrors the same exclusion MISPExporter
    applies before publishing.
    """
    objects: list[dict] = []
    for record in records:
        if exclude_synthetic and bool(_field(record, "is_synthetic", default=False)):
            continue
        objects.extend(record_to_stix_objects(record))

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
