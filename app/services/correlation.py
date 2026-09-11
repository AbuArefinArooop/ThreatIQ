"""
ThreatIQ v4.0 -- Cross-Source IoC Correlation

Independent corroboration is one of the oldest principles in intelligence
analysis: a fact confirmed by two unrelated sources is more credible than
the same fact from one source repeated twice (see e.g. the Admiralty/NATO
System's separate reliability/credibility axes, and the "redundant
information adds value... corroboration is often important" principle
in classical CTI collection doctrine). This is also the mechanical core
of what makes MISP/OpenCTI valuable as *correlation* engines rather than
just aggregators: the same IP seen in an OTX pulse AND a Wazuh alert AND
a MISP event is a stronger signal than any one of those alone.

This module is a pure, side-effect-free function -- no I/O, no database,
no dependency on any specific connector -- so it works identically
whether fed live connector output or offline samples, and is trivially
unit-testable.

Deliberately NOT wired into the default pipeline path: pipeline.py's
classification/GAT stages are already tested and their reported metrics
match the numbers cited in the IEEE paper. Correlation changes record
*counts* (merging duplicates), so it's exposed as a separate, opt-in
step (see POST /api/v1/connectors/correlate) rather than silently
altering pipeline.py's existing, verified behaviour.
"""
from typing import Any

# Confidence bonus per additional corroborating source, applied
# multiplicatively to the remaining "headroom" below 1.0 -- i.e. each
# extra source closes some of the gap to full confidence rather than
# adding a flat amount (which would let enough low-quality sources
# artificially reach 100% confidence).
_CORROBORATION_FACTOR = 0.35

# Confidence bonus caps out after this many independent sources -- beyond
# this, additional "confirmations" are assumed to be noise/redundant
# reporting of the same underlying feed rather than genuinely new signal.
_MAX_CORROBORATING_SOURCES = 4


def _field(record: Any, *names: str, default=None):
    """Reads a field from either a raw connector dict or an object with
    attributes -- same dual-accessor pattern used by misp_export.py and
    stix_export.py, so correlation works on any ThreatIQ record shape."""
    for name in names:
        if isinstance(record, dict):
            if name in record:
                return record[name]
        elif hasattr(record, name):
            return getattr(record, name)
    return default


def _normalize_value(ioc_value: str, ioc_type: str) -> str:
    """Normalizes an IoC value for correlation matching. Domains and URLs
    are case-insensitive by spec (RFC 1035 / RFC 3986); hashes and IPs are
    compared as-is since case *can* be meaningful there (e.g. IPv6) or
    connectors already normalize them."""
    if ioc_type in ("Domain Name", "URL", "Email Address"):
        return ioc_value.strip().lower()
    return ioc_value.strip()


def _confidence(record: Any) -> float:
    return float(_field(record, "confidence", "label_confidence", default=0.0) or 0.0)


def correlate_iocs(records: list[Any]) -> list[dict]:
    """Groups records by normalized (ioc_value, ioc_type) and merges
    matches into a single correlated record per unique observable.

    A record seen from only one source passes through with
    corroborating_sources=[that source] and correlation_boost=0.0 --
    correlation never *reduces* confidence, it only rewards independent
    confirmation.

    For a merged group, the returned record:
      - keeps the highest-severity variant's descriptive fields
        (text/label/severity/severity_label/ioc_type/tlp) as the primary
      - sets confidence to the highest individual confidence in the group,
        boosted by _CORROBORATION_FACTOR per additional distinct source
        (capped at _MAX_CORROBORATING_SOURCES), never exceeding 1.0
      - lists every contributing source in corroborating_sources
      - retains every original record's raw_payload for traceability
    """
    groups: dict[tuple[str, str], list[Any]] = {}
    for record in records:
        ioc_type = _field(record, "ioc_type", default="")
        ioc_value = _field(record, "ioc_value", default="")
        key = (_normalize_value(ioc_value, ioc_type), ioc_type)
        groups.setdefault(key, []).append(record)

    correlated: list[dict] = []
    for (_norm_value, ioc_type), group in groups.items():
        sources = sorted({_field(r, "source", default="unknown") for r in group})
        primary = max(group, key=_confidence)
        base_confidence = _confidence(primary)

        if len(group) == 1:
            correlated.append({
                "ioc_value": _field(primary, "ioc_value", default=""),
                "ioc_type": ioc_type,
                "text": _field(primary, "text", default=""),
                "label": _field(primary, "label", default="unclassified"),
                "severity": _field(primary, "severity", default=1),
                "severity_label": _field(primary, "severity_label", default="Informational"),
                "confidence": base_confidence,
                "tlp": _field(primary, "tlp", default="TLP:AMBER"),
                "is_synthetic": bool(_field(primary, "is_synthetic", default=False)),
                "corroborating_sources": sources,
                "source_count": 1,
                "correlation_boost": 0.0,
                "raw_payloads": [_field(primary, "raw_payload", default={})],
            })
            continue

        n_corroborating = min(len(sources) - 1, _MAX_CORROBORATING_SOURCES)
        headroom = 1.0 - base_confidence
        boost = round(headroom * (1 - (1 - _CORROBORATION_FACTOR) ** n_corroborating), 4)
        boosted_confidence = round(min(1.0, base_confidence + boost), 4)

        correlated.append({
            "ioc_value": _field(primary, "ioc_value", default=""),
            "ioc_type": ioc_type,
            "text": _field(primary, "text", default=""),
            "label": _field(primary, "label", default="unclassified"),
            "severity": max(int(_field(r, "severity", default=1) or 1) for r in group),
            "severity_label": _field(primary, "severity_label", default="Informational"),
            "confidence": boosted_confidence,
            "tlp": _field(primary, "tlp", default="TLP:AMBER"),
            "is_synthetic": all(bool(_field(r, "is_synthetic", default=False)) for r in group),
            "corroborating_sources": sources,
            "source_count": len(sources),
            "correlation_boost": boost,
            "raw_payloads": [_field(r, "raw_payload", default={}) for r in group],
        })

    # Highest-confidence, most-corroborated first -- the records an
    # analyst should look at first.
    correlated.sort(key=lambda r: (r["source_count"], r["confidence"]), reverse=True)
    return correlated
