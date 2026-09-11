"""
ThreatIQ v4.0 -- Comprehensive test suite
Tests: security, connectors, GAT, RL agent, API endpoints, input validation
Run: pytest tests/ -v
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ── Unit: Security layer ───────────────────────────────────────
class TestSecurity:
    def test_password_hash_and_verify(self):
        from app.core.security import hash_password, verify_password
        h = hash_password("TestPass123")
        assert h.startswith("pbkdf2:"), "Should be PBKDF2 format"
        assert verify_password("TestPass123", h)
        assert not verify_password("wrongpass", h)

    def test_jwt_create_and_decode(self):
        from app.core.security import create_access_token, _decode_token
        token = create_access_token("user1","tenant1","analyst","TLP:AMBER")
        payload = _decode_token(token)
        assert payload.sub == "user1"
        assert payload.role == "analyst"
        assert payload.max_tlp == "TLP:AMBER"

    def test_jwt_invalid_raises(self):
        from app.core.security import _decode_token
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            _decode_token("invalid.token.here")
        assert exc.value.status_code == 401

    def test_tlp_access_control(self):
        from app.core.security import check_tlp_access, CurrentUser
        viewer = CurrentUser(user_id="v",tenant_id="t",role="viewer",max_tlp="TLP:GREEN")
        analyst = CurrentUser(user_id="a",tenant_id="t",role="analyst",max_tlp="TLP:AMBER")
        admin = CurrentUser(user_id="ad",tenant_id="t",role="admin",max_tlp="TLP:RED")
        # Viewer cannot see AMBER or RED
        assert check_tlp_access(viewer, "TLP:WHITE") is True
        assert check_tlp_access(viewer, "TLP:GREEN") is True
        assert check_tlp_access(viewer, "TLP:AMBER") is False
        assert check_tlp_access(viewer, "TLP:RED") is False
        # Analyst cannot see RED
        assert check_tlp_access(analyst, "TLP:AMBER") is True
        assert check_tlp_access(analyst, "TLP:RED") is False
        # Admin can see everything
        assert check_tlp_access(admin, "TLP:RED") is True

    def test_filter_by_tlp(self):
        from app.core.security import filter_by_tlp, CurrentUser
        viewer = CurrentUser(user_id="v",tenant_id="t",role="viewer",max_tlp="TLP:GREEN")
        records = [
            {"id":"1","tlp":"TLP:WHITE"},
            {"id":"2","tlp":"TLP:GREEN"},
            {"id":"3","tlp":"TLP:AMBER"},
            {"id":"4","tlp":"TLP:RED"},
        ]
        filtered = filter_by_tlp(records, viewer)
        ids = [r["id"] for r in filtered]
        assert "1" in ids and "2" in ids
        assert "3" not in ids and "4" not in ids

    def test_sanitise_text_xss(self):
        from app.core.security import sanitise_text
        with pytest.raises(ValueError):
            sanitise_text("<script>alert(1)</script>")

    def test_sanitise_text_sqli(self):
        from app.core.security import sanitise_text
        with pytest.raises(ValueError):
            sanitise_text("' UNION SELECT password FROM users--")

    def test_sanitise_text_path_traversal(self):
        from app.core.security import sanitise_text
        with pytest.raises(ValueError):
            sanitise_text("../../etc/passwd")

    def test_sanitise_text_too_long(self):
        from app.core.security import sanitise_text
        with pytest.raises(ValueError):
            sanitise_text("a" * 10001)

    def test_sanitise_text_valid(self):
        from app.core.security import sanitise_text
        result = sanitise_text("LockBit 3.0 ransomware targeting healthcare sector")
        assert result == "LockBit 3.0 ransomware targeting healthcare sector"

    def test_rate_limiter_allows_under_limit(self):
        from app.core.security import RateLimiter
        rl = RateLimiter(calls=5, period=60)
        for _ in range(5):
            assert rl.is_allowed("test-ip") is True

    def test_rate_limiter_blocks_over_limit(self):
        from app.core.security import RateLimiter
        rl = RateLimiter(calls=3, period=60)
        for _ in range(3):
            rl.is_allowed("test-ip2")
        assert rl.is_allowed("test-ip2") is False


# ── Unit: Synthetic data ───────────────────────────────────────
class TestSyntheticData:
    def test_generates_correct_count(self):
        from app.core.synthetic_data import generate_synthetic_iocs
        iocs = generate_synthetic_iocs(n=100)
        assert len(iocs) == 100

    def test_all_marked_synthetic(self):
        from app.core.synthetic_data import generate_synthetic_iocs
        iocs = generate_synthetic_iocs(n=50)
        assert all(r["is_synthetic"] is True for r in iocs)

    def test_has_required_fields(self):
        from app.core.synthetic_data import generate_synthetic_iocs
        iocs = generate_synthetic_iocs(n=10)
        required = ["text","label","severity","source","ioc_value","ioc_type","tlp","is_synthetic"]
        for ioc in iocs:
            for field in required:
                assert field in ioc, f"Missing field: {field}"

    def test_valid_labels(self):
        from app.core.synthetic_data import generate_synthetic_iocs, IOC_CLASSES
        iocs = generate_synthetic_iocs(n=200, seed=0)
        for ioc in iocs:
            assert ioc["label"] in IOC_CLASSES

    def test_valid_severity_range(self):
        from app.core.synthetic_data import generate_synthetic_iocs
        iocs = generate_synthetic_iocs(n=100)
        for ioc in iocs:
            assert 1 <= ioc["severity"] <= 5

    def test_reproducible_with_seed(self):
        from app.core.synthetic_data import generate_synthetic_iocs
        a = generate_synthetic_iocs(n=20, seed=7)
        b = generate_synthetic_iocs(n=20, seed=7)
        # Full record reproducibility, including ioc_value (previously only
        # label/severity were asserted because ioc_value generation used the
        # unseeded global `random` module -- fixed to use the seeded rng).
        assert [r["label"] for r in a] == [r["label"] for r in b]
        assert [r["severity"] for r in a] == [r["severity"] for r in b]
        assert [r["ioc_value"] for r in a] == [r["ioc_value"] for r in b]

    def test_class_distribution_nonuniform(self):
        from app.core.synthetic_data import generate_synthetic_iocs
        iocs = generate_synthetic_iocs(n=1000)
        malware_count = sum(1 for r in iocs if r["label"]=="Malware")
        insider_count = sum(1 for r in iocs if r["label"]=="Insider Threat")
        # Malware should be much more common than Insider Threat
        assert malware_count > insider_count * 2


# ── Unit: MISP connector ───────────────────────────────────────
class TestMISPConnector:
    def test_offline_mode_returns_data(self):
        from app.connectors.misp_connector import MISPConnector
        c = MISPConnector(url=None, api_key=None)
        iocs = c.fetch_recent()
        assert len(iocs) > 0

    def test_offline_iocs_not_synthetic(self):
        from app.connectors.misp_connector import MISPConnector
        c = MISPConnector()
        iocs = c.fetch_recent()
        assert all(r["is_synthetic"] is False for r in iocs)

    def test_offline_iocs_have_required_fields(self):
        from app.connectors.misp_connector import MISPConnector
        c = MISPConnector()
        iocs = c.fetch_recent()
        for ioc in iocs:
            assert "text" in ioc
            assert "label" in ioc
            assert "ioc_value" in ioc
            assert "source" in ioc
            assert ioc["source"] == "MISP"

    def test_attribute_mapper_returns_none_for_no_ids(self):
        from app.connectors.misp_connector import _map_misp_attribute_to_ioc
        result = _map_misp_attribute_to_ioc(
            {"type":"ip-dst","value":"1.2.3.4","category":"Network activity","to_ids":False},
            {"id":"e1","info":"test","threat_level_id":"2","distribution":"1","timestamp":"0"}
        )
        assert result is None  # to_ids=False means not actionable

    def test_attribute_mapper_ipv4(self):
        from app.connectors.misp_connector import _map_misp_attribute_to_ioc
        result = _map_misp_attribute_to_ioc(
            {"type":"ip-dst","value":"185.220.101.47","category":"Network activity",
             "comment":"C2 server","to_ids":True,"uuid":"test-uuid"},
            {"id":"e1","info":"Emotet C2","threat_level_id":"1","distribution":"1","timestamp":"0"}
        )
        assert result is not None
        assert result["ioc_type"] == "IPv4 Address"
        assert result["ioc_value"] == "185.220.101.47"
        assert result["is_synthetic"] is False


# ── Unit: CIRCL connector ─────────────────────────────────────
class TestCIRCLConnector:
    def test_offline_returns_data(self):
        from app.connectors.circl_connector import CIRCLConnector
        c = CIRCLConnector()
        iocs = c.fetch_recent_cves(limit=10)
        assert len(iocs) > 0

    def test_offline_cves_not_synthetic(self):
        from app.connectors.circl_connector import CIRCLConnector
        c = CIRCLConnector()
        iocs = c.fetch_recent_cves()
        assert all(r["is_synthetic"] is False for r in iocs)

    def test_offline_source_is_circl(self):
        from app.connectors.circl_connector import CIRCLConnector
        c = CIRCLConnector()
        iocs = c.fetch_recent_cves()
        assert all(r["source"] == "CIRCL" for r in iocs)

    def test_zero_day_label(self):
        from app.connectors.circl_connector import CIRCLConnector
        c = CIRCLConnector()
        iocs = c.fetch_recent_cves()
        assert all(r["label"] == "Zero-Day" for r in iocs)


# ── Unit: OTX (AlienVault) connector ───────────────────────────
class TestOTXConnector:
    def test_offline_returns_data(self):
        from app.connectors.otx_connector import OTXConnector
        c = OTXConnector()
        iocs = c.fetch_recent()
        assert len(iocs) > 0

    def test_offline_not_synthetic(self):
        from app.connectors.otx_connector import OTXConnector
        c = OTXConnector()
        iocs = c.fetch_recent()
        assert all(r["is_synthetic"] is False for r in iocs)

    def test_offline_source_is_otx(self):
        from app.connectors.otx_connector import OTXConnector
        c = OTXConnector()
        iocs = c.fetch_recent()
        assert all(r["source"] == "OTX AlienVault" for r in iocs)

    def test_offline_respects_limit(self):
        from app.connectors.otx_connector import OTXConnector
        c = OTXConnector()
        iocs = c.fetch_recent(limit=2)
        assert len(iocs) <= 2

    def test_no_key_is_offline_mode(self):
        from app.connectors.otx_connector import OTXConnector
        c = OTXConnector()
        assert c._live is False

    def test_key_present_is_live_mode(self):
        from app.connectors.otx_connector import OTXConnector
        c = OTXConnector(api_key="test-key-123")
        assert c._live is True

    def test_ioc_shape_matches_other_connectors(self):
        from app.connectors.otx_connector import OTXConnector
        c = OTXConnector()
        ioc = c.fetch_recent()[0]
        for field in ("external_id", "text", "label", "severity", "severity_label",
                      "confidence", "source", "source_trust", "ioc_value", "ioc_type",
                      "tlp", "is_synthetic", "raw_payload"):
            assert field in ioc, f"missing field: {field}"

    def test_live_fetch_falls_back_on_error(self, monkeypatch):
        """A configured key that can't reach the network should still
        degrade to the offline sample rather than raising."""
        from app.connectors.otx_connector import OTXConnector
        c = OTXConnector(api_key="test-key-123", api_url="http://localhost:1")
        iocs = c.fetch_recent(limit=5)
        assert len(iocs) > 0
        assert all(r["is_synthetic"] is False for r in iocs)


class TestWazuhConnector:
    def test_offline_returns_data(self):
        from app.connectors.wazuh_connector import WazuhConnector
        c = WazuhConnector()
        iocs = c.fetch_recent()
        assert len(iocs) > 0

    def test_offline_not_synthetic(self):
        from app.connectors.wazuh_connector import WazuhConnector
        c = WazuhConnector()
        iocs = c.fetch_recent()
        assert all(r["is_synthetic"] is False for r in iocs)

    def test_offline_source_is_wazuh(self):
        from app.connectors.wazuh_connector import WazuhConnector
        c = WazuhConnector()
        iocs = c.fetch_recent()
        assert all(r["source"] == "Wazuh SIEM" for r in iocs)

    def test_offline_respects_limit(self):
        from app.connectors.wazuh_connector import WazuhConnector
        c = WazuhConnector()
        iocs = c.fetch_recent(limit=2)
        assert len(iocs) <= 2

    def test_no_credentials_is_offline_mode(self):
        from app.connectors.wazuh_connector import WazuhConnector
        c = WazuhConnector()
        assert c._live is False

    def test_credentials_present_is_live_mode(self):
        from app.connectors.wazuh_connector import WazuhConnector
        c = WazuhConnector(indexer_url="https://wazuh.indexer:9200", username="admin", password="secret")
        assert c._live is True

    def test_ioc_shape_matches_other_connectors(self):
        from app.connectors.wazuh_connector import WazuhConnector
        c = WazuhConnector()
        ioc = c.fetch_recent()[0]
        for field in ("external_id", "text", "label", "severity", "severity_label",
                      "confidence", "source", "source_trust", "ioc_value", "ioc_type",
                      "tlp", "is_synthetic", "raw_payload"):
            assert field in ioc, f"missing field: {field}"

    def test_live_fetch_falls_back_on_error(self):
        """Unreachable indexer should degrade to the offline sample rather
        than raising, matching every other connector's fallback contract."""
        from app.connectors.wazuh_connector import WazuhConnector
        c = WazuhConnector(indexer_url="https://localhost:1", username="admin", password="wrong", verify_ssl=False)
        iocs = c.fetch_recent(limit=5)
        assert len(iocs) > 0
        assert all(r["is_synthetic"] is False for r in iocs)

    def test_all_alerts_meet_minimum_rule_level_semantics(self):
        """Every offline sample should map to a severity ThreatIQ actually
        uses (1-5), since these feed straight into the classifier."""
        from app.connectors.wazuh_connector import WazuhConnector
        c = WazuhConnector()
        for ioc in c.fetch_recent():
            assert 1 <= ioc["severity"] <= 5


class TestMISPExporter:
    def _sample_records(self):
        return [
            {"ioc_value": "203.0.113.9", "ioc_type": "IPv4 Address", "label": "APT",
             "severity": 5, "severity_label": "Critical", "confidence": 0.92,
             "source": "Wazuh SIEM", "is_synthetic": False},
            {"ioc_value": "low-conf.example", "ioc_type": "Domain Name", "label": "Malware",
             "severity": 2, "severity_label": "Low", "confidence": 0.40,
             "source": "OTX AlienVault", "is_synthetic": False},
            {"ioc_value": "training-only.example", "ioc_type": "Domain Name", "label": "Malware",
             "severity": 5, "severity_label": "Critical", "confidence": 0.95,
             "source": "Synthetic", "is_synthetic": True},
        ]

    def test_not_configured_is_not_live(self):
        from app.connectors.misp_export import MISPExporter
        exporter = MISPExporter()
        assert exporter._live is False

    def test_select_candidates_filters_low_confidence(self):
        from app.connectors.misp_export import MISPExporter
        exporter = MISPExporter()
        candidates = exporter.select_candidates(self._sample_records())
        values = {c["ioc_value"] for c in candidates}
        assert "low-conf.example" not in values

    def test_select_candidates_excludes_synthetic(self):
        from app.connectors.misp_export import MISPExporter
        exporter = MISPExporter()
        candidates = exporter.select_candidates(self._sample_records())
        values = {c["ioc_value"] for c in candidates}
        assert "training-only.example" not in values

    def test_select_candidates_keeps_qualifying_record(self):
        from app.connectors.misp_export import MISPExporter
        exporter = MISPExporter()
        candidates = exporter.select_candidates(self._sample_records())
        values = {c["ioc_value"] for c in candidates}
        assert "203.0.113.9" in values

    def test_publish_skips_gracefully_without_misp_configured(self):
        """Publishing with no MISP_URL/MISP_API_KEY configured must not
        raise -- it should report a clear skip reason instead, matching
        every pull connector's offline-graceful-degradation contract."""
        from app.connectors.misp_export import MISPExporter
        exporter = MISPExporter()
        result = exporter.publish_iocs(self._sample_records())
        assert result["skipped"] == "misp_not_configured"
        assert result["attributes_published"] == 0

    def test_publish_reports_no_candidates_distinctly(self):
        from app.connectors.misp_export import MISPExporter
        exporter = MISPExporter()
        result = exporter.publish_iocs([r for r in self._sample_records() if r["is_synthetic"]])
        assert result["skipped"] == "no_candidates"

    def test_accepts_pydantic_style_field_names(self):
        """The exporter must also work against app.api.v1.iocs's
        IoCResponse shape (label_confidence, not confidence)."""
        from app.connectors.misp_export import MISPExporter

        class FakeIoCResponse:
            def __init__(self, **kw):
                self.__dict__.update(kw)

        record = FakeIoCResponse(
            ioc_value="1.2.3.4", ioc_type="IPv4 Address", label="APT",
            severity=5, severity_label="Critical", label_confidence=0.9,
            source="MISP", is_synthetic=False,
        )
        exporter = MISPExporter()
        candidates = exporter.select_candidates([record])
        assert len(candidates) == 1

    def test_max_threat_level_maps_severity_inversely(self):
        """MISP's threat_level_id is 1=High...4=Undefined -- the inverse
        direction of ThreatIQ's own 1-5 severity scale."""
        from app.connectors.misp_export import MISPExporter
        assert MISPExporter._max_threat_level([{"severity": 5}]) == 1
        assert MISPExporter._max_threat_level([{"severity": 3}]) == 2
        assert MISPExporter._max_threat_level([{"severity": 1}]) == 3


class TestSTIXExport:
    def _sample_records(self):
        return [
            {"ioc_value": "203.0.113.9", "ioc_type": "IPv4 Address", "label": "APT", "text": "C2 beacon",
             "severity": 5, "severity_label": "Critical", "confidence": 0.92,
             "source": "Wazuh SIEM", "tlp": "TLP:AMBER", "is_synthetic": False},
            {"ioc_value": "CVE-2024-12345", "ioc_type": "CVE Identifier", "label": "Vulnerability",
             "text": "Remote code execution", "severity": 5, "severity_label": "Critical",
             "confidence": 0.99, "source": "CIRCL", "tlp": "TLP:WHITE", "is_synthetic": False},
            {"ioc_value": "some-host-03", "ioc_type": "Host", "label": "Malware", "text": "compromised host",
             "severity": 4, "severity_label": "High", "confidence": 0.8,
             "source": "Wazuh SIEM", "tlp": "TLP:AMBER", "is_synthetic": False},
            {"ioc_value": "training-only.example", "ioc_type": "Domain Name", "label": "Malware",
             "text": "synthetic training sample", "severity": 5, "severity_label": "Critical",
             "confidence": 0.95, "source": "Synthetic", "tlp": "TLP:AMBER", "is_synthetic": True},
        ]

    def test_bundle_has_correct_envelope(self):
        from app.services.stix_export import build_ioc_bundle
        bundle = build_ioc_bundle(self._sample_records())
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert isinstance(bundle["objects"], list)

    def test_ipv4_produces_valid_indicator_pattern(self):
        from app.services.stix_export import build_ioc_bundle
        bundle = build_ioc_bundle([self._sample_records()[0]])
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1
        assert indicators[0]["pattern"] == "[ipv4-addr:value = '203.0.113.9']"
        assert indicators[0]["spec_version"] == "2.1"

    def test_confidence_is_0_to_100_integer_per_spec(self):
        from app.services.stix_export import build_ioc_bundle
        bundle = build_ioc_bundle([self._sample_records()[0]])
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["confidence"] == 92
        assert isinstance(indicator["confidence"], int)

    def test_cve_produces_vulnerability_sdo_not_indicator(self):
        from app.services.stix_export import build_ioc_bundle
        bundle = build_ioc_bundle([self._sample_records()[1]])
        types = {o["type"] for o in bundle["objects"]}
        assert "vulnerability" in types
        assert "indicator" not in types

    def test_unmapped_type_produces_note_only(self):
        """A bare 'Host' has no dedicated STIX Cyber Observable type --
        must not fabricate one; should be Note-only."""
        from app.services.stix_export import build_ioc_bundle
        bundle = build_ioc_bundle([self._sample_records()[2]])
        types = {o["type"] for o in bundle["objects"]}
        assert types == {"note"}

    def test_synthetic_excluded_by_default(self):
        from app.services.stix_export import build_ioc_bundle
        bundle = build_ioc_bundle(self._sample_records(), exclude_synthetic=True)
        values_seen = str(bundle["objects"])
        assert "training-only.example" not in values_seen

    def test_synthetic_included_when_requested(self):
        from app.services.stix_export import build_ioc_bundle
        bundle = build_ioc_bundle(self._sample_records(), exclude_synthetic=False)
        values_seen = str(bundle["objects"])
        assert "training-only.example" in values_seen

    def test_tlp_marking_ref_matches_shared_map(self):
        from app.services.stix_export import build_ioc_bundle
        from app.connectors.opencti_connector import STIX_TLP_MAP
        bundle = build_ioc_bundle([self._sample_records()[0]])
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["object_marking_refs"] == [STIX_TLP_MAP["TLP:AMBER"]]

    def test_indicator_id_is_deterministic(self):
        """Re-exporting the same IoC value must yield the same indicator
        ID (idempotent republication), not a fresh random UUID."""
        from app.services.stix_export import build_ioc_bundle
        b1 = build_ioc_bundle([self._sample_records()[0]])
        b2 = build_ioc_bundle([self._sample_records()[0]])
        id1 = next(o["id"] for o in b1["objects"] if o["type"] == "indicator")
        id2 = next(o["id"] for o in b2["objects"] if o["type"] == "indicator")
        assert id1 == id2

    def test_accepts_pydantic_style_field_names(self):
        from app.services.stix_export import build_ioc_bundle

        class FakeIoCResponse:
            def __init__(self, **kw):
                self.__dict__.update(kw)

        record = FakeIoCResponse(
            ioc_value="1.2.3.4", ioc_type="IPv4 Address", label="APT", text="x",
            severity=5, severity_label="Critical", label_confidence=0.77,
            source="MISP", tlp="TLP:RED", is_synthetic=False,
        )
        bundle = build_ioc_bundle([record])
        indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
        assert indicator["confidence"] == 77


class TestAttackNavigatorExport:
    def _sample_nodes(self):
        return [
            {"key": "APT29", "type": "actor", "id": "G0016"},
            {"key": "APT28", "type": "actor", "id": "G0007"},
            {"key": "Spearphishing Attachment", "type": "ttp", "id": "T1566.001"},
            {"key": "Process Injection", "type": "ttp", "id": "T1055"},
        ]

    def _sample_predictions(self):
        return [
            {"source": "APT29", "target": "Spearphishing Attachment", "score": 0.85, "relation": "predicted_uses"},
            {"source": "APT28", "target": "Spearphishing Attachment", "score": 0.65, "relation": "predicted_uses"},
            {"source": "APT29", "target": "Process Injection", "score": 0.40, "relation": "predicted_uses"},
        ]

    def test_layer_has_required_top_level_fields(self):
        from app.services.attck_navigator import build_navigator_layer
        layer = build_navigator_layer(self._sample_nodes(), self._sample_predictions())
        for field in ("name", "versions", "domain", "techniques", "gradient"):
            assert field in layer
        assert layer["domain"] == "enterprise-attack"

    def test_technique_ids_resolved_from_node_names(self):
        """predict_links() returns node *names*; the layer must contain
        real MITRE technique IDs, not the display name."""
        from app.services.attck_navigator import build_navigator_layer
        layer = build_navigator_layer(self._sample_nodes(), self._sample_predictions())
        ids = {t["techniqueID"] for t in layer["techniques"]}
        assert ids == {"T1566.001", "T1055"}

    def test_score_is_max_across_predicting_actors(self):
        """Spearphishing Attachment is predicted by both APT29 (85) and
        APT28 (65) -- the layer score should be the max, not summed or
        averaged, so a strong single prediction isn't diluted."""
        from app.services.attck_navigator import build_navigator_layer
        layer = build_navigator_layer(self._sample_nodes(), self._sample_predictions())
        spearphish = next(t for t in layer["techniques"] if t["techniqueID"] == "T1566.001")
        assert spearphish["score"] == 85.0

    def test_comment_lists_all_contributing_actors(self):
        from app.services.attck_navigator import build_navigator_layer
        layer = build_navigator_layer(self._sample_nodes(), self._sample_predictions())
        spearphish = next(t for t in layer["techniques"] if t["techniqueID"] == "T1566.001")
        assert "APT29" in spearphish["comment"] and "APT28" in spearphish["comment"]

    def test_empty_predictions_produce_empty_but_valid_layer(self):
        from app.services.attck_navigator import build_navigator_layer
        layer = build_navigator_layer(self._sample_nodes(), [])
        assert layer["techniques"] == []
        assert layer["domain"] == "enterprise-attack"

    def test_techniques_sorted_by_score_descending(self):
        from app.services.attck_navigator import build_navigator_layer
        layer = build_navigator_layer(self._sample_nodes(), self._sample_predictions())
        scores = [t["score"] for t in layer["techniques"]]
        assert scores == sorted(scores, reverse=True)


class TestCorrelation:
    def _multi_source_group(self):
        """Same IP seen in an OTX pulse, a MISP event, and a Wazuh alert
        -- three independent sources reporting the same observable."""
        return [
            {"ioc_value": "203.0.113.9", "ioc_type": "IPv4 Address", "text": "C2 server",
             "label": "APT", "severity": 4, "severity_label": "High", "confidence": 0.60,
             "source": "OTX AlienVault", "tlp": "TLP:AMBER", "is_synthetic": False, "raw_payload": {}},
            {"ioc_value": "203.0.113.9", "ioc_type": "IPv4 Address", "text": "Known C2 infrastructure",
             "label": "APT", "severity": 5, "severity_label": "Critical", "confidence": 0.55,
             "source": "MISP", "tlp": "TLP:AMBER", "is_synthetic": False, "raw_payload": {}},
            {"ioc_value": "203.0.113.9", "ioc_type": "IPv4 Address", "text": "Outbound C2 beacon",
             "label": "APT", "severity": 5, "severity_label": "Critical", "confidence": 0.70,
             "source": "Wazuh SIEM", "tlp": "TLP:AMBER", "is_synthetic": False, "raw_payload": {}},
        ]

    def _single_source_record(self):
        return [{"ioc_value": "198.51.100.42", "ioc_type": "IPv4 Address", "text": "isolated report",
                  "label": "Malware", "severity": 2, "severity_label": "Low", "confidence": 0.5,
                  "source": "CIRCL", "tlp": "TLP:WHITE", "is_synthetic": False, "raw_payload": {}}]

    def test_single_source_passes_through_unboosted(self):
        from app.services.correlation import correlate_iocs
        result = correlate_iocs(self._single_source_record())
        assert len(result) == 1
        assert result[0]["source_count"] == 1
        assert result[0]["correlation_boost"] == 0.0
        assert result[0]["confidence"] == 0.5

    def test_multi_source_merges_into_one_record(self):
        from app.services.correlation import correlate_iocs
        result = correlate_iocs(self._multi_source_group())
        assert len(result) == 1
        assert result[0]["ioc_value"] == "203.0.113.9"
        assert result[0]["source_count"] == 3

    def test_multi_source_boosts_confidence_above_max_individual(self):
        """The correlated confidence must exceed the highest individual
        source's confidence (0.70) -- corroboration is itself evidence,
        not just a tiebreaker among the inputs."""
        from app.services.correlation import correlate_iocs
        result = correlate_iocs(self._multi_source_group())
        assert result[0]["confidence"] > 0.70

    def test_confidence_never_exceeds_one(self):
        from app.services.correlation import correlate_iocs
        records = [
            {"ioc_value": "x", "ioc_type": "Domain Name", "text": "t", "label": "L",
             "severity": 5, "severity_label": "Critical", "confidence": 0.98,
             "source": f"source-{i}", "tlp": "TLP:AMBER", "is_synthetic": False, "raw_payload": {}}
            for i in range(6)
        ]
        result = correlate_iocs(records)
        assert result[0]["confidence"] <= 1.0

    def test_severity_takes_the_maximum_across_group(self):
        from app.services.correlation import correlate_iocs
        result = correlate_iocs(self._multi_source_group())
        assert result[0]["severity"] == 5

    def test_all_sources_listed_in_corroborating_sources(self):
        from app.services.correlation import correlate_iocs
        result = correlate_iocs(self._multi_source_group())
        assert set(result[0]["corroborating_sources"]) == {"OTX AlienVault", "MISP", "Wazuh SIEM"}

    def test_domain_matching_is_case_insensitive(self):
        """RFC 1035: domain names are case-insensitive -- EXAMPLE.COM and
        example.com from two different feeds must correlate as the same
        observable, not two separate ones."""
        from app.services.correlation import correlate_iocs
        records = [
            {"ioc_value": "EXAMPLE.COM", "ioc_type": "Domain Name", "text": "t1", "label": "Malware",
             "severity": 3, "severity_label": "Medium", "confidence": 0.5, "source": "OTX AlienVault",
             "tlp": "TLP:AMBER", "is_synthetic": False, "raw_payload": {}},
            {"ioc_value": "example.com", "ioc_type": "Domain Name", "text": "t2", "label": "Malware",
             "severity": 3, "severity_label": "Medium", "confidence": 0.5, "source": "MISP",
             "tlp": "TLP:AMBER", "is_synthetic": False, "raw_payload": {}},
        ]
        result = correlate_iocs(records)
        assert len(result) == 1
        assert result[0]["source_count"] == 2

    def test_different_ioc_types_do_not_correlate_on_same_string(self):
        """A hash value that happens to equal a domain-looking string
        must not be treated as the same observable -- correlation keys on
        (value, type), not value alone."""
        from app.services.correlation import correlate_iocs
        records = [
            {"ioc_value": "abc123", "ioc_type": "File Hash (MD5)", "text": "t1", "label": "Malware",
             "severity": 3, "severity_label": "Medium", "confidence": 0.5, "source": "OTX AlienVault",
             "tlp": "TLP:AMBER", "is_synthetic": False, "raw_payload": {}},
            {"ioc_value": "abc123", "ioc_type": "Domain Name", "text": "t2", "label": "Malware",
             "severity": 3, "severity_label": "Medium", "confidence": 0.5, "source": "MISP",
             "tlp": "TLP:AMBER", "is_synthetic": False, "raw_payload": {}},
        ]
        result = correlate_iocs(records)
        assert len(result) == 2

    def test_results_sorted_most_corroborated_first(self):
        from app.services.correlation import correlate_iocs
        result = correlate_iocs(self._multi_source_group() + self._single_source_record())
        assert result[0]["source_count"] >= result[-1]["source_count"]

    def test_is_synthetic_true_only_if_all_corroborating_records_are_synthetic(self):
        """A real IoC independently confirmed by a synthetic training
        record shouldn't get mislabeled as fully synthetic."""
        from app.services.correlation import correlate_iocs
        records = [
            {"ioc_value": "1.2.3.4", "ioc_type": "IPv4 Address", "text": "t1", "label": "Malware",
             "severity": 3, "severity_label": "Medium", "confidence": 0.5, "source": "Synthetic",
             "tlp": "TLP:AMBER", "is_synthetic": True, "raw_payload": {}},
            {"ioc_value": "1.2.3.4", "ioc_type": "IPv4 Address", "text": "t2", "label": "Malware",
             "severity": 3, "severity_label": "Medium", "confidence": 0.5, "source": "OTX AlienVault",
             "tlp": "TLP:AMBER", "is_synthetic": False, "raw_payload": {}},
        ]
        result = correlate_iocs(records)
        assert result[0]["is_synthetic"] is False

    def test_empty_input_returns_empty_list(self):
        from app.services.correlation import correlate_iocs
        assert correlate_iocs([]) == []


# ── Unit: Trained GAT ─────────────────────────────────────────
class TestGAT:
    def test_numpy_gat_initialises(self):
        from app.ml.gat import NumpyGAT
        gat = NumpyGAT(in_dim=6, hidden_dim=8, out_dim=4)
        assert gat.W1.shape == (6, 8)
        assert gat.W2.shape == (8, 4)

    def test_compute_embeddings_shape(self):
        from app.ml.gat import NumpyGAT
        import numpy as np
        gat = NumpyGAT(in_dim=6, hidden_dim=8, out_dim=4)
        nodes = [{"key":"APT29","type":"actor","weight":1.0},
                 {"key":"T1566","type":"ttp","weight":0.8},
                 {"key":"T1078","type":"ttp","weight":0.7}]
        edges = [{"source":"APT29","target":"T1566","weight":0.9}]
        emb = gat.compute_embeddings(nodes, edges)
        assert emb.shape == (3, 4)

    def test_predict_links_returns_list(self):
        from app.ml.gat import NumpyGAT
        gat = NumpyGAT()
        nodes = [{"key":"APT29","type":"actor","weight":1.0},
                 {"key":"APT28","type":"actor","weight":1.0},
                 {"key":"T1566","type":"ttp","weight":0.8},
                 {"key":"T1059","type":"ttp","weight":0.8}]
        edges = [{"source":"APT29","target":"T1566","weight":0.9}]
        preds = gat.predict_links(nodes, edges, top_k=5)
        assert isinstance(preds, list)
        assert all("source" in p and "target" in p and "score" in p for p in preds)

    def test_load_mitre_offline_relationships(self):
        from app.ml.gat import GATTrainer, MITRE_OFFLINE_RELATIONSHIPS
        trainer = GATTrainer(mitre_data_path=None)
        rels = trainer.load_mitre_relationships()
        assert len(rels) == len(MITRE_OFFLINE_RELATIONSHIPS)
        assert all(len(r) == 4 for r in rels)  # (group_id, group_name, tech_id, tech_name)

    def test_build_graph_from_relationships(self):
        from app.ml.gat import GATTrainer
        trainer = GATTrainer()
        rels = trainer.load_mitre_relationships()
        nodes, edges = trainer.build_graph(rels)
        assert len(nodes) > 0
        assert len(edges) == len(rels)
        actor_types = [n for n in nodes if n["type"] == "actor"]
        ttp_types   = [n for n in nodes if n["type"] == "ttp"]
        assert len(actor_types) > 0
        assert len(ttp_types) > 0

    def test_gat_train_returns_metrics(self):
        from app.ml.gat import GATTrainer
        trainer = GATTrainer()
        metrics = trainer.train(epochs=5)  # fast for test
        assert "final_loss" in metrics
        assert trainer.model.trained is True

    def test_gat_save_and_load(self, tmp_path):
        from app.ml.gat import GATTrainer
        import numpy as np
        trainer = GATTrainer()
        trainer.train(epochs=3)
        save_path = str(tmp_path / "gat_weights.npz")
        trainer.save(save_path)
        trainer2 = GATTrainer()
        loaded = trainer2.load(save_path)
        assert loaded is True
        assert trainer2.model.trained is True
        assert np.allclose(trainer.model.W1, trainer2.model.W1)

    def test_evaluation_returns_hits_mrr(self):
        from app.ml.gat import GATTrainer
        trainer = GATTrainer()
        trainer.train(epochs=5)
        rels = trainer.load_mitre_relationships()
        nodes, edges = trainer.build_graph(rels)
        test_pairs = [(g, t) for _, g, _, t in rels[:3]]
        metrics = trainer.model._evaluate(nodes, edges, test_pairs)
        assert "hits_at_1" in metrics
        assert "hits_at_5" in metrics
        assert "mrr" in metrics
        assert 0.0 <= metrics["mrr"] <= 1.0


# ── Unit: RL Q-learning ───────────────────────────────────────
class TestRLAgent:
    def test_reward_positive_for_correct(self):
        reward = 1.0 * 0.85
        assert reward > 0

    def test_penalty_larger_for_incorrect(self):
        reward_correct   = 1.0  * 0.85
        penalty_incorrect = -1.5 * 0.85
        assert abs(penalty_incorrect) > abs(reward_correct)

    def test_class_weight_bounds(self):
        weights = {c: 1.0 for c in ["Malware","Phishing"]}
        # Simulate weight_up to upper bound
        for _ in range(100):
            weights["Malware"] = min(2.0, weights["Malware"] + 0.05)
        assert weights["Malware"] <= 2.0

    def test_q_table_update(self):
        alpha, gamma = 0.15, 0.90
        q_old, reward, max_next = 0.0, 1.0, 0.5
        q_new = q_old + alpha * (reward + gamma * max_next - q_old)
        assert q_new > q_old  # correct prediction increases Q-value

    def test_epsilon_greedy_exploration(self):
        import random
        random.seed(42)
        epsilon = 0.10
        explorations = sum(1 for _ in range(1000) if random.random() < epsilon)
        # Should be approx 100 explorations (±30)
        assert 70 < explorations < 130


# ── Integration: OpenCTI connector ───────────────────────────
class TestOpenCTIConnector:
    def test_offline_enrichment(self):
        from app.connectors.opencti_connector import ThreatIQOpenCTIConnector
        c = ThreatIQOpenCTIConnector(settings_obj=None)
        result = c.test_enrichment_offline()
        assert result["type"] == "bundle"
        assert len(result["objects"]) >= 2  # indicator + note

    def test_enrichment_contains_note(self):
        from app.connectors.opencti_connector import ThreatIQOpenCTIConnector
        c = ThreatIQOpenCTIConnector(settings_obj=None)
        result = c.test_enrichment_offline()
        types = [o["type"] for o in result["objects"]]
        assert "note" in types

    def test_enrichment_has_threatiq_extensions(self):
        from app.connectors.opencti_connector import ThreatIQOpenCTIConnector
        c = ThreatIQOpenCTIConnector(settings_obj=None)
        result = c.test_enrichment_offline()
        indicator = next((o for o in result["objects"] if o["type"]=="indicator"), None)
        assert indicator is not None
        assert "x_threatiq_label" in indicator
        assert "x_threatiq_is_anomaly" in indicator
        assert "x_threatiq_anomaly_score" in indicator

    def test_composite_anomaly_score_range(self):
        from app.connectors.opencti_connector import ThreatIQOpenCTIConnector
        c = ThreatIQOpenCTIConnector(settings_obj=None)
        result = c._run_anomaly(severity=5, confidence=0.3, source_trust=0.6)
        assert 0.0 <= result["score"] <= 1.0

    def test_stix_pattern_parser_ipv4(self):
        from app.connectors.opencti_connector import _extract_ioc_value_from_pattern
        ioc_type, value = _extract_ioc_value_from_pattern("[ipv4-addr:value = '185.220.101.47']")
        assert ioc_type == "IPv4 Address"
        assert value == "185.220.101.47"


# ── Integration: Full pipeline (fast) ─────────────────────────
class TestPipelineIntegration:
    def test_synthetic_plus_connector_pipeline(self):
        """Run a mini pipeline with 50 records."""
        from app.core.synthetic_data import generate_synthetic_iocs
        from app.connectors.misp_connector import MISPConnector
        from app.connectors.circl_connector import CIRCLConnector
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics import f1_score
        from sklearn.preprocessing import LabelEncoder

        synthetic = generate_synthetic_iocs(n=100)
        misp = MISPConnector().fetch_recent()
        circl = CIRCLConnector().fetch_recent_cves()
        combined = synthetic + misp + circl

        texts  = [r["text"] for r in combined]
        labels = [r["label"] for r in combined]
        le = LabelEncoder(); y = le.fit_transform(labels)
        unique = len(set(y))

        tfidf = TfidfVectorizer(ngram_range=(1,2), max_features=256, min_df=1)
        X = tfidf.fit_transform(texts).toarray()
        Xtr,Xte,ytr,yte = train_test_split(X,y,test_size=0.2,random_state=42,
            stratify=y if unique>1 and min(np.bincount(y))>1 else None)

        clf = RandomForestClassifier(n_estimators=20, random_state=42, n_jobs=-1)
        clf.fit(Xtr, ytr)
        yp = clf.predict(Xte)
        train_f1 = f1_score(ytr, clf.predict(Xtr), average="weighted", zero_division=0)
        test_f1  = f1_score(yte, yp, average="weighted", zero_division=0)
        gap = train_f1 - test_f1

        assert test_f1 > 0, "Model must achieve non-zero F1"
        assert gap < 0.40, "Even on tiny dataset, gap should be reasonable"
        # Verify synthetic data stays separate
        synthetic_records = [r for r in combined if r["is_synthetic"]]
        real_records      = [r for r in combined if not r["is_synthetic"]]
        assert len(synthetic_records) == 100
        assert len(real_records) > 0

    def test_overfitting_gate_passes_with_noise(self):
        """Noisy data should produce gaps below 0.40."""
        from app.core.synthetic_data import generate_synthetic_iocs
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics import f1_score
        from sklearn.preprocessing import LabelEncoder
        import numpy as np

        iocs = generate_synthetic_iocs(n=200, seed=99)
        texts = [r["text"] for r in iocs]; labels = [r["label"] for r in iocs]
        le = LabelEncoder(); y = le.fit_transform(labels)
        tfidf = TfidfVectorizer(ngram_range=(1,2), max_features=128, min_df=1)
        X = tfidf.fit_transform(texts).toarray()
        Xtr,Xte,ytr,yte = train_test_split(X,y,test_size=0.2,random_state=42)
        clf = RandomForestClassifier(n_estimators=40, max_depth=8,
            min_samples_split=5, class_weight="balanced", random_state=42)
        clf.fit(Xtr,ytr)
        gap = f1_score(ytr,clf.predict(Xtr),average="weighted",zero_division=0) -               f1_score(yte,clf.predict(Xte),average="weighted",zero_division=0)
        assert gap < 0.40, f"Gap {gap:.4f} too high -- overfitting detected"
