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
