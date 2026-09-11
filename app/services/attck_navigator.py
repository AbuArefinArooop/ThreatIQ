"""
ThreatIQ v4.0 -- MITRE ATT&CK Navigator Layer Export

Converts GAT link predictions (GATModel.predict_links output, see
app/ml/gat.py) into a MITRE ATT&CK Navigator layer file -- the standard
JSON format for https://mitre-attack.github.io/attack-navigator, the
single most widely used free analyst tool for visualizing ATT&CK
technique coverage.

Why this matters for ThreatIQ specifically: predict_links() already
produces (actor, technique, score) triples, but as raw JSON they're only
useful to someone reading the API response. A Navigator layer turns the
exact same predictions into a heatmap over the real ATT&CK matrix that
any analyst can open, filter, and compare against their own coverage --
without writing a single line of code. This is the most direct way to
make GAT's predictions genuinely "practical" rather than just a metric
in an evaluation report.

Layer format reference:
https://github.com/mitre-attack/attack-navigator/blob/master/layers/LAYERFORMATv4_5.md
"""
from typing import Any

NAVIGATOR_LAYER_VERSION = "4.5"
NAVIGATOR_TOOL_VERSION = "4.9.1"


def _technique_id_by_name(nodes: list[dict]) -> dict[str, str]:
    """Maps a ttp node's display name (its graph "key") back to its real
    MITRE technique ID ("id" field, e.g. "T1566") -- predict_links() only
    returns node keys/names, and the Navigator layer format needs actual
    technique IDs to place scores on the matrix correctly."""
    return {
        node["key"]: node.get("id", node["key"])
        for node in nodes
        if node.get("type") == "ttp"
    }


def build_navigator_layer(
    nodes: list[dict],
    predictions: list[dict],
    layer_name: str = "ThreatIQ GAT Predictions",
    description: str | None = None,
) -> dict:
    """Builds a MITRE ATT&CK Navigator layer from GAT predictions.

    Where multiple predicted (actor, technique) pairs share the same
    technique, the technique's score is the maximum across predicting
    actors, and the comment lists every contributing actor -- a technique
    predicted as likely by several different actors is exactly the kind
    of signal an analyst wants surfaced, not averaged away.
    """
    id_by_name = _technique_id_by_name(nodes)

    # technique_id -> {"score": float 0-100, "actors": {name: score}}
    by_technique: dict[str, dict[str, Any]] = {}
    for pred in predictions:
        technique_name = pred.get("target", "")
        technique_id = id_by_name.get(technique_name, technique_name)
        score_pct = round(float(pred.get("score", 0.0)) * 100, 1)
        actor = pred.get("source", "unknown actor")

        entry = by_technique.setdefault(technique_id, {"score": 0.0, "actors": {}})
        entry["actors"][actor] = max(entry["actors"].get(actor, 0.0), score_pct)
        entry["score"] = max(entry["score"], score_pct)

    techniques = []
    for technique_id, entry in sorted(by_technique.items(), key=lambda kv: -kv[1]["score"]):
        actor_summary = ", ".join(
            f"{name} ({score:.0f}%)"
            for name, score in sorted(entry["actors"].items(), key=lambda kv: -kv[1])
        )
        techniques.append({
            "techniqueID": technique_id,
            "score": entry["score"],
            "color": "",
            "comment": f"ThreatIQ GAT-predicted: {actor_summary}",
            "enabled": True,
            "metadata": [
                {"name": "predicting_actors", "value": str(len(entry["actors"]))},
            ],
            "showSubtechniques": False,
        })

    return {
        "name": layer_name,
        "versions": {
            "attack": "14",
            "navigator": NAVIGATOR_TOOL_VERSION,
            "layer": NAVIGATOR_LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": description or (
            "Adversary-technique associations predicted by ThreatIQ's Graph "
            "Attention Network, not yet directly observed. Scores are model "
            "confidence (0-100), not observed-frequency counts."
        ),
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 3,  # sort by score, descending
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#ffe766", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Low model confidence", "color": "#ffffff"},
            {"label": "High model confidence", "color": "#ff6666"},
        ],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
