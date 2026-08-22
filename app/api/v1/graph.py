"""Knowledge graph + trained GAT endpoints -- secured."""
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from app.core.security import get_current_user, CurrentUser, require_role, default_limiter, strict_limiter, rate_limit, audit_log

router = APIRouter()

class GraphStats(BaseModel):
    nodes: int; edges: int; density: float; dynamic_nodes: int
    gat_trained: bool; predictions: list[dict]; model_version: str

@router.get("", response_model=GraphStats, summary="Get graph and GAT predictions")
async def get_graph(
    request: Request,
    user: CurrentUser = Depends(get_current_user),
    _rl=Depends(rate_limit(default_limiter)),
):
    from app.ml.gat import GATTrainer
    from app.core.config import settings
    trainer = GATTrainer(settings.MITRE_ATTACK_DATA_PATH)
    loaded = trainer.load("./model_artifacts/gat_weights.npz")
    rels = trainer.load_mitre_relationships()
    nodes, edges = trainer.build_graph(rels)
    preds = trainer.model.predict_links(nodes, edges, top_k=8)
    audit_log.log(user.user_id, user.tenant_id, "get_graph", "graph")
    return GraphStats(
        nodes=len(nodes), edges=len(edges),
        density=round(len(edges)/(len(nodes)*(len(nodes)-1)+1e-9), 4),
        dynamic_nodes=sum(1 for n in nodes if n.get("is_dynamic", False)),
        gat_trained=trainer.model.trained, predictions=preds,
        model_version="4.0.0-trained" if trainer.model.trained else "4.0.0-fixed",
    )

@router.post("/train", summary="Retrain GAT (admin only)")
async def retrain_gat(
    request: Request,
    epochs: int = 100,
    user: CurrentUser = Depends(require_role("admin")),
    _rl=Depends(rate_limit(strict_limiter)),
):
    if not 10 <= epochs <= 1000:
        from fastapi import HTTPException
        raise HTTPException(400, "epochs must be 10-1000")
    from app.ml.gat import GATTrainer
    from app.core.config import settings
    trainer = GATTrainer(settings.MITRE_ATTACK_DATA_PATH)
    metrics = trainer.train(epochs=epochs)
    trainer.save()
    audit_log.log(user.user_id, user.tenant_id, "retrain_gat", "graph", details={"epochs":epochs})
    return {"status": "trained", "metrics": metrics}
