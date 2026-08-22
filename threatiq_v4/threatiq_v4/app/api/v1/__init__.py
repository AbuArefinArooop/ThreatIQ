"""API v1 router -- all endpoints with auth."""
from fastapi import APIRouter
from app.api.v1 import auth, iocs, pipeline, graph, feedback, connectors, evaluation

router = APIRouter()
router.include_router(auth.router,        prefix="/auth",       tags=["Auth"])
router.include_router(iocs.router,        prefix="/iocs",       tags=["IoCs"])
router.include_router(pipeline.router,    prefix="/pipeline",   tags=["Pipeline"])
router.include_router(graph.router,       prefix="/graph",      tags=["Knowledge Graph"])
router.include_router(feedback.router,    prefix="/feedback",   tags=["RL Feedback"])
router.include_router(connectors.router,  prefix="/connectors", tags=["CTI Connectors"])
router.include_router(evaluation.router,  prefix="/evaluation", tags=["Evaluation"])
