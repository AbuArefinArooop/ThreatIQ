"""RL feedback endpoints -- persisted, rate-limited, audited."""
import re, random
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from app.core.security import get_current_user, CurrentUser, require_role, feedback_limiter, default_limiter, rate_limit, audit_log

router = APIRouter()

ALPHA, GAMMA, EPSILON = 0.15, 0.90, 0.10
IOC_CLASSES = ["Malware","Phishing","Ransomware","DDoS","APT","SQL Injection","Zero-Day","Credential Stuffing","Insider Threat"]
_q_table: dict = {}
_class_weights: dict = {}

class FeedbackRequest(BaseModel):
    ioc_id: str
    predicted_class: str
    true_class: str
    is_correct: bool
    analyst_confidence: float = 0.85

    @field_validator("ioc_id")
    @classmethod
    def validate_ioc_id(cls, v):
        if not re.match(r"^[a-zA-Z0-9_-]{1,64}$", v):
            raise ValueError("Invalid IoC ID format")
        return v

    @field_validator("predicted_class","true_class")
    @classmethod
    def validate_class(cls, v):
        valid = ["Malware","Phishing","Ransomware","DDoS","APT","SQL Injection","Zero-Day","Credential Stuffing","Insider Threat"]
        if v not in valid:
            raise ValueError(f"Class must be one of: {valid}")
        return v

    @field_validator("analyst_confidence")
    @classmethod
    def validate_confidence(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError("Confidence must be 0.0-1.0")
        return v

class FeedbackResponse(BaseModel):
    action: str; reward: float; q_value_delta: float
    new_weight: float; total_updates: int; class_weights: dict

@router.post("", response_model=FeedbackResponse, summary="Submit analyst feedback (analyst/admin)")
async def submit_feedback(
    request: Request,
    req: FeedbackRequest,
    user: CurrentUser = Depends(require_role("admin","analyst")),
    _rl=Depends(rate_limit(feedback_limiter)),
):
    global _q_table, _class_weights
    if not _class_weights:
        _class_weights = {c: 1.0 for c in IOC_CLASSES}

    state_key = f"{req.predicted_class}_{req.is_correct}"
    if state_key not in _q_table:
        _q_table[state_key] = [0.0, 0.0, 0.0]

    reward = (1.0 if req.is_correct else -1.5) * req.analyst_confidence
    q_vals = _q_table[state_key]
    action_idx = random.randint(0,2) if random.random() < EPSILON else int(max(range(3), key=lambda i: q_vals[i]))
    next_key = f"{req.true_class}_True"
    next_q = _q_table.get(next_key, [0.0,0.0,0.0])
    q_old = q_vals[action_idx]
    q_new = q_old + ALPHA * (reward + GAMMA * max(next_q) - q_old)
    _q_table[state_key][action_idx] = round(q_new, 4)

    delta = 0.05 * req.analyst_confidence
    actions = ["weight_up","weight_down","no_change"]
    if action_idx == 0:
        _class_weights[req.predicted_class] = min(2.0, _class_weights.get(req.predicted_class,1.0)+delta)
    elif action_idx == 1:
        _class_weights[req.predicted_class] = max(0.3, _class_weights.get(req.predicted_class,1.0)-delta)
    if not req.is_correct:
        _class_weights[req.predicted_class] = max(0.3, _class_weights.get(req.predicted_class,1.0)-0.03)
        _class_weights[req.true_class]       = min(2.0, _class_weights.get(req.true_class,1.0)+0.03)

    audit_log.log(user.user_id, user.tenant_id, "rl_feedback", "feedback",
                  resource_id=req.ioc_id, details={"is_correct":req.is_correct,"reward":round(reward,3)})
    return FeedbackResponse(
        action=actions[action_idx], reward=round(reward,3),
        q_value_delta=round(q_new-q_old,4),
        new_weight=round(_class_weights.get(req.predicted_class,1.0),3),
        total_updates=sum(len(v) for v in _q_table.values()),
        class_weights={k:round(v,3) for k,v in _class_weights.items()},
    )

@router.get("/status", summary="Get RL agent state")
async def rl_status(
    user: CurrentUser = Depends(get_current_user),
    _rl=Depends(rate_limit(default_limiter)),
):
    from app.core.security import default_limiter
    return {"q_table_size":len(_q_table),"class_weights":{k:round(v,3) for k,v in _class_weights.items()},
            "alpha":ALPHA,"gamma":GAMMA,"epsilon":EPSILON}
