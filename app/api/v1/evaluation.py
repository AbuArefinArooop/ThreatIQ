"""Evaluation endpoints -- separated by dataset type, fully secured."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from app.core.security import get_current_user, CurrentUser, require_role, strict_limiter, default_limiter, rate_limit, audit_log

router = APIRouter()

class EvalRequest(BaseModel):
    dataset_type: str = "synthetic"
    n_records: int = 500
    model: str = "RandomForest"

    @field_validator("dataset_type")
    @classmethod
    def validate_dtype(cls, v):
        allowed = {"synthetic","real_misp","real_circl","real_otx","real_wazuh","mixed"}
        if v not in allowed:
            raise ValueError(f"dataset_type must be one of: {allowed}")
        return v

    @field_validator("n_records")
    @classmethod
    def validate_n(cls, v):
        if not 10 <= v <= 10000:
            raise ValueError("n_records must be 10-10,000")
        return v

    @field_validator("model")
    @classmethod
    def validate_model(cls, v):
        if v not in {"RandomForest","GradientBoosting","LogisticRegression","DecisionTree"}:
            raise ValueError("Invalid model name")
        return v

class EvalResult(BaseModel):
    dataset_type: str; dataset_size: int; model: str
    metrics: dict; is_synthetic_warning: bool

@router.post("/run", response_model=EvalResult, summary="Run evaluation (analyst/admin)")
async def run_evaluation(
    request: Request,
    req: EvalRequest,
    user: CurrentUser = Depends(require_role("admin","analyst")),
    _rl=Depends(rate_limit(strict_limiter)),
):
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import f1_score, roc_auc_score, matthews_corrcoef, accuracy_score
    from sklearn.preprocessing import LabelEncoder

    if req.dataset_type == "synthetic":
        from app.core.synthetic_data import generate_synthetic_iocs
        iocs = generate_synthetic_iocs(n=req.n_records)
    elif req.dataset_type == "real_misp":
        from app.connectors.misp_connector import MISPConnector
        from app.core.config import settings
        iocs = MISPConnector(settings.MISP_URL, settings.MISP_API_KEY).fetch_recent(limit=req.n_records)
    elif req.dataset_type == "real_circl":
        from app.connectors.circl_connector import CIRCLConnector
        from app.core.config import settings
        iocs = CIRCLConnector(settings.CIRCL_USERNAME, settings.CIRCL_PASSWORD).fetch_recent_cves(limit=req.n_records)
    elif req.dataset_type == "real_otx":
        from app.connectors.otx_connector import OTXConnector
        from app.core.config import settings
        iocs = OTXConnector(settings.OTX_API_KEY, settings.OTX_API_URL).fetch_recent(limit=req.n_records)
    elif req.dataset_type == "real_wazuh":
        from app.connectors.wazuh_connector import WazuhConnector
        from app.core.config import settings
        iocs = WazuhConnector(settings.WAZUH_INDEXER_URL, settings.WAZUH_API_USERNAME,
            settings.WAZUH_API_PASSWORD, settings.WAZUH_VERIFY_SSL).fetch_recent(limit=req.n_records)
    else:
        from app.core.synthetic_data import generate_synthetic_iocs
        from app.connectors.misp_connector import MISPConnector
        from app.core.config import settings
        iocs = generate_synthetic_iocs(n=req.n_records//2)
        iocs += MISPConnector(settings.MISP_URL, settings.MISP_API_KEY).fetch_recent(limit=req.n_records//2)

    if len(iocs) < 10:
        return EvalResult(dataset_type=req.dataset_type, dataset_size=len(iocs),
            model=req.model, metrics={"error":f"Insufficient data ({len(iocs)} records)"},
            is_synthetic_warning=req.dataset_type=="synthetic")

    texts=[r["text"] for r in iocs]; labels=[r["label"] for r in iocs]
    le=LabelEncoder(); y=le.fit_transform(labels)
    unique=len(set(y))
    tfidf=TfidfVectorizer(ngram_range=(1,3),max_features=512,sublinear_tf=True,min_df=1)
    X=tfidf.fit_transform(texts).toarray()
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=0.2,random_state=42,
        stratify=y if unique>1 and min(np.bincount(y))>1 else None)

    clf=RandomForestClassifier(n_estimators=80,max_depth=12,class_weight="balanced",random_state=42,n_jobs=-1)
    clf.fit(Xtr,ytr); yp=clf.predict(Xte)
    train_f1=f1_score(ytr,clf.predict(Xtr),average="weighted",zero_division=0)
    test_f1=f1_score(yte,yp,average="weighted",zero_division=0)
    gap=train_f1-test_f1
    try: auc=float(roc_auc_score(yte,clf.predict_proba(Xte),multi_class="ovr",average="weighted"))
    except: auc=0.0
    mcc=float(matthews_corrcoef(yte,yp))
    cv=float(cross_val_score(clf,Xtr,ytr,cv=StratifiedKFold(n_splits=min(3,unique)),scoring="f1_weighted",n_jobs=-1).mean())

    metrics={"accuracy":round(float(accuracy_score(yte,yp)),4),"f1_test":round(float(test_f1),4),
             "f1_train":round(float(train_f1),4),"gap":round(float(gap),4),
             "overfitting":bool(gap>0.10),"auc":round(auc,4),"mcc":round(mcc,4),"cv_f1":round(cv,4),
             "dataset_type":req.dataset_type,"classes_found":unique}
    audit_log.log(user.user_id, user.tenant_id, "run_evaluation", "evaluation",
                  details={"dataset_type":req.dataset_type,"n":len(iocs),"f1":round(float(test_f1),4)})
    return EvalResult(dataset_type=req.dataset_type, dataset_size=len(iocs),
        model="RandomForest", metrics=metrics, is_synthetic_warning=req.dataset_type=="synthetic")

@router.get("/gat", summary="Evaluate GAT against MITRE ground truth")
async def evaluate_gat(
    user: CurrentUser = Depends(get_current_user),
    _rl=Depends(rate_limit(default_limiter)),
):
    from app.ml.gat import GATTrainer
    from app.core.config import settings
    trainer = GATTrainer(settings.MITRE_ATTACK_DATA_PATH)
    trainer.load("./model_artifacts/gat_weights.npz")
    rels = trainer.load_mitre_relationships()
    nodes, edges = trainer.build_graph(rels)
    import random; random.seed(42); random.shuffle(rels)
    test_rels = rels[:max(1, len(rels)//10)]
    test_pairs = [(g,t) for _,g,_,t in test_rels]
    metrics = trainer.model._evaluate(nodes, edges, test_pairs)
    return {"model":"NumpyGAT","trained":trainer.model.trained,"metrics":metrics}
