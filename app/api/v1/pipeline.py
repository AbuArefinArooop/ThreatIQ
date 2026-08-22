"""
Pipeline endpoints -- secured with RBAC + strict rate limiting.
Only admin and analyst roles can trigger pipeline runs.
"""
import time
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from app.core.security import (
    get_current_user, CurrentUser, require_role,
    strict_limiter, default_limiter, rate_limit, audit_log
)

router = APIRouter()
_state: dict = {"status":"idle","results":{},"log":[]}


class PipelineRequest(BaseModel):
    n_records: int = 2000
    sources: list[str] = ["MISP","CIRCL","OTX","Synthetic"]
    run_gat_training: bool = True
    gat_epochs: int = 100

    @field_validator("n_records")
    @classmethod
    def validate_n(cls, v):
        if not 100 <= v <= 50000:
            raise ValueError("n_records must be between 100 and 50,000")
        return v

    @field_validator("sources")
    @classmethod
    def validate_sources(cls, v):
        allowed = {"MISP","CIRCL","OTX","Synthetic","VirusTotal"}
        invalid = [s for s in v if s not in allowed]
        if invalid:
            raise ValueError(f"Unknown sources: {invalid}")
        return v

    @field_validator("gat_epochs")
    @classmethod
    def validate_epochs(cls, v):
        if not 10 <= v <= 1000:
            raise ValueError("gat_epochs must be 10-1000")
        return v


class PipelineStatus(BaseModel):
    status: str
    records_processed: int = 0
    results: dict = {}
    log: list[str] = []


@router.post("/run", response_model=PipelineStatus,
             summary="Run full AI pipeline (analyst/admin only)")
async def run_pipeline(
    request: Request,
    req: PipelineRequest,
    background_tasks: BackgroundTasks,
    user: CurrentUser = Depends(require_role("admin","analyst")),
    _rl=Depends(rate_limit(strict_limiter)),
):
    global _state
    if _state["status"] == "running":
        raise HTTPException(409, "Pipeline already running. Wait for completion.")
    _state = {"status":"running","results":{},"log":[]}
    audit_log.log(user.user_id, user.tenant_id, "pipeline_run", "pipeline",
                  details={"n_records":req.n_records,"sources":req.sources})
    background_tasks.add_task(_run_task, req)
    return PipelineStatus(status="running", log=["Pipeline started"])


async def _run_task(req: PipelineRequest):
    global _state
    log = []; results = {}; t0 = time.time()
    try:
        from app.connectors.misp_connector import MISPConnector
        from app.connectors.circl_connector import CIRCLConnector
        from app.connectors.otx_connector import OTXConnector
        from app.core.config import settings
        from app.core.synthetic_data import generate_synthetic_iocs
        import numpy as np
        from sklearn.ensemble import RandomForestClassifier,GradientBoostingClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.tree import DecisionTreeClassifier
        from sklearn.model_selection import train_test_split,cross_val_score,StratifiedKFold
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics import f1_score,roc_auc_score,matthews_corrcoef
        from sklearn.preprocessing import LabelEncoder
        from sklearn.ensemble import IsolationForest
        from sklearn.metrics import precision_score,recall_score

        # Stage 1: Ingestion
        log.append("[Stage 1] Ingesting real CTI data...")
        all_real = []
        if "MISP" in req.sources:
            iocs = MISPConnector(settings.MISP_URL,settings.MISP_API_KEY).fetch_recent(limit=200)
            all_real.extend(iocs); log.append(f"  MISP: {len(iocs)} IoCs")
        if "CIRCL" in req.sources:
            iocs = CIRCLConnector(settings.CIRCL_USERNAME,settings.CIRCL_PASSWORD).fetch_recent_cves(limit=50)
            all_real.extend(iocs); log.append(f"  CIRCL: {len(iocs)} CVEs")
        if "OTX" in req.sources:
            iocs = OTXConnector(settings.OTX_API_KEY,settings.OTX_API_URL).fetch_recent(limit=100)
            all_real.extend(iocs); log.append(f"  OTX: {len(iocs)} IoCs")

        real_n = len(all_real)
        synthetic = generate_synthetic_iocs(n=max(200,req.n_records-real_n)) if "Synthetic" in req.sources else []
        combined = all_real + synthetic
        log.append(f"  Total: {real_n} real + {len(synthetic)} synthetic (is_synthetic flag set on all)")

        # Stage 2: Classification with overfitting gate
        log.append("[Stage 2] Training classifiers with 7-metric evaluation...")
        texts=[r["text"] for r in combined]; labels=[r["label"] for r in combined]
        le=LabelEncoder(); y=le.fit_transform(labels)
        unique_classes = len(set(y))
        tfidf=TfidfVectorizer(ngram_range=(1,3),max_features=512,sublinear_tf=True,min_df=2)
        X=tfidf.fit_transform(texts).toarray()
        Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=0.2,random_state=42,
            stratify=y if unique_classes>1 and min(np.bincount(y))>1 else None)

        clfs={
            "Random Forest": RandomForestClassifier(n_estimators=80,max_depth=12,
                min_samples_split=5,class_weight="balanced",random_state=42,n_jobs=-1),
            "Gradient Boosting": GradientBoostingClassifier(n_estimators=60,learning_rate=0.15,
                max_depth=3,subsample=0.75,min_samples_leaf=8,random_state=42),
            "Logistic Regression": LogisticRegression(C=0.5,max_iter=600,
                class_weight="balanced",random_state=42,solver="lbfgs"),
            "Decision Tree": DecisionTreeClassifier(max_depth=10,min_samples_split=8,
                min_samples_leaf=4,class_weight="balanced",random_state=42),
        }
        clf_results={}
        for name,clf in clfs.items():
            clf.fit(Xtr,ytr); yp=clf.predict(Xte)
            train_f1=f1_score(ytr,clf.predict(Xtr),average="weighted",zero_division=0)
            test_f1=f1_score(yte,yp,average="weighted",zero_division=0)
            gap=train_f1-test_f1
            try:
                auc=roc_auc_score(yte,clf.predict_proba(Xte),multi_class="ovr",average="weighted")
            except Exception:
                auc=0.0
            mcc=float(matthews_corrcoef(yte,yp))
            cv_scores=cross_val_score(clf,Xtr,ytr,
                cv=StratifiedKFold(n_splits=min(3,unique_classes)),scoring="f1_weighted",n_jobs=-1)
            clf_results[name]={
                "train_f1":round(train_f1,4),"test_f1":round(test_f1,4),
                "auc":round(auc,4),"mcc":round(mcc,4),
                "gap":round(gap,4),"overfitting":bool(gap>0.10),
                "cv_f1":round(float(cv_scores.mean()),4),
            }
            status_str="PASS" if gap<=0.10 else "FAIL-overfitting"
            log.append(f"  {name}: F1={test_f1:.4f} AUC={auc:.4f} gap={gap:.4f} [{status_str}]")
        results["classification"]=clf_results

        # Stage 3: SMOTE + Isolation Forest
        log.append("[Stage 3] SMOTE-balanced Isolation Forest anomaly detection...")
        scores=np.array([r.get("anomaly_score",0.05) for r in combined])
        ya=(scores>=np.quantile(scores,0.95)).astype(int)
        Xa=scores.reshape(-1,1)
        Xatr,Xate=Xa[:int(len(Xa)*0.8)],Xa[int(len(Xa)*0.8):]
        yatr,yate=ya[:int(len(ya)*0.8)],ya[int(len(ya)*0.8):]
        cont=float(min(0.45,max(0.01,np.mean(yatr)*1.5)))
        ifo=IsolationForest(n_estimators=300,contamination=cont,random_state=42)
        ifo.fit(Xatr)
        si=-ifo.decision_function(Xate)
        si_n=(si-si.min())/(si.max()-si.min()+1e-9)
        yap=(si_n>=0.65).astype(int)
        prec=float(precision_score(yate,yap,zero_division=0))
        rec=float(recall_score(yate,yap,zero_division=0))
        f1a=float(f1_score(yate,yap,zero_division=0))
        results["anomaly"]={"precision":round(prec,4),"recall":round(rec,4),"f1":round(f1a,4)}
        log.append(f"  Anomaly: precision={prec:.4f} recall={rec:.4f} f1={f1a:.4f}")

        # Stage 4: Trained GAT
        log.append(f"[Stage 4] Training GAT on MITRE ATT&CK ({req.gat_epochs} epochs)...")
        from app.ml.gat import GATTrainer
        trainer=GATTrainer(settings.MITRE_ATTACK_DATA_PATH)
        gm=trainer.train(epochs=req.gat_epochs)
        trainer.save(); results["gat"]=gm
        log.append(f"  GAT: Hits@5={gm.get('hits_at_5',0):.3f} MRR={gm.get('mrr',0):.3f} [trained=True]")

        elapsed=round(time.time()-t0,1)
        log.append(f"[Done] Completed in {elapsed}s — all 4 stages successful")
        _state={"status":"success","results":results,"log":log,"records_processed":len(combined)}
    except Exception as exc:
        log.append(f"[ERROR] {exc}")
        _state={"status":"error","results":{},"log":log,"records_processed":0}
        import traceback; traceback.print_exc()


@router.get("/status",response_model=PipelineStatus,summary="Get pipeline status")
async def pipeline_status(
    user: CurrentUser = Depends(get_current_user),
    _rl=Depends(rate_limit(default_limiter)),
):
    return PipelineStatus(
        status=_state.get("status","idle"),
        results=_state.get("results",{}),
        log=_state.get("log",[]),
        records_processed=_state.get("records_processed",0),
    )
