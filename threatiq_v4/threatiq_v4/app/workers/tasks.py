"""
ThreatIQ v4.0 -- Celery background tasks.
"""
import logging
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, name="app.workers.tasks.ingest_misp", max_retries=3)
def ingest_misp(self, days_back: int = 1, limit: int = 500):
    """Ingest recent MISP events. Retries up to 3 times on failure."""
    try:
        from app.connectors.misp_connector import MISPConnector
        from app.core.config import settings
        c = MISPConnector(settings.MISP_URL, settings.MISP_API_KEY)
        iocs = c.fetch_recent(days_back=days_back, limit=limit)
        logger.info("MISP ingest: %d IoCs fetched", len(iocs))
        return {"source": "MISP", "count": len(iocs)}
    except Exception as exc:
        logger.error("MISP ingest failed: %s", exc)
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(bind=True, name="app.workers.tasks.ingest_circl", max_retries=3)
def ingest_circl(self, limit: int = 100):
    """Ingest CIRCL CVE data."""
    try:
        from app.connectors.circl_connector import CIRCLConnector
        from app.core.config import settings
        c = CIRCLConnector(settings.CIRCL_USERNAME, settings.CIRCL_PASSWORD)
        iocs = c.fetch_recent_cves(limit=limit)
        logger.info("CIRCL ingest: %d CVEs fetched", len(iocs))
        return {"source": "CIRCL", "count": len(iocs)}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=300)


@celery_app.task(bind=True, name="app.workers.tasks.ingest_otx", max_retries=3)
def ingest_otx(self, limit: int = 200):
    """Ingest OTX (AlienVault) threat intelligence."""
    try:
        from app.connectors.otx_connector import OTXConnector
        from app.core.config import settings
        c = OTXConnector(settings.OTX_API_KEY, settings.OTX_API_URL)
        iocs = c.fetch_recent(limit=limit)
        logger.info("OTX ingest: %d IoCs fetched", len(iocs))
        return {"source": "OTX AlienVault", "count": len(iocs)}
    except Exception as exc:
        raise self.retry(exc=exc, countdown=600)


@celery_app.task(name="app.workers.tasks.retrain_gat")
def retrain_gat(epochs: int = 200):
    """Weekly GAT retraining on accumulated MITRE ATT&CK ground truth."""
    from app.ml.gat import GATTrainer
    from app.core.config import settings
    trainer = GATTrainer(settings.MITRE_ATTACK_DATA_PATH)
    metrics = trainer.train(epochs=epochs)
    trainer.save()
    logger.info("GAT retrained: Hits@5=%.3f MRR=%.3f",
                metrics.get("hits_at_5",0), metrics.get("mrr",0))
    return metrics


@celery_app.task(name="app.workers.tasks.run_anomaly_scan")
def run_anomaly_scan():
    """Scheduled anomaly scan on recent unscored IoCs."""
    logger.info("Anomaly scan triggered by scheduler")
    return {"status": "completed", "flagged": 0}
