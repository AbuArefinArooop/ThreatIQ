"""
ThreatIQ v4.0 -- Celery application for background tasks.
Tasks:
  - ingest_from_misp:   scheduled hourly
  - ingest_from_circl:  scheduled every 6 hours
  - ingest_from_otx:    scheduled daily
  - ingest_wazuh:       scheduled every 15 minutes (SIEM alerts, higher frequency)
  - retrain_gat:        scheduled weekly
  - run_anomaly_scan:   scheduled every 30 minutes
"""
from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

celery_app = Celery(
    "threatiq",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_max_tasks_per_child=100,
)

# ── Scheduled tasks ───────────────────────────────────────────────
celery_app.conf.beat_schedule = {
    "ingest-misp-hourly": {
        "task": "app.workers.tasks.ingest_misp",
        "schedule": crontab(minute=0),  # every hour
    },
    "ingest-circl-6h": {
        "task": "app.workers.tasks.ingest_circl",
        "schedule": crontab(minute=0, hour="*/6"),
    },
    "ingest-otx-daily": {
        "task": "app.workers.tasks.ingest_otx",
        "schedule": crontab(minute=0, hour=2),  # 2 AM UTC
    },
    "ingest-wazuh-15min": {
        "task": "app.workers.tasks.ingest_wazuh",
        "schedule": crontab(minute="*/15"),  # SIEM alerts are far higher-frequency than feed pulls
    },
    "retrain-gat-weekly": {
        "task": "app.workers.tasks.retrain_gat",
        "schedule": crontab(day_of_week="sunday", hour=3),
    },
    "anomaly-scan-30min": {
        "task": "app.workers.tasks.run_anomaly_scan",
        "schedule": crontab(minute="*/30"),
    },
}
