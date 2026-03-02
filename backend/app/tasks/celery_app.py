"""Celery application configuration."""

from __future__ import annotations

import logging

from celery import Celery
from celery.signals import worker_init
from celery.schedules import crontab

from app.config import settings

logger = logging.getLogger(__name__)

celery_app = Celery(
    "abusecve",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.tasks.cve_tasks",
        "app.tasks.health_tasks",
        "app.tasks.init_tasks",
    ],
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Reliability
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,

    # Resource management
    worker_max_memory_per_child=200_000,  # 200MB, then restart
    worker_max_tasks_per_child=100,       # restart after 100 tasks

    # Result expiry
    result_expires=3600,

    # Worker hooks
    worker_hijack_root_logger=False,

    # Beat schedule
    beat_schedule={
        "cve-scan-cycle": {
            "task": "app.tasks.cve_tasks.run_cve_scan",
            "schedule": settings.scan_interval_minutes * 60,  # seconds
        },
        "daily-health-report": {
            "task": "app.tasks.health_tasks.generate_and_send_health_report",
            "schedule": crontab(
                hour=settings.health_report_hour,
                minute=settings.health_report_minute,
            ),
        },
    },
)


@worker_init.connect
def init_worker(**kwargs):
    """Load filter rules when the Celery worker starts."""
    from app.engine.rule_loader import load_rules, set_rules_path

    if settings.rules_file_path:
        set_rules_path(settings.rules_file_path)

    rules = load_rules()
    logger.info(f"Celery worker loaded {len(rules)} filter rules from config")
