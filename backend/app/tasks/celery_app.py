"""Celery application configuration."""

from __future__ import annotations

import logging

from celery import Celery
from celery.signals import (
    worker_init,
    task_prerun,
    task_success,
    task_failure,
    task_retry,
)
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
    # Broker
    broker_connection_retry_on_startup=True,

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
        "weekly-cpe-sync": {
            "task": "app.tasks.cve_tasks.sync_cpe_dictionary",
            "schedule": crontab(hour=3, minute=0, day_of_week=0),  # Sunday 03:00 UTC
        },
        "worker-heartbeat-kuma": {
            "task": "app.tasks.health_tasks.kuma_worker_heartbeat",
            "schedule": 90,  # Every 90s (under Kuma's 120s threshold)
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


# ── Task lifecycle logging ────────────────────────────────────────────────────

def _task_name_to_worker_type(task_name: str) -> str:
    """Map full dotted task name to a short human-readable worker type."""
    mapping = {
        "app.tasks.cve_tasks.run_cve_scan": "cve_scan",
        "app.tasks.cve_tasks.sync_cpe_dictionary": "cpe_sync",
        "app.tasks.cve_tasks.enrich_cve_vendor_product": "enrichment",
        "app.tasks.cve_tasks.cleanup_vendor_product": "cleanup",
        "app.tasks.health_tasks.generate_and_send_health_report": "health",
        "app.tasks.init_tasks.initialize_database": "init",
        "app.tasks.init_tasks.initialize_database_local": "init_local",
        "app.tasks.init_tasks.initialize_database_upload": "init_upload",
    }
    return mapping.get(task_name, task_name.split(".")[-1])


@task_prerun.connect
def on_task_prerun(task_id, task, *args, **kwargs):
    try:
        from app.tasks.worker_log_writer import write_log
        write_log(
            _task_name_to_worker_type(task.name),
            f"Task started: {task.name}",
            level="INFO",
            task_id=task_id,
        )
    except Exception as exc:
        logger.warning(f"on_task_prerun log failed: {exc}")


@task_success.connect
def on_task_success(sender, result, **kwargs):
    try:
        from app.tasks.worker_log_writer import write_log
        write_log(
            _task_name_to_worker_type(sender.name),
            f"Task completed successfully: {sender.name}",
            level="INFO",
            task_id=sender.request.id,
            details=str(result)[:1000] if result else None,
        )
    except Exception as exc:
        logger.warning(f"on_task_success log failed: {exc}")


@task_failure.connect
def on_task_failure(task_id, exception, traceback, sender, *args, **kwargs):
    try:
        import traceback as tb_mod
        from app.tasks.worker_log_writer import write_log
        write_log(
            _task_name_to_worker_type(sender.name),
            f"Task FAILED: {type(exception).__name__}: {exception}",
            level="ERROR",
            task_id=task_id,
            details=tb_mod.format_exc()[:2000],
        )
    except Exception as exc:
        logger.warning(f"on_task_failure log failed: {exc}")


@task_retry.connect
def on_task_retry(request, reason, einfo, *args, **kwargs):
    try:
        from app.tasks.worker_log_writer import write_log
        task_name = request.task if hasattr(request, "task") else "unknown"
        write_log(
            _task_name_to_worker_type(task_name),
            f"Task retrying: {reason}",
            level="WARNING",
            task_id=request.id,
            details=str(einfo)[:1000] if einfo else None,
        )
    except Exception as exc:
        logger.warning(f"on_task_retry log failed: {exc}")
