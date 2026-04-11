"""AbuseCVE – Main FastAPI application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import init_db

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown lifecycle."""
    logger.info("🛡️  AbuseCVE (≖_≖ ) — Starting up...")
    # Initialize database tables
    await init_db()
    logger.info("✅ Database tables initialized")
    # Load filter rules from YAML config file
    from app.engine.rule_loader import load_rules, set_rules_path
    if settings.rules_file_path:
        set_rules_path(settings.rules_file_path)
    load_rules()
    logger.info("✅ Filter rules loaded from config file")
    yield
    logger.info("🛡️  AbuseCVE (≖_≖ ) — Shutting down...")


app = FastAPI(
    title="AbuseCVE (≖_≖ )",
    description="Lightweight CTI Platform — CVE Monitoring, Filtering & Alerting",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth middleware ────────────────────────────────
# Attaches the current user (or None) to request.state so downstream
# routes can enforce RBAC without re-parsing the token themselves.
# Also enforces SOC restrictions centrally: blocks DELETE on KAs and
# filter rules, and blocks all writes to integrations/webhooks.
@app.middleware("http")
async def rbac_middleware(request, call_next):
    from app.api.routes_auth import resolve_user

    user = resolve_user(request)
    request.state.user = user

    path = request.url.path
    method = request.method.upper()

    # Endpoints that never require auth — health probes and login.
    public_prefixes = (
        "/api/auth/login", "/api/health", "/api/auth/logout",
    )
    if path.startswith(public_prefixes) or path == "/":
        return await call_next(request)

    # All other /api/* routes require a valid session
    if path.startswith("/api/"):
        if not user:
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)

        role = user.get("role")
        if role == "SOC":
            # Block SOC writes on restricted surfaces
            blocked = False
            if path.startswith("/api/knowledge-articles") and method == "DELETE":
                blocked = True
            elif path.startswith("/api/filters") and (
                method == "DELETE"
                or path.startswith("/api/filters/create")
                or path.startswith("/api/filters/refine")
            ):
                blocked = True
            elif path.startswith("/api/integrations") and method != "GET":
                blocked = True
            elif path.startswith("/api/auth/toggles") and method != "GET":
                blocked = True
            if blocked:
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    {"detail": "SOC role cannot perform this action"},
                    status_code=403,
                )

    return await call_next(request)

# ── Register API routes ──────────────────────────────
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_filters import router as filters_router
from app.api.routes_cves import router as cves_router
from app.api.routes_alerts import router as alerts_router
from app.api.routes_ka import router as ka_router
from app.api.routes_test import router as test_router
from app.api.routes_health import router as health_router
from app.api.routes_logs import router as logs_router
from app.api.routes_integrations import router as integrations_router
from app.api.routes_export import router as export_router
from app.api.routes_vendor_product import router as vendor_product_router
from app.api.routes_feedback import router as feedback_router
from app.api.routes_auth import router as auth_router

app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(filters_router)
app.include_router(cves_router)
app.include_router(alerts_router)
app.include_router(ka_router)
app.include_router(test_router)
app.include_router(health_router)
app.include_router(logs_router)
app.include_router(integrations_router)
app.include_router(export_router)
app.include_router(vendor_product_router)
app.include_router(feedback_router)


@app.get("/api/health")
async def health_check():
    """Simple health check endpoint used by Docker/Nginx."""
    return {"status": "ok", "service": "AbuseCVE (≖_≖ )"}


@app.get("/api/health/deep")
async def deep_health_check():
    """Deep health check — probes Postgres, Redis, and Celery workers.

    Returns a JSON diagnostic object suitable for Uptime Kuma keyword monitoring.
    Overall status is 'healthy' only when ALL components pass.
    """
    import asyncio
    from datetime import datetime

    components = {}

    # ── Postgres ──────────────────────────────────────────
    try:
        from sqlalchemy import text
        from app.database import engine
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            result.fetchone()
        components["postgres"] = {"status": "up", "detail": "query OK"}
    except Exception as e:
        components["postgres"] = {"status": "down", "detail": str(e)[:200]}

    # ── Redis ─────────────────────────────────────────────
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url, socket_connect_timeout=5)
        pong = await r.ping()
        info = await r.info("memory")
        used_mb = round(info.get("used_memory", 0) / 1024 / 1024, 1)
        await r.aclose()
        components["redis"] = {
            "status": "up" if pong else "down",
            "detail": f"PONG, {used_mb}MB used",
        }
    except Exception as e:
        components["redis"] = {"status": "down", "detail": str(e)[:200]}

    # ── Celery Workers ────────────────────────────────────
    try:
        from app.tasks.celery_app import celery_app as _celery
        inspect = _celery.control.inspect(timeout=5)
        ping_result = inspect.ping()
        if ping_result:
            worker_names = list(ping_result.keys())
            active = inspect.active() or {}
            active_count = sum(len(v) for v in active.values())
            components["celery_workers"] = {
                "status": "up",
                "detail": f"{len(worker_names)} worker(s), {active_count} active task(s)",
                "workers": worker_names,
            }
        else:
            components["celery_workers"] = {"status": "down", "detail": "no workers responded to ping"}
    except Exception as e:
        components["celery_workers"] = {"status": "down", "detail": str(e)[:200]}

    # ── Celery Beat ───────────────────────────────────────
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.redis_url, socket_connect_timeout=5)
        # Beat writes its schedule to disk; check if the schedule key exists in Redis
        # or simply verify the beat process is reachable via the worker's registered tasks
        beat_info = await r.get("celery-beat-last-heartbeat")
        await r.aclose()
        if beat_info:
            components["celery_beat"] = {"status": "up", "detail": "heartbeat present"}
        else:
            # Fall back — beat might work but not set this key; mark as unknown
            components["celery_beat"] = {"status": "unknown", "detail": "no heartbeat key — check beat logs"}
    except Exception as e:
        components["celery_beat"] = {"status": "down", "detail": str(e)[:200]}

    # ── Overall ───────────────────────────────────────────
    critical = ["postgres", "redis", "celery_workers"]
    all_up = all(components.get(c, {}).get("status") == "up" for c in critical)

    return {
        "status": "healthy" if all_up else "degraded",
        "service": "AbuseCVE (≖_≖ )",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "components": components,
    }
