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

# ── Register API routes ──────────────────────────────
from app.api.routes_dashboard import router as dashboard_router
from app.api.routes_filters import router as filters_router
from app.api.routes_cves import router as cves_router
from app.api.routes_alerts import router as alerts_router
from app.api.routes_ka import router as ka_router
from app.api.routes_config import router as config_router
from app.api.routes_test import router as test_router
from app.api.routes_health import router as health_router

app.include_router(dashboard_router)
app.include_router(filters_router)
app.include_router(cves_router)
app.include_router(alerts_router)
app.include_router(ka_router)
app.include_router(config_router)
app.include_router(test_router)
app.include_router(health_router)


@app.get("/api/health")
async def health_check():
    """Simple health check endpoint used by Docker/Nginx."""
    return {"status": "ok", "service": "AbuseCVE (≖_≖ )"}
