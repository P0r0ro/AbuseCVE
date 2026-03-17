"""AbuseCVE – Async SQLAlchemy database engine and session management."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=settings.app_env == "development",
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    pool_recycle=300,
)

async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    """FastAPI dependency – yields an async DB session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables and add any missing columns (lightweight migration)."""
    async with engine.begin() as conn:
        from app.models import cve, filter_rule, alert_log, knowledge_article, health_report  # noqa
        from app.models import worker_log, integration  # noqa  – new tables
        from app.models import vendor_product  # noqa  – normalized vendor/product entities
        await conn.run_sync(Base.metadata.create_all)

        # Lightweight migration: add columns that may be missing from older schemas.
        # Each statement uses a DO block to check if the column exists first.
        migrations = [
            # FilterRule new columns
            ("filter_rules", "alert_on_modified", "BOOLEAN DEFAULT FALSE"),
            ("filter_rules", "conditions", "JSONB"),
            ("filter_rules", "severity_mapping", "JSONB"),
            ("filter_rules", "include_unknown", "BOOLEAN DEFAULT FALSE"),
            ("filter_rules", "pql_query", "TEXT"),
            # CVE new columns
            ("cves", "sources", "JSONB"),
            ("cves", "cvss_scores", "JSONB"),
            ("cves", "weaknesses", "JSONB"),
            ("cves", "affected_products", "JSONB"),
            # CVE normalized vendor/product FK columns
            ("cves", "vendor_id", "INTEGER REFERENCES vendors(id) ON DELETE SET NULL"),
            ("cves", "product_id", "INTEGER REFERENCES products(id) ON DELETE SET NULL"),
            ("cves", "extraction_method", "VARCHAR(30)"),
            # AlertLog new columns
            ("alert_logs", "rule_name", "VARCHAR(255)"),
            ("alert_logs", "is_new_cve", "BOOLEAN"),
        ]

        from sqlalchemy import text
        for table, column, col_type in migrations:
            stmt = text(f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = '{table}' AND column_name = '{column}'
                    ) THEN
                        ALTER TABLE {table} ADD COLUMN {column} {col_type};
                        RAISE NOTICE 'Added column %.% ', '{table}', '{column}';
                    END IF;
                END $$;
            """)
            await conn.execute(stmt)

