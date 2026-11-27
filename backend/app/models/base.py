from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from app.core.config import settings

Base = declarative_base()

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Safe column addition migrations for SQLite / PostgreSQL when extending tables
        def apply_migrations(connection):
            import sqlite3
            raw_conn = connection.connection
            cursor = raw_conn.cursor()
            # 1. Check scans columns
            for col, col_type in [("project_id", "VARCHAR(36)"), ("user_id", "VARCHAR(36)")]:
                try:
                    cursor.execute(f"ALTER TABLE scans ADD COLUMN {col} {col_type}")
                except Exception:
                    pass
            # 2. Check version_comparisons columns
            for col, col_type in [("project_id", "VARCHAR(36)"), ("user_id", "VARCHAR(36)")]:
                try:
                    cursor.execute(f"ALTER TABLE version_comparisons ADD COLUMN {col} {col_type}")
                except Exception:
                    pass
            # 3. Check projects columns
            try:
                cursor.execute("ALTER TABLE projects ADD COLUMN owner_id VARCHAR(36)")
            except Exception:
                pass
            # 4. Check policies.trigger_type, action
            try:
                cursor.execute("ALTER TABLE policies ADD COLUMN trigger_type VARCHAR(64) DEFAULT 'vulnerability'")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE policies ADD COLUMN action VARCHAR(32) DEFAULT 'BLOCK'")
            except Exception:
                pass
        await conn.run_sync(apply_migrations)
