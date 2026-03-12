"""Database v2 — SQLite local / PostgreSQL producción"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

class Base(DeclarativeBase):
    pass

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./fraud_engine_v2.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

# Pool explícito: 100 usuarios concurrentes requieren headroom
# pool_size=10: conexiones persistentes base
# max_overflow=20: conexiones extra en picos (total máx 30)
# pool_timeout=30: esperar hasta 30s antes de error
# pool_recycle=1800: reciclar conexiones cada 30 min (evita conexiones muertas en Railway)
if "sqlite" in DATABASE_URL:
    _engine = create_engine(DATABASE_URL, connect_args=connect_args)
else:
    _engine = create_engine(
        DATABASE_URL,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_recycle=1800,
        pool_pre_ping=True,   # verifica que la conexión esté viva antes de usarla
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

async def init_db():
    import models      # noqa
    import auth_models # noqa
    Base.metadata.create_all(bind=_engine)
    print(f"✅ BD inicializada: {DATABASE_URL[:50]}...")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
