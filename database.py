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
_engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

async def init_db():
    # Import all models so Base knows about them
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

