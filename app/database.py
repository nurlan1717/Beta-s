"""Database configuration and session management for RANSOMRUN."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .models import Base
from .models_directory import DirectoryUser, DirectoryDevice, DirectoryGroup  # Import directory lab models

# SQLite database file path
SQLALCHEMY_DATABASE_URL = "sqlite:///./ransomrun.db"

# Create engine with SQLite-specific settings
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)

# Enable WAL mode for better concurrent read performance
from sqlalchemy import event
from sqlalchemy.engine import Engine
import sqlite3

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    if isinstance(dbapi_conn, sqlite3.Connection):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA cache_size=-32000")  # 32MB cache
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.close()

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database tables."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """Dependency that provides a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
