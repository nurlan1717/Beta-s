"""Database configuration and session management for RANSOMRUN."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .models import Base

# SQLite database file path
SQLALCHEMY_DATABASE_URL = "sqlite:///./ransomrun.db"

# Create engine with SQLite-specific settings
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}  # Required for SQLite
)

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
