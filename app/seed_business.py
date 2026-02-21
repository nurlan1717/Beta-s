"""Seed script for Business Portal data.

Creates a default business user and initializes business portal tables.

Usage:
    python -m app.seed_business
    
    Or from Python:
        from app.seed_business import seed_business_user
        seed_business_user(db)
"""

from datetime import datetime
from sqlalchemy.orm import Session

from .database import SessionLocal, engine
from .models import AuthUser, UserRole, Base
from .models_business import (
    BusinessSettings, Organization, OrganizationPlan,
    PilotConfig, Base as BusinessBase
)
from .auth.security import hash_password


def seed_business_user(db: Session, 
                       email: str = "business@ransomrun.local",
                       password: str = "ChangeMe123!") -> AuthUser:
    """
    Create a default business user for portal access.
    
    Args:
        db: Database session
        email: Email for the business user (default: business@ransomrun.local)
        password: Password for the business user (default: ChangeMe123!)
        
    Returns:
        The created or existing AuthUser
    """
    # Check if user already exists
    existing = db.query(AuthUser).filter(AuthUser.email == email.lower()).first()
    if existing:
        print(f"[SEED] Business user already exists: {email}")
        # Update role if not already business
        if existing.role != UserRole.BUSINESS:
            existing.role = UserRole.BUSINESS
            db.commit()
            print(f"[SEED] Updated user role to BUSINESS")
        return existing
    
    # Create new business user
    user = AuthUser(
        email=email.lower(),
        username="business_admin",
        password_hash=hash_password(password),
        role=UserRole.BUSINESS,
        is_active=True,
        created_at=datetime.utcnow()
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    print(f"[SEED] Created business user: {email}")
    print(f"[SEED] Password: {password}")
    print(f"[SEED] Role: {user.role.value}")
    
    return user


def seed_business_settings(db: Session, user_id: int = None) -> BusinessSettings:
    """Create default business settings."""
    existing = db.query(BusinessSettings).filter(
        BusinessSettings.user_id == user_id
    ).first()
    
    if existing:
        print(f"[SEED] Business settings already exist for user {user_id}")
        return existing
    
    settings = BusinessSettings(
        user_id=user_id,
        hourly_revenue=10000.0,
        hourly_it_cost=500.0,
        baseline_downtime_hours=4.0,
        target_rto_minutes=60,
        target_rpo_minutes=15
    )
    db.add(settings)
    db.commit()
    db.refresh(settings)
    
    print(f"[SEED] Created default business settings")
    return settings


def seed_demo_organization(db: Session) -> Organization:
    """Create a demo organization."""
    existing = db.query(Organization).filter(Organization.name == "Demo Corp").first()
    if existing:
        print(f"[SEED] Demo organization already exists")
        return existing
    
    org = Organization(
        name="Demo Corp",
        industry="Technology",
        plan=OrganizationPlan.PRO,
        contact_email="admin@democorp.local",
        max_endpoints=50,
        max_users=10,
        is_active=True
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    
    print(f"[SEED] Created demo organization: Demo Corp")
    return org


def seed_pilot_config(db: Session) -> PilotConfig:
    """Create default pilot configuration."""
    existing = db.query(PilotConfig).first()
    if existing:
        print(f"[SEED] Pilot config already exists")
        return existing
    
    config = PilotConfig(
        target_users_count=20,
        duration_days=14,
        success_threshold=0.70,
        conversion_target=0.30,
        is_active=True
    )
    db.add(config)
    db.commit()
    db.refresh(config)
    
    print(f"[SEED] Created pilot configuration")
    return config


def create_business_tables():
    """Create all business portal tables."""
    from .models_business import (
        BusinessSettings, Organization, OrganizationUser, RoiCalcHistory,
        TrainingCampaign, TrainingResult, Feedback, PilotConfig,
        BusinessAuditLog, ComplianceExport
    )
    
    # Import Base from models to ensure all tables are registered
    from .models import Base
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    print("[SEED] Business portal tables created")


def run_business_seed():
    """Run all business portal seed operations."""
    print("=" * 50)
    print("  RANSOMRUN - Business Portal Seed")
    print("=" * 50)
    
    # Create tables first
    create_business_tables()
    
    db = SessionLocal()
    try:
        # Create business user
        user = seed_business_user(db)
        
        # Create default settings
        seed_business_settings(db, user.id)
        
        # Create demo organization
        seed_demo_organization(db)
        
        # Create pilot config
        seed_pilot_config(db)
        
        print("=" * 50)
        print("  Business Portal Seed Complete!")
        print("=" * 50)
        print("")
        print("  Login credentials:")
        print("  Email:    business@ransomrun.local")
        print("  Password: ChangeMe123!")
        print("")
        print("  Access the Business Portal at: /business/login")
        print("=" * 50)
        
    finally:
        db.close()


if __name__ == "__main__":
    run_business_seed()
