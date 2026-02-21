"""
Advanced Features API Router
=============================
Endpoints for:
- Behavior DNA Lab
- What-If Analysis
- Coach Feedback
- Business Impact
- Compliance Reports
- User/Analyst Profiles
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from ..database import get_db
from ..models import (
    Run, User, BehaviorProfile, WhatIfScenario, RunFeedback,
    BusinessImpact, ComplianceReport, IRSession, UserSkillProfile,
    ReportType, UserRole
)
from ..services import behavior, whatif, coach, business_impact, compliance


router = APIRouter(prefix="/api/advanced", tags=["Advanced Features"])


# =============================================================================
# Pydantic Schemas
# =============================================================================

class BehaviorProfileResponse(BaseModel):
    id: int
    run_id: int
    techniques: Optional[list] = None
    actions_sequence: Optional[list] = None
    intensity_score: float
    stealthiness_score: float
    dna_vector: Optional[dict] = None
    profile_label: Optional[str] = None

    class Config:
        from_attributes = True


class WhatIfRequest(BaseModel):
    template_key: str


class WhatIfCustomRequest(BaseModel):
    name: str
    assumptions: dict


class WhatIfResponse(BaseModel):
    id: int
    run_id: int
    name: str
    assumptions: Optional[dict] = None
    recalculated_metrics: Optional[dict] = None

    class Config:
        from_attributes = True


class BusinessImpactRequest(BaseModel):
    business_unit: str = "Generic"
    criticality_level: int = 3
    cost_per_hour: float = 500.0
    data_sensitivity: int = 3


class BusinessImpactResponse(BaseModel):
    id: int
    run_id: int
    business_unit: str
    criticality_level: int
    assumed_cost_per_hour: float
    estimated_downtime_hours: float
    estimated_data_recovery_hours: float
    estimated_total_cost: float
    notes: Optional[str] = None

    class Config:
        from_attributes = True


class ComplianceRequest(BaseModel):
    report_type: str = "Generic"
    data_sensitivity: int = 3
    personal_data_involved: Optional[bool] = None


class FeedbackResponse(BaseModel):
    id: int
    run_id: int
    positives: Optional[str] = None
    negatives: Optional[str] = None
    recommendations: Optional[str] = None

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    username: str
    full_name: Optional[str] = None
    role: str = "analyst"


class UserResponse(BaseModel):
    id: int
    username: str
    full_name: Optional[str] = None
    role: str

    class Config:
        from_attributes = True


# =============================================================================
# Behavior DNA Endpoints
# =============================================================================

@router.get("/behavior/profiles", response_model=List[BehaviorProfileResponse])
def list_behavior_profiles(
    limit: int = Query(50, le=100),
    db: Session = Depends(get_db)
):
    """List all behavior profiles for DNA Lab."""
    profiles = behavior.get_all_behavior_profiles(db, limit)
    return profiles


@router.get("/behavior/run/{run_id}", response_model=BehaviorProfileResponse)
def get_behavior_profile(run_id: int, db: Session = Depends(get_db)):
    """Get behavior profile for a specific run."""
    profile = behavior.get_behavior_profile_by_run(db, run_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Behavior profile not found")
    return profile


@router.post("/behavior/generate/{run_id}", response_model=BehaviorProfileResponse)
def generate_behavior_profile(run_id: int, db: Session = Depends(get_db)):
    """Generate or regenerate behavior profile for a run."""
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    profile = behavior.generate_behavior_profile(db, run)
    return profile


# =============================================================================
# What-If Analysis Endpoints
# =============================================================================

@router.get("/whatif/templates")
def get_whatif_templates():
    """Get available What-If scenario templates."""
    return whatif.get_whatif_templates()


@router.get("/whatif/run/{run_id}", response_model=List[WhatIfResponse])
def get_whatif_scenarios(run_id: int, db: Session = Depends(get_db)):
    """Get all What-If scenarios for a run."""
    scenarios = whatif.get_whatif_scenarios_for_run(db, run_id)
    return scenarios


@router.post("/whatif/run/{run_id}", response_model=WhatIfResponse)
def create_whatif_scenario(
    run_id: int, 
    request: WhatIfRequest,
    db: Session = Depends(get_db)
):
    """Create a What-If scenario from a template."""
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    try:
        scenario = whatif.create_whatif_scenario(db, run, request.template_key)
        return scenario
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/whatif/run/{run_id}/custom", response_model=WhatIfResponse)
def create_custom_whatif(
    run_id: int,
    request: WhatIfCustomRequest,
    db: Session = Depends(get_db)
):
    """Create a custom What-If scenario."""
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    scenario = whatif.create_custom_whatif(db, run, request.name, request.assumptions)
    return scenario


# =============================================================================
# Coach Feedback Endpoints
# =============================================================================

@router.get("/coach/run/{run_id}", response_model=FeedbackResponse)
def get_coach_feedback(run_id: int, db: Session = Depends(get_db)):
    """Get coach feedback for a run."""
    feedback = coach.get_feedback_for_run(db, run_id)
    if not feedback:
        raise HTTPException(status_code=404, detail="Feedback not found")
    return feedback


@router.post("/coach/generate/{run_id}", response_model=FeedbackResponse)
def generate_coach_feedback(
    run_id: int,
    user_id: Optional[int] = None,
    db: Session = Depends(get_db)
):
    """Generate coach feedback for a run."""
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    user = None
    if user_id:
        user = db.query(User).filter(User.id == user_id).first()
    
    feedback = coach.generate_run_feedback(db, run, user)
    return feedback


# =============================================================================
# Business Impact Endpoints
# =============================================================================

@router.get("/impact/run/{run_id}", response_model=BusinessImpactResponse)
def get_business_impact(run_id: int, db: Session = Depends(get_db)):
    """Get business impact for a run."""
    impact = business_impact.get_business_impact_for_run(db, run_id)
    if not impact:
        raise HTTPException(status_code=404, detail="Business impact not found")
    return impact


@router.post("/impact/calculate/{run_id}", response_model=BusinessImpactResponse)
def calculate_business_impact(
    run_id: int,
    request: BusinessImpactRequest,
    db: Session = Depends(get_db)
):
    """Calculate business impact for a run."""
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    impact = business_impact.calculate_business_impact(
        db, run,
        business_unit=request.business_unit,
        criticality_level=request.criticality_level,
        cost_per_hour=request.cost_per_hour,
        data_sensitivity=request.data_sensitivity
    )
    return impact


@router.get("/impact/run/{run_id}/comparison")
def get_impact_comparison(run_id: int, db: Session = Depends(get_db)):
    """Compare this run's impact to others."""
    return business_impact.get_impact_comparison(db, run_id)


# =============================================================================
# Compliance Report Endpoints
# =============================================================================

@router.get("/compliance/run/{run_id}")
def get_compliance_report(
    run_id: int,
    report_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Get compliance report for a run."""
    rt = None
    if report_type:
        try:
            rt = ReportType(report_type)
        except ValueError:
            pass
    
    report = compliance.get_compliance_report_for_run(db, run_id, rt)
    if not report:
        raise HTTPException(status_code=404, detail="Compliance report not found")
    return report


@router.post("/compliance/generate/{run_id}")
def generate_compliance_report(
    run_id: int,
    request: ComplianceRequest,
    db: Session = Depends(get_db)
):
    """Generate compliance report for a run."""
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    try:
        report_type = ReportType(request.report_type)
    except ValueError:
        report_type = ReportType.GENERIC
    
    report = compliance.generate_compliance_report(
        db, run,
        report_type=report_type,
        data_sensitivity=request.data_sensitivity,
        personal_data_involved=request.personal_data_involved
    )
    return report


@router.get("/compliance/run/{run_id}/export")
def export_compliance_report(run_id: int, db: Session = Depends(get_db)):
    """Export compliance report as text."""
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    report = compliance.get_compliance_report_for_run(db, run_id)
    if not report:
        raise HTTPException(status_code=404, detail="Compliance report not found")
    
    return {"text": compliance.format_report_for_export(report, run)}


# =============================================================================
# User/Analyst Endpoints
# =============================================================================

@router.get("/users", response_model=List[UserResponse])
def list_users(db: Session = Depends(get_db)):
    """List all users."""
    users = db.query(User).all()
    return users


@router.post("/users", response_model=UserResponse)
def create_user(request: UserCreate, db: Session = Depends(get_db)):
    """Create a new user."""
    existing = db.query(User).filter(User.username == request.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    try:
        role = UserRole(request.role)
    except ValueError:
        role = UserRole.ANALYST
    
    user = User(
        username=request.username,
        full_name=request.full_name,
        role=role
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/users/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    """Get user details with skill profile."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get IR sessions
    sessions = db.query(IRSession).filter(IRSession.user_id == user_id).all()
    
    # Get recent feedback
    feedbacks = coach.get_recent_feedback_for_user(db, user_id, limit=5)
    
    return {
        "user": user,
        "sessions_count": len(sessions),
        "recent_feedbacks": feedbacks,
        "skill_profile": user.skill_profile
    }


@router.post("/users/{user_id}/start-session/{run_id}")
def start_ir_session(user_id: int, run_id: int, db: Session = Depends(get_db)):
    """Start an IR session for a user on a run."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    session = IRSession(
        run_id=run_id,
        user_id=user_id
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    
    return {"session_id": session.id, "message": "IR session started"}
