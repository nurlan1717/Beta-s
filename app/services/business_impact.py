"""
Business Impact Simulator - Technical to $$$ Translation Service
=================================================================
Translates technical incident facts into business impact estimates:
- Downtime costs
- Recovery time
- Data sensitivity impact
- Total estimated cost
"""

from datetime import datetime
from typing import Dict, Optional
from sqlalchemy.orm import Session

from ..models import (
    Run, AffectedFile, Metric, BusinessImpact, ScenarioCategory
)


# Business unit cost multipliers
BUSINESS_UNIT_MULTIPLIERS = {
    "Finance": 2.0,
    "HR": 1.2,
    "Production": 2.5,
    "IT": 1.5,
    "Sales": 1.8,
    "Legal": 1.7,
    "Executive": 2.2,
    "Generic": 1.0
}

# Scenario category impact factors
CATEGORY_IMPACT = {
    ScenarioCategory.CRYPTO: {"downtime_factor": 1.5, "recovery_factor": 2.0},
    ScenarioCategory.WIPER: {"downtime_factor": 2.5, "recovery_factor": 3.0},
    ScenarioCategory.LOCKER: {"downtime_factor": 1.0, "recovery_factor": 0.5},
    ScenarioCategory.EXFIL: {"downtime_factor": 0.5, "recovery_factor": 1.0},
    ScenarioCategory.FAKE: {"downtime_factor": 0.1, "recovery_factor": 0.1},
    ScenarioCategory.MULTI_STAGE: {"downtime_factor": 2.0, "recovery_factor": 2.5}
}


def calculate_business_impact(
    db: Session,
    run: Run,
    business_unit: str = "Generic",
    criticality_level: int = 3,
    cost_per_hour: float = 500.0,
    data_sensitivity: int = 3
) -> BusinessImpact:
    """
    Calculate business impact for a simulation run.
    
    Args:
        db: Database session
        run: The Run to analyze
        business_unit: Department/unit affected
        criticality_level: 1-5 scale of system criticality
        cost_per_hour: Hourly cost of downtime in dollars
        data_sensitivity: 1-5 scale of data sensitivity
        
    Returns:
        BusinessImpact with calculated estimates
    """
    # Gather data
    affected_files = db.query(AffectedFile).filter(AffectedFile.run_id == run.id).all()
    metrics = db.query(Metric).filter(Metric.run_id == run.id).all()
    
    file_count = len(affected_files)
    
    # Get metrics
    execution_time_ms = 0
    for m in metrics:
        if m.name == "execution_time_ms":
            execution_time_ms = m.value
    
    # Calculate base estimates
    estimates = _calculate_estimates(
        run=run,
        file_count=file_count,
        execution_time_ms=execution_time_ms,
        business_unit=business_unit,
        criticality_level=criticality_level,
        cost_per_hour=cost_per_hour,
        data_sensitivity=data_sensitivity
    )
    
    # Check for existing impact record
    existing = db.query(BusinessImpact).filter(BusinessImpact.run_id == run.id).first()
    
    if existing:
        existing.business_unit = business_unit
        existing.criticality_level = criticality_level
        existing.assumed_cost_per_hour = cost_per_hour
        existing.estimated_downtime_hours = estimates["downtime_hours"]
        existing.estimated_data_recovery_hours = estimates["recovery_hours"]
        existing.data_sensitivity_level = data_sensitivity
        existing.estimated_total_cost = estimates["total_cost"]
        existing.notes = estimates["notes"]
        db.commit()
        return existing
    
    # Create new impact record
    impact = BusinessImpact(
        run_id=run.id,
        business_unit=business_unit,
        criticality_level=criticality_level,
        assumed_cost_per_hour=cost_per_hour,
        estimated_downtime_hours=estimates["downtime_hours"],
        estimated_data_recovery_hours=estimates["recovery_hours"],
        data_sensitivity_level=data_sensitivity,
        estimated_total_cost=estimates["total_cost"],
        notes=estimates["notes"]
    )
    
    db.add(impact)
    db.commit()
    db.refresh(impact)
    
    return impact


def _calculate_estimates(
    run: Run,
    file_count: int,
    execution_time_ms: float,
    business_unit: str,
    criticality_level: int,
    cost_per_hour: float,
    data_sensitivity: int
) -> Dict:
    """
    Calculate downtime, recovery, and cost estimates.
    
    Heuristic formulas documented inline.
    """
    notes_parts = []
    
    # Get category impact factors
    category = run.scenario.category if run.scenario else ScenarioCategory.CRYPTO
    impact_factors = CATEGORY_IMPACT.get(category, CATEGORY_IMPACT[ScenarioCategory.CRYPTO])
    
    # Get business unit multiplier
    unit_multiplier = BUSINESS_UNIT_MULTIPLIERS.get(business_unit, 1.0)
    
    # --- Downtime calculation ---
    # Base: 1 hour per 50 files affected
    base_downtime = max(0.5, file_count / 50)
    
    # Apply criticality factor (1-5 maps to 0.5x - 2.5x)
    criticality_factor = 0.5 + (criticality_level * 0.4)
    
    # Apply category factor
    downtime_hours = base_downtime * criticality_factor * impact_factors["downtime_factor"]
    
    # Cap at reasonable maximum
    downtime_hours = min(72, downtime_hours)
    
    notes_parts.append(f"Downtime based on {file_count} files, criticality {criticality_level}")
    
    # --- Recovery calculation ---
    # Base: 0.5 hours per 20 files (technician speed)
    base_recovery = max(0.25, file_count / 40)
    
    # Apply data sensitivity factor (1-5 maps to 0.5x - 2.5x)
    sensitivity_factor = 0.5 + (data_sensitivity * 0.4)
    
    # Apply category factor
    recovery_hours = base_recovery * sensitivity_factor * impact_factors["recovery_factor"]
    
    # Add verification time for sensitive data
    if data_sensitivity >= 4:
        recovery_hours += 2  # Extra verification time
        notes_parts.append("Added verification time for sensitive data")
    
    # Cap at reasonable maximum
    recovery_hours = min(120, recovery_hours)
    
    # --- Total cost calculation ---
    total_hours = downtime_hours + recovery_hours
    
    # Apply business unit multiplier
    adjusted_cost = cost_per_hour * unit_multiplier
    
    total_cost = total_hours * adjusted_cost
    
    # Add incident response costs (fixed overhead)
    ir_overhead = 500 * criticality_level  # $500-$2500 based on criticality
    total_cost += ir_overhead
    
    notes_parts.append(f"IR overhead: ${ir_overhead}")
    
    # Add potential regulatory costs for high sensitivity
    if data_sensitivity >= 4:
        regulatory_cost = 5000 * (data_sensitivity - 3)
        total_cost += regulatory_cost
        notes_parts.append(f"Potential regulatory cost: ${regulatory_cost}")
    
    # Round values
    downtime_hours = round(downtime_hours, 1)
    recovery_hours = round(recovery_hours, 1)
    total_cost = round(total_cost, 2)
    
    return {
        "downtime_hours": downtime_hours,
        "recovery_hours": recovery_hours,
        "total_cost": total_cost,
        "notes": "; ".join(notes_parts)
    }


def get_impact_summary(impact: BusinessImpact) -> str:
    """Generate human-readable impact summary."""
    total_hours = impact.estimated_downtime_hours + impact.estimated_data_recovery_hours
    
    severity = "minimal"
    if impact.estimated_total_cost > 50000:
        severity = "severe"
    elif impact.estimated_total_cost > 20000:
        severity = "significant"
    elif impact.estimated_total_cost > 5000:
        severity = "moderate"
    
    return (
        f"Under the selected assumptions, this incident could cause approximately "
        f"{total_hours:.1f} hours of disruption and cost an estimated "
        f"${impact.estimated_total_cost:,.2f}. "
        f"This represents a {severity} business impact for the {impact.business_unit} unit."
    )


def get_impact_comparison(db: Session, run_id: int) -> Dict:
    """Compare this run's impact to others."""
    current = db.query(BusinessImpact).filter(BusinessImpact.run_id == run_id).first()
    
    if not current:
        return {"percentile": None, "comparison": "No impact data available"}
    
    # Get all impacts
    all_impacts = db.query(BusinessImpact).all()
    
    if len(all_impacts) < 2:
        return {"percentile": 50, "comparison": "Not enough data for comparison"}
    
    # Calculate percentile
    costs = sorted([i.estimated_total_cost for i in all_impacts])
    current_cost = current.estimated_total_cost
    
    below_count = sum(1 for c in costs if c < current_cost)
    percentile = int((below_count / len(costs)) * 100)
    
    if percentile >= 80:
        comparison = f"This incident is in the top {100 - percentile}% most costly"
    elif percentile >= 50:
        comparison = f"This incident is above average (top {100 - percentile}%)"
    else:
        comparison = f"This incident is below average in cost (bottom {percentile}%)"
    
    return {
        "percentile": percentile,
        "comparison": comparison,
        "avg_cost": sum(costs) / len(costs),
        "max_cost": max(costs),
        "min_cost": min(costs)
    }


def get_business_impact_for_run(db: Session, run_id: int) -> Optional[BusinessImpact]:
    """Get business impact for a specific run."""
    return db.query(BusinessImpact).filter(BusinessImpact.run_id == run_id).first()
