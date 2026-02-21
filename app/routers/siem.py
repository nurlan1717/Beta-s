"""SIEM API routes for RansomRun platform.

This module provides SIEM integration using ELK/Elasticsearch as the backend.
"""

from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from .. import crud, schemas
from ..models import MITRE_MAPPING, EventType
from ..integrations.elk_client import ELKClient, get_elk_client_from_env, get_elk_client_from_config

router = APIRouter(prefix="/api/siem", tags=["SIEM"])


@router.get("/stats")
def get_siem_stats(
    hours: int = Query(24, description="Hours to look back"),
    db: Session = Depends(get_db)
):
    """Get SIEM statistics for dashboard."""
    stats = crud.get_alert_stats(db, hours=hours)
    alerts_over_time = crud.get_alerts_over_time(db, hours=hours)
    
    # Add MITRE mapping to rule stats
    rules_with_mitre = {}
    for rule_id, count in stats['alerts_by_rule'].items():
        mitre = MITRE_MAPPING.get(rule_id, {})
        rules_with_mitre[rule_id] = {
            'count': count,
            'technique': mitre.get('technique', 'N/A'),
            'name': mitre.get('name', 'Unknown')
        }
    
    return {
        **stats,
        'alerts_by_rule': rules_with_mitre,
        'alerts_over_time': alerts_over_time
    }


@router.get("/alerts")
def get_alerts_filtered(
    host_id: Optional[int] = None,
    rule_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    min_severity: Optional[int] = None,
    limit: int = Query(100, le=500),
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """Get filtered alerts for SIEM explorer."""
    alerts = crud.get_alerts_filtered(
        db,
        host_id=host_id,
        rule_id=rule_id,
        start_time=start_time,
        end_time=end_time,
        min_severity=min_severity,
        limit=limit,
        offset=offset
    )
    
    # Enrich with MITRE mapping
    result = []
    for alert in alerts:
        alert_dict = {
            'id': alert.id,
            'host_id': alert.host_id,
            'run_id': alert.run_id,
            'rule_id': alert.rule_id,
            'rule_description': alert.rule_description,
            'agent_name': alert.agent_name,
            'severity': alert.severity,
            'timestamp': alert.timestamp.isoformat() if alert.timestamp else None,
            'host_name': alert.host.name if alert.host else None
        }
        
        mitre = MITRE_MAPPING.get(alert.rule_id, {})
        alert_dict['mitre_technique'] = mitre.get('technique')
        alert_dict['mitre_name'] = mitre.get('name')
        
        result.append(alert_dict)
    
    return {
        'alerts': result,
        'count': len(result),
        'offset': offset,
        'limit': limit
    }


@router.get("/alerts/{alert_id}")
def get_alert_detail(alert_id: int, db: Session = Depends(get_db)):
    """Get detailed alert information."""
    alert = crud.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    mitre = MITRE_MAPPING.get(alert.rule_id, {})
    
    return {
        'id': alert.id,
        'host_id': alert.host_id,
        'run_id': alert.run_id,
        'rule_id': alert.rule_id,
        'rule_description': alert.rule_description,
        'agent_name': alert.agent_name,
        'severity': alert.severity,
        'timestamp': alert.timestamp.isoformat() if alert.timestamp else None,
        'raw': alert.raw,
        'mitre': {
            'technique': mitre.get('technique'),
            'name': mitre.get('name')
        },
        'host': {
            'id': alert.host.id,
            'name': alert.host.name
        } if alert.host else None,
        'run': {
            'id': alert.run.id,
            'status': alert.run.status.value
        } if alert.run else None
    }


@router.get("/top-rules")
def get_top_rules(
    limit: int = Query(10, le=50),
    hours: int = Query(24),
    db: Session = Depends(get_db)
):
    """Get top triggered rules."""
    stats = crud.get_alert_stats(db, hours=hours)
    
    rules = []
    for rule_id, count in sorted(
        stats['alerts_by_rule'].items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:limit]:
        mitre = MITRE_MAPPING.get(rule_id, {})
        rules.append({
            'rule_id': rule_id,
            'count': count,
            'technique': mitre.get('technique', 'N/A'),
            'name': mitre.get('name', 'Unknown')
        })
    
    return {'rules': rules}


# ============ ELK SIEM Integration ============

@router.get("/elk/status")
def get_elk_status(db: Session = Depends(get_db)):
    """Get ELK/Elasticsearch connection status with detected indices."""
    config = crud.get_elk_config(db)
    
    # Try environment-based client if no DB config
    client = get_elk_client_from_config(db) if config else get_elk_client_from_env()
    
    try:
        status = client.test_connection()
        
        # Detect available indices
        indices_info = {"winlogbeat": False, "filebeat": False}
        if status.get('connected'):
            try:
                indices_result = client.detect_indices()
                indices_info = {
                    "winlogbeat": indices_result.get("winlogbeat", False),
                    "filebeat": indices_result.get("filebeat", False)
                }
            except Exception:
                pass
        
        return {
            'configured': config is not None,
            'connected': status.get('connected', False),
            'url': config.url if config else 'From environment',
            'last_sync': config.last_sync.isoformat() if config and config.last_sync else None,
            'source': 'ELK',
            'indices': indices_info,
            **status
        }
    except Exception as e:
        return {
            'configured': config is not None,
            'connected': False,
            'url': config.url if config else 'From environment',
            'source': 'ELK',
            'indices': {"winlogbeat": False, "filebeat": False},
            'error': str(e)
        }


@router.get("/elk/indices")
def get_elk_indices(db: Session = Depends(get_db)):
    """Detect which index patterns exist in Elasticsearch."""
    client = get_elk_client_from_config(db)
    if not client:
        client = get_elk_client_from_env()
    
    try:
        result = client.detect_indices()
        return {
            **result,
            'source': 'ELK'
        }
    except Exception as e:
        return {
            'winlogbeat': False,
            'filebeat': False,
            'resolved': {'winlogbeat': [], 'filebeat': []},
            'error': str(e),
            'source': 'ELK'
        }


@router.get("/elk/logs")
def get_elk_logs(
    source: str = Query("all", regex="^(all|winlogbeat|filebeat)$"),
    host_name: Optional[str] = None,
    dataset: Optional[str] = None,
    service: Optional[str] = None,
    q: Optional[str] = None,
    minutes: int = Query(60, ge=1, le=1440),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """
    Get logs from Elasticsearch (winlogbeat and/or filebeat).
    
    Query params:
    - source: "all" | "winlogbeat" | "filebeat"
    - host_name: Filter by hostname
    - dataset: Filter by event.dataset / data_stream.dataset
    - service: Filter by service.name / fileset.module
    - q: Free text search
    - minutes: Time range (max 1440 = 24h)
    - limit: Max results (max 500)
    """
    client = get_elk_client_from_config(db)
    if not client:
        client = get_elk_client_from_env()
    
    try:
        logs = client.get_logs(
            source=source,
            limit=limit,
            host_name=host_name,
            dataset=dataset,
            service=service,
            q=q,
            minutes=minutes
        )
        return {
            'logs': logs,
            'count': len(logs),
            'source': source,
            'filters': {
                'host_name': host_name,
                'dataset': dataset,
                'service': service,
                'q': q,
                'minutes': minutes
            }
        }
    except Exception as e:
        return {
            'logs': [],
            'count': 0,
            'source': source,
            'error': str(e)
        }


@router.get("/elk/filebeat/hosts")
def get_filebeat_hosts(
    minutes: int = Query(1440, ge=1, le=10080),
    db: Session = Depends(get_db)
):
    """Get unique hosts from filebeat-* index."""
    client = get_elk_client_from_config(db)
    if not client:
        client = get_elk_client_from_env()
    
    try:
        hosts = client.get_filebeat_hosts(minutes=minutes)
        return {
            'hosts': hosts,
            'count': len(hosts),
            'source': 'filebeat'
        }
    except Exception as e:
        return {
            'hosts': [],
            'count': 0,
            'source': 'filebeat',
            'error': str(e)
        }


@router.get("/elk/filebeat/stats")
def get_filebeat_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db)
):
    """Get Filebeat statistics."""
    client = get_elk_client_from_config(db)
    if not client:
        client = get_elk_client_from_env()
    
    try:
        stats = client.get_filebeat_stats(hours=hours)
        return {
            **stats,
            'source': 'filebeat',
            'time_range_hours': hours
        }
    except Exception as e:
        return {
            'total_logs': 0,
            'logs_by_host': {},
            'logs_by_dataset': {},
            'logs_by_level': {},
            'source': 'filebeat',
            'error': str(e)
        }


@router.get("/elk/agents")
def get_elk_agents(db: Session = Depends(get_db)):
    """Get endpoints/hosts from ELK."""
    client = get_elk_client_from_config(db)
    
    if not client:
        client = get_elk_client_from_env()
    
    try:
        agents = client.get_agents()
        return {
            'agents': agents,
            'count': len(agents),
            'source': 'ELK'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elk/alerts")
def get_elk_alerts(
    limit: int = Query(50, le=500),
    host_name: Optional[str] = None,
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db)
):
    """Get alerts from database (generated by detection engine)."""
    from datetime import datetime, timedelta
    from ..models import Alert, Host
    
    try:
        since = datetime.utcnow() - timedelta(hours=hours)
        
        # Query alerts from database
        query = db.query(Alert).filter(Alert.timestamp >= since)
        
        # Host filter
        if host_name:
            host = db.query(Host).filter(Host.name.ilike(f"%{host_name}%")).first()
            if host:
                query = query.filter(Alert.host_id == host.id)
        
        alerts_db = query.order_by(Alert.timestamp.desc()).limit(limit).all()
        
        # Convert to response format matching ELK dashboard expectations
        alerts = []
        for a in alerts_db:
            raw = a.raw or {}
            mitre_data = raw.get('mitre', [])
            
            # Build mitre object for frontend compatibility
            mitre_obj = {'technique': 'N/A', 'technique_name': '', 'tactic': ''}
            if isinstance(mitre_data, list) and mitre_data:
                mitre_obj['technique'] = mitre_data[0] if mitre_data else 'N/A'
            elif isinstance(mitre_data, dict):
                mitre_obj = mitre_data
            
            endpoint = a.agent_name or (a.host.name if a.host else 'Unknown')
            
            alerts.append({
                'id': str(a.id),
                'timestamp': a.timestamp.isoformat() if a.timestamp else None,
                'host': endpoint,
                'endpoint': endpoint,  # Add endpoint field for frontend
                'agent_name': a.agent_name,
                'rule_id': a.rule_id,
                'rule_name': raw.get('rule_name', a.rule_id),
                'rule_description': a.rule_description or raw.get('summary', ''),
                'description': a.rule_description,
                'severity': a.severity,
                'severity_label': 'CRITICAL' if a.severity >= 15 else 'HIGH' if a.severity >= 10 else 'MEDIUM' if a.severity >= 5 else 'LOW',
                'mitre': mitre_obj,  # Object with technique field
                'raw': raw
            })
        
        return {
            'alerts': alerts,
            'count': len(alerts),
            'source': 'DATABASE'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elk/sync-alerts/{agent_name}")
def sync_elk_alerts(
    agent_name: str,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db)
):
    """Sync alerts from ELK for a specific endpoint."""
    client = get_elk_client_from_config(db)
    
    if not client:
        client = get_elk_client_from_env()
    
    try:
        # Get alerts from ELK
        elk_alerts = client.get_alerts(host_name=agent_name, limit=limit)
        
        # Find matching host
        host = crud.get_host_by_name(db, agent_name)
        host_id = host.id if host else None
        
        # Find active run for host
        run = crud.get_active_run_for_host(db, host_id) if host_id else None
        run_id = run.id if run else None
        
        synced = 0
        for alert in elk_alerts:
            # Create alert in local database
            crud.create_alert(
                db,
                rule_id=str(alert.get('rule_id', 'unknown')),
                rule_description=alert.get('rule_description'),
                agent_name=agent_name,
                severity=alert.get('severity', 0),
                timestamp=datetime.fromisoformat(alert.get('timestamp', datetime.utcnow().isoformat()).replace('Z', '+00:00')),
                raw=alert.get('raw', {}),
                host_id=host_id,
                run_id=run_id
            )
            synced += 1
        
        crud.update_elk_last_sync(db)
        
        return {
            'synced': synced,
            'agent_name': agent_name,
            'host_id': host_id,
            'source': 'ELK'
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elk/config")
def configure_elk(
    config: schemas.ELKConfigCreate,
    db: Session = Depends(get_db)
):
    """Configure ELK/Elasticsearch connection."""
    elk_config = crud.create_or_update_elk_config(
        db,
        url=config.url,
        username=config.username,
        password=config.password,
        api_key=config.api_key,
        index_alerts=config.index_alerts,
        index_logs=config.index_logs,
        enabled=config.enabled
    )
    
    # Test connection
    try:
        client = ELKClient(
            url=config.url,
            username=config.username,
            password=config.password,
            api_key=config.api_key,
            index_alerts=config.index_alerts,
            index_logs=config.index_logs
        )
        status = client.test_connection()
        
        return {
            'success': True,
            'config_id': elk_config.id,
            'connection_test': status,
            'source': 'ELK'
        }
    except Exception as e:
        return {
            'success': True,
            'config_id': elk_config.id,
            'connection_test': {'connected': False, 'error': str(e)},
            'source': 'ELK'
        }


@router.get("/elk/stats")
def get_elk_stats(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db)
):
    """Get ELK SIEM statistics from database."""
    from datetime import datetime, timedelta
    from ..models import Alert, Host
    
    try:
        since = datetime.utcnow() - timedelta(hours=hours)
        
        # Get alert counts from database
        total_alerts = db.query(Alert).filter(Alert.timestamp >= since).count()
        high_severity = db.query(Alert).filter(
            Alert.timestamp >= since,
            Alert.severity >= 10
        ).count()
        
        # Get endpoint counts
        total_endpoints = db.query(Host).count()
        active_endpoints = db.query(Host).filter(Host.status == 'ONLINE').count()
        
        return {
            'total_agents': total_endpoints,
            'active_agents': active_endpoints,
            'total_alerts': total_alerts,
            'high_severity_alerts': high_severity,
            'alerts_by_severity': {
                'low': db.query(Alert).filter(Alert.timestamp >= since, Alert.severity < 5).count(),
                'medium': db.query(Alert).filter(Alert.timestamp >= since, Alert.severity >= 5, Alert.severity < 10).count(),
                'high': db.query(Alert).filter(Alert.timestamp >= since, Alert.severity >= 10, Alert.severity < 15).count(),
                'critical': db.query(Alert).filter(Alert.timestamp >= since, Alert.severity >= 15).count()
            },
            'source': 'DATABASE'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elk/mitre/heatmap")
def get_elk_mitre_heatmap(
    hours: int = Query(168, ge=1, le=720),
    db: Session = Depends(get_db)
):
    """Get MITRE ATT&CK heatmap data from ELK."""
    client = get_elk_client_from_config(db)
    
    if not client:
        client = get_elk_client_from_env()
    
    try:
        heatmap = client.get_mitre_heatmap(time_range_hours=hours)
        return {
            **heatmap,
            'source': 'ELK'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ Extended Agent Results ============

# ============ Detection Engine Status ============

@router.get("/elk/events")
def get_elk_sysmon_events(
    limit: int = Query(50, le=200),
    hours: int = Query(1, ge=1, le=24),
    db: Session = Depends(get_db)
):
    """
    Debug endpoint: Get raw Sysmon events from Elasticsearch.
    
    Returns last N Sysmon events for inspection.
    """
    client = get_elk_client_from_config(db)
    if not client:
        client = get_elk_client_from_env()
    
    try:
        events = client.search_events(
            filters={'event.provider': 'Microsoft-Windows-Sysmon'},
            time_range_hours=hours,
            size=limit
        )
        
        return {
            'events': [
                {
                    'id': e.get('_id'),
                    'timestamp': e.get('_source', {}).get('@timestamp'),
                    'event_id': e.get('_source', {}).get('winlog', {}).get('event_id'),
                    'host': e.get('_source', {}).get('host', {}).get('name'),
                    'process': e.get('_source', {}).get('process', {}).get('name'),
                    'command_line': e.get('_source', {}).get('process', {}).get('command_line'),
                    'source': e.get('_source', {})
                }
                for e in events
            ],
            'count': len(events),
            'source': 'ELK'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/elk/detections/status")
def get_detection_engine_status():
    """
    Get detection engine status.
    
    Returns whether the engine is running, last poll time, cursor position, etc.
    """
    try:
        from ..detection.engine import get_detection_engine
        
        engine = get_detection_engine()
        if not engine:
            return {
                'running': False,
                'message': 'Detection engine not initialized (SIEM_MODE may be "mock")',
                'siem_mode': 'mock'
            }
        
        status = engine.get_status()
        status['siem_mode'] = 'elastic'
        return status
    except Exception as e:
        return {
            'running': False,
            'error': str(e),
            'siem_mode': 'unknown'
        }


@router.post("/agent/extended-result")
def receive_extended_result(
    data: dict,
    db: Session = Depends(get_db)
):
    """Receive extended forensic results from agent."""
    run_id = data.get('run_id')
    
    if not run_id:
        raise HTTPException(status_code=400, detail="run_id required")
    
    run = crud.get_run_by_id(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    host_id = run.host_id
    
    # Store affected files
    files = data.get('files_affected', [])
    for f in files:
        f['run_id'] = run_id
        f['host_id'] = host_id
    files_count = crud.bulk_create_affected_files(db, files) if files else 0
    
    # Store IOCs
    iocs = data.get('iocs', [])
    for i in iocs:
        i['run_id'] = run_id
        i['host_id'] = host_id
    iocs_count = crud.bulk_create_iocs(db, iocs) if iocs else 0
    
    # Store metrics
    metrics = data.get('metrics', {})
    for name, value in metrics.items():
        crud.create_metric(db, run_id, name, float(value), host_id)
    
    # Store events
    events = data.get('events', [])
    for e in events:
        try:
            event_type = EventType(e.get('event_type', 'TASK_COMPLETED'))
        except ValueError:
            event_type = EventType.TASK_COMPLETED
        
        crud.create_run_event(
            db, run_id, event_type,
            host_id=host_id,
            details=e.get('details')
        )
    
    return {
        'success': True,
        'files_stored': files_count,
        'iocs_stored': iocs_count,
        'metrics_stored': len(metrics),
        'events_stored': len(events)
    }


@router.post("/agent/sensor-alert")
def receive_sensor_alert(
    data: dict,
    db: Session = Depends(get_db)
):
    """
    Receive sensor alerts from agent (entropy monitor, honeyfile deception).
    
    Alert types:
    - POSSIBLE_RANSOMWARE: Entropy-based detection of file encryption
    - HONEYFILE_TOUCHED: Honeyfile was accessed/modified
    - HONEYFILE_DELETED: Honeyfile was deleted
    """
    run_id = data.get('run_id')
    agent_id = data.get('agent_id')
    alert_type = data.get('alert_type')
    timestamp = data.get('timestamp')
    details = data.get('details', {})
    severity = data.get('severity', 70)
    mitre_technique = data.get('mitre_technique')
    
    if not run_id:
        raise HTTPException(status_code=400, detail="run_id required")
    
    run = crud.get_run_by_id(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    
    host_id = run.host_id
    
    # Map sensor alert types to event types
    event_type_map = {
        "POSSIBLE_RANSOMWARE": EventType.FILE_ENCRYPTED,
        "HONEYFILE_TOUCHED": EventType.FILE_ACCESSED,
        "HONEYFILE_DELETED": EventType.FILE_DELETED,
    }
    
    event_type = event_type_map.get(alert_type, EventType.TASK_COMPLETED)
    
    # Create run event for the sensor alert
    crud.create_run_event(
        db, run_id, event_type,
        host_id=host_id,
        details={
            "sensor_type": "entropy" if alert_type == "POSSIBLE_RANSOMWARE" else "honeyfile",
            "alert_type": alert_type,
            "file": details.get("file"),
            "mitre_technique": mitre_technique,
            **details
        }
    )
    
    # Create alert record
    rule_id = f"SENSOR_{alert_type}"
    alert_data = {
        "run_id": run_id,
        "host_id": host_id,
        "rule_id": rule_id,
        "severity": severity,
        "message": f"Sensor Alert: {alert_type} - {details.get('file', 'Unknown file')}",
        "details": details,
        "mitre_technique": mitre_technique
    }
    
    crud.create_alert(db, alert_data)
    
    return {
        'success': True,
        'alert_type': alert_type,
        'message': f'Sensor alert {alert_type} recorded'
    }


@router.post("/detection/reset-cursor")
def reset_detection_cursor(db: Session = Depends(get_db)):
    """Reset the detection cursor to reprocess historical events."""
    from ..models import DetectionCursor
    
    try:
        # Delete existing cursor to force reprocessing from 24h ago
        db.query(DetectionCursor).delete()
        db.commit()
        
        return {
            'success': True,
            'message': 'Detection cursor reset. Engine will reprocess events from 24h ago.'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/detection/status")
def get_detection_status(db: Session = Depends(get_db)):
    """Get detection engine status."""
    from ..models import DetectionCursor, Alert
    
    try:
        cursor = db.query(DetectionCursor).first()
        total_alerts = db.query(Alert).count()
        recent_alerts = db.query(Alert).filter(
            Alert.timestamp >= datetime.utcnow() - timedelta(hours=1)
        ).count()
        
        return {
            'cursor': {
                'last_timestamp': cursor.last_timestamp if cursor else None,
                'events_processed': cursor.events_processed if cursor else 0,
                'alerts_generated': cursor.alerts_generated if cursor else 0
            } if cursor else None,
            'total_alerts': total_alerts,
            'recent_alerts_1h': recent_alerts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/sync-filebeat-alerts")
def sync_filebeat_critical_alerts(
    time_range_hours: int = 24,
    db: Session = Depends(get_db)
):
    """
    Sync critical filebeat logs to alerts table.
    
    Fetches logs with level=critical from ELK and creates alerts in the database.
    This makes filebeat critical events appear in the Recent Alerts section.
    """
    from ..integrations.elk_client import ELKClient
    from ..models import Alert, Host
    
    elk = ELKClient()
    
    # Query for critical logs from filebeat
    query = {
        'size': 100,
        'sort': [{'@timestamp': {'order': 'desc'}}],
        'query': {
            'bool': {
                'must': [
                    {
                        'range': {
                            '@timestamp': {
                                'gte': f'now-{time_range_hours}h',
                                'lte': 'now'
                            }
                        }
                    },
                    {
                        'bool': {
                            'should': [
                                {'term': {'log.level': 'critical'}},
                                {'term': {'event.severity': 'critical'}},
                                {'match': {'message': 'POSSIBLE_RANSOMWARE'}},
                                {'match': {'event.type': 'POSSIBLE_RANSOMWARE'}}
                            ],
                            'minimum_should_match': 1
                        }
                    }
                ]
            }
        }
    }
    
    try:
        result = elk._request('POST', f'/{elk.index_logs}/_search', body=query)
        hits = result.get('hits', {}).get('hits', [])
        
        alerts_created = 0
        alerts_skipped = 0
        
        for hit in hits:
            source = hit.get('_source', {})
            doc_id = hit.get('_id')
            
            # Check if alert already exists (by doc_id in raw)
            existing = db.query(Alert).filter(
                Alert.raw.contains({'elk_doc_id': doc_id})
            ).first()
            
            if existing:
                alerts_skipped += 1
                continue
            
            # Extract fields
            timestamp_str = source.get('@timestamp')
            host_name = source.get('host', {}).get('name') or source.get('agent', {}).get('name')
            message = source.get('message', '')
            event_type = source.get('event', {}).get('type', 'CRITICAL_LOG')
            
            # Parse timestamp
            try:
                if timestamp_str:
                    if 'T' in timestamp_str:
                        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    else:
                        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                else:
                    timestamp = datetime.utcnow()
            except:
                timestamp = datetime.utcnow()
            
            # Find host by name
            host = None
            host_id = None
            if host_name:
                host = db.query(Host).filter(Host.name == host_name).first()
                if host:
                    host_id = host.id
            
            # Determine severity (critical = 20)
            severity = 20
            
            # Create rule_id from event type
            if 'POSSIBLE_RANSOMWARE' in message or event_type == 'POSSIBLE_RANSOMWARE':
                rule_id = 'FILEBEAT_POSSIBLE_RANSOMWARE'
                rule_description = 'Possible Ransomware Activity Detected'
            else:
                rule_id = f'FILEBEAT_CRITICAL_{event_type.upper()}'
                rule_description = f'Critical Event: {event_type}'
            
            # Create alert
            alert = Alert(
                host_id=host_id,
                rule_id=rule_id,
                rule_description=rule_description,
                agent_name=host_name,
                severity=severity,
                timestamp=timestamp,
                raw={
                    'elk_doc_id': doc_id,
                    'source': 'filebeat',
                    'message': message[:500] if message else None,
                    'host': host_name,
                    'original': source
                }
            )
            db.add(alert)
            alerts_created += 1
        
        db.commit()
        
        return {
            'success': True,
            'alerts_created': alerts_created,
            'alerts_skipped': alerts_skipped,
            'total_hits': len(hits),
            'message': f'Synced {alerts_created} critical filebeat logs as alerts'
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': 'Failed to sync filebeat alerts. Check ELK connection.'
        }
