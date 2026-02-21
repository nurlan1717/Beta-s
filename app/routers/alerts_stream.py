"""SSE Streaming endpoint for live alerts.

This module provides Server-Sent Events (SSE) streaming for real-time
alert delivery to the UI without page refresh.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Optional, AsyncGenerator

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..detection.engine import get_detection_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/alerts", tags=["Alerts Stream"])


async def event_generator(
    request: Request,
    since: Optional[str] = None
) -> AsyncGenerator[str, None]:
    """
    Generate SSE events for alert streaming.
    
    Yields:
        SSE formatted events with alert data
    """
    engine = get_detection_engine()
    
    # Send initial connection event
    yield f"event: connected\ndata: {json.dumps({'status': 'connected', 'timestamp': datetime.utcnow().isoformat()})}\n\n"
    
    # Heartbeat interval
    heartbeat_interval = 15  # seconds
    last_heartbeat = datetime.utcnow()
    
    while True:
        # Check if client disconnected
        if await request.is_disconnected():
            logger.info("SSE client disconnected")
            break
        
        # Try to get alert from queue
        if engine and engine.status.running:
            try:
                # Non-blocking get with short timeout
                alert = await asyncio.wait_for(
                    engine.alert_queue.get(),
                    timeout=1.0
                )
                
                # Send alert event
                yield f"event: alert\ndata: {json.dumps(alert)}\n\n"
                continue
                
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logger.error(f"SSE queue error: {e}")
        else:
            # Engine not running, wait a bit
            await asyncio.sleep(1.0)
        
        # Send heartbeat periodically
        now = datetime.utcnow()
        if (now - last_heartbeat).total_seconds() >= heartbeat_interval:
            heartbeat_data = {
                'type': 'heartbeat',
                'timestamp': now.isoformat(),
                'engine_running': engine.status.running if engine else False
            }
            yield f"event: heartbeat\ndata: {json.dumps(heartbeat_data)}\n\n"
            last_heartbeat = now


@router.get("/stream")
async def stream_alerts(
    request: Request,
    since: Optional[str] = Query(None, description="ISO timestamp to get alerts since")
):
    """
    SSE endpoint for streaming live alerts.
    
    Connect to this endpoint to receive real-time alerts as they are detected.
    
    Events:
        - connected: Initial connection confirmation
        - alert: New alert detected
        - heartbeat: Keep-alive signal (every 15s)
    
    Example usage (JavaScript):
        const es = new EventSource('/api/alerts/stream');
        es.addEventListener('alert', (e) => {
            const alert = JSON.parse(e.data);
            console.log('New alert:', alert);
        });
    """
    return StreamingResponse(
        event_generator(request, since),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        }
    )


@router.get("")
async def get_alerts_since(
    since: Optional[str] = Query(None, description="ISO timestamp to get alerts since"),
    limit: int = Query(50, le=500, description="Maximum alerts to return"),
    severity_min: int = Query(0, ge=0, le=15, description="Minimum severity (0-15)")
):
    """
    REST fallback endpoint for getting recent alerts.
    
    Use this if SSE is not available or for initial page load.
    """
    from ..crud import get_alerts
    from ..database import SessionLocal
    
    db = SessionLocal()
    try:
        alerts = get_alerts(
            db,
            limit=limit,
            since=since,
            min_severity=severity_min
        )
        
        return {
            'alerts': [
                {
                    'id': a.id,
                    'rule_id': a.rule_id,
                    'description': a.description,
                    'severity': a.severity,
                    'severity_label': _severity_label(a.severity),
                    'host_id': a.host_id,
                    'host_name': a.host.name if a.host else None,
                    'run_id': a.run_id,
                    'timestamp': a.timestamp.isoformat() if a.timestamp else None,
                    'raw_data': a.raw_data
                }
                for a in alerts
            ],
            'count': len(alerts),
            'since': since
        }
    finally:
        db.close()


def _severity_label(severity: int) -> str:
    """Convert numeric severity to label."""
    if severity >= 12:
        return 'CRITICAL'
    elif severity >= 10:
        return 'HIGH'
    elif severity >= 6:
        return 'MEDIUM'
    return 'LOW'
