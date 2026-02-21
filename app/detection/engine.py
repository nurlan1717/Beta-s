"""Detection Engine for RansomRun platform.

This module implements a background service that:
1. Polls Elasticsearch for Sysmon events
2. Runs detection rules against events
3. Creates alerts in the database
4. Pushes alerts to SSE stream for live UI updates

The engine uses search_after pagination to avoid duplicates and
persists cursor state to survive restarts.
"""

import os
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field

from .ransomware_rules import (
    DETECTION_RULES,
    DetectionContext,
    DetectionAlert,
    get_all_event_ids
)

logger = logging.getLogger(__name__)


@dataclass
class EngineCursor:
    """Cursor state for incremental polling."""
    last_timestamp: Optional[str] = None
    search_after: Optional[List] = None
    last_poll_time: Optional[datetime] = None
    events_processed: int = 0
    alerts_generated: int = 0


@dataclass
class EngineStatus:
    """Engine runtime status."""
    running: bool = False
    started_at: Optional[datetime] = None
    last_poll: Optional[datetime] = None
    last_error: Optional[str] = None
    cursor: EngineCursor = field(default_factory=EngineCursor)
    poll_count: int = 0
    total_events_processed: int = 0
    total_alerts_generated: int = 0


class DetectionEngine:
    """
    Background detection engine that polls Elasticsearch and generates alerts.
    
    Usage:
        engine = DetectionEngine(elk_client, db_session_factory, alert_callback)
        await engine.start()
        # ... later ...
        await engine.stop()
    """
    
    def __init__(
        self,
        elk_client,
        db_session_factory: Callable,
        alert_callback: Callable[[DetectionAlert], None] = None,
        poll_interval: float = 3.0,
        batch_size: int = 100
    ):
        """
        Initialize detection engine.
        
        Args:
            elk_client: ELKClient instance for querying Elasticsearch
            db_session_factory: Callable that returns a DB session
            alert_callback: Optional callback for each alert (for SSE streaming)
            poll_interval: Seconds between polls (default 3s)
            batch_size: Events per poll (default 100)
        """
        self.elk_client = elk_client
        self.db_session_factory = db_session_factory
        self.alert_callback = alert_callback
        self.poll_interval = poll_interval
        self.batch_size = batch_size
        
        self.status = EngineStatus()
        self.context = DetectionContext()
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        
        # Alert queue for SSE streaming
        self.alert_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    
    async def start(self):
        """Start the detection engine background task."""
        if self.status.running:
            logger.warning("Detection engine already running")
            return
        
        logger.info("Starting detection engine...")
        self.status.running = True
        self.status.started_at = datetime.utcnow()
        self._stop_event.clear()
        
        # Load cursor from DB
        await self._load_cursor()
        
        # Start background task
        self._task = asyncio.create_task(self._poll_loop())
        logger.info("Detection engine started")
    
    async def stop(self):
        """Stop the detection engine."""
        if not self.status.running:
            return
        
        logger.info("Stopping detection engine...")
        self._stop_event.set()
        
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        # Save cursor to DB
        await self._save_cursor()
        
        self.status.running = False
        logger.info("Detection engine stopped")
    
    async def _poll_loop(self):
        """Main polling loop."""
        while not self._stop_event.is_set():
            try:
                await self._poll_once()
                self.status.poll_count += 1
                self.status.last_poll = datetime.utcnow()
                self.status.last_error = None
            except Exception as e:
                logger.error(f"Detection engine poll error: {e}")
                self.status.last_error = str(e)
            
            # Wait for next poll or stop signal
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.poll_interval
                )
                break  # Stop event was set
            except asyncio.TimeoutError:
                pass  # Continue polling
    
    async def _poll_once(self):
        """Execute one polling cycle."""
        # Get event IDs we care about
        event_ids = get_all_event_ids()
        
        # Query Elasticsearch
        result = self.elk_client.query_sysmon_events(
            since_ts=self.status.cursor.last_timestamp,
            size=self.batch_size,
            search_after=self.status.cursor.search_after,
            event_ids=event_ids
        )
        
        if result.get('error'):
            raise Exception(result['error'])
        
        hits = result.get('hits', [])
        if not hits:
            return
        
        # Process events through rules
        alerts = []
        for hit in hits:
            source = hit.get('_source', {})
            event_id_raw = source.get('winlog', {}).get('event_id')
            # Convert to int for comparison (ES stores as string "1", rules use int 1)
            try:
                event_id = int(event_id_raw) if event_id_raw else None
            except (ValueError, TypeError):
                event_id = None
            
            # Run applicable rules
            for rule in DETECTION_RULES:
                if event_id and event_id in rule.event_ids:
                    try:
                        alert = rule.evaluate(hit, self.context)
                        if alert:
                            alerts.append(alert)
                    except Exception as e:
                        logger.error(f"Rule {rule.rule_id} error: {e}")
        
        # Update cursor
        if hits:
            last_hit = hits[-1]
            self.status.cursor.last_timestamp = last_hit.get('_source', {}).get('@timestamp')
            self.status.cursor.search_after = result.get('search_after')
            self.status.cursor.events_processed += len(hits)
            self.status.total_events_processed += len(hits)
        
        # Save alerts to DB and notify
        if alerts:
            await self._save_alerts(alerts)
            self.status.cursor.alerts_generated += len(alerts)
            self.status.total_alerts_generated += len(alerts)
        
        # Periodically save cursor
        if self.status.poll_count % 10 == 0:
            await self._save_cursor()
    
    async def _save_alerts(self, alerts: List[DetectionAlert]):
        """Save alerts to database and push to queue."""
        db = self.db_session_factory()
        try:
            from ..models import Alert, Host
            
            for alert in alerts:
                # Find host by name
                host = db.query(Host).filter(Host.name == alert.host).first()
                host_id = host.id if host else None
                
                # Create alert directly using correct column names
                db_alert = Alert(
                    host_id=host_id,
                    run_id=None,
                    rule_id=alert.rule_id,
                    rule_description=alert.summary,
                    agent_name=alert.host,
                    severity=alert.severity_num,
                    raw=alert.to_dict()
                )
                db.add(db_alert)
                
                try:
                    db.flush()
                    logger.info(f"Alert created: {alert.rule_id} - {alert.summary}")
                except Exception as e:
                    logger.error(f"Failed to save alert: {e}")
                    db.rollback()
                
                # Push to SSE queue
                try:
                    self.alert_queue.put_nowait(alert.to_dict())
                except asyncio.QueueFull:
                    # Remove oldest and add new
                    try:
                        self.alert_queue.get_nowait()
                        self.alert_queue.put_nowait(alert.to_dict())
                    except:
                        pass
                
                # Call callback if provided
                if self.alert_callback:
                    try:
                        self.alert_callback(alert)
                    except Exception as e:
                        logger.error(f"Alert callback error: {e}")
            
            db.commit()
        finally:
            db.close()
    
    async def _load_cursor(self):
        """Load cursor state from database."""
        db = self.db_session_factory()
        try:
            from ..models import DetectionCursor
            
            cursor = db.query(DetectionCursor).filter(
                DetectionCursor.engine_id == 'main'
            ).first()
            
            if cursor:
                self.status.cursor.last_timestamp = cursor.last_timestamp
                self.status.cursor.search_after = cursor.search_after_json
                logger.info(f"Loaded cursor: {cursor.last_timestamp}")
            else:
                # Start from 24 hours ago if no cursor to catch recent events
                start_time = datetime.utcnow() - timedelta(hours=24)
                self.status.cursor.last_timestamp = start_time.isoformat() + 'Z'
                logger.info("No cursor found, starting from 24 hours ago")
        except Exception as e:
            logger.warning(f"Could not load cursor: {e}")
            # Start from 24 hours ago
            start_time = datetime.utcnow() - timedelta(hours=24)
            self.status.cursor.last_timestamp = start_time.isoformat() + 'Z'
        finally:
            db.close()
    
    async def _save_cursor(self):
        """Save cursor state to database."""
        db = self.db_session_factory()
        try:
            from ..models import DetectionCursor
            
            cursor = db.query(DetectionCursor).filter(
                DetectionCursor.engine_id == 'main'
            ).first()
            
            if cursor:
                cursor.last_timestamp = self.status.cursor.last_timestamp
                cursor.search_after_json = self.status.cursor.search_after
                cursor.updated_at = datetime.utcnow()
            else:
                cursor = DetectionCursor(
                    engine_id='main',
                    last_timestamp=self.status.cursor.last_timestamp,
                    search_after_json=self.status.cursor.search_after
                )
                db.add(cursor)
            
            db.commit()
            logger.debug(f"Saved cursor: {self.status.cursor.last_timestamp}")
        except Exception as e:
            logger.warning(f"Could not save cursor: {e}")
            db.rollback()
        finally:
            db.close()
    
    def get_status(self) -> Dict[str, Any]:
        """Get engine status for API."""
        return {
            'running': self.status.running,
            'started_at': self.status.started_at.isoformat() if self.status.started_at else None,
            'last_poll': self.status.last_poll.isoformat() if self.status.last_poll else None,
            'last_error': self.status.last_error,
            'poll_count': self.status.poll_count,
            'poll_interval_seconds': self.poll_interval,
            'cursor': {
                'last_timestamp': self.status.cursor.last_timestamp,
                'events_processed': self.status.cursor.events_processed,
                'alerts_generated': self.status.cursor.alerts_generated
            },
            'totals': {
                'events_processed': self.status.total_events_processed,
                'alerts_generated': self.status.total_alerts_generated
            },
            'queue_size': self.alert_queue.qsize()
        }


# Global engine instance (initialized in main.py lifespan)
_engine: Optional[DetectionEngine] = None


def get_detection_engine() -> Optional[DetectionEngine]:
    """Get the global detection engine instance."""
    return _engine


def set_detection_engine(engine: DetectionEngine):
    """Set the global detection engine instance."""
    global _engine
    _engine = engine
