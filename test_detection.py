"""Test detection rules against live Elasticsearch data."""
import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from app.integrations.elk_client import ELKClient
from app.detection.ransomware_rules import DETECTION_RULES, DetectionContext

client = ELKClient()
context = DetectionContext()

# Query recent events
result = client.query_sysmon_events(since_ts='2025-12-14T00:00:00Z', size=500, event_ids=[1,3,10,11,13])
hits = result.get('hits', [])
print(f"Events fetched: {len(hits)}")

alerts_count = 0
for hit in hits:
    source = hit.get('_source', {})
    event_id_raw = source.get('winlog', {}).get('event_id')
    try:
        event_id = int(event_id_raw) if event_id_raw else None
    except:
        event_id = None
    
    image = source.get('winlog', {}).get('event_data', {}).get('Image', 'N/A')
    
    for rule in DETECTION_RULES:
        if event_id and event_id in rule.event_ids:
            try:
                alert = rule.evaluate(hit, context)
                if alert:
                    alerts_count += 1
                    print(f"ALERT: {alert.rule_id} - {alert.summary[:80]}")
            except Exception as e:
                print(f"Rule {rule.rule_id} error: {e}")

print(f"\nTotal alerts generated: {alerts_count}")
