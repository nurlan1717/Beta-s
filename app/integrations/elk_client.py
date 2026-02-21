"""ELK/Elasticsearch API Client for RansomRun platform.

This module provides a reusable client for connecting to Elasticsearch/OpenSearch
as the SIEM backend for security alerts and detection data.

Supports:
- Basic auth OR API key authentication
- SSL verification toggle
- Connection to Elastic Security / OpenSearch
- Mock mode for offline development
- Real-time queries to Elasticsearch indices

Severity Mapping (Elastic 0-100 → RansomRun labels):
- 0-20:   LOW
- 21-40:  MEDIUM  
- 41-70:  HIGH
- 71-100: CRITICAL
"""

import os
import json
import requests
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta
import urllib3
from dotenv import load_dotenv

# Disable SSL warnings for lab environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables from .env file
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.env')
load_dotenv(env_path)


class ELKClient:
    """Client for interacting with Elasticsearch/OpenSearch REST API."""
    
    def __init__(
        self,
        url: str = None,
        username: str = None,
        password: str = None,
        api_key: str = None,
        verify_ssl: bool = None,
        index_alerts: str = None,
        index_logs: str = None
    ):
        # Read from environment if not provided (support both old and new var names)
        self.url = (url or os.getenv('ELASTICSEARCH_URL') or os.getenv('ELK_URL', 'https://localhost:9200')).rstrip('/')
        self.username = username or os.getenv('ELASTICSEARCH_USERNAME') or os.getenv('ELK_USERNAME')
        self.password = password or os.getenv('ELASTICSEARCH_PASSWORD') or os.getenv('ELK_PASSWORD')
        self.api_key = api_key or os.getenv('ELASTICSEARCH_API_KEY') or os.getenv('ELK_API_KEY')
        
        # Index patterns - support multiple indices
        self.index_alerts = index_alerts or os.getenv('ELASTICSEARCH_INDEX_ALERTS') or os.getenv('ELK_INDEX_ALERTS', '.alerts-security.alerts-*')
        self.index_logs = index_logs or os.getenv('ELASTICSEARCH_INDEX_LOGS') or os.getenv('ELK_INDEX_LOGS', 'logs-*,winlogbeat-*,filebeat-*')
        
        # Handle verify_ssl from env
        if verify_ssl is None:
            env_verify = (os.getenv('ELASTICSEARCH_VERIFY_SSL') or os.getenv('ELK_VERIFY_SSL', 'false')).lower()
            self.verify_ssl = env_verify in ('true', '1', 'yes')
        else:
            self.verify_ssl = verify_ssl
        
        # SIEM Mode: "mock" for offline development, "elastic" for live ELK
        siem_mode = os.getenv('SIEM_MODE', 'mock').lower()
        self._mock_mode = siem_mode == 'mock'
    
    def _get_auth(self) -> Optional[tuple]:
        """Get authentication tuple for requests."""
        if self.username and self.password:
            return (self.username, self.password)
        return None
    
    def _get_headers(self) -> Dict[str, str]:
        """Get headers for requests including API key if configured."""
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = f'ApiKey {self.api_key}'
        return headers
    
    def _request(
        self,
        method: str,
        endpoint: str,
        body: Dict = None,
        params: Dict = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Make request to Elasticsearch API."""
        if self._mock_mode:
            return self._mock_response(endpoint, body)
        
        url = f"{self.url}{endpoint}"
        
        try:
            response = requests.request(
                method,
                url,
                headers=self._get_headers(),
                auth=self._get_auth(),
                json=body,
                params=params,
                verify=self.verify_ssl,
                timeout=30,
                **kwargs
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise ConnectionError(f"Elasticsearch API request failed: {e}")
    
    def _mock_response(self, endpoint: str, body: Dict = None) -> Dict[str, Any]:
        """Return mock responses for offline development."""
        if '/_search' in endpoint:
            return self._mock_search_response(body)
        elif '/_count' in endpoint:
            return {'count': 42}
        elif '/_cluster/health' in endpoint:
            return {
                'cluster_name': 'mock-cluster',
                'status': 'green',
                'number_of_nodes': 3
            }
        elif '/_cat/indices' in endpoint:
            return []
        return {}
    
    def _mock_search_response(self, body: Dict = None) -> Dict[str, Any]:
        """Generate mock search response with sample alerts."""
        mock_alerts = []
        for i in range(10):
            mock_alerts.append({
                '_index': '.alerts-security.alerts-default',
                '_id': f'mock-alert-{i}',
                '_source': {
                    '@timestamp': (datetime.utcnow() - timedelta(hours=i)).isoformat() + 'Z',
                    'host': {'name': f'endpoint-{i % 3 + 1}'},
                    'signal': {
                        'rule': {
                            'id': f'rule-{100101 + i % 8}',
                            'name': f'Mock Detection Rule {i}',
                            'severity': ['low', 'medium', 'high', 'critical'][i % 4]
                        },
                        'severity': [25, 50, 75, 100][i % 4]
                    },
                    'threat': {
                        'technique': {
                            'id': ['T1486', 'T1490', 'T1059', 'T1547'][i % 4],
                            'name': ['Data Encrypted for Impact', 'Inhibit System Recovery', 
                                    'Command and Scripting Interpreter', 'Boot or Logon Autostart Execution'][i % 4]
                        },
                        'tactic': {
                            'id': ['TA0040', 'TA0040', 'TA0002', 'TA0003'][i % 4],
                            'name': ['Impact', 'Impact', 'Execution', 'Persistence'][i % 4]
                        }
                    },
                    'event': {
                        'action': 'mock-action',
                        'category': ['malware', 'intrusion_detection'][i % 2]
                    },
                    'message': f'Mock alert message {i} - Simulated detection for training'
                }
            })
        
        return {
            'took': 5,
            'timed_out': False,
            'hits': {
                'total': {'value': len(mock_alerts), 'relation': 'eq'},
                'hits': mock_alerts
            }
        }
    
    def test_connection(self) -> Dict[str, Any]:
        """Test connection to Elasticsearch cluster."""
        try:
            if self._mock_mode:
                return {
                    'connected': True,
                    'mock_mode': True,
                    'cluster_name': 'mock-cluster',
                    'status': 'green',
                    'version': '8.x (mock)'
                }
            
            # Get cluster health
            health = self._request('GET', '/_cluster/health')
            
            # Get version info
            info = self._request('GET', '/')
            
            return {
                'connected': True,
                'mock_mode': False,
                'cluster_name': health.get('cluster_name', 'unknown'),
                'status': health.get('status', 'unknown'),
                'number_of_nodes': health.get('number_of_nodes', 0),
                'version': info.get('version', {}).get('number', 'unknown')
            }
        except Exception as e:
            return {
                'connected': False,
                'mock_mode': self._mock_mode,
                'error': str(e)
            }
    
    def get_agents(self, limit: int = 500) -> List[Dict]:
        """
        Get list of endpoints/hosts from Elasticsearch.
        
        In ELK, agents are represented by unique host.name values in the logs.
        """
        query = {
            'size': 0,
            'aggs': {
                'unique_hosts': {
                    'terms': {
                        'field': 'host.name',
                        'size': limit
                    },
                    'aggs': {
                        'last_seen': {'max': {'field': '@timestamp'}},
                        'host_ip': {'terms': {'field': 'host.ip', 'size': 1}}
                    }
                }
            }
        }
        
        try:
            result = self._request('POST', f'/{self.index_logs}/_search', body=query)
            buckets = result.get('aggregations', {}).get('unique_hosts', {}).get('buckets', [])
            
            agents = []
            for bucket in buckets:
                ip_buckets = bucket.get('host_ip', {}).get('buckets', [])
                agents.append({
                    'name': bucket.get('key'),
                    'doc_count': bucket.get('doc_count', 0),
                    'last_seen': bucket.get('last_seen', {}).get('value_as_string'),
                    'ip': ip_buckets[0].get('key') if ip_buckets else None,
                    'status': 'active'  # Simplified status
                })
            
            return agents
        except Exception:
            return []
    
    def get_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        host_name: str = None,
        min_severity: int = None,
        time_range_hours: int = 24
    ) -> List[Dict]:
        """
        Get security alerts from Elasticsearch.
        
        Maps ELK alert structure to normalized format.
        """
        must_clauses = [
            {
                'range': {
                    '@timestamp': {
                        'gte': f'now-{time_range_hours}h',
                        'lte': 'now'
                    }
                }
            }
        ]
        
        if host_name:
            must_clauses.append({'term': {'host.name': host_name}})
        
        if min_severity:
            # Map severity 0-100 scale
            must_clauses.append({
                'range': {'signal.severity': {'gte': min_severity}}
            })
        
        query = {
            'size': limit,
            'from': offset,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'bool': {'must': must_clauses}
            }
        }
        
        try:
            result = self._request('POST', f'/{self.index_alerts}/_search', body=query)
            hits = result.get('hits', {}).get('hits', [])
            
            alerts = []
            for hit in hits:
                alerts.append(self._normalize_alert(hit))
            
            return alerts
        except Exception:
            return []
    
    def search_alerts(self, query_string: str, limit: int = 50) -> List[Dict]:
        """Search alerts by query string."""
        query = {
            'size': limit,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'query_string': {
                    'query': query_string,
                    'default_field': '*'
                }
            }
        }
        
        try:
            result = self._request('POST', f'/{self.index_alerts}/_search', body=query)
            hits = result.get('hits', {}).get('hits', [])
            
            return [self._normalize_alert(hit) for hit in hits]
        except Exception:
            return []
    
    def get_alert_by_id(self, alert_id: str) -> Optional[Dict]:
        """Get a specific alert by its document ID."""
        try:
            result = self._request('GET', f'/{self.index_alerts}/_doc/{alert_id}')
            if result.get('found'):
                return self._normalize_alert(result)
            return None
        except Exception:
            return None
    
    def get_stats(self, time_range_hours: int = 24) -> Dict[str, Any]:
        """Get SIEM statistics for dashboard."""
        query = {
            'size': 0,
            'query': {
                'range': {
                    '@timestamp': {
                        'gte': f'now-{time_range_hours}h',
                        'lte': 'now'
                    }
                }
            },
            'aggs': {
                'total_alerts': {'value_count': {'field': '@timestamp'}},
                'by_severity': {
                    'range': {
                        'field': 'signal.severity',
                        'ranges': [
                            {'key': 'low', 'to': 25},
                            {'key': 'medium', 'from': 25, 'to': 50},
                            {'key': 'high', 'from': 50, 'to': 75},
                            {'key': 'critical', 'from': 75}
                        ]
                    }
                },
                'by_host': {
                    'terms': {'field': 'host.name', 'size': 20}
                },
                'by_rule': {
                    'terms': {'field': 'signal.rule.id', 'size': 20}
                }
            }
        }
        
        try:
            result = self._request('POST', f'/{self.index_alerts}/_search', body=query)
            aggs = result.get('aggregations', {})
            
            # Get unique hosts count
            agents = self.get_agents(limit=1000)
            
            severity_buckets = aggs.get('by_severity', {}).get('buckets', [])
            severity_map = {b['key']: b['doc_count'] for b in severity_buckets}
            
            return {
                'total_agents': len(agents),
                'active_agents': len([a for a in agents if a.get('status') == 'active']),
                'total_alerts': aggs.get('total_alerts', {}).get('value', 0),
                'high_severity_alerts': severity_map.get('high', 0) + severity_map.get('critical', 0),
                'alerts_by_severity': severity_map,
                'alerts_by_host': {
                    b['key']: b['doc_count'] 
                    for b in aggs.get('by_host', {}).get('buckets', [])
                },
                'alerts_by_rule': {
                    b['key']: b['doc_count']
                    for b in aggs.get('by_rule', {}).get('buckets', [])
                }
            }
        except Exception:
            return {
                'total_agents': 0,
                'active_agents': 0,
                'total_alerts': 0,
                'high_severity_alerts': 0,
                'alerts_by_severity': {},
                'alerts_by_host': {},
                'alerts_by_rule': {}
            }
    
    def get_mitre_heatmap(self, time_range_hours: int = 168) -> Dict[str, Any]:
        """
        Get MITRE ATT&CK technique frequency data for heatmap visualization.
        
        Reads from threat.technique.id field in ELK alerts.
        """
        query = {
            'size': 0,
            'query': {
                'range': {
                    '@timestamp': {
                        'gte': f'now-{time_range_hours}h',
                        'lte': 'now'
                    }
                }
            },
            'aggs': {
                'techniques': {
                    'terms': {
                        'field': 'threat.technique.id',
                        'size': 100
                    },
                    'aggs': {
                        'technique_name': {
                            'terms': {'field': 'threat.technique.name', 'size': 1}
                        },
                        'tactic': {
                            'terms': {'field': 'threat.tactic.name', 'size': 1}
                        }
                    }
                },
                'tactics': {
                    'terms': {
                        'field': 'threat.tactic.name',
                        'size': 20
                    }
                }
            }
        }
        
        try:
            result = self._request('POST', f'/{self.index_alerts}/_search', body=query)
            aggs = result.get('aggregations', {})
            
            techniques = []
            for bucket in aggs.get('techniques', {}).get('buckets', []):
                name_buckets = bucket.get('technique_name', {}).get('buckets', [])
                tactic_buckets = bucket.get('tactic', {}).get('buckets', [])
                
                techniques.append({
                    'technique_id': bucket.get('key'),
                    'technique_name': name_buckets[0].get('key') if name_buckets else 'Unknown',
                    'tactic': tactic_buckets[0].get('key') if tactic_buckets else 'Unknown',
                    'count': bucket.get('doc_count', 0)
                })
            
            tactics = {
                b['key']: b['doc_count']
                for b in aggs.get('tactics', {}).get('buckets', [])
            }
            
            return {
                'techniques': techniques,
                'tactics': tactics,
                'total_techniques': len(techniques)
            }
        except Exception:
            return {
                'techniques': [],
                'tactics': {},
                'total_techniques': 0
            }
    
    def get_alerts_timeline(
        self,
        time_range_hours: int = 24,
        interval: str = '1h'
    ) -> List[Dict]:
        """Get alerts aggregated over time for timeline visualization."""
        query = {
            'size': 0,
            'query': {
                'range': {
                    '@timestamp': {
                        'gte': f'now-{time_range_hours}h',
                        'lte': 'now'
                    }
                }
            },
            'aggs': {
                'alerts_over_time': {
                    'date_histogram': {
                        'field': '@timestamp',
                        'fixed_interval': interval
                    },
                    'aggs': {
                        'by_severity': {
                            'range': {
                                'field': 'signal.severity',
                                'ranges': [
                                    {'key': 'low', 'to': 25},
                                    {'key': 'medium', 'from': 25, 'to': 50},
                                    {'key': 'high', 'from': 50, 'to': 75},
                                    {'key': 'critical', 'from': 75}
                                ]
                            }
                        }
                    }
                }
            }
        }
        
        try:
            result = self._request('POST', f'/{self.index_alerts}/_search', body=query)
            buckets = result.get('aggregations', {}).get('alerts_over_time', {}).get('buckets', [])
            
            timeline = []
            for bucket in buckets:
                severity_buckets = bucket.get('by_severity', {}).get('buckets', [])
                severity_map = {b['key']: b['doc_count'] for b in severity_buckets}
                
                timeline.append({
                    'time': bucket.get('key_as_string'),
                    'timestamp': bucket.get('key'),
                    'count': bucket.get('doc_count', 0),
                    'by_severity': severity_map
                })
            
            return timeline
        except Exception:
            return []
    
    def _normalize_alert(self, hit: Dict) -> Dict:
        """
        Normalize ELK alert to standard RansomRun alert format.
        
        Elastic → RansomRun mapping:
        - @timestamp               → timestamp
        - host.name                → endpoint
        - rule.name                → detection_rule
        - rule.description         → description
        - rule.severity            → severity (0-100)
        - rule.threat.technique.id → mitre_technique
        - event.category           → category
        - process.name             → process
        - file.path                → affected_file
        """
        source = hit.get('_source', {})
        
        # Support both Elastic Security (signal.*) and standard rule fields
        signal = source.get('signal', {})
        rule = signal.get('rule', source.get('rule', {}))
        
        # Extract threat/MITRE data from multiple possible locations
        threat = source.get('threat', {})
        rule_threat = rule.get('threat', [])
        
        # Handle threat as list (Elastic Security format) or dict
        if isinstance(rule_threat, list) and rule_threat:
            threat_item = rule_threat[0] if rule_threat else {}
            technique = threat_item.get('technique', [{}])
            technique = technique[0] if isinstance(technique, list) and technique else technique
            tactic = threat_item.get('tactic', {})
        else:
            technique = threat.get('technique', {})
            tactic = threat.get('tactic', {})
        
        host = source.get('host', {})
        event = source.get('event', {})
        process = source.get('process', {})
        file_info = source.get('file', {})
        
        # Get severity from multiple possible sources (0-100 scale)
        elk_severity = (
            rule.get('severity') or 
            signal.get('severity') or 
            source.get('kibana.alert.severity') or
            0
        )
        
        # Convert string severity to numeric
        if isinstance(elk_severity, str):
            severity_str_map = {'low': 15, 'medium': 35, 'high': 55, 'critical': 85}
            elk_severity = severity_str_map.get(elk_severity.lower(), 25)
        
        # Get severity label based on 0-100 scale
        severity_label = self._severity_label_from_score(elk_severity)
        
        # Extract MITRE technique ID
        mitre_technique_id = (
            technique.get('id') or 
            technique.get('technique_id') or
            'N/A'
        )
        mitre_technique_name = (
            technique.get('name') or 
            technique.get('technique_name') or
            'Unknown'
        )
        mitre_tactic_name = (
            tactic.get('name') or 
            tactic.get('tactic_name') or
            'Unknown'
        )
        mitre_tactic_id = (
            tactic.get('id') or 
            tactic.get('tactic_id') or
            'N/A'
        )
        
        return {
            'id': hit.get('_id'),
            'index': hit.get('_index'),
            'rule_id': rule.get('id') or rule.get('rule_id') or 'unknown',
            'rule_name': rule.get('name') or rule.get('rule_name') or 'Unknown Rule',
            'rule_description': rule.get('description') or source.get('message') or '',
            'endpoint': host.get('name') or host.get('hostname') or 'unknown',
            'agent_name': host.get('name') or host.get('hostname') or 'unknown',  # Alias for compatibility
            'host_ip': host.get('ip', [None])[0] if isinstance(host.get('ip'), list) else host.get('ip'),
            'severity': elk_severity,
            'severity_label': severity_label,
            'timestamp': source.get('@timestamp'),
            'mitre': {
                'technique': mitre_technique_id,
                'technique_name': mitre_technique_name,
                'tactic': mitre_tactic_name,
                'tactic_id': mitre_tactic_id
            },
            'category': event.get('category', 'unknown'),
            'process': process.get('name'),
            'affected_file': file_info.get('path'),
            'event': event,
            'raw': source
        }
    
    def _severity_label_from_score(self, score: int) -> str:
        """
        Convert Elastic severity score (0-100) to RansomRun label.
        
        Mapping:
        - 0-20:   LOW
        - 21-40:  MEDIUM
        - 41-70:  HIGH
        - 71-100: CRITICAL
        """
        if score >= 71:
            return 'CRITICAL'
        elif score >= 41:
            return 'HIGH'
        elif score >= 21:
            return 'MEDIUM'
        return 'LOW'
    
    def _severity_label(self, severity: int) -> str:
        """Convert numeric severity to label (legacy 0-15 scale)."""
        if severity >= 12:
            return 'CRITICAL'
        elif severity >= 8:
            return 'HIGH'
        elif severity >= 4:
            return 'MEDIUM'
        return 'LOW'


    # ========================================================================
    # Sysmon-Specific Query Methods (for Detection Engine)
    # ========================================================================
    
    def query_sysmon_events(
        self,
        since_ts: str = None,
        size: int = 100,
        search_after: List = None,
        event_ids: List[int] = None
    ) -> Dict[str, Any]:
        """
        Query Sysmon events from winlogbeat-* index with search_after pagination.
        
        Args:
            since_ts: ISO timestamp to query events after (e.g., "2024-01-01T00:00:00Z")
            size: Number of events to return (max 1000)
            search_after: Sort values from previous query for pagination
            event_ids: Filter by specific Sysmon event IDs (1=ProcessCreate, 3=NetworkConnect, etc.)
        
        Returns:
            Dict with 'hits', 'total', 'search_after' for pagination
        
        Sysmon Event IDs:
            1  = Process Create
            3  = Network Connection
            10 = Process Access
            11 = File Create
            12 = Registry Event (Create/Delete)
            13 = Registry Value Set
            22 = DNS Query
        """
        # Build query
        must_clauses = [
            # Filter for Sysmon provider
            {'term': {'event.provider.keyword': 'Microsoft-Windows-Sysmon'}}
        ]
        
        # Time range filter
        if since_ts:
            must_clauses.append({
                'range': {
                    '@timestamp': {
                        'gt': since_ts
                    }
                }
            })
        
        # Event ID filter (convert ints to strings for ES)
        if event_ids:
            must_clauses.append({
                'terms': {'winlog.event_id': [str(eid) for eid in event_ids]}
            })
        
        query = {
            'size': min(size, 1000),
            'sort': [
                {'@timestamp': {'order': 'asc'}}
            ],
            'query': {
                'bool': {'must': must_clauses}
            }
        }
        
        # Add search_after for pagination
        if search_after:
            query['search_after'] = search_after
        
        try:
            # Query winlogbeat index
            index = os.getenv('ELK_INDEX', 'winlogbeat-*')
            result = self._request('POST', f'/{index}/_search', body=query)
            
            hits = result.get('hits', {}).get('hits', [])
            total = result.get('hits', {}).get('total', {}).get('value', 0)
            
            # Get search_after value from last hit for pagination
            last_sort = None
            if hits:
                last_sort = hits[-1].get('sort')
            
            return {
                'hits': hits,
                'total': total,
                'search_after': last_sort,
                'returned': len(hits)
            }
        except Exception as e:
            return {
                'hits': [],
                'total': 0,
                'search_after': None,
                'returned': 0,
                'error': str(e)
            }
    
    def search_events(
        self,
        query_string: str = None,
        filters: Dict = None,
        time_range_hours: int = 24,
        size: int = 100
    ) -> List[Dict]:
        """
        General event search for debugging/exploration.
        
        Args:
            query_string: Lucene query string
            filters: Dict of field:value filters
            time_range_hours: How far back to search
            size: Max results
        """
        must_clauses = [
            {
                'range': {
                    '@timestamp': {
                        'gte': f'now-{time_range_hours}h',
                        'lte': 'now'
                    }
                }
            }
        ]
        
        if query_string:
            must_clauses.append({
                'query_string': {
                    'query': query_string,
                    'default_field': '*'
                }
            })
        
        if filters:
            for field, value in filters.items():
                # Use .keyword suffix for text fields that need exact matching
                keyword_field = f"{field}.keyword" if not field.endswith('.keyword') else field
                if isinstance(value, list):
                    must_clauses.append({'terms': {keyword_field: value}})
                else:
                    must_clauses.append({'term': {keyword_field: value}})
        
        query = {
            'size': size,
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'bool': {'must': must_clauses}
            }
        }
        
        try:
            index = os.getenv('ELK_INDEX', 'winlogbeat-*')
            result = self._request('POST', f'/{index}/_search', body=query)
            return result.get('hits', {}).get('hits', [])
        except Exception:
            return []
    
    def get_hosts(self, time_range_hours: int = 24) -> List[Dict]:
        """
        Get unique hosts from winlogbeat index.
        
        Returns list of hosts with last seen timestamp.
        """
        query = {
            'size': 0,
            'query': {
                'range': {
                    '@timestamp': {
                        'gte': f'now-{time_range_hours}h'
                    }
                }
            },
            'aggs': {
                'hosts': {
                    'terms': {
                        'field': 'host.name',
                        'size': 500
                    },
                    'aggs': {
                        'last_seen': {'max': {'field': '@timestamp'}},
                        'ip': {'terms': {'field': 'host.ip', 'size': 1}},
                        'os': {'terms': {'field': 'host.os.name', 'size': 1}}
                    }
                }
            }
        }
        
        try:
            index = os.getenv('ELK_INDEX', 'winlogbeat-*')
            result = self._request('POST', f'/{index}/_search', body=query)
            buckets = result.get('aggregations', {}).get('hosts', {}).get('buckets', [])
            
            hosts = []
            for bucket in buckets:
                ip_buckets = bucket.get('ip', {}).get('buckets', [])
                os_buckets = bucket.get('os', {}).get('buckets', [])
                
                hosts.append({
                    'name': bucket.get('key'),
                    'event_count': bucket.get('doc_count', 0),
                    'last_seen': bucket.get('last_seen', {}).get('value_as_string'),
                    'ip': ip_buckets[0].get('key') if ip_buckets else None,
                    'os': os_buckets[0].get('key') if os_buckets else None
                })
            
            return hosts
        except Exception:
            return []
    
    def count_events_by_process(
        self,
        host_name: str,
        process_name: str = None,
        process_entity_id: str = None,
        event_id: int = None,
        time_window_seconds: int = 60
    ) -> int:
        """
        Count events for a specific process within a time window.
        Used for rate-based detections (e.g., mass file creation).
        """
        must_clauses = [
            {'term': {'host.name': host_name}},
            {'range': {'@timestamp': {'gte': f'now-{time_window_seconds}s'}}}
        ]
        
        if process_name:
            must_clauses.append({'term': {'process.name': process_name}})
        
        if process_entity_id:
            must_clauses.append({'term': {'process.entity_id': process_entity_id}})
        
        if event_id:
            must_clauses.append({'term': {'winlog.event_id': event_id}})
        
        query = {
            'query': {'bool': {'must': must_clauses}}
        }
        
        try:
            index = os.getenv('ELK_INDEX', 'winlogbeat-*')
            result = self._request('POST', f'/{index}/_count', body=query)
            return result.get('count', 0)
        except Exception:
            return 0


def get_elk_client_from_env() -> ELKClient:
    """Create ELKClient from environment variables."""
    return ELKClient()


def get_elk_client_from_config(db) -> Optional[ELKClient]:
    """Create ELKClient from database configuration."""
    from ..models import ELKConfig
    
    config = db.query(ELKConfig).filter(ELKConfig.enabled == True).first()
    if not config:
        # Fall back to environment variables
        return get_elk_client_from_env()
    
    return ELKClient(
        url=config.url,
        username=config.username,
        password=config.password,
        api_key=config.api_key,
        index_alerts=config.index_alerts,
        index_logs=config.index_logs
    )
