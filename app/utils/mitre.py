"""MITRE ATT&CK mapping utilities for RansomRun platform."""

import json
import os
from typing import Dict, Optional, Any

# Cache for loaded mapping
_mitre_mapping_cache: Optional[Dict[str, Any]] = None


def load_mitre_mapping() -> Dict[str, Any]:
    """
    Load MITRE ATT&CK mapping from JSON file.
    
    Returns:
        Dictionary mapping rule IDs to MITRE technique info.
    """
    global _mitre_mapping_cache
    
    if _mitre_mapping_cache is not None:
        return _mitre_mapping_cache
    
    # Get the path to the mitre_mapping.json file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(os.path.dirname(current_dir), 'data')
    mapping_file = os.path.join(data_dir, 'mitre_mapping.json')
    
    try:
        with open(mapping_file, 'r', encoding='utf-8') as f:
            _mitre_mapping_cache = json.load(f)
    except FileNotFoundError:
        _mitre_mapping_cache = {}
    except json.JSONDecodeError:
        _mitre_mapping_cache = {}
    
    return _mitre_mapping_cache


def map_rule_to_mitre(rule_id: str) -> Optional[Dict[str, str]]:
    """
    Map a Wazuh rule ID to MITRE ATT&CK technique.
    
    Args:
        rule_id: The Wazuh rule ID to look up.
        
    Returns:
        Dictionary with 'technique' and 'name' keys, or None if not found.
    """
    mapping = load_mitre_mapping()
    return mapping.get(str(rule_id))


def get_mitre_technique(rule_id: str) -> str:
    """
    Get MITRE technique ID for a rule.
    
    Args:
        rule_id: The Wazuh rule ID.
        
    Returns:
        MITRE technique ID (e.g., "T1059") or "N/A" if not found.
    """
    mitre_info = map_rule_to_mitre(rule_id)
    if mitre_info:
        return mitre_info.get('technique', 'N/A')
    return 'N/A'


def get_mitre_name(rule_id: str) -> str:
    """
    Get MITRE technique name for a rule.
    
    Args:
        rule_id: The Wazuh rule ID.
        
    Returns:
        MITRE technique name or "Unknown" if not found.
    """
    mitre_info = map_rule_to_mitre(rule_id)
    if mitre_info:
        return mitre_info.get('name', 'Unknown')
    return 'Unknown'


def get_all_techniques() -> Dict[str, Dict[str, str]]:
    """
    Get all unique MITRE techniques from the mapping.
    
    Returns:
        Dictionary mapping technique IDs to their names.
    """
    mapping = load_mitre_mapping()
    techniques = {}
    
    for rule_id, info in mapping.items():
        technique = info.get('technique')
        if technique and technique not in techniques:
            techniques[technique] = {
                'id': technique,
                'name': info.get('name', 'Unknown')
            }
    
    return techniques


def get_technique_heatmap_data() -> Dict[str, int]:
    """
    Get technique frequency data for heatmap visualization.
    
    Returns:
        Dictionary mapping technique IDs to count of rules using them.
    """
    mapping = load_mitre_mapping()
    technique_counts = {}
    
    for rule_id, info in mapping.items():
        technique = info.get('technique')
        if technique:
            technique_counts[technique] = technique_counts.get(technique, 0) + 1
    
    return technique_counts
