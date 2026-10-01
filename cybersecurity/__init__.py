"""Cybersecurity module - attack classification, severity, and mitigations (FR-12, FR-13)"""
from typing import Dict, Any, List


ATTACK_CATEGORIES = [
    'Normal',
    'Brute Force',
    'Port Scan',
    'Malware Activity',
    'SQL Injection',
    'Privilege Escalation',
    'DoS Indicators',
]

# FR-13: Severity levels — Low, Medium, High, Critical
SEVERITY_MAPPING = {
    'Normal':               'Low',
    'Brute Force':          'High',
    'Port Scan':            'Medium',
    'Malware Activity':     'Critical',
    'SQL Injection':        'High',
    'Privilege Escalation': 'Critical',
    'DoS Indicators':       'High',
}

MITIGATION_SUGGESTIONS = {
    'Normal':
        'No action required. Traffic appears normal.',
    'Brute Force':
        'Implement account lockout policies, enforce strong passwords, enable MFA, '
        'monitor failed login attempts, consider IP blocking for repeated failures.',
    'Port Scan':
        'Configure firewall to block scanning IPs, implement port knocking, '
        'use IDS/IPS to detect and alert on scanning activity, minimize exposed ports.',
    'Malware Activity':
        'Isolate affected systems immediately, run full antivirus/EDR scan, '
        'check for lateral movement, update signatures, review network traffic for C2 communication.',
    'SQL Injection':
        'Use parameterized queries/prepared statements, implement WAF rules, '
        'validate and sanitize all inputs, apply least privilege to database accounts.',
    'Privilege Escalation':
        'Audit user permissions, remove unnecessary admin rights, patch known vulnerabilities, '
        'monitor for unusual privilege changes, implement PAM solutions.',
    'DoS Indicators':
        'Implement rate limiting, configure DDoS protection (CDN/WAF), '
        'monitor bandwidth usage, set up auto-scaling, have incident response plan for volumetric attacks.',
}

SEVERITY_ORDER = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}


def classify_attacks(predictions: list) -> list:
    """Add category label to each prediction (FR-12)."""
    for pred in predictions:
        category = pred.get('predicted_category', 'Normal')
        pred['category'] = category
    return predictions


def get_severity(category: str) -> str:
    """Get severity level for an attack category (FR-13)."""
    return SEVERITY_MAPPING.get(category, 'Medium')


def get_mitigation(category: str) -> str:
    """Get mitigation recommendation for an attack category."""
    return MITIGATION_SUGGESTIONS.get(
        category,
        'Investigate and apply appropriate security controls.'
    )


def get_all_categories() -> list:
    """Get list of all supported attack categories."""
    return ATTACK_CATEGORIES.copy()


def get_severity_order() -> Dict[str, int]:
    """Get severity ordering for sorting."""
    return SEVERITY_ORDER.copy()


def filter_attacks(results: list, category: str = None, severity: str = None) -> list:
    """Filter results by category and/or severity."""
    filtered = results

    if category and category != 'All':
        filtered = [r for r in filtered if r.get('category') == category]

    if severity and severity != 'All':
        filtered = [r for r in filtered if r.get('severity') == severity]

    return filtered


def get_attack_statistics(results: list) -> Dict[str, Any]:
    """Calculate summary statistics from classified results (SRS §2.2g)."""
    total = len(results)
    attacks = [r for r in results if r.get('category') != 'Normal']
    normal = [r for r in results if r.get('category') == 'Normal']

    category_counts = {}
    severity_counts = {}

    for r in attacks:
        cat = r.get('category', 'Unknown')
        sev = r.get('severity', 'Medium')
        category_counts[cat] = category_counts.get(cat, 0) + 1
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        'total_records': total,
        'total_attacks': len(attacks),
        'normal_records': len(normal),
        'attack_percentage': round((len(attacks) / total * 100) if total > 0 else 0, 2),
        'category_distribution': category_counts,
        'severity_distribution': severity_counts,
    }
