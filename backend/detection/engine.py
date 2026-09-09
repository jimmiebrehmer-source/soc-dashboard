def detect_brute_force(events):
    failed_logins = [
        event for event in events
        if event.event_type == "Failed Login"
    ]

    if len(failed_logins) >= 3:
        return {
            "rule": "Brute Force Authentication",
            "technique": "T1110",
            "severity": "HIGH",
            "description": "Multiple failed authentication attempts detected.",
            "matched_events": len(failed_logins),
        }

    return None


def detect_suspicious_powershell(events):
    powershell_events = [
        event for event in events
        if event.event_type == "PowerShell Execution"
    ]

    if len(powershell_events) >= 1:
        return {
            "rule": "Suspicious PowerShell",
            "technique": "T1059.001",
            "severity": "HIGH",
            "description": "Suspicious PowerShell command execution detected.",
            "matched_events": len(powershell_events),
        }

    return None


def detect_privilege_escalation(events):
    privilege_events = [
        event for event in events
        if event.event_type == "Privilege Escalation"
    ]

    if len(privilege_events) >= 1:
        return {
            "rule": "Privilege Escalation",
            "technique": "T1068",
            "severity": "CRITICAL",
            "description": "Potential privilege escalation activity detected.",
            "matched_events": len(privilege_events),
        }

    return None


def detect_lateral_movement(events):
    remote_service_events = [
        event for event in events
        if event.event_type == "Remote Service Execution"
    ]

    if len(remote_service_events) >= 2:
        return {
            "rule": "Lateral Movement",
            "technique": "T1021",
            "severity": "HIGH",
            "description": "Multiple remote service connections detected between internal systems.",
            "matched_events": len(remote_service_events),
        }

    return None
