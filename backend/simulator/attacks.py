from datetime import datetime
from models.security_event import SecurityEvent


def simulate_brute_force():
    events = []

    for attempt in range(1, 6):
        events.append(
            SecurityEvent(
                id=1000 + attempt,
                timestamp=datetime.now(),
                event_type="Failed Login",
                source="VPN Gateway",
                username="administrator",
                source_ip="185.42.17.91",
                hostname="VPN-GATEWAY-01",
                severity="HIGH",
                description=f"Failed authentication attempt {attempt}.",
            )
        )

    return events


def simulate_powershell():
    events = [
        SecurityEvent(
            id=2001,
            timestamp=datetime.now(),
            event_type="PowerShell Execution",
            source="Windows Endpoint",
            username="administrator",
            source_ip="10.0.0.24",
            hostname="WIN-CLIENT-04",
            severity="HIGH",
            description="Suspicious PowerShell command execution detected.",
        ),
        SecurityEvent(
            id=2002,
            timestamp=datetime.now(),
            event_type="PowerShell Execution",
            source="Windows Endpoint",
            username="administrator",
            source_ip="10.0.0.24",
            hostname="WIN-CLIENT-04",
            severity="HIGH",
            description="PowerShell process executed with encoded command parameters.",
        ),
    ]

    return events


def simulate_privilege_escalation():
    events = [
        SecurityEvent(
            id=3001,
            timestamp=datetime.now(),
            event_type="Privilege Escalation",
            source="Windows Server",
            username="svc-backup",
            source_ip="10.0.0.31",
            hostname="WIN-SRV-02",
            severity="CRITICAL",
            description="Potential exploitation of a vulnerability resulted in elevated privileges.",
        ),
        SecurityEvent(
            id=3002,
            timestamp=datetime.now(),
            event_type="Privilege Escalation",
            source="Windows Server",
            username="svc-backup",
            source_ip="10.0.0.31",
            hostname="WIN-SRV-02",
            severity="CRITICAL",
            description="Process executed with elevated privileges outside expected administrative activity.",
        ),
    ]

    return events


def simulate_lateral_movement():
    events = [
        SecurityEvent(
            id=4001,
            timestamp=datetime.now(),
            event_type="Remote Service Execution",
            source="Windows Server",
            username="administrator",
            source_ip="10.0.0.24",
            hostname="WIN-SRV-03",
            severity="HIGH",
            description="Remote service execution detected from an internal workstation.",
        ),
        SecurityEvent(
            id=4002,
            timestamp=datetime.now(),
            event_type="Remote Service Execution",
            source="Windows Server",
            username="administrator",
            source_ip="10.0.0.24",
            hostname="WIN-SRV-04",
            severity="HIGH",
            description="Additional remote service connection detected to another internal host.",
        ),
    ]

    return events
