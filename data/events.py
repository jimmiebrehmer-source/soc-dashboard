from datetime import datetime, timedelta

from models.security_event import SecurityEvent


now = datetime.now()


security_events = [
    SecurityEvent(
        id=1,
        timestamp=now - timedelta(minutes=2),
        event_type="Failed Login",
        source="Authentication",
        username="administrator",
        source_ip="185.42.17.91",
        hostname="VPN-GATEWAY-01",
        severity="HIGH",
        description="Multiple failed authentication attempts detected.",
    ),
    SecurityEvent(
        id=2,
        timestamp=now - timedelta(minutes=5),
        event_type="PowerShell Execution",
        source="Windows Endpoint",
        username="administrator",
        source_ip="10.0.0.24",
        hostname="WIN-CLIENT-04",
        severity="HIGH",
        description="Encoded PowerShell command detected.",
    ),
    SecurityEvent(
        id=3,
        timestamp=now - timedelta(minutes=8),
        event_type="Successful Login",
        source="Authentication",
        username="j.smith",
        source_ip="10.0.0.52",
        hostname="VPN-GATEWAY-01",
        severity="INFO",
        description="Successful authentication.",
    ),
    SecurityEvent(
        id=4,
        timestamp=now - timedelta(minutes=11),
        event_type="Impossible Travel",
        source="Identity Provider",
        username="a.johnson",
        source_ip="91.198.12.44",
        hostname=None,
        severity="MEDIUM",
        description="User authentication detected from geographically distant locations.",
    ),
    SecurityEvent(
        id=5,
        timestamp=now - timedelta(minutes=14),
        event_type="Privilege Escalation",
        source="Windows Endpoint",
        username="svc-backup",
        source_ip="10.0.0.31",
        hostname="WIN-SRV-02",
        severity="CRITICAL",
        description="Unexpected privilege escalation detected.",
    ),
]