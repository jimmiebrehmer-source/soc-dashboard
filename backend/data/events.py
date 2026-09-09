from datetime import datetime, timedelta

from models.security_event import SecurityEvent


security_events = [
    SecurityEvent(
        id=1,
        timestamp=datetime.now() - timedelta(minutes=5),
        event_type="Failed Login",
        source="VPN Gateway",
        username="administrator",
        source_ip="185.42.17.91",
        hostname="VPN-GATEWAY-01",
        severity="HIGH",
        description="Multiple failed authentication attempts detected.",
    ),
    SecurityEvent(
        id=2,
        timestamp=datetime.now() - timedelta(minutes=12),
        event_type="PowerShell Execution",
        source="Windows Endpoint",
        username="administrator",
        source_ip="10.0.0.24",
        hostname="WIN-CLIENT-04",
        severity="HIGH",
        description="Suspicious PowerShell command execution detected.",
    ),
    SecurityEvent(
        id=3,
        timestamp=datetime.now() - timedelta(minutes=18),
        event_type="Successful Login",
        source="VPN Gateway",
        username="j.smith",
        source_ip="10.0.0.52",
        hostname="VPN-GATEWAY-01",
        severity="INFO",
        description="Successful user authentication.",
    ),
    SecurityEvent(
        id=4,
        timestamp=datetime.now() - timedelta(minutes=25),
        event_type="Impossible Travel",
        source="Identity Provider",
        username="a.johnson",
        source_ip="91.198.12.44",
        hostname=None,
        severity="MEDIUM",
        description="User authenticated from geographically distant locations within an impossible timeframe.",
    ),
    SecurityEvent(
        id=5,
        timestamp=datetime.now() - timedelta(minutes=32),
        event_type="Privilege Escalation",
        source="Windows Server",
        username="svc-backup",
        source_ip="10.0.0.31",
        hostname="WIN-SRV-02",
        severity="CRITICAL",
        description="Potential privilege escalation activity detected.",
    ),
]