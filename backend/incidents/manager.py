from datetime import datetime


def create_incident(alert):
    if alert is None:
        return None

    return {
        "incident_id": f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "created_at": datetime.now(),
        "title": alert["rule"],
        "severity": alert["severity"],
        "status": "OPEN",
        "technique": alert["technique"],
        "source": alert["source"],
        "username": alert["username"],
        "source_ip": alert["source_ip"],
        "hostname": alert["hostname"],
        "description": alert["description"],
        "alert_id": alert["alert_id"],
    }