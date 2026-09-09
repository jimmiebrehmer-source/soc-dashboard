from datetime import datetime


def contain_incident(incident):
    if incident is None:
        return None

    return {
        "response_id": f"RESP-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "timestamp": datetime.now(),
        "incident_id": incident["incident_id"],
        "action": "CONTAIN",
        "status": "EXECUTED",
        "details": [
            "Source IP blocked",
            "Compromised account disabled",
            "Affected endpoint isolated",
        ],
    }