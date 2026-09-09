from datetime import datetime


def create_alert(detection_result, events):
    if detection_result is None:
        return None

    return {
        "alert_id": f"ALT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "created_at": datetime.now(),
        "rule": detection_result["rule"],
        "technique": detection_result["technique"],
        "severity": detection_result["severity"],
        "status": "OPEN",
        "description": detection_result["description"],
        "matched_events": detection_result["matched_events"],
        "source": events[0].source,
        "username": events[0].username,
        "source_ip": events[0].source_ip,
        "hostname": events[0].hostname,
    }