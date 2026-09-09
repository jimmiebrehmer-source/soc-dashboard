from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from data.events import security_events

from simulator.attacks import (
    simulate_brute_force,
    simulate_powershell,
    simulate_privilege_escalation,
    simulate_lateral_movement,
)

from detection.engine import (
    detect_brute_force,
    detect_suspicious_powershell,
    detect_privilege_escalation,
    detect_lateral_movement,
)

from alerts.manager import create_alert
from incidents.manager import create_incident
from response.actions import contain_incident
from storage.store import alerts, incidents, responses, events


app = FastAPI(
    title="SOC Dashboard API",
    description="Security Operations Center API",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "name": "SOC Dashboard API",
        "status": "operational",
        "version": "1.0.0",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/events")
def get_events():
    return security_events


# BRUTE FORCE
@app.post("/simulate/brute-force")
def simulate_brute_force_attack():
    generated_events = simulate_brute_force()
    detection_result = detect_brute_force(generated_events)
    alert = create_alert(detection_result, generated_events)
    incident = create_incident(alert)
    response = contain_incident(incident)

    events.extend(generated_events)
    if alert is not None:
        alerts.append(alert)
    if incident is not None:
        incidents.append(incident)
    if response is not None:
        responses.append(response)

    return {
        "attack": "Brute Force Authentication",
        "events": generated_events,
        "detection": detection_result,
        "alert": alert,
        "incident": incident,
        "response": response,
    }


# POWERSHELL
@app.post("/simulate/powershell")
def simulate_powershell_attack():
    generated_events = simulate_powershell()
    detection_result = detect_suspicious_powershell(generated_events)
    alert = create_alert(detection_result, generated_events)
    incident = create_incident(alert)
    response = contain_incident(incident)

    events.extend(generated_events)
    if alert is not None:
        alerts.append(alert)
    if incident is not None:
        incidents.append(incident)
    if response is not None:
        responses.append(response)

    return {
        "attack": "Suspicious PowerShell",
        "events": generated_events,
        "detection": detection_result,
        "alert": alert,
        "incident": incident,
        "response": response,
    }


# PRIVILEGE ESCALATION
@app.post("/simulate/privilege-escalation")
def simulate_privilege_escalation_attack():
    generated_events = simulate_privilege_escalation()
    detection_result = detect_privilege_escalation(generated_events)
    alert = create_alert(detection_result, generated_events)
    incident = create_incident(alert)
    response = contain_incident(incident)

    events.extend(generated_events)
    if alert is not None:
        alerts.append(alert)
    if incident is not None:
        incidents.append(incident)
    if response is not None:
        responses.append(response)

    return {
        "attack": "Privilege Escalation",
        "events": generated_events,
        "detection": detection_result,
        "alert": alert,
        "incident": incident,
        "response": response,
    }


# LATERAL MOVEMENT
@app.post("/simulate/lateral-movement")
def simulate_lateral_movement_attack():
    generated_events = simulate_lateral_movement()
    detection_result = detect_lateral_movement(generated_events)
    alert = create_alert(detection_result, generated_events)
    incident = create_incident(alert)
    response = contain_incident(incident)

    events.extend(generated_events)
    if alert is not None:
        alerts.append(alert)
    if incident is not None:
        incidents.append(incident)
    if response is not None:
        responses.append(response)

    return {
        "attack": "Lateral Movement",
        "events": generated_events,
        "detection": detection_result,
        "alert": alert,
        "incident": incident,
        "response": response,
    }


@app.get("/alerts")
def get_alerts():
    return alerts


@app.get("/incidents")
def get_incidents():
    return incidents


@app.get("/responses")
def get_responses():
    return responses


@app.get("/events/all")
def get_all_events():
    return events


@app.patch("/incidents/{incident_id}/status")
def update_incident_status(incident_id: str, status: str):
    allowed_statuses = [
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
        "RESOLVED",
    ]

    if status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid incident status",
                "allowed_statuses": allowed_statuses,
            },
        )

    for incident in incidents:
        if incident["incident_id"] == incident_id:
            incident["status"] = status
            return {
                "message": "Incident status updated",
                "incident": incident,
            }

    raise HTTPException(status_code=404, detail="Incident not found")
