# BREMR SOC Platform

A security operations center (SOC) simulation and detection engineering
platform built to demonstrate how security events can be transformed
into detections, alerts, incidents, and response actions.

> **Portfolio project --- Cyber Security Officer**

## Overview

BREMR SOC Platform is a controlled security simulation environment
designed to demonstrate core SOC workflows without pretending to be a
production SIEM.

The project focuses on the security operations lifecycle:

``` text
Attack Simulation
       ↓
Security Events
       ↓
Detection Engine
       ↓
MITRE ATT&CK Mapping
       ↓
Alert
       ↓
Incident
       ↓
Response / Containment
```

The goal is to demonstrate practical understanding of detection
engineering, alert triage, incident management, MITRE ATT&CK and
security response.

## Key Features

-   SOC dashboard with security metrics
-   Security event stream
-   Alert management
-   Incident management
-   Incident lifecycle:
    -   OPEN
    -   INVESTIGATING
    -   CONTAINED
    -   RESOLVED
-   Detection rule catalogue
-   MITRE ATT&CK technique mapping
-   Controlled attack simulation
-   Simulated containment response
-   REST API built with FastAPI
-   React-based SOC interface

## Attack Simulations

The implemented simulations demonstrate:

  -----------------------------------------------------------------------
  Attack            MITRE ATT&CK      Detection         Status
  ----------------- ----------------- ----------------- -----------------
  Brute Force       T1110             Brute Force       Implemented
  Authentication                      Authentication    

  Suspicious        T1059.001         Suspicious        Implemented
  PowerShell                          PowerShell        

  Privilege         T1068             Privilege         Implemented
  Escalation                          Escalation        

  Lateral Movement  T1021             Lateral Movement  Implemented
  -----------------------------------------------------------------------

Additional detection rules are represented in the detection-rule
catalogue and can be expanded independently of the simulator.

## Detection Engineering

Detection logic is separated from attack simulation.

This makes it possible to demonstrate the difference between:

1.  generating security telemetry,
2.  evaluating that telemetry against a detection rule,
3.  creating an alert,
4.  escalating the alert into an incident,
5.  executing a simulated response.

Example:

``` text
Remote Service Execution
        ↓
Detection Rule: T1021
        ↓
HIGH Alert
        ↓
Open Incident
        ↓
Containment Response
```

## Technology Stack

### Frontend

-   React
-   Vite
-   CSS

### Backend

-   Python
-   FastAPI
-   Pydantic

### Architecture

``` text
frontend/
    React SOC interface

backend/
    FastAPI API
    ├── data/
    ├── models/
    ├── detection/
    ├── simulator/
    ├── alerts/
    ├── incidents/
    ├── response/
    └── storage/

detection-rules/
    Detection rule definitions

docs/
    Project documentation
```

## API

The backend exposes endpoints for health checks, events, alerts,
incidents and controlled attack simulations.

Examples:

``` text
GET  /health
GET  /events
GET  /alerts
GET  /incidents
GET  /responses

POST /simulate/brute-force
POST /simulate/powershell
POST /simulate/privilege-escalation
POST /simulate/lateral-movement

PATCH /incidents/{incident_id}/status
```

## Running the Project Locally

### Backend

``` bash
cd backend
source venv/bin/activate
uvicorn main:app --reload --port 8000
```

Backend:

``` text
http://127.0.0.1:8000
```

Health check:

``` bash
curl http://127.0.0.1:8000/health
```

### Frontend

From the project root:

``` bash
cd frontend
npm run dev
```

Open the local Vite URL shown in the terminal.

## Example SOC Workflow

A typical demonstration can be performed as follows:

### 1. Launch Attack Simulator

Select an attack such as:

**Lateral Movement**

### 2. Generate Security Events

The simulator creates controlled `Remote Service Execution` events.

### 3. Detection

The detection engine evaluates the generated events and matches:

**MITRE ATT&CK T1021**

### 4. Alert Creation

A HIGH severity alert is generated.

### 5. Incident Creation

The alert is promoted to an incident with status:

**OPEN**

### 6. Response

A simulated containment action is executed:

-   Source IP blocked
-   Compromised account disabled
-   Affected endpoint isolated

This demonstrates the complete detection-to-response chain.

## Security Scope

This is a **controlled simulation environment**.

The attack simulations generate synthetic security events for
educational and portfolio purposes. They do not perform real
exploitation against external systems.

The response actions are also simulated rather than performing
destructive actions on a real environment.

## Project Goals

The project was built to demonstrate practical knowledge in:

-   Security Operations Center workflows
-   Detection engineering
-   Security event modelling
-   MITRE ATT&CK
-   Alert triage
-   Incident response
-   Incident lifecycle management
-   Containment concepts
-   REST API development
-   Security-focused frontend development

## What This Project Is Not

BREMR SOC Platform is intentionally not positioned as:

-   a production SIEM,
-   a replacement for Splunk, Microsoft Sentinel or similar platforms,
-   a full EDR,
-   a real malware sandbox,
-   a production incident-response automation platform.

The focus is on demonstrating security operations concepts and
implementation skills in a controlled environment.

## Portfolio Context

This project is part of a broader cybersecurity portfolio and
complements the user's larger security product work.

The SOC Platform demonstrates **operational security and detection
engineering**, while the broader Northwall project focuses more heavily
on security architecture, risk, compliance and security-product
thinking.

## Author

**Jimmie Brehmer**

Cyber Security Officer student / cybersecurity portfolio project.

------------------------------------------------------------------------

### Portfolio Summary

> **BREMR SOC Platform** is a SOC simulation and detection engineering
> platform demonstrating the complete security operations workflow from
> controlled attack simulation and security-event generation through
> MITRE ATT&CK detection, alert creation, incident management and
> simulated containment response.
