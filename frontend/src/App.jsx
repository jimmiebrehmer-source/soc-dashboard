import { useEffect, useState } from "react"

const API_URL = "http://127.0.0.1:8000"

const detectionRules = [
  {
    id: "DET-001",
    name: "Brute Force Authentication",
    technique: "T1110",
    tactic: "Credential Access",
    severity: "HIGH",
    status: "ACTIVE",
    description:
      "Detects multiple failed authentication attempts against a user account or authentication service.",
    dataSources: [
      "Authentication Logs",
      "VPN Gateway",
      "Identity Provider",
    ],
    logic:
      "Trigger when 3 or more failed authentication attempts are detected within a short time window.",
    response: [
      "Block source IP",
      "Disable compromised account",
      "Create security incident",
    ],
  },
  {
    id: "DET-002",
    name: "Suspicious PowerShell",
    technique: "T1059.001",
    tactic: "Execution",
    severity: "HIGH",
    status: "ACTIVE",
    description:
      "Detects suspicious PowerShell execution patterns that may indicate malicious activity.",
    dataSources: [
      "Windows Event Logs",
      "Endpoint Telemetry",
      "Process Creation Logs",
    ],
    logic:
      "Trigger when PowerShell execution matches suspicious command or encoded payload patterns.",
    response: [
      "Create security alert",
      "Investigate endpoint",
      "Collect process evidence",
    ],
  },
  {
    id: "DET-003",
    name: "Privilege Escalation",
    technique: "T1068",
    tactic: "Privilege Escalation",
    severity: "CRITICAL",
    status: "ACTIVE",
    description:
      "Detects potential exploitation or abuse of vulnerabilities to obtain elevated privileges.",
    dataSources: [
      "Windows Security Logs",
      "Endpoint Telemetry",
      "EDR",
    ],
    logic:
      "Trigger when suspicious privilege escalation behaviour is detected on an endpoint or server.",
    response: [
      "Create critical alert",
      "Isolate endpoint",
      "Investigate privileged account activity",
    ],
  },
  {
    id: "DET-004",
    name: "Lateral Movement",
    technique: "T1021",
    tactic: "Lateral Movement",
    severity: "HIGH",
    status: "ACTIVE",
    description:
      "Detects suspicious remote service activity that may indicate lateral movement.",
    dataSources: [
      "Windows Logs",
      "Network Logs",
      "Authentication Logs",
    ],
    logic:
      "Trigger when abnormal remote service authentication or connection patterns are detected.",
    response: [
      "Investigate source host",
      "Review authentication activity",
      "Contain affected systems",
    ],
  },
  {
    id: "DET-005",
    name: "Impossible Travel",
    technique: "T1078",
    tactic: "Initial Access",
    severity: "MEDIUM",
    status: "ACTIVE",
    description:
      "Detects authentication activity from geographically impossible locations.",
    dataSources: [
      "Identity Provider",
      "Authentication Logs",
      "VPN Logs",
    ],
    logic:
      "Trigger when a user authenticates from geographically distant locations within an impossible timeframe.",
    response: [
      "Verify user identity",
      "Review session activity",
      "Reset credentials if required",
    ],
  },
  {
    id: "DET-006",
    name: "Suspicious Process Creation",
    technique: "T1059",
    tactic: "Execution",
    severity: "HIGH",
    status: "ACTIVE",
    description:
      "Detects suspicious process creation patterns that may indicate execution of malicious code.",
    dataSources: [
      "Endpoint Telemetry",
      "Windows Event Logs",
      "EDR",
    ],
    logic:
      "Trigger when suspicious parent-child process relationships or command execution patterns are detected.",
    response: [
      "Investigate process tree",
      "Collect endpoint evidence",
      "Isolate endpoint if required",
    ],
  },
  {
    id: "DET-007",
    name: "Data Exfiltration",
    technique: "T1041",
    tactic: "Exfiltration",
    severity: "CRITICAL",
    status: "ACTIVE",
    description:
      "Detects suspicious outbound data transfer that may indicate data exfiltration.",
    dataSources: [
      "Network Traffic",
      "Firewall Logs",
      "Proxy Logs",
    ],
    logic:
      "Trigger when abnormal outbound traffic or large data transfers are detected.",
    response: [
      "Block destination",
      "Investigate network activity",
      "Preserve evidence",
    ],
  },
  {
    id: "DET-008",
    name: "Ransomware Behaviour",
    technique: "T1486",
    tactic: "Impact",
    severity: "CRITICAL",
    status: "ACTIVE",
    description:
      "Detects behaviour associated with ransomware execution and mass file encryption.",
    dataSources: [
      "Endpoint Telemetry",
      "File System Events",
      "EDR",
    ],
    logic:
      "Trigger when rapid file modification or encryption-like behaviour is detected across multiple files.",
    response: [
      "Isolate endpoint",
      "Disable compromised account",
      "Initiate incident response",
    ],
  },
]

function App() {
  const [page, setPage] = useState("dashboard")

  const [selectedAlert, setSelectedAlert] = useState(null)
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [selectedRule, setSelectedRule] = useState(null)

  const [simulation, setSimulation] = useState(null)
  const [loading, setLoading] = useState(false)
  const [activeSimulation, setActiveSimulation] = useState(null)

  const [alerts, setAlerts] = useState([])
  const [incidents, setIncidents] = useState([])
  const [events, setEvents] = useState([])

  useEffect(() => {
    loadData()
  }, [])

  async function loadData() {
    try {
      const [alertsResponse, incidentsResponse, eventsResponse] =
        await Promise.all([
          fetch(`${API_URL}/alerts`),
          fetch(`${API_URL}/incidents`),
          fetch(`${API_URL}/events/all`),
        ])

      const alertsData = await alertsResponse.json()
      const incidentsData = await incidentsResponse.json()
      const eventsData = await eventsResponse.json()

      setAlerts(alertsData)
      setIncidents(incidentsData)
      setEvents(eventsData)

      if (selectedIncident) {
        const updatedIncident = incidentsData.find(
          (incident) =>
            incident.incident_id === selectedIncident.incident_id
        )

        if (updatedIncident) {
          setSelectedIncident(updatedIncident)
        }
      }
    } catch (error) {
      console.error("Failed to load SOC data:", error)
    }
  }

  async function runSimulation(endpoint, label) {
    setLoading(true)
    setActiveSimulation(label)

    try {
      const response = await fetch(`${API_URL}${endpoint}`, {
        method: "POST",
      })

      if (!response.ok) {
        throw new Error(`${label} simulation failed`)
      }

      const data = await response.json()

      setSimulation(data)
      await loadData()
    } catch (error) {
      console.error(`${label} simulation failed:`, error)
    } finally {
      setActiveSimulation(null)
      setLoading(false)
    }
  }

  async function simulateBruteForce() {
    await runSimulation("/simulate/brute-force", "brute-force")
  }

  async function simulatePrivilegeEscalation() {
    await runSimulation(
      "/simulate/privilege-escalation",
      "privilege-escalation"
    )
  }

  async function simulateLateralMovement() {
    await runSimulation(
      "/simulate/lateral-movement",
      "lateral-movement"
    )
  }

  async function updateIncidentStatus(newStatus) {
    if (!selectedIncident) {
      return
    }

    try {
      const response = await fetch(
        `${API_URL}/incidents/${selectedIncident.incident_id}/status?status=${newStatus}`,
        {
          method: "PATCH",
        }
      )

      if (!response.ok) {
        throw new Error("Failed to update incident status")
      }

      const data = await response.json()

      setSelectedIncident(data.incident)

      await loadData()
    } catch (error) {
      console.error("Incident status update failed:", error)
    }
  }

  const criticalAlerts = alerts.filter(
    (alert) => alert.severity === "CRITICAL"
  ).length

  const highAlerts = alerts.filter(
    (alert) => alert.severity === "HIGH"
  ).length

  const mediumAlerts = alerts.filter(
    (alert) => alert.severity === "MEDIUM"
  ).length

  const openIncidents = incidents.filter(
    (incident) =>
      incident.status === "OPEN" ||
      incident.status === "INVESTIGATING"
  ).length

  function statusClass(status) {
    return `status-badge status-${status.toLowerCase()}`
  }

  function renderHeader() {
    let title = "Security Operations Center"

    if (page === "alerts") {
      title = "Alerts"
    }

    if (page === "alert-details") {
      title = "Alert Details"
    }

    if (page === "incidents") {
      title = "Incident Management"
    }

    if (page === "incident-details") {
      title = "Incident Details"
    }

    if (page === "detection-rules") {
      title = "Detection Rules"
    }

    if (page === "rule-details") {
      title = "Detection Rule Details"
    }

    if (page === "mitre") {
      title = "MITRE ATT&CK"
    }

    if (page === "simulator") {
      title = "Attack Simulator"
    }

    return (
      <header className="topbar">
        <div>
          <div className="breadcrumb">
            BREMR SOC PLATFORM / {title.toUpperCase()}
          </div>

          <h1>{title}</h1>
        </div>

        <div className="system-status">
          <span className="status-dot"></span>
          SYSTEM OPERATIONAL
        </div>
      </header>
    )
  }

  function renderSidebar() {
    return (
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">Ξ</div>

          <div>
            <div className="brand-name">BREMR</div>
            <div className="brand-subtitle">SOC PLATFORM</div>
          </div>
        </div>

        <nav>
          <button
            className={page === "dashboard" ? "nav-active" : ""}
            onClick={() => setPage("dashboard")}
          >
            Dashboard
          </button>

          <button
            className={
              page === "alerts" || page === "alert-details"
                ? "nav-active"
                : ""
            }
            onClick={() => setPage("alerts")}
          >
            Alerts
            {alerts.length > 0 && (
              <span className="nav-count">{alerts.length}</span>
            )}
          </button>

          <button
            className={
              page === "incidents" || page === "incident-details"
                ? "nav-active"
                : ""
            }
            onClick={() => setPage("incidents")}
          >
            Incidents
            {openIncidents > 0 && (
              <span className="nav-count">{openIncidents}</span>
            )}
          </button>

          <button
            className={
              page === "detection-rules" ||
              page === "rule-details"
                ? "nav-active"
                : ""
            }
            onClick={() => setPage("detection-rules")}
          >
            Detection Rules
          </button>

          <button
            className={page === "mitre" ? "nav-active" : ""}
            onClick={() => setPage("mitre")}
          >
            MITRE ATT&CK
          </button>

          <button
            className={page === "simulator" ? "nav-active" : ""}
            onClick={() => setPage("simulator")}
          >
            Attack Simulator
          </button>
        </nav>
      </aside>
    )
  }

  function renderDashboard() {
    return (
      <div className="page-content">
        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-label">CRITICAL ALERTS</div>
            <div className="stat-value critical">
              {criticalAlerts}
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-label">HIGH ALERTS</div>
            <div className="stat-value high">
              {highAlerts}
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-label">MEDIUM ALERTS</div>
            <div className="stat-value medium">
              {mediumAlerts}
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-label">OPEN INCIDENTS</div>
            <div className="stat-value">
              {openIncidents}
            </div>
          </div>
        </div>

        <div className="dashboard-grid">
          <section className="panel">
            <div className="panel-header">
              <div>
                <div className="panel-title">RECENT ALERTS</div>
                <div className="panel-subtitle">
                  Latest security detections
                </div>
              </div>

              <button
                className="text-button"
                onClick={() => setPage("alerts")}
              >
                VIEW ALL
              </button>
            </div>

            {alerts.length === 0 ? (
              <div className="empty-state">
                No alerts detected.
              </div>
            ) : (
              <div className="alert-list">
                {alerts
                  .slice()
                  .reverse()
                  .slice(0, 5)
                  .map((alert) => (
                    <div
                      key={alert.alert_id}
                      className="alert-row clickable"
                      onClick={() => {
                        setSelectedAlert(alert)
                        setPage("alert-details")
                      }}
                    >
                      <div className="alert-main">
                        <div className="alert-title">
                          {alert.rule}
                        </div>

                        <div className="alert-meta">
                          {alert.source} · {alert.username}
                        </div>
                      </div>

                      <div className={statusClass(alert.status)}>
                        {alert.status}
                      </div>

                      <div className={`severity ${alert.severity.toLowerCase()}`}>
                        {alert.severity}
                      </div>
                    </div>
                  ))}
              </div>
            )}
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <div className="panel-title">ATTACK SIMULATOR</div>
                <div className="panel-subtitle">
                  Generate controlled security events
                </div>
              </div>
            </div>

            <div className="simulator-card">
              <div className="simulator-icon">⚡</div>

              <div>
                <div className="simulator-title">
                  Brute Force Authentication
                </div>

                <div className="simulator-description">
                  Generates multiple failed authentication
                  attempts and triggers detection rule T1110.
                </div>
              </div>

              <button
                className="primary-button"
                onClick={simulateBruteForce}
                disabled={loading}
              >
                {loading ? "SIMULATING..." : "SIMULATE ATTACK"}
              </button>
            </div>
          </section>
        </div>
      </div>
    )
  }

  function renderAlerts() {
    return (
      <div className="page-content">
        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">SECURITY ALERTS</div>
              <div className="panel-subtitle">
                Detected security events requiring investigation
              </div>
            </div>
          </div>

          {alerts.length === 0 ? (
            <div className="empty-state">
              No alerts available.
            </div>
          ) : (
            <div className="table">
              <div className="table-header">
                <span>ALERT</span>
                <span>SEVERITY</span>
                <span>SOURCE</span>
                <span>USER</span>
                <span>STATUS</span>
              </div>

              {alerts
                .slice()
                .reverse()
                .map((alert) => (
                  <div
                    key={alert.alert_id}
                    className="table-row clickable"
                    onClick={() => {
                      setSelectedAlert(alert)
                      setPage("alert-details")
                    }}
                  >
                    <span>
                      <strong>{alert.rule}</strong>
                      <small>{alert.alert_id}</small>
                    </span>

                    <span className={`severity ${alert.severity.toLowerCase()}`}>
                      {alert.severity}
                    </span>

                    <span>{alert.source}</span>

                    <span>{alert.username}</span>

                    <span className={statusClass(alert.status)}>
                      {alert.status}
                    </span>
                  </div>
                ))}
            </div>
          )}
        </section>
      </div>
    )
  }

  function renderAlertDetails() {
    if (!selectedAlert) {
      return (
        <div className="page-content">
          <div className="empty-state">
            No alert selected.
          </div>
        </div>
      )
    }

    const relatedEvents = events.filter(
      (event) =>
        event.source_ip === selectedAlert.source_ip &&
        event.username === selectedAlert.username
    )

    const linkedIncident = incidents.find(
      (incident) =>
        incident.alert_id === selectedAlert.alert_id
    )

    return (
      <div className="page-content">
        <button
          className="back-button"
          onClick={() => setPage("alerts")}
        >
          ← BACK TO ALERTS
        </button>

        <section className="panel">
          <div className="incident-header">
            <div>
              <div className="eyebrow">SECURITY ALERT</div>

              <h2>{selectedAlert.rule}</h2>

              <div className="alert-id">
                {selectedAlert.alert_id}
              </div>
            </div>

            <div className={`severity large ${selectedAlert.severity.toLowerCase()}`}>
              {selectedAlert.severity}
            </div>
          </div>

          <div className="alert-detail-grid">
            <div>
              <span>TECHNIQUE</span>
              <strong>{selectedAlert.technique}</strong>
            </div>

            <div>
              <span>SOURCE</span>
              <strong>{selectedAlert.source}</strong>
            </div>

            <div>
              <span>USERNAME</span>
              <strong>{selectedAlert.username}</strong>
            </div>

            <div>
              <span>SOURCE IP</span>
              <strong>{selectedAlert.source_ip}</strong>
            </div>

            <div>
              <span>HOSTNAME</span>
              <strong>{selectedAlert.hostname}</strong>
            </div>

            <div>
              <span>STATUS</span>
              <strong>{selectedAlert.status}</strong>
            </div>
          </div>

          <div className="description-box">
            <div className="eyebrow">DESCRIPTION</div>
            <p>{selectedAlert.description}</p>
          </div>

          <div className="attack-chain-panel">
            <div className="panel-title">DETECTION CHAIN</div>

            <div className="investigation-chain">
              <div className="chain-node">
                ATTACK
              </div>

              <div className="chain-arrow">→</div>

              <div className="chain-node">
                EVENTS
              </div>

              <div className="chain-arrow">→</div>

              <div className="chain-node mitre-node">
                {selectedAlert.technique}
              </div>

              <div className="chain-arrow">→</div>

              <div className="chain-node">
                ALERT
              </div>

              <div className="chain-arrow">→</div>

              <div className="chain-node">
                INCIDENT
              </div>
            </div>
          </div>

          <div className="panel-section">
            <div className="panel-title">
              EVIDENCE ({relatedEvents.length})
            </div>

            <div className="evidence-list">
              {relatedEvents.map((event) => (
                <div
                  key={event.id}
                  className="evidence-row"
                >
                  <div className="evidence-icon">!</div>

                  <div>
                    <strong>{event.event_type}</strong>
                    <div>{event.description}</div>
                  </div>

                  <span>{event.timestamp}</span>
                </div>
              ))}
            </div>
          </div>

          {linkedIncident && (
            <div className="linked-alert">
              <div className="linked-alert-top">
                <div>
                  <div className="eyebrow">
                    LINKED INCIDENT
                  </div>

                  <strong>
                    {linkedIncident.incident_id}
                  </strong>
                </div>

                <div className={statusClass(linkedIncident.status)}>
                  {linkedIncident.status}
                </div>
              </div>

              <button
                className="secondary-button"
                onClick={() => {
                  setSelectedIncident(linkedIncident)
                  setPage("incident-details")
                }}
              >
                OPEN INCIDENT
              </button>
            </div>
          )}
        </section>
      </div>
    )
  }

  function renderIncidents() {
    return (
      <div className="page-content">
        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                INCIDENT MANAGEMENT
              </div>

              <div className="panel-subtitle">
                Security incidents and response lifecycle
              </div>
            </div>
          </div>

          {incidents.length === 0 ? (
            <div className="empty-state">
              No incidents available.
            </div>
          ) : (
            <div className="table">
              <div className="table-header">
                <span>INCIDENT</span>
                <span>SEVERITY</span>
                <span>TECHNIQUE</span>
                <span>SOURCE</span>
                <span>STATUS</span>
              </div>

              {incidents
                .slice()
                .reverse()
                .map((incident) => (
                  <div
                    key={incident.incident_id}
                    className="table-row clickable"
                    onClick={() => {
                      setSelectedIncident(incident)
                      setPage("incident-details")
                    }}
                  >
                    <span>
                      <strong>{incident.title}</strong>
                      <small>{incident.incident_id}</small>
                    </span>

                    <span className={`severity ${incident.severity.toLowerCase()}`}>
                      {incident.severity}
                    </span>

                    <span>{incident.technique}</span>

                    <span>{incident.source}</span>

                    <span className={statusClass(incident.status)}>
                      {incident.status}
                    </span>
                  </div>
                ))}
            </div>
          )}
        </section>
      </div>
    )
  }

  function renderIncidentDetails() {
    if (!selectedIncident) {
      return (
        <div className="page-content">
          <div className="empty-state">
            No incident selected.
          </div>
        </div>
      )
    }

    const linkedAlert = alerts.find(
      (alert) =>
        alert.alert_id === selectedIncident.alert_id
    )

    const canInvestigate =
      selectedIncident.status === "OPEN"

    const canContain =
      selectedIncident.status === "INVESTIGATING"

    const canResolve =
      selectedIncident.status === "CONTAINED"

    return (
      <div className="page-content">
        <button
          className="back-button"
          onClick={() => setPage("incidents")}
        >
          ← BACK TO INCIDENTS
        </button>

        <section className="panel">
          <div className="incident-header">
            <div>
              <div className="eyebrow">SECURITY INCIDENT</div>

              <h2>{selectedIncident.title}</h2>

              <div className="alert-id">
                {selectedIncident.incident_id}
              </div>
            </div>

            <div className={`severity large ${selectedIncident.severity.toLowerCase()}`}>
              {selectedIncident.severity}
            </div>
          </div>

          <div className="incident-lifecycle">
            <div className="panel-title">
              INCIDENT LIFECYCLE
            </div>

            <div className="lifecycle">
              {[
                "OPEN",
                "INVESTIGATING",
                "CONTAINED",
                "RESOLVED",
              ].map((status, index) => {
                const statuses = [
                  "OPEN",
                  "INVESTIGATING",
                  "CONTAINED",
                  "RESOLVED",
                ]

                const currentIndex = statuses.indexOf(
                  selectedIncident.status
                )

                const statusIndex = index

                let className = "lifecycle-step"

                if (statusIndex < currentIndex) {
                  className += " completed"
                }

                if (statusIndex === currentIndex) {
                  className += " current"
                }

                return (
                  <div
                    key={status}
                    className={className}
                  >
                    <div className="lifecycle-number">
                      {statusIndex + 1}
                    </div>

                    <div className="lifecycle-label">
                      {status}
                    </div>

                    {index < 3 && (
                      <div className="lifecycle-line"></div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>

          <div className="incident-actions">
            <div className="panel-title">
              RESPONSE ACTIONS
            </div>

            <div className="response-actions">
              <button
                className="secondary-button"
                disabled={!canInvestigate}
                onClick={() =>
                  updateIncidentStatus("INVESTIGATING")
                }
              >
                INVESTIGATE
              </button>

              <button
                className="secondary-button"
                disabled={!canContain}
                onClick={() =>
                  updateIncidentStatus("CONTAINED")
                }
              >
                CONTAIN INCIDENT
              </button>

              <button
                className="primary-button"
                disabled={!canResolve}
                onClick={() =>
                  updateIncidentStatus("RESOLVED")
                }
              >
                RESOLVE INCIDENT
              </button>
            </div>
          </div>

          <div className="alert-detail-grid">
            <div>
              <span>INCIDENT STATUS</span>
              <strong className={statusClass(selectedIncident.status)}>
                {selectedIncident.status}
              </strong>
            </div>

            <div>
              <span>SEVERITY</span>
              <strong>{selectedIncident.severity}</strong>
            </div>

            <div>
              <span>MITRE TECHNIQUE</span>
              <strong>{selectedIncident.technique}</strong>
            </div>

            <div>
              <span>SOURCE</span>
              <strong>{selectedIncident.source}</strong>
            </div>

            <div>
              <span>USERNAME</span>
              <strong>{selectedIncident.username}</strong>
            </div>

            <div>
              <span>SOURCE IP</span>
              <strong>{selectedIncident.source_ip}</strong>
            </div>

            <div>
              <span>HOSTNAME</span>
              <strong>{selectedIncident.hostname}</strong>
            </div>

            <div>
              <span>LINKED ALERT</span>
              <strong>{selectedIncident.alert_id}</strong>
            </div>
          </div>

          <div className="description-box">
            <div className="eyebrow">
              INCIDENT DESCRIPTION
            </div>

            <p>{selectedIncident.description}</p>
          </div>

          {linkedAlert && (
            <div className="linked-alert">
              <div className="linked-alert-top">
                <div>
                  <div className="eyebrow">
                    LINKED SECURITY ALERT
                  </div>

                  <strong>{linkedAlert.alert_id}</strong>
                </div>

                <div className={statusClass(linkedAlert.status)}>
                  {linkedAlert.status}
                </div>
              </div>

              <button
                className="secondary-button"
                onClick={() => {
                  setSelectedAlert(linkedAlert)
                  setPage("alert-details")
                }}
              >
                OPEN ALERT
              </button>
            </div>
          )}

          <div className="response-panel">
            <div className="panel-title">
              AUTOMATED RESPONSE
            </div>

            <div className="response-grid">
              <div className="response-action">
                <strong>CONTAIN</strong>
                <span>Source IP blocked</span>
              </div>

              <div className="response-action">
                <strong>ACCOUNT</strong>
                <span>Compromised account disabled</span>
              </div>

              <div className="response-action">
                <strong>ENDPOINT</strong>
                <span>Affected endpoint isolated</span>
              </div>
            </div>
          </div>
        </section>
      </div>
    )
  }

  function renderDetectionRules() {
    return (
      <div className="page-content">
        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                DETECTION RULES
              </div>

              <div className="panel-subtitle">
                Detection engineering library
              </div>
            </div>

            <div className="rule-count">
              {detectionRules.length} ACTIVE RULES
            </div>
          </div>

          <div className="rules-table">
            <div className="rules-header">
              <span>ID</span>
              <span>RULE</span>
              <span>MITRE</span>
              <span>TACTIC</span>
              <span>SEVERITY</span>
              <span>STATUS</span>
            </div>

            {detectionRules.map((rule) => (
              <div
                key={rule.id}
                className="rule-row clickable"
                onClick={() => {
                  setSelectedRule(rule)
                  setPage("rule-details")
                }}
              >
                <span>{rule.id}</span>

                <strong>{rule.name}</strong>

                <span className="mitre-badge">
                  {rule.technique}
                </span>

                <span>{rule.tactic}</span>

                <span className={`severity ${rule.severity.toLowerCase()}`}>
                  {rule.severity}
                </span>

                <span className="rule-status">
                  {rule.status}
                </span>
              </div>
            ))}
          </div>
        </section>
      </div>
    )
  }

  function renderRuleDetails() {
    if (!selectedRule) {
      return (
        <div className="page-content">
          <div className="empty-state">
            No detection rule selected.
          </div>
        </div>
      )
    }

    return (
      <div className="page-content">
        <button
          className="back-button"
          onClick={() => setPage("detection-rules")}
        >
          ← BACK TO DETECTION RULES
        </button>

        <section className="panel">
          <div className="incident-header">
            <div>
              <div className="eyebrow">
                DETECTION RULE
              </div>

              <h2>{selectedRule.name}</h2>

              <div className="alert-id">
                {selectedRule.id}
              </div>
            </div>

            <div className={`severity large ${selectedRule.severity.toLowerCase()}`}>
              {selectedRule.severity}
            </div>
          </div>

          <div className="rules-detail-grid">
            <div>
              <span>MITRE ATT&CK</span>
              <strong className="mitre-detail">
                {selectedRule.technique}
              </strong>
            </div>

            <div>
              <span>TACTIC</span>
              <strong>{selectedRule.tactic}</strong>
            </div>

            <div>
              <span>STATUS</span>
              <strong>{selectedRule.status}</strong>
            </div>

            <div>
              <span>RULE ID</span>
              <strong>{selectedRule.id}</strong>
            </div>
          </div>

          <div className="description-box">
            <div className="eyebrow">DESCRIPTION</div>
            <p>{selectedRule.description}</p>
          </div>

          <div className="rules-detail-grid">
            <div className="logic-box">
              <div className="eyebrow">DETECTION LOGIC</div>
              <p>{selectedRule.logic}</p>
            </div>

            <div>
              <div className="eyebrow">DATA SOURCES</div>

              <div className="source-list">
                {selectedRule.dataSources.map((source) => (
                  <div
                    key={source}
                    className="source-item"
                  >
                    {source}
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="response-panel">
            <div className="panel-title">
              RESPONSE ACTIONS
            </div>

            <div className="response-grid">
              {selectedRule.response.map((action) => (
                <div
                  key={action}
                  className="response-action"
                >
                  <strong>ACTION</strong>
                  <span>{action}</span>
                </div>
              ))}
            </div>
          </div>
        </section>
      </div>
    )
  }

  function renderMitre() {
    return (
      <div className="page-content">
        <section className="panel">
          <div className="panel-header">
            <div>
              <div className="panel-title">
                MITRE ATT&CK
              </div>

              <div className="panel-subtitle">
                Techniques represented in the detection library
              </div>
            </div>
          </div>

          <div className="rules-table">
            <div className="rules-header">
              <span>TECHNIQUE</span>
              <span>NAME</span>
              <span>TACTIC</span>
              <span>SEVERITY</span>
            </div>

            {detectionRules.map((rule) => (
              <div
                key={rule.technique}
                className="rule-row"
              >
                <span className="mitre-badge">
                  {rule.technique}
                </span>

                <strong>{rule.name}</strong>

                <span>{rule.tactic}</span>

                <span className={`severity ${rule.severity.toLowerCase()}`}>
                  {rule.severity}
                </span>
              </div>
            ))}
          </div>
        </section>
      </div>
    )
  }

  function renderSimulator() {
    const simulatorCards = [
      {
        key: "brute-force",
        icon: "⚡",
        title: "Brute Force Authentication",
        description:
          "Simulates five failed authentication attempts against the administrator account.",
        technique: "T1110",
        action: simulateBruteForce,
        button: "SIMULATE BRUTE FORCE",
      },
      {
        key: "privilege-escalation",
        icon: "⚠",
        title: "Privilege Escalation",
        description:
          "Simulates exploitation of a vulnerability followed by execution with elevated privileges.",
        technique: "T1068",
        action: simulatePrivilegeEscalation,
        button: "SIMULATE PRIVILEGE ESCALATION",
      },
      {
        key: "lateral-movement",
        icon: "↔",
        title: "Lateral Movement",
        description:
          "Simulates remote service activity used to move between systems inside the environment.",
        technique: "T1021",
        action: simulateLateralMovement,
        button: "SIMULATE LATERAL MOVEMENT",
      },
    ]

    return (
      <>
        <style>{`
          .simulator-page {
            width: 100% !important;
            box-sizing: border-box !important;
          }

          .simulator-page .simulator-panel {
            display: block !important;
            width: 100% !important;
            max-width: none !important;
            box-sizing: border-box !important;
            overflow: visible !important;
            grid-template-columns: none !important;
            grid-template-rows: none !important;
            align-items: stretch !important;
            justify-items: stretch !important;
            gap: 0 !important;
          }

          .simulator-page .simulator-header {
            margin-bottom: 24px !important;
          }

          .simulator-page .simulator-grid {
            display: grid !important;
            grid-template-columns: repeat(3, minmax(0, 1fr)) !important;
            grid-template-rows: auto !important;
            gap: 18px !important;
            width: 100% !important;
            max-width: none !important;
            align-items: stretch !important;
            box-sizing: border-box !important;
          }

          .simulator-page .simulator-card-v2 {
            display: flex !important;
            flex-direction: column !important;
            justify-content: space-between !important;
            align-items: stretch !important;
            gap: 22px !important;
            width: 100% !important;
            min-width: 0 !important;
            min-height: 235px !important;
            padding: 22px !important;
            box-sizing: border-box !important;
            border: 1px solid #203040 !important;
            border-radius: 8px !important;
            background: #0d1722 !important;
            overflow: hidden !important;
          }

          .simulator-page .simulator-card-top {
            display: flex !important;
            flex-direction: column !important;
            align-items: flex-start !important;
            gap: 14px !important;
            min-width: 0 !important;
          }

          .simulator-page .simulator-icon-v2 {
            width: 36px !important;
            height: 36px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
            font-size: 22px !important;
            line-height: 1 !important;
            color: #8fbce8 !important;
          }

          .simulator-page .simulator-card-content {
            width: 100% !important;
            min-width: 0 !important;
          }

          .simulator-page .simulator-title {
            margin: 0 0 9px 0 !important;
            font-size: 18px !important;
            line-height: 1.3 !important;
            font-weight: 650 !important;
            color: #e8eef5 !important;
          }

          .simulator-page .simulator-description {
            margin: 0 0 16px 0 !important;
            font-size: 13px !important;
            line-height: 1.55 !important;
            color: #8b9aaa !important;
          }

          .simulator-page .simulator-mitre-badge {
            display: inline-flex !important;
            width: auto !important;
            box-sizing: border-box !important;
            padding: 6px 9px !important;
            border: 1px solid #29445c !important;
            border-radius: 4px !important;
            background: #101e2b !important;
            font-size: 10px !important;
            line-height: 1 !important;
            font-weight: 700 !important;
            letter-spacing: .8px !important;
            color: #8fbce8 !important;
          }

          .simulator-page .simulator-button-v2 {
            width: 100% !important;
            min-height: 42px !important;
            margin: 0 !important;
            box-sizing: border-box !important;
            border-radius: 5px !important;
            font-size: 11px !important;
            font-weight: 800 !important;
            letter-spacing: 1px !important;
            white-space: nowrap !important;
          }

          .simulator-page .simulation-summary-v2 {
            display: block !important;
            width: 100% !important;
            max-width: none !important;
            margin-top: 24px !important;
            padding: 22px !important;
            box-sizing: border-box !important;
            border: 1px solid #203040 !important;
            border-radius: 8px !important;
            background: #0a141e !important;
          }

          .simulator-page .simulation-summary-heading {
            display: flex !important;
            align-items: center !important;
            justify-content: space-between !important;
            gap: 20px !important;
            margin-bottom: 18px !important;
          }

          .simulator-page .simulation-summary-status {
            font-size: 12px !important;
            color: #7f93a7 !important;
            text-align: right !important;
          }

          .simulator-page .simulation-summary-grid-v2 {
            display: grid !important;
            grid-template-columns: repeat(3, minmax(0, 1fr)) !important;
            gap: 14px !important;
            width: 100% !important;
          }

          .simulator-page .simulation-summary-card-v2 {
            min-width: 0 !important;
            min-height: 92px !important;
            padding: 16px !important;
            box-sizing: border-box !important;
            display: flex !important;
            flex-direction: column !important;
            justify-content: center !important;
            gap: 9px !important;
            border: 1px solid #203040 !important;
            border-radius: 6px !important;
            background: #0d1722 !important;
            overflow: hidden !important;
          }

          .simulator-page .simulation-summary-card-v2 span {
            display: block !important;
            font-size: 10px !important;
            line-height: 1.2 !important;
            font-weight: 800 !important;
            letter-spacing: 1.5px !important;
            color: #71859a !important;
          }

          .simulator-page .simulation-summary-card-v2 strong {
            display: block !important;
            min-width: 0 !important;
            font-size: 14px !important;
            line-height: 1.35 !important;
            font-weight: 650 !important;
            color: #e8eef5 !important;
            overflow-wrap: anywhere !important;
          }

          @media (max-width: 1100px) {
            .simulator-page .simulator-grid,
            .simulator-page .simulation-summary-grid-v2 {
              grid-template-columns: repeat(2, minmax(0, 1fr)) !important;
            }
          }

          @media (max-width: 700px) {
            .simulator-page .simulator-grid,
            .simulator-page .simulation-summary-grid-v2 {
              grid-template-columns: 1fr !important;
            }

            .simulator-page .simulation-summary-heading {
              align-items: flex-start !important;
              flex-direction: column !important;
            }

            .simulator-page .simulation-summary-status {
              text-align: left !important;
            }
          }
        `}</style>

        <div className="page-content simulator-page">
        <section className="panel simulator-panel">
          <div className="panel-header simulator-header">
            <div>
              <div className="panel-title">ATTACK SIMULATOR</div>
              <div className="panel-subtitle">
                Controlled attack simulation and detection validation
              </div>
            </div>
          </div>

          <div className="simulator-grid">
            {simulatorCards.map((card) => {
              const isRunning = activeSimulation === card.key
              const anotherIsRunning =
                loading && activeSimulation !== card.key

              return (
                <article className="simulator-card simulator-card-v2" key={card.key}>
                  <div className="simulator-card-top">
                    <div className="simulator-icon simulator-icon-v2">
                      {card.icon}
                    </div>

                    <div className="simulator-card-content">
                      <div className="simulator-title">{card.title}</div>
                      <div className="simulator-description">
                        {card.description}
                      </div>
                      <div className="mitre-badge simulator-mitre-badge">
                        MITRE ATT&CK {card.technique}
                      </div>
                    </div>
                  </div>

                  <button
                    className="primary-button simulator-button-v2"
                    onClick={card.action}
                    disabled={loading}
                  >
                    {isRunning
                      ? "SIMULATING..."
                      : anotherIsRunning
                        ? "WAITING..."
                        : card.button}
                  </button>
                </article>
              )
            })}
          </div>

          {simulation && (
            <div className="simulation-summary-v2">
              <div className="simulation-summary-heading">
                <div className="panel-title">LAST SIMULATION</div>
                <div className="simulation-summary-status">
                  {simulation.attack || "Simulation completed"}
                </div>
              </div>

              <div className="simulation-summary-grid-v2">
                <div className="simulation-summary-card-v2">
                  <span>EVENTS</span>
                  <strong>{simulation.events?.length || 0} generated</strong>
                </div>

                <div className="simulation-summary-card-v2">
                  <span>DETECTION</span>
                  <strong>{simulation.detection?.technique || "N/A"}</strong>
                </div>

                <div className="simulation-summary-card-v2">
                  <span>MITRE</span>
                  <strong>{simulation.detection?.rule || "N/A"}</strong>
                </div>

                <div className="simulation-summary-card-v2">
                  <span>ALERT</span>
                  <strong>{simulation.alert?.alert_id || "N/A"}</strong>
                </div>

                <div className="simulation-summary-card-v2">
                  <span>INCIDENT</span>
                  <strong>{simulation.incident?.incident_id || "N/A"}</strong>
                </div>

                <div className="simulation-summary-card-v2">
                  <span>RESPONSE</span>
                  <strong>{simulation.response?.status || "N/A"}</strong>
                </div>
              </div>
            </div>
          )}
        </section>
        </div>
      </>
    )
  }

  function renderPage() {
    if (page === "dashboard") {
      return renderDashboard()
    }

    if (page === "alerts") {
      return renderAlerts()
    }

    if (page === "alert-details") {
      return renderAlertDetails()
    }

    if (page === "incidents") {
      return renderIncidents()
    }

    if (page === "incident-details") {
      return renderIncidentDetails()
    }

    if (page === "detection-rules") {
      return renderDetectionRules()
    }

    if (page === "rule-details") {
      return renderRuleDetails()
    }

    if (page === "mitre") {
      return renderMitre()
    }

    if (page === "simulator") {
      return renderSimulator()
    }

    return renderDashboard()
  }

  return (
    <div className="app">
      {renderSidebar()}

      <main className="main">
        {renderHeader()}

        {renderPage()}
      </main>
    </div>
  )
}

export default App