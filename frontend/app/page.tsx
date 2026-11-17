"use client";

import { type FormEvent, type ReactNode, useEffect, useMemo, useRef, useState } from "react";

type Account = {
  account_id: string;
  name: string;
  assume_role_enabled: boolean;
};

type Count = { name: string; count: number };
type EventRow = {
  id: string;
  account_id: string;
  region: string;
  event_source: string;
  event_name: string;
  event_time: string;
  source_ip: string | null;
  principal_arn: string | null;
  is_synthetic: boolean;
};
type IncidentRow = {
  id: string;
  title: string;
  status: string;
  severity: string;
  account_id: string;
  region: string;
  last_observed_at: string;
};
type IncidentDetail = {
  incident: IncidentRow & { assigned_to: string | null };
  alerts: {
    id: string;
    title: string;
    rule_id: string;
    severity: string;
    investigation_steps: string[];
    response_recommendations: string[];
  }[];
  events: (EventRow & { event_details: Record<string, unknown> })[];
  audit_findings: AuditFinding[];
  notes: { id: string; author_email: string | null; body: string; created_at: string }[];
  timeline: { entry_type: string; occurred_at: string; summary: string }[];
};
type AuditFinding = {
  id: string;
  report_id: string;
  report_generated_at: string;
  source_finding_id: string;
  account_id: string;
  region: string;
  control_id: string;
  title: string;
  resource_id: string;
  resource_type: string;
  severity: string;
  status: string;
  message: string;
  evidence: Record<string, unknown>;
  sources: string[];
  observed_at: string;
  remediation: string;
  uncertainty: string[];
  suppression: { reason: string; owner: string; expires: string } | null;
};
type AuditReport = {
  id: string;
  account_id: string;
  regions: string[];
  audit_profile: string;
  tool_name: string;
  tool_version: string;
  catalog_version: string;
  generated_at: string;
  finding_count: number;
};
type Integration = {
  account_id: string;
  integration: string;
  region: string;
  status: string;
  last_error_code: string | null;
  last_checked_at: string;
};
type Dashboard = {
  generated_at: string;
  since: string;
  until: string;
  metrics: {
    total_events: number;
    total_alerts: number;
    open_incidents: number;
    critical_high_incidents: number;
    guardduty_findings: number;
    securityhub_findings: number;
    monitored_accounts: number;
    monitored_regions: number;
    notifications_pending: number;
    notifications_failed: number;
    active_audit_failures: number;
  };
  severity_distribution: Count[];
  top_detection_rules: Count[];
  top_source_ips: Count[];
  top_resources: Count[];
  top_identities: Count[];
  recent_events: EventRow[];
  recent_incidents: IncidentRow[];
  integrations: Integration[];
  latest_audit_report: AuditReport | null;
  audit_findings: AuditFinding[];
  aws_connection_status: string;
};

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
const severityOrder = ["critical", "high", "medium", "low", "informational"];
const allowedIncidentTransitions: Record<string, string[]> = {
  new: ["acknowledged", "investigating", "contained", "resolved", "false_positive"],
  acknowledged: ["investigating", "contained", "resolved", "false_positive"],
  investigating: ["acknowledged", "contained", "resolved", "false_positive"],
  contained: ["investigating", "resolved", "false_positive"],
  resolved: ["investigating"],
  false_positive: ["investigating"],
};

async function request<T>(path: string, token: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const detail =
      typeof body === "object" && body !== null && "detail" in body
        ? String((body as { detail: unknown }).detail)
        : `Request failed (${response.status})`;
    throw new Error(detail);
  }
  return body as T;
}

function formatTime(value: string) {
  return new Date(value).toLocaleString();
}

function SeverityPill({ severity }: { severity: string }) {
  return <span className={`severity-pill ${severity.toLowerCase()}`}>{severity}</span>;
}

export default function Home() {
  const [token, setToken] = useState<string | null>(null);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [userRole, setUserRole] = useState<string | null>(null);
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [windowHours, setWindowHours] = useState("24");
  const [accountId, setAccountId] = useState("");
  const [region, setRegion] = useState("");
  const [severity, setSeverity] = useState("");
  const [reloadKey, setReloadKey] = useState(0);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetail, setIncidentDetail] = useState<IncidentDetail | null>(null);
  const [detailBusy, setDetailBusy] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const activeIncidentId = useRef<string | null>(null);
  const incidentRequest = useRef<AbortController | null>(null);
  const canInvestigate = userRole === "administrator" || userRole === "security_analyst";
  const query = useMemo(() => {
    const end = new Date();
    const start = new Date(end.getTime() - Number(windowHours) * 60 * 60 * 1000);
    const params = new URLSearchParams({ since: start.toISOString(), until: end.toISOString() });
    if (accountId) params.set("account_id", accountId);
    if (region.trim()) params.set("region", region.trim());
    if (severity) params.set("severity", severity);
    return params.toString();
  }, [windowHours, accountId, region, severity]);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    Promise.all([
      request<Account[]>("/api/v1/accounts", token, { signal: controller.signal }),
      request<{ role: string }>("/api/v1/auth/me", token, { signal: controller.signal }),
    ])
      .then(([loadedAccounts, user]) => {
        setAccounts(loadedAccounts);
        setUserRole(user.role);
      })
      .catch((cause: unknown) => {
        if (!(cause instanceof Error && cause.name === "AbortError")) {
          setError(cause instanceof Error ? cause.message : "Could not load AWS accounts.");
        }
      });
    return () => controller.abort();
  }, [token]);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    setBusy(true);
    request<Dashboard>(`/api/v1/dashboard/summary?${query}`, token, {
      signal: controller.signal,
    })
      .then((result) => {
        setDashboard(result);
        setError(null);
      })
      .catch((cause: unknown) => {
        if (!(cause instanceof Error && cause.name === "AbortError")) {
          setError(cause instanceof Error ? cause.message : "Could not load dashboard data.");
        }
      })
      .finally(() => setBusy(false));
    return () => controller.abort();
  }, [token, query, reloadKey]);

  async function loadIncident(incidentId: string) {
    if (!token) return;
    incidentRequest.current?.abort();
    const controller = new AbortController();
    incidentRequest.current = controller;
    activeIncidentId.current = incidentId;
    setSelectedIncidentId(incidentId);
    setIncidentDetail(null);
    setDetailBusy(true);
    setDetailError(null);
    try {
      const detail = await request<IncidentDetail>(`/api/v1/incidents/${incidentId}`, token, {
        signal: controller.signal,
      });
      if (activeIncidentId.current === incidentId) setIncidentDetail(detail);
    } catch (cause) {
      if (!(cause instanceof Error && cause.name === "AbortError")) {
        setDetailError(cause instanceof Error ? cause.message : "Could not load incident evidence.");
      }
    } finally {
      if (incidentRequest.current === controller) {
        incidentRequest.current = null;
        setDetailBusy(false);
      }
    }
  }

  async function changeIncidentStatus(nextStatus: string) {
    if (!token || !incidentDetail) return;
    setDetailError(null);
    try {
      const incident = await request<IncidentRow>(
        `/api/v1/incidents/${incidentDetail.incident.id}/status`,
        token,
        {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: nextStatus }),
        },
      );
      if (activeIncidentId.current === incidentDetail.incident.id) {
        setIncidentDetail({ ...incidentDetail, incident: { ...incidentDetail.incident, ...incident } });
      }
      setReloadKey((value) => value + 1);
    } catch (cause) {
      setDetailError(cause instanceof Error ? cause.message : "Could not update incident status.");
    }
  }

  async function addInvestigationNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token || !incidentDetail || !noteDraft.trim()) return;
    setDetailError(null);
    try {
      await request(`/api/v1/incidents/${incidentDetail.incident.id}/notes`, token, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body: noteDraft }),
      });
      setNoteDraft("");
      if (activeIncidentId.current === incidentDetail.incident.id) {
        await loadIncident(incidentDetail.incident.id);
      }
    } catch (cause) {
      setDetailError(cause instanceof Error ? cause.message : "Could not save investigation note.");
    }
  }

  async function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
        cache: "no-store",
      });
      if (!response.ok) throw new Error("Sign-in failed. Check your email and password.");
      const result = (await response.json()) as { access_token: string };
      setToken(result.access_token);
      setPassword("");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Monitoring API is unavailable.");
    } finally {
      setBusy(false);
    }
  }

  if (!token) {
    return (
      <main className="login-shell">
        <form className="login-card" onSubmit={signIn}>
          <div className="brand login-brand"><span className="brand-mark">A</span> AWS Monitor</div>
          <p className="eyebrow">SECURITY OPERATIONS</p>
          <h1>Sign in to your workspace</h1>
          <p className="login-copy">Use your platform analyst or administrator account.</p>
          <label htmlFor="email">Email</label>
          <input
            autoComplete="username"
            id="email"
            onChange={(event) => setEmail(event.target.value)}
            required
            type="email"
            value={email}
          />
          <label htmlFor="password">Password</label>
          <input
            autoComplete="current-password"
            id="password"
            onChange={(event) => setPassword(event.target.value)}
            required
            type="password"
            value={password}
          />
          {error && <p className="error-message" role="alert">{error}</p>}
          <button className="primary-button" disabled={busy} type="submit">
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="login-foot">Session tokens are held in memory and cleared on sign-out.</p>
        </form>
      </main>
    );
  }

  const metrics = dashboard?.metrics;
  const maxSeverity = Math.max(1, ...(dashboard?.severity_distribution.map((item) => item.count) ?? []));

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">A</span> AWS Monitor</div>
        <div className="nav-label">WORKSPACE</div>
        <a className="nav-item active" href="#overview"><span>◈</span> Overview</a>
        <a className="nav-item" href="#incidents"><span>◉</span> Incidents</a>
        <a className="nav-item" href="#events"><span>⌁</span> Events</a>
        <a className="nav-item" href="#detections"><span>◇</span> Detections</a>
        <div className="sidebar-footer">
          <span className={`status-dot ${dashboard?.aws_connection_status === "unhealthy" ? "danger-dot" : ""}`} />
          {dashboard?.aws_connection_status === "not_configured"
            ? "AWS not configured"
            : `AWS ${dashboard?.aws_connection_status ?? "checking"}`}
        </div>
      </aside>
      <section className="content" id="overview">
        <header className="topbar">
          <div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Overview</h1></div>
          <div className="header-actions">
            <span className="environment"><span className="status-dot" /> LIVE BACKEND DATA</span>
            <button className="quiet-button" onClick={() => setReloadKey((value) => value + 1)} type="button">
              Refresh
            </button>
            <button className="quiet-button" onClick={() => {
              incidentRequest.current?.abort();
              activeIncidentId.current = null;
              setToken(null);
              setDashboard(null);
              setUserRole(null);
              setIncidentDetail(null);
              setSelectedIncidentId(null);
            }} type="button">
              Sign out
            </button>
          </div>
        </header>

        <section className="filters" aria-label="Dashboard filters">
          <label>Time range
            <select onChange={(event) => setWindowHours(event.target.value)} value={windowHours}>
              <option value="24">Last 24 hours</option>
              <option value="168">Last 7 days</option>
              <option value="720">Last 30 days</option>
            </select>
          </label>
          <label>AWS account
            <select onChange={(event) => setAccountId(event.target.value)} value={accountId}>
              <option value="">All accounts</option>
              {accounts.map((account) => (
                <option key={account.account_id} value={account.account_id}>
                  {account.name} · {account.account_id}
                </option>
              ))}
            </select>
          </label>
          <label>Region
            <input onChange={(event) => setRegion(event.target.value)} placeholder="All regions" value={region} />
          </label>
          <label>Severity
            <select onChange={(event) => setSeverity(event.target.value)} value={severity}>
              <option value="">All severities</option>
              {severityOrder.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </label>
          <span className="updated-at">
            {busy ? "Updating…" : dashboard ? `Updated ${formatTime(dashboard.generated_at)}` : "Loading…"}
          </span>
        </section>

        {error && <div className="notice error-notice" role="alert">{error}</div>}
        {!dashboard && !error && <div className="loading-panel">Loading persisted monitoring data…</div>}
        {dashboard && (
          <>
            <div className="metric-grid">
              <Metric label="Events processed" value={metrics?.total_events ?? 0} tone="teal" />
              <Metric label="Detection alerts" value={metrics?.total_alerts ?? 0} tone="blue" />
              <Metric label="Open incidents" value={metrics?.open_incidents ?? 0} tone="amber" />
              <Metric label="Critical / high" value={metrics?.critical_high_incidents ?? 0} tone="red" />
              <Metric label="GuardDuty findings" value={metrics?.guardduty_findings ?? 0} />
              <Metric label="Security Hub findings" value={metrics?.securityhub_findings ?? 0} />
              <Metric label="Notifications pending" value={metrics?.notifications_pending ?? 0} tone="amber" />
              <Metric label="Notifications failed" value={metrics?.notifications_failed ?? 0} tone="red" />
              <Metric label="Audit failures" value={metrics?.active_audit_failures ?? 0} tone="red" />
            </div>

            <div className="context-line">
              <span><strong>{metrics?.monitored_accounts}</strong> configured accounts</span>
              <span><strong>{metrics?.monitored_regions}</strong> regions with sync records</span>
              <span>AWS connection: <strong className={`connection-${dashboard.aws_connection_status}`}>
                {dashboard.aws_connection_status.replaceAll("_", " ")}
              </strong></span>
            </div>

            <div className="dashboard-grid">
              <Panel id="detections" title="Alert severity" subtitle="Persisted detection alerts in the selected window">
                <div className="severity-chart">
                  {severityOrder.map((name) => {
                    const count = dashboard.severity_distribution.find((item) => item.name === name)?.count ?? 0;
                    return (
                      <div className="bar-row" key={name}>
                        <span className="bar-label">{name}</span>
                        <div className="bar-track">
                          <div className={`bar-fill ${name}`} style={{ width: `${(count / maxSeverity) * 100}%` }} />
                        </div>
                        <strong>{count}</strong>
                      </div>
                    );
                  })}
                </div>
              </Panel>
              <Panel title="Top detection rules" subtitle="Highest alert counts in this window">
                <CountList items={dashboard.top_detection_rules} empty="No alerts in this time range." />
              </Panel>
            </div>

            <div className="dashboard-grid">
              <Panel id="incidents" title="Incident queue" subtitle="Most urgent recent incidents">
                {dashboard.recent_incidents.length === 0 ? <Empty>No incidents in this time range.</Empty> : (
                  <div className="incident-list">
                    {dashboard.recent_incidents.map((incident) => (
                      <article className="incident-row" key={incident.id}>
                        <div className="incident-main">
                          <button
                            className="incident-title"
                            onClick={() => void loadIncident(incident.id)}
                            type="button"
                          >
                            {incident.title}
                          </button>
                          <span>{incident.account_id} · {incident.region} · {formatTime(incident.last_observed_at)}</span>
                        </div>
                        <SeverityPill severity={incident.severity} />
                        <span className="status-label">{incident.status.replaceAll("_", " ")}</span>
                      </article>
                    ))}
                  </div>
                )}
              </Panel>
              <Panel title="Integration health" subtitle="Latest persisted AWS checks and syncs">
                {dashboard.integrations.length === 0 ? (
                  <Empty>
                    {dashboard.aws_connection_status === "not_configured"
                      ? "No AWS accounts configured."
                      : "No health checks recorded yet."}
                  </Empty>
                ) : (
                  <div className="integration-list">
                    {dashboard.integrations.map((integration) => (
                      <div className="integration-row" key={`${integration.account_id ?? ""}-${integration.integration}-${integration.region}`}>
                        <span className={`status-dot ${integration.status === "unhealthy" ? "danger-dot" : ""}`} />
                        <strong>{integration.integration}</strong>
                        <span>{integration.region || "account"}</span>
                        <small>{integration.last_error_code ?? integration.status}</small>
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            </div>

            <Panel title="Imported posture assessment" subtitle="Latest point-in-time report from the AWS Security Auditing Tool">
              {!dashboard.latest_audit_report ? (
                <Empty>No audit report imported. Import a schema-v1 JSON report to correlate posture findings.</Empty>
              ) : (
                <>
                  <div className="audit-report-summary">
                    <strong>{dashboard.latest_audit_report.tool_name} · catalog {dashboard.latest_audit_report.catalog_version}</strong>
                    <span>Account {dashboard.latest_audit_report.account_id} · {dashboard.latest_audit_report.audit_profile}</span>
                    <span>Assessed {formatTime(dashboard.latest_audit_report.generated_at)} · {dashboard.latest_audit_report.finding_count} checks</span>
                  </div>
                  {dashboard.audit_findings.length === 0 ? (
                    <Empty>No failing or unknown checks in this imported report for the selected filters.</Empty>
                  ) : (
                    <div className="audit-finding-list">
                      {dashboard.audit_findings.map((finding) => <AuditFindingCard finding={finding} key={finding.id} />)}
                    </div>
                  )}
                </>
              )}
            </Panel>

            {selectedIncidentId && (
              <Panel title="Incident investigation" subtitle="Evidence, timeline, recommendations, and analyst notes">
                <div className="detail-toolbar">
                  <span>{incidentDetail?.incident.id ?? selectedIncidentId}</span>
                  <button
                    className="quiet-button"
                    onClick={() => {
                      incidentRequest.current?.abort();
                      activeIncidentId.current = null;
                      setSelectedIncidentId(null);
                      setIncidentDetail(null);
                      setDetailBusy(false);
                    }}
                    type="button"
                  >
                    Close
                  </button>
                </div>
                {detailBusy && <Empty>Loading incident evidence…</Empty>}
                {detailError && <p className="error-message" role="alert">{detailError}</p>}
                {incidentDetail && (
                  <>
                    <div className="incident-detail-heading">
                      <div>
                        <h3>{incidentDetail.incident.title}</h3>
                        <p>{incidentDetail.incident.account_id} · {incidentDetail.incident.region} · Last observed {formatTime(incidentDetail.incident.last_observed_at)}</p>
                      </div>
                      <div className="incident-controls">
                        <SeverityPill severity={incidentDetail.incident.severity} />
                        {canInvestigate ? (
                          <label className="status-control">Status
                            <select
                              onChange={(event) => void changeIncidentStatus(event.target.value)}
                              value={incidentDetail.incident.status}
                            >
                              <option value={incidentDetail.incident.status}>{incidentDetail.incident.status.replaceAll("_", " ")}</option>
                              {(allowedIncidentTransitions[incidentDetail.incident.status] ?? []).map((status) => (
                                <option key={status} value={status}>{status.replaceAll("_", " ")}</option>
                              ))}
                            </select>
                          </label>
                        ) : (
                          <span className="status-label">{incidentDetail.incident.status.replaceAll("_", " ")}</span>
                        )}
                      </div>
                    </div>
                    <div className="detail-columns">
                      <section>
                        <h4>Detection evidence</h4>
                        {incidentDetail.alerts.length === 0 ? <Empty>No linked alerts.</Empty> : incidentDetail.alerts.map((alert) => (
                          <article className="evidence-card" key={alert.id}>
                            <div><SeverityPill severity={alert.severity} /> <strong>{alert.rule_id}: {alert.title}</strong></div>
                            <h5>Investigation steps</h5>
                            <ul>{alert.investigation_steps.map((step) => <li key={step}>{step}</li>)}</ul>
                            <h5>Recommended actions</h5>
                            <ul>{alert.response_recommendations.map((step) => <li key={step}>{step}</li>)}</ul>
                          </article>
                        ))}
                        <h4>Related auditor findings</h4>
                        {incidentDetail.audit_findings.length === 0 ? (
                          <Empty>No imported audit weakness matches this account and resource.</Empty>
                        ) : incidentDetail.audit_findings.map((finding) => (
                          <AuditFindingCard finding={finding} key={finding.id} />
                        ))}
                        <h4>Related events</h4>
                        {incidentDetail.events.map((event) => (
                          <details className="evidence-event" key={event.id}>
                            <summary>{event.event_source}:{event.event_name} · {formatTime(event.event_time)}</summary>
                            <pre>{JSON.stringify(event.event_details, null, 2)}</pre>
                          </details>
                        ))}
                      </section>
                      <section>
                        <h4>Incident timeline</h4>
                        <ol className="timeline">
                          {incidentDetail.timeline.map((item, index) => (
                            <li key={`${item.entry_type}-${item.occurred_at}-${index}`}>
                              <span>{item.entry_type}</span>
                              <strong>{item.summary}</strong>
                              <time>{formatTime(item.occurred_at)}</time>
                            </li>
                          ))}
                        </ol>
                        <h4>Investigation notes</h4>
                        {incidentDetail.notes.map((note) => (
                          <article className="note-card" key={note.id}>
                            <p>{note.body}</p>
                            <small>{note.author_email ?? "Former user"} · {formatTime(note.created_at)}</small>
                          </article>
                        ))}
                        {canInvestigate && (
                          <form className="note-form" onSubmit={addInvestigationNote}>
                            <label htmlFor="note-body">Add an investigation note</label>
                            <textarea
                              id="note-body"
                              maxLength={4000}
                              onChange={(event) => setNoteDraft(event.target.value)}
                              required
                              value={noteDraft}
                            />
                            <button className="primary-button" disabled={!noteDraft.trim()} type="submit">Save note</button>
                          </form>
                        )}
                      </section>
                    </div>
                  </>
                )}
              </Panel>
            )}

            <Panel id="events" title="Recent security events" subtitle="Normalized events from the selected account, region, and time filters">
              {dashboard.recent_events.length === 0 ? <Empty>No events in this time range.</Empty> : (
                <div className="table-scroll">
                  <table>
                    <thead><tr><th>Event</th><th>Source</th><th>Account / region</th><th>Identity / IP</th><th>Observed</th></tr></thead>
                    <tbody>
                      {dashboard.recent_events.map((event) => (
                        <tr key={event.id}>
                          <td><strong>{event.event_name}</strong>{event.is_synthetic && <span className="demo-tag">DEMO</span>}</td>
                          <td>{event.event_source}</td>
                          <td>{event.account_id}<br /><span className="subtle">{event.region}</span></td>
                          <td>{event.principal_arn ?? event.source_ip ?? "—"}</td>
                          <td>{formatTime(event.event_time)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>

            <div className="dashboard-grid lower-grid">
              <Panel title="Top source IPs" subtitle="From the latest matching alerts">
                <CountList items={dashboard.top_source_ips} empty="No source IPs in alert evidence." />
              </Panel>
              <Panel title="Most affected resources" subtitle="From the latest matching alerts">
                <CountList items={dashboard.top_resources} empty="No resource references in alert evidence." />
              </Panel>
              <Panel title="Active identities" subtitle="From the latest matching alerts">
                <CountList items={dashboard.top_identities} empty="No identity references in alert evidence." />
              </Panel>
            </div>
          </>
        )}
      </section>
    </main>
  );
}

function Metric({ label, value, tone = "" }: { label: string; value: number; tone?: string }) {
  return (
    <article className={`metric-card ${tone}`}>
      <span>{label}</span>
      <strong>{value.toLocaleString()}</strong>
      <small>Selected time range</small>
    </article>
  );
}

function Panel({
  children,
  id,
  title,
  subtitle,
}: {
  children: ReactNode;
  id?: string;
  title: string;
  subtitle: string;
}) {
  return (
    <section className="panel" id={id}>
      <header className="panel-heading"><div><h2>{title}</h2><p>{subtitle}</p></div></header>
      {children}
    </section>
  );
}

function CountList({ items, empty }: { items: Count[]; empty: string }) {
  if (items.length === 0) return <Empty>{empty}</Empty>;
  const max = Math.max(...items.map((item) => item.count), 1);
  return (
    <div className="count-list">
      {items.map((item) => (
        <div className="count-row" key={item.name}>
          <span title={item.name}>{item.name}</span>
          <div className="count-track"><div style={{ width: `${(item.count / max) * 100}%` }} /></div>
          <strong>{item.count}</strong>
        </div>
      ))}
    </div>
  );
}

function Empty({ children }: { children: ReactNode }) {
  return <div className="empty-state">{children}</div>;
}

function AuditFindingCard({ finding }: { finding: AuditFinding }) {
  const severity = finding.severity === "info" ? "informational" : finding.severity;
  return (
    <article className="audit-finding-card">
      <div className="audit-finding-heading">
        <SeverityPill severity={severity} />
        <span className={`finding-status status-${finding.status.toLowerCase()}`}>{finding.status.replaceAll("_", " ")}</span>
        <strong>{finding.control_id}: {finding.title}</strong>
      </div>
      <p>{finding.message}</p>
      <small>{finding.resource_id} · {finding.account_id} · {finding.region} · Observed {formatTime(finding.observed_at)}</small>
      {finding.suppression && (
        <p className="suppression-note">Suppressed until {finding.suppression.expires}: {finding.suppression.reason}</p>
      )}
      <details>
        <summary>Remediation, evidence, and limitations</summary>
        <p><strong>Remediation:</strong> {finding.remediation}</p>
        <pre>{JSON.stringify(finding.evidence, null, 2)}</pre>
        {finding.uncertainty.length > 0 && (
          <ul>{finding.uncertainty.map((item) => <li key={item}>{item}</li>)}</ul>
        )}
      </details>
    </article>
  );
}
