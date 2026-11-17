"use client";

import { useEffect, useState } from "react";

type Health = {
  status: "healthy" | "unhealthy";
  database: "healthy" | "unavailable";
};

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export default function Home() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${apiBaseUrl}/api/v1/health`, { signal: controller.signal, cache: "no-store" })
      .then(async (response) => {
        const result = (await response.json()) as Health;
        if (!response.ok) throw new Error(result.database);
        setHealth(result);
      })
      .catch((cause: unknown) => {
        if (cause instanceof Error && cause.name === "AbortError") return;
        setError("Monitoring API is unavailable. Check that the backend is running.");
      });
    return () => controller.abort();
  }, []);

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">A</span> AWS Monitor</div>
        <div className="nav-label">WORKSPACE</div>
        <div className="nav-item active"><span>◈</span> Overview</div>
        <div className="nav-item muted"><span>◉</span> Incidents <small>Phase 4</small></div>
        <div className="nav-item muted"><span>⌁</span> Events <small>Phase 2</small></div>
        <div className="nav-item muted"><span>◇</span> Detections <small>Phase 3</small></div>
        <div className="sidebar-footer"><span className="status-dot" /> Foundation mode</div>
      </aside>
      <section className="content">
        <header className="topbar">
          <div><p className="eyebrow">SECURITY OPERATIONS</p><h1>Overview</h1></div>
          <div className="environment"><span className="status-dot" /> LOCAL ENVIRONMENT</div>
        </header>
        <div className="notice">
          <strong>Monitoring is not connected yet.</strong>
          <span>This foundation shows live service health only. No AWS accounts, events, or incidents are configured.</span>
        </div>
        <div className="section-heading"><div><h2>System health</h2><p>Live status from the monitoring API</p></div></div>
        <div className="cards">
          <article className="card">
            <div className="card-label">API SERVICE</div>
            <div className="card-value">{error ? "Unavailable" : health?.status ?? "Checking…"}</div>
            <div className={`card-foot ${error ? "danger" : health ? "good" : ""}`}>
              <span className="status-dot" />{error ? "Connection failed" : health ? "Responding normally" : "Contacting backend"}
            </div>
          </article>
          <article className="card">
            <div className="card-label">DATABASE</div>
            <div className="card-value">{health?.database ?? (error ? "Unknown" : "Checking…")}</div>
            <div className={`card-foot ${health?.database === "healthy" ? "good" : error ? "danger" : ""}`}>
              <span className="status-dot" />{health?.database === "healthy" ? "Connection verified" : error ? "No health response" : "Waiting for health check"}
            </div>
          </article>
          <article className="card">
            <div className="card-label">AWS CONNECTIONS</div>
            <div className="card-value">Not configured</div>
            <div className="card-foot"><span className="status-dot neutral" />AWS integration planned for Phase 5</div>
          </article>
        </div>
        {error && <p className="error-message" role="status">{error}</p>}
        <div className="section-heading lower"><div><h2>Milestone progress</h2><p>Capabilities appear as they are implemented</p></div></div>
        <div className="milestone">
          <div className="milestone-check">✓</div><div className="milestone-copy"><strong>Foundation</strong><span>API, database, authentication and service health</span></div><span className="tag complete">ACTIVE</span>
        </div>
        <div className="milestone">
          <div className="milestone-number">02</div><div className="milestone-copy"><strong>Event ingestion</strong><span>Durable CloudTrail event pipeline</span></div><span className="tag planned">PLANNED</span>
        </div>
      </section>
    </main>
  );
}
