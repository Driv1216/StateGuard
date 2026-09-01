import { NavLink, Outlet } from "react-router-dom";

import { useDashboardState } from "./state";

const nav = [
  ["/", "Overview", "01"],
  ["/graph", "Safety Graph", "02"],
  ["/failure-lab", "Failure Lab", "03"],
  ["/findings", "Findings", "04"],
  ["/setup", "Project Setup", "05"],
] as const;

export function Shell() {
  const state = useDashboardState();
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">SG</span>
          <div><strong>StateGuard</strong><span>Payment reliability</span></div>
        </div>
        <nav aria-label="Primary navigation">
          {nav.map(([to, label, number]) => (
            <NavLink key={to} to={to} end={to === "/"}>
              <span aria-hidden="true">{number}</span>{label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className="connection-dot" aria-hidden="true" />
          <div><strong>Local control</strong><span>Same-origin /api/v1</span></div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div className="project-crumb">
            <span>Project</span>
            <strong>{state.project?.project_id ?? "Loading…"}</strong>
          </div>
          {state.verificationPending ? (
            <div className="verification-indicator" role="status">
              <span aria-hidden="true" /> Verification running
            </div>
          ) : state.busyAction ? (
            <div className="busy-indicator" role="status">{state.busyAction}</div>
          ) : (
            <div className="ready-indicator">Dashboard ready</div>
          )}
        </header>
        <main id="main-content" tabIndex={-1}>
          {state.startupError ? <div className="global-error" role="alert">{state.startupError}</div> : null}
          {state.actionError ? <div className="global-error" role="alert">{state.actionError}</div> : null}
          <Outlet />
        </main>
      </div>
      <div className="sr-only" aria-live="polite" aria-atomic="true">{state.announcement}</div>
    </div>
  );
}
