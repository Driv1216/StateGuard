import { type ReactNode, useEffect, useRef } from "react";

import type { ApplicabilityState, EvidenceTier, ResultState } from "../api/contracts";

export function PageHeader({ eyebrow, title, children, actions }: { eyebrow: string; title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <div className="page-intro">{children}</div>
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </header>
  );
}

export function Panel({ title, eyebrow, children, className = "" }: { title?: string; eyebrow?: string; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`.trim()}>
      {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
      {title ? <h2>{title}</h2> : null}
      {children}
    </section>
  );
}

export function StateMessage({ kind = "empty", title, children }: { kind?: "loading" | "empty" | "blocked" | "error"; title: string; children: ReactNode }) {
  return (
    <div className={`state-message state-${kind}`} role={kind === "error" ? "alert" : "status"}>
      <strong>{title}</strong>
      <span>{children}</span>
    </div>
  );
}

export function StatusBadge({ value }: { value: ResultState | ApplicabilityState | string }) {
  const tone =
    value === "VERIFIED_FAIL"
      ? "critical"
      : value === "VERIFIED_PASS"
        ? "positive"
        : value === "STATIC_WARNING"
          ? "warning"
          : value === "NEEDS_INPUT" || value === "INDETERMINATE"
            ? "attention"
            : "neutral";
  return <span className={`badge badge-${tone}`}>{value.replaceAll("_", " ")}</span>;
}

export function EvidenceBadge({ value }: { value: EvidenceTier | null }) {
  return <span className="badge badge-evidence">{value ? value.replaceAll("_", " ") : "NO EVIDENCE TIER"}</span>;
}

export function DefinitionList({ items }: { items: Array<[string, ReactNode]> }) {
  return (
    <dl className="definition-list">
      {items.map(([term, value]) => (
        <div key={term}>
          <dt>{term}</dt>
          <dd>{value ?? "Not recorded"}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Fingerprint({ value }: { value: string | null | undefined }) {
  return value ? <code className="fingerprint" title={value}>{value.slice(0, 12)}…</code> : <span>Not recorded</span>;
}

export function Dialog({ title, children, onClose }: { title: string; children: ReactNode; onClose(): void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog ref={ref} className="dialog" onCancel={onClose} onClick={(event) => {
      if (event.target === ref.current) onClose();
    }}>
      <div className="dialog-heading">
        <h2>{title}</h2>
        <button className="icon-button" onClick={onClose} aria-label="Close dialog">×</button>
      </div>
      {children}
    </dialog>
  );
}

export function Button({ children, variant = "secondary", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "quiet" }) {
  return <button className={`button button-${variant}`} {...props}>{children}</button>;
}

export function Field({ label, hint, error, children }: { label: string; hint?: string; error?: string; children: ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint ? <small>{hint}</small> : null}
      {error ? <small className="field-error">{error}</small> : null}
    </label>
  );
}

export function formatDate(value: string | null | undefined) {
  if (!value) return "Not recorded";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export function formatLocation(value: { path: string; line_start: number; column_start: number } | null | undefined) {
  return value ? `${value.path}:${value.line_start}:${value.column_start}` : "No source location";
}
