import type { ReactNode } from "react";

export function Badge({ confidence }: { confidence: string }) {
  return <span className={`badge ${confidence}`}>{confidence}</span>;
}

export function ErrorBox({ children }: { children: ReactNode }) {
  if (!children) return null;
  return <div className="error">{children}</div>;
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return <div className="muted">{label}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MiB`;
}

export function timestamp(value: string | null): string {
  if (!value) return "—";
  return value.replace("T", " ").replace(/\.\d+Z$/, "Z");
}
