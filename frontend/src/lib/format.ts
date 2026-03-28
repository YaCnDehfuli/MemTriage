import type { Risk } from "../types";

export function bytes(n: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
}

export const pct = (x: number | null | undefined) =>
  x == null ? "—" : `${(x * 100).toFixed(1)}%`;

export const RISK_ORDER: Risk[] = ["Critical", "High", "Medium", "Low"];

export function riskColor(risk: Risk | null | undefined): string {
  switch (risk) {
    case "Critical":
      return "risk-critical";
    case "High":
      return "risk-high";
    case "Medium":
      return "risk-medium";
    case "Low":
      return "risk-low";
    default:
      return "risk-none";
  }
}
