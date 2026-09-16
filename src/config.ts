import { readFileSync, existsSync } from "node:fs";

function loadDotEnv(): void {
  if (!existsSync(".env")) return;
  for (const line of readFileSync(".env", "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
}
loadDotEnv();

const vulnNames = [
  "WEAK_AUTH", "IDOR", "SQLI", "XSS", "UPLOAD", "EXPOSE",
  "SESSION", "NO_INTEGRITY", "LOGIC", "AI", "MISCONFIG",
] as const;
export type VulnName = (typeof vulnNames)[number];

export const vuln: Record<VulnName, boolean> = Object.fromEntries(
  vulnNames.map((n) => [n, process.env[`VULN_${n}`] === "1"]),
) as Record<VulnName, boolean>;

export function setVuln(name: VulnName, on: boolean): void {
  vuln[name] = on;
}

export const config = {
  port: Number(process.env.PORT ?? 8443),
  sessionSecret: process.env.SESSION_SECRET ?? "dev-secret-dev-secret-dev-secret-dev",
  masterKeyHex: process.env.MASTER_KEY_HEX ?? "",
  anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? "",
  anthropicModel: process.env.ANTHROPIC_MODEL ?? "claude-sonnet-5",
  adminPassword: process.env.ADMIN_PASSWORD ?? "Admin#MaxPay2026",
  dbPath: process.env.DB_PATH ?? "data/maxpay.db",
  uploadDir: process.env.UPLOAD_DIR ?? "uploads",
  certDir: "certs",
  maxLoginFailures: 5,
  lockoutMinutes: 15,
  maxUploadBytes: 2 * 1024 * 1024,
};
