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
  sessionSecret: process.env.SESSION_SECRET ?? "",
  masterKeyHex: process.env.MASTER_KEY_HEX ?? "",
  deepseekApiKey: process.env.DEEPSEEK_API_KEY ?? "",
  deepseekModel: process.env.DEEPSEEK_MODEL ?? "deepseek-flash",
  adminPassword: process.env.ADMIN_PASSWORD ?? "Admin#MaxPay2026",
  dbPath: process.env.DB_PATH ?? "data/maxpay.db",
  uploadDir: process.env.UPLOAD_DIR ?? "uploads",
  certDir: "certs",
  maxLoginFailures: 5,
  lockoutMinutes: 15,
  maxUploadBytes: 2 * 1024 * 1024,
};

export function validateSecrets(): void {
  if (config.sessionSecret.length < 32 || ["dev-secret-dev-secret-dev-secret-dev", "change-me-32-bytes-minimum-please-change-me"].includes(config.sessionSecret)) {
    throw new Error("Configure um SESSION_SECRET aleatório com npm run keys. Em banco existente, use npm run keys:rotate com o serviço parado.");
  }
  if (!/^[a-f0-9]{64}$/i.test(config.masterKeyHex)) throw new Error("Configure MASTER_KEY_HEX com 32 bytes aleatórios. Use npm run keys para instalação nova ou npm run keys:rotate para preservar um banco existente.");
}
