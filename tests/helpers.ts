import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { config, setVuln, vuln, type VulnName } from "../src/config.js";
import { resetDbForTests } from "../src/db/index.js";
import { seed } from "../src/db/seed.js";
import { buildApp } from "../src/app.js";

export const ALICE = { email: "alice@example.com", password: "Alice#Segura2026" };
export const BRUNO = { email: "bruno@example.com", password: "Bruno#Segura2026" };
export const ADMIN = { email: "admin@maxpay.local", password: "Admin#MaxPay2026" };

export async function freshApp(flags: Partial<Record<VulnName, boolean>> = {}): Promise<FastifyInstance> {
  for (const k of Object.keys(vuln) as VulnName[]) setVuln(k, flags[k] ?? false);
  config.deepseekApiKey = "";
  config.sessionSecret = randomBytes(32).toString("hex");
  config.masterKeyHex = randomBytes(32).toString("hex");
  const dir = mkdtempSync(join(tmpdir(), "maxpay-"));
  config.uploadDir = join(dir, "uploads");
  config.certDir = join(dir, "certs");
  resetDbForTests(join(dir, "test.db"));
  await seed();
  return buildApp();
}

export async function loginAs(app: FastifyInstance, creds: { email: string; password: string }): Promise<string> {
  const res = await app.inject({ method: "POST", url: "/api/login", payload: creds });
  if (res.statusCode !== 200) throw new Error(`login failed: ${res.body}`);
  return res.headers["set-cookie"]!.toString().split(";")[0];
}

export function multipart(name: string, mime: string, data: Buffer, boundary = "XBOUNDARYX"): { payload: Buffer; headers: Record<string, string> } {
  const head = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${name}"\r\nContent-Type: ${mime}\r\n\r\n`);
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
  return { payload: Buffer.concat([head, data, tail]), headers: { "content-type": `multipart/form-data; boundary=${boundary}` } };
}
