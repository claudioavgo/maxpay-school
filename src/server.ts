import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { join } from "node:path";
import { buildApp } from "./app.js";
import { initializeDatabase } from "./db/initialize.js";
import { config, validateSecrets } from "./config.js";

function ensureTlsCert(): { key: Buffer; cert: Buffer } {
  mkdirSync(config.certDir, { recursive: true });
  const key = join(config.certDir, "tls-key.pem");
  const cert = join(config.certDir, "tls-cert.pem");
  if (!existsSync(key) || !existsSync(cert)) {
    execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout "${key}" -out "${cert}" -days 365 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"`, { stdio: "ignore" });
  }
  return { key: readFileSync(key), cert: readFileSync(cert) };
}

validateSecrets();
await initializeDatabase();
const isRender = process.env.RENDER === "true";
const app = await buildApp({
  logger: true,
  ...(isRender ? {} : { https: ensureTlsCert() }),
});

await app.listen({
  port: config.port,
  host: "0.0.0.0",
});

app.log.info(`MaxPay rodando na porta ${config.port}`);
