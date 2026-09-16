import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { config, validateSecrets } from "../config.js";
import { ensureSigningKeys } from "./keys.js";

try {
  validateSecrets();
} catch {
  if (existsSync(config.dbPath)) throw new Error("Banco existente: pare o serviço e execute npm run keys:rotate para preservar os dados.");
  const env = existsSync(".env") ? readFileSync(".env", "utf8") : readFileSync(".env.example", "utf8");
  const lines = env.split("\n").filter(line => !/^\s*(SESSION_SECRET|MASTER_KEY_HEX)\s*=/.test(line));
  config.sessionSecret = randomBytes(32).toString("hex");
  config.masterKeyHex = randomBytes(32).toString("hex");
  writeFileSync(".env", lines.join("\n").trimEnd() + `\nSESSION_SECRET=${config.sessionSecret}\nMASTER_KEY_HEX=${config.masterKeyHex}\n`, { mode: 0o600 });
  chmodSync(".env", 0o600);
}
ensureSigningKeys();
console.log("Chaves prontas. Segredos mantidos na configuração local, sem exibição no terminal.");
