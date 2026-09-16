import Fastify from "fastify";
import fastifySecureSession from "@fastify/secure-session";
import fastifyView from "@fastify/view";
import fastifyFormbody from "@fastify/formbody";
import fastifyMultipart from "@fastify/multipart";
import fastifyHelmet from "@fastify/helmet";
import fastifyRateLimit from "@fastify/rate-limit";
import ejs from "ejs";
import { createHash } from "node:crypto";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { config, vuln } from "./config.js";
import { getDb } from "./db/index.js";
import { ensureSigningKeys } from "./crypto/keys.js";
import { apiRoutes } from "./routes/api.js";
import { pageRoutes } from "./routes/pages.js";

const here = dirname(fileURLToPath(import.meta.url));

export async function buildApp(opts: { logger?: boolean; https?: { key: Buffer; cert: Buffer } } = {}) {
  getDb();
  ensureSigningKeys();
  const app = Fastify({ logger: opts.logger ?? false, trustProxy: false, bodyLimit: config.maxUploadBytes + 64 * 1024, ...(opts.https ? { https: opts.https } : {}) });

  if (!vuln.MISCONFIG) {
    await app.register(fastifyHelmet, {
      contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", "data:"] } },
      hsts: { maxAge: 31536000 },
    });
  }
  await app.register(fastifyRateLimit, { max: 300, timeWindow: "1 minute" });
  await app.register(fastifyFormbody);
  await app.register(fastifyMultipart, { limits: { fileSize: vuln.UPLOAD ? 50 * 1024 * 1024 : config.maxUploadBytes, files: 1 } });
  await app.register(fastifySecureSession, {
    key: createHash("sha256").update(config.sessionSecret).digest(),
    cookieName: "maxpay_session",
    cookie: vuln.SESSION
      ? { path: "/", httpOnly: false, secure: false, sameSite: "none" }
      : { path: "/", httpOnly: true, secure: true, sameSite: "strict", maxAge: 60 * 60 },
  });
  await app.register(fastifyView, {
    engine: { ejs },
    root: join(here, "views"),
    defaultContext: { vuln, escapeOff: () => vuln.XSS },
  });

  app.setErrorHandler((err: Error & { statusCode?: number }, req, reply) => {
    req.log.error(err);
    const status = err.statusCode ?? 500;
    if (vuln.MISCONFIG) return reply.code(status).send({ error: err.message, stack: err.stack });
    return reply.code(status).send({ error: status >= 500 ? "Erro interno." : err.message });
  });

  await app.register(apiRoutes);
  await app.register(pageRoutes);
  return app;
}
