import type { FastifyReply, FastifyRequest } from "fastify";
import { vuln } from "../config.js";
import type { Role } from "../db/index.js";
import { logSecurityEvent } from "../security/events.js";
import { currentUser, type SessionUser } from "../auth/session.js";

const rank: Record<Role, number> = { customer: 1, analyst: 2, admin: 3 };

export function requireAuth(req: FastifyRequest, reply: FastifyReply): SessionUser | null {
  const user = currentUser(req);
  if (user) return user;
  if (req.url.startsWith("/api/")) reply.code(401).send({ error: "Não autenticado." });
  else reply.redirect("/login");
  return null;
}

export function requireRole(req: FastifyRequest, reply: FastifyReply, ...roles: Role[]): SessionUser | null {
  const user = requireAuth(req, reply);
  if (!user) return null;
  if (roles.includes(user.role)) return user;
  logSecurityEvent("authz_denied", "warn", { userId: user.id, ip: req.ip, details: { url: req.url, needed: roles } });
  reply.code(403).send({ error: "Acesso negado." });
  return null;
}

export function atLeast(user: SessionUser, role: Role): boolean {
  return rank[user.role] >= rank[role];
}

export function ownsOrPrivileged(req: FastifyRequest, user: SessionUser, ownerId: number, minRole: Role = "analyst"): boolean {
  if (vuln.IDOR) return true;
  if (user.id === ownerId || atLeast(user, minRole)) return true;
  logSecurityEvent("idor_blocked", "warn", { userId: user.id, ip: req.ip, details: { url: req.url, ownerId } });
  return false;
}
