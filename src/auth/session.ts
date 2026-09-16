import type { FastifyReply, FastifyRequest } from "fastify";
import { vuln } from "../config.js";
import { getDb, type Role, type UserRow } from "../db/index.js";

export interface SessionUser {
  id: number;
  email: string;
  name: string;
  role: Role;
}

declare module "@fastify/secure-session" {
  interface SessionData {
    user: SessionUser;
    csrf: string;
    lastSeen: number;
  }
}

export const IDLE_TIMEOUT_MS = 15 * 60_000;

export function establishSession(req: FastifyRequest, user: UserRow): void {
  if (!vuln.SESSION) req.session.regenerate();
  req.session.set("user", { id: user.id, email: user.email, name: user.name, role: user.role });
  req.session.set("lastSeen", Date.now());
}

export function currentUser(req: FastifyRequest): SessionUser | null {
  const user = req.session.get("user");
  if (!user) return null;
  if (!vuln.SESSION) {
    const lastSeen = req.session.get("lastSeen") ?? 0;
    if (Date.now() - lastSeen > IDLE_TIMEOUT_MS) {
      req.session.delete();
      return null;
    }
    req.session.set("lastSeen", Date.now());
  }
  return user;
}

export function loadUser(id: number): UserRow | undefined {
  return getDb().prepare("SELECT * FROM users WHERE id = ?").get(id) as UserRow | undefined;
}

export function destroySession(req: FastifyRequest, reply: FastifyReply): void {
  req.session.delete();
  reply.clearCookie("maxpay_session");
}
