import { getDb } from "./index.js";
import { seed } from "./seed.js";

export async function initializeDatabase(): Promise<void> {
  const existing = getDb().prepare("SELECT COUNT(*) AS count FROM users").get() as { count: number };
  if (existing.count === 0) await seed();
}
