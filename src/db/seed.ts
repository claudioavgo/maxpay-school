import { fakerPT_BR as faker } from "@faker-js/faker";
import { config } from "../config.js";
import { getDb } from "./index.js";
import { hashPassword } from "../auth/password.js";
import { encryptString } from "../crypto/symmetric.js";
import { cpfLookupHash } from "../crypto/hash.js";
import { recordTransaction } from "../accounts/service.js";
import { ensureSigningKeys } from "../crypto/keys.js";

const CATEGORIES = ["mercado", "transporte", "lazer", "contas", "saúde", "educação"];

function fakeCpf(): string {
  const n = Array.from({ length: 9 }, () => faker.number.int(9));
  const d = (arr: number[], w: number) => {
    const s = arr.reduce((acc, v, i) => acc + v * (w - i), 0) % 11;
    return s < 2 ? 0 : 11 - s;
  };
  const d1 = d(n, 10);
  const d2 = d([...n, d1], 11);
  return [...n, d1, d2].join("");
}

export interface SeedUser {
  email: string;
  password: string;
  role: "customer" | "analyst" | "admin";
  name: string;
}

export async function seed(): Promise<SeedUser[]> {
  faker.seed(42);
  const db = getDb();
  ensureSigningKeys();
  db.exec("DELETE FROM ai_messages; DELETE FROM security_events; DELETE FROM receipts; DELETE FROM transaction_reviews; DELETE FROM transactions; DELETE FROM accounts; DELETE FROM users;");

  const users: SeedUser[] = [
    { email: "admin@maxpay.local", password: config.adminPassword, role: "admin", name: "Administrador MaxPay" },
    { email: "analista@maxpay.local", password: "Analista#2026", role: "analyst", name: "Marina Analista" },
    { email: "alice@example.com", password: "Alice#Segura2026", role: "customer", name: "Alice Ferreira" },
    { email: "bruno@example.com", password: "Bruno#Segura2026", role: "customer", name: "Bruno Carvalho" },
    { email: "carla@example.com", password: "Carla#Segura2026", role: "customer", name: "Carla Nogueira" },
  ];
  const insertUser = db.prepare(
    "INSERT INTO users (email, name, password_hash, role, cpf_enc, cpf_hash, phone, birth_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  );
  const insertAccount = db.prepare("INSERT INTO accounts (owner_id, number, balance_cents) VALUES (?, ?, ?)");
  const accountIds: number[] = [];
  for (const [i, u] of users.entries()) {
    const cpf = fakeCpf();
    const r = insertUser.run(u.email, u.name, await hashPassword(u.password), u.role, encryptString(cpf), cpfLookupHash(cpf), faker.phone.number({ style: "national" }), faker.date.birthdate({ min: 20, max: 65, mode: "age" }).toISOString().slice(0, 10));
    if (u.role === "customer") {
      const a = insertAccount.run(r.lastInsertRowid, `MP-${String(1000 + i).padStart(6, "0")}`, 0);
      accountIds.push(Number(a.lastInsertRowid));
    }
  }
  for (const id of accountIds) {
    const deposit = faker.number.int({ min: 200_000, max: 800_000 });
    db.prepare("UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?").run(deposit, id);
    recordTransaction({ from: null, to: id, amountCents: deposit, description: "Depósito inicial", category: "depósito" });
    for (let k = 0; k < 8; k++) {
      const amount = faker.number.int({ min: 500, max: 40_000 });
      const to = accountIds[(accountIds.indexOf(id) + 1 + k) % accountIds.length];
      if (to === id) continue;
      db.prepare("UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?").run(amount, id);
      db.prepare("UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?").run(amount, to);
      recordTransaction({ from: id, to, amountCents: amount, description: faker.commerce.productName(), category: faker.helpers.arrayElement(CATEGORIES) });
    }
  }
  return users;
}

if (process.argv[1]?.endsWith("seed.ts")) {
  if (getDb().prepare("SELECT 1 FROM users LIMIT 1").get() && !process.argv.includes("--reset")) throw new Error("Banco já inicializado. Use npm run seed -- --reset somente para apagar e recriar os dados.");
  const users = await seed();
  console.log("Seed concluído. Usuários:");
  for (const u of users) console.log(`  ${u.role.padEnd(8)} ${u.email.padEnd(24)} ${u.password}`);
}
