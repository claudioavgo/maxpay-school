import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { config } from "../config.js";

export type Role = "customer" | "analyst" | "admin";

export interface UserRow {
  id: number;
  email: string;
  name: string;
  password_hash: string;
  role: Role;
  cpf_enc: string;
  cpf_hash: string;
  phone: string;
  birth_date: string;
  mfa_secret: string | null;
  failed_logins: number;
  locked_until: string | null;
  created_at: string;
}

export interface AccountRow {
  id: number;
  owner_id: number;
  number: string;
  balance_cents: number;
}

export interface TransactionRow {
  id: number;
  from_account_id: number | null;
  to_account_id: number | null;
  amount_cents: number;
  description: string;
  category: string | null;
  status: "completed" | "flagged" | "reversed";
  prev_hash: string;
  hash: string;
  signature: string;
  created_at: string;
}

export interface ReceiptRow {
  id: number;
  owner_id: number;
  transaction_id: number | null;
  original_name: string;
  stored_name: string;
  mime: string;
  size: number;
  sha256: string;
  iv: string;
  auth_tag: string;
  key_id: string;
  signature: string;
  created_at: string;
}

let db: Database.Database | null = null;

export function getDb(): Database.Database {
  if (db) return db;
  mkdirSync(dirname(config.dbPath), { recursive: true });
  db = new Database(config.dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migrate(db);
  return db;
}

export function resetDbForTests(path: string): Database.Database {
  db?.close();
  config.dbPath = path;
  db = null;
  return getDb();
}

function migrate(d: Database.Database): void {
  d.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('customer','analyst','admin')),
      cpf_enc TEXT NOT NULL,
      cpf_hash TEXT NOT NULL UNIQUE,
      phone TEXT NOT NULL,
      birth_date TEXT NOT NULL,
      mfa_secret TEXT,
      failed_logins INTEGER NOT NULL DEFAULT 0,
      locked_until TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      number TEXT NOT NULL UNIQUE,
      balance_cents INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_account_id INTEGER REFERENCES accounts(id),
      to_account_id INTEGER REFERENCES accounts(id),
      amount_cents INTEGER NOT NULL,
      description TEXT NOT NULL DEFAULT '',
      category TEXT,
      status TEXT NOT NULL DEFAULT 'completed',
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL,
      signature TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      transaction_id INTEGER REFERENCES transactions(id),
      original_name TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      mime TEXT NOT NULL,
      size INTEGER NOT NULL,
      sha256 TEXT NOT NULL,
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      key_id TEXT NOT NULL,
      signature TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS security_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      severity TEXT NOT NULL,
      user_id INTEGER,
      ip TEXT,
      details TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS ai_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      question TEXT NOT NULL,
      answer TEXT NOT NULL,
      injection_detected INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}
