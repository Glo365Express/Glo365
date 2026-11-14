GLO 365 SUB-ADMIN SERVER
========================

This is a starter service only. It is NOT ready for production point transfers.
The Main Server still needs matching authenticated APIs and a durable
outbox/reconciliation process before any real point allocation is enabled.

RENDER ENVIRONMENT VARIABLES
----------------------------
DATABASE_URL          New Sub-Admin PostgreSQL Internal Database URL
JWT_SECRET            Unique random secret, at least 32 characters
MAIN_SERVER_API_KEY   Shared secret, at least 32 characters
FRONTEND_URL          Allowed dashboard origin(s), comma-separated
NODE_ENV              production

Do not put secrets in GitHub or send them in chat.

FILE: subadmin-server/package.json
----------------------------------
{
  "name": "glo365-subadmin-server",
  "version": "1.0.0",
  "private": true,
  "description": "GLO 365 Sub-Admin Service",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "engines": {
    "node": ">=20"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.4.7",
    "express": "^4.21.2",
    "helmet": "^8.0.0",
    "jsonwebtoken": "^9.0.2",
    "pg": "^8.13.1"
  }
}

FILE: subadmin-server/server.js
-------------------------------
"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET;
const MAIN_SERVER_API_KEY = process.env.MAIN_SERVER_API_KEY;

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters.");
if (!MAIN_SERVER_API_KEY || MAIN_SERVER_API_KEY.length < 32) throw new Error("MAIN_SERVER_API_KEY must be at least 32 characters.");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "1mb" }));

const origins = (process.env.FRONTEND_URL || "")
  .split(",").map(x => x.trim().replace(/\/+$/, "")).filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || origins.includes(origin.replace(/\/+$/, ""))) return callback(null, true);
    return callback(new Error("Origin not allowed."));
  },
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization", "X-Main-Server-Key"],
  methods: ["GET", "POST", "PATCH", "OPTIONS"]
}));

function fail(res, status, message) {
  return res.status(status).json({ success: false, message });
}
function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}
function text(value, max = 255) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
function validUsername(value) {
  return /^[a-z0-9_]{3,30}$/.test(value);
}
function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}
function validAmount(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 && n <= 10000000 &&
    Math.round(n * 100) === n * 100;
}
function authenticate(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return fail(res, 401, "Authentication required.");
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: "glo365-subadmin" });
    if (!payload.id || payload.role !== "subadmin") return fail(res, 401, "Invalid session.");
    req.auth = payload;
    next();
  } catch {
    return fail(res, 401, "Invalid or expired session.");
  }
}
function requireMainServer(req, res, next) {
  const supplied = req.headers["x-main-server-key"];
  if (typeof supplied !== "string") return fail(res, 401, "Main Server authentication required.");
  const a = Buffer.from(supplied);
  const b = Buffer.from(MAIN_SERVER_API_KEY);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return fail(res, 401, "Invalid Main Server credentials.");
  }
  next();
}
const requireActive = asyncRoute(async (req, res, next) => {
  const r = await pool.query("SELECT id,status FROM subadmins WHERE id=$1", [req.auth.id]);
  if (!r.rows.length) return fail(res, 401, "Sub-Admin not found.");
  if (r.rows[0].status !== "active") return fail(res, 403, "Sub-Admin suspended.");
  next();
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS subadmins (
      id BIGSERIAL PRIMARY KEY,
      main_server_id VARCHAR(120) UNIQUE NOT NULL,
      username VARCHAR(30) UNIQUE NOT NULL,
      email VARCHAR(255),
      password_hash TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','suspended')),
      balance NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (balance >= 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS subadmin_users (
      id BIGSERIAL PRIMARY KEY,
      subadmin_id BIGINT NOT NULL REFERENCES subadmins(id),
      username VARCHAR(30) NOT NULL,
      email VARCHAR(255),
      password_hash TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active','suspended')),
      balance NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (balance >= 0),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(subadmin_id, username),
      UNIQUE(subadmin_id, email)
    );
    CREATE TABLE IF NOT EXISTS subadmin_wallet_transactions (
      id BIGSERIAL PRIMARY KEY,
      subadmin_id BIGINT NOT NULL REFERENCES subadmins(id),
      type VARCHAR(40) NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      reference VARCHAR(150) UNIQUE NOT NULL,
      description TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS main_server_transfers (
      id BIGSERIAL PRIMARY KEY,
      transfer_id VARCHAR(150) UNIQUE NOT NULL,
      subadmin_id BIGINT NOT NULL REFERENCES subadmins(id),
      amount NUMERIC(14,2) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS subadmin_payment_methods (
      id BIGSERIAL PRIMARY KEY,
      subadmin_id BIGINT NOT NULL REFERENCES subadmins(id),
      name VARCHAR(80) NOT NULL,
      label VARCHAR(100),
      account VARCHAR(180) NOT NULL,
      currency VARCHAR(10) NOT NULL DEFAULT 'BDT',
      instructions TEXT,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_subadmin_users_owner ON subadmin_users(subadmin_id);
    CREATE INDEX IF NOT EXISTS idx_subadmin_wallet_owner ON subadmin_wallet_transactions(subadmin_id);
  `);
}

app.get("/health", asyncRoute(async (req, res) => {
  await pool.query("SELECT 1");
  res.json({ success: true, service: "GLO 365 Sub-Admin Server", database: "connected" });
}));

// Main Server creates/updates a Sub-Admin identity.
// It must call this endpoint over HTTPS with X-Main-Server-Key.
app.post("/internal/subadmins", requireMainServer, asyncRoute(async (req, res) => {
  const mainId = text(req.body.main_server_id, 120);
  const username = text(req.body.username, 30).toLowerCase();
  const email = text(req.body.email, 255).toLowerCase();
  const password = req.body.password;
  if (!mainId || !validUsername(username) || (email && !validEmail(email)) ||
      typeof password !== "string" || password.length < 10 || password.length > 200) {
    return fail(res, 400, "Invalid Sub-Admin details.");
  }
  const hash = await bcrypt.hash(password, 12);
  const r = await pool.query(`
    INSERT INTO subadmins(main_server_id,username,email,password_hash)
    VALUES($1,$2,$3,$4)
    ON CONFLICT(main_server_id) DO UPDATE SET
      username=EXCLUDED.username,email=EXCLUDED.email,
      password_hash=EXCLUDED.password_hash,updated_at=NOW()
    RETURNING id,main_server_id,username,email,status,balance,created_at
  `, [mainId, username, email || null, hash]);
  res.status(201).json({ success: true, subadmin: r.rows[0] });
}));

// Main Server credits one transfer reference once.
// Main Server must maintain its own outbox and reconciliation before use.
app.post("/internal/points/credit", requireMainServer, asyncRoute(async (req, res) => {
  const transferId = text(req.body.transfer_id, 150);
  const mainId = text(req.body.main_server_id, 120);
  const amount = Number(req.body.amount);
  if (!transferId || !mainId || !validAmount(amount)) return fail(res, 400, "Invalid transfer.");

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const old = await c.query("SELECT transfer_id,amount FROM main_server_transfers WHERE transfer_id=$1", [transferId]);
    if (old.rows.length) {
      if (Number(old.rows[0].amount) !== amount) {
        await c.query("ROLLBACK");
        return fail(res, 409, "Transfer reference reused with a different amount.");
      }
      await c.query("COMMIT");
      return res.json({ success: true, duplicate: true, transfer_id: transferId });
    }
    const s = await c.query("SELECT id,status FROM subadmins WHERE main_server_id=$1 FOR UPDATE", [mainId]);
    if (!s.rows.length) {
      await c.query("ROLLBACK");
      return fail(res, 404, "Sub-Admin not found.");
    }
    if (s.rows[0].status !== "active") {
      await c.query("ROLLBACK");
      return fail(res, 403, "Sub-Admin suspended.");
    }
    const sid = s.rows[0].id;
    await c.query("UPDATE subadmins SET balance=balance+$1,updated_at=NOW() WHERE id=$2", [amount.toFixed(2), sid]);
    await c.query("INSERT INTO main_server_transfers(transfer_id,subadmin_id,amount) VALUES($1,$2,$3)", [transferId, sid, amount.toFixed(2)]);
    await c.query(
      "INSERT INTO subadmin_wallet_transactions(subadmin_id,type,amount,reference,description) VALUES($1,'main_allocation',$2,$3,$4)",
      [sid, amount.toFixed(2), "MAIN-" + transferId, "Points allocated by Main Admin"]
    );
    const balance = await c.query("SELECT balance FROM subadmins WHERE id=$1", [sid]);
    await c.query("COMMIT");
    res.json({ success: true, duplicate: false, credited: amount, balance: balance.rows[0].balance });
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}));

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const username = text(req.body.username, 30).toLowerCase();
  const password = req.body.password;
  if (!username || typeof password !== "string") return fail(res, 400, "Username and password required.");
  const r = await pool.query("SELECT * FROM subadmins WHERE username=$1", [username]);
  if (!r.rows.length || !(await bcrypt.compare(password, r.rows[0].password_hash))) {
    return fail(res, 401, "Invalid username or password.");
  }
  const u = r.rows[0];
  if (u.status !== "active") return fail(res, 403, "Sub-Admin suspended.");
  const token = jwt.sign({ id: u.id, role: "subadmin" }, JWT_SECRET, {
    expiresIn: "7d", issuer: "glo365-subadmin"
  });
  res.json({
    success: true, token,
    user: { id: u.id, username: u.username, email: u.email, role: "subadmin", balance: u.balance }
  });
}));

app.get("/api/auth/me", authenticate, requireActive, asyncRoute(async (req, res) => {
  const r = await pool.query(
    "SELECT id,username,email,status,balance,created_at FROM subadmins WHERE id=$1",
    [req.auth.id]
  );
  res.json({ success: true, user: { ...r.rows[0], role: "subadmin" } });
}));

app.get("/api/wallet", authenticate, requireActive, asyncRoute(async (req, res) => {
  const r = await pool.query("SELECT balance FROM subadmins WHERE id=$1", [req.auth.id]);
  res.json({ success: true, currency: "DEMO", is_demo: true, balance: r.rows[0].balance });
}));

app.get("/api/wallet/transactions", authenticate, requireActive, asyncRoute(async (req, res) => {
  const r = await pool.query(
    "SELECT id,type,amount,reference,description,created_at FROM subadmin_wallet_transactions WHERE subadmin_id=$1 ORDER BY created_at DESC LIMIT 100",
    [req.auth.id]
  );
  res.json({ success: true, transactions: r.rows });
}));

app.get("/api/users", authenticate, requireActive, asyncRoute(async (req, res) => {
  const r = await pool.query(
    "SELECT id,username,email,status,balance,created_at FROM subadmin_users WHERE subadmin_id=$1 ORDER BY created_at DESC LIMIT 500",
    [req.auth.id]
  );
  res.json({ success: true, users: r.rows });
}));

app.post("/api/users", authenticate, requireActive, asyncRoute(async (req, res) => {
  const username = text(req.body.username, 30).toLowerCase();
  const email = text(req.body.email, 255).toLowerCase();
  const password = req.body.password;
  if (!validUsername(username) || (email && !validEmail(email)) ||
      typeof password !== "string" || password.length < 10 || password.length > 200) {
    return fail(res, 400, "Invalid user details.");
  }
  const hash = await bcrypt.hash(password, 12);
  const r = await pool.query(
    "INSERT INTO subadmin_users(subadmin_id,username,email,password_hash) VALUES($1,$2,$3,$4) RETURNING id,username,email,status,balance,created_at",
    [req.auth.id, username, email || null, hash]
  );
  res.status(201).json({ success: true, user: r.rows[0] });
}));

app.post("/api/users/:id/points", authenticate, requireActive, asyncRoute(async (req, res) => {
  const userId = Number(req.params.id);
  const amount = Number(req.body.amount);
  const ref = text(req.body.reference, 120);
  if (!Number.isSafeInteger(userId) || userId < 1 || !validAmount(amount) ||
      !/^[a-zA-Z0-9_-]{6,120}$/.test(ref)) return fail(res, 400, "Invalid distribution request.");

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const reference = "DIST-" + ref;
    const dup = await c.query("SELECT id FROM subadmin_wallet_transactions WHERE reference=$1", [reference]);
    if (dup.rows.length) {
      await c.query("ROLLBACK");
      return fail(res, 409, "Reference already used.");
    }
    const owner = await c.query("SELECT balance FROM subadmins WHERE id=$1 FOR UPDATE", [req.auth.id]);
    const user = await c.query("SELECT id FROM subadmin_users WHERE id=$1 AND subadmin_id=$2 FOR UPDATE", [userId, req.auth.id]);
    if (!user.rows.length) {
      await c.query("ROLLBACK");
      return fail(res, 404, "User not found under this Sub-Admin.");
    }
    if (Number(owner.rows[0].balance) < amount) {
      await c.query("ROLLBACK");
      return fail(res, 400, "Insufficient points.");
    }
    await c.query("UPDATE subadmins SET balance=balance-$1,updated_at=NOW() WHERE id=$2", [amount.toFixed(2), req.auth.id]);
    await c.query("UPDATE subadmin_users SET balance=balance+$1,updated_at=NOW() WHERE id=$2 AND subadmin_id=$3", [amount.toFixed(2), userId, req.auth.id]);
    await c.query(
      "INSERT INTO subadmin_wallet_transactions(subadmin_id,type,amount,reference,description) VALUES($1,'user_distribution',$2,$3,$4)",
      [req.auth.id, (-amount).toFixed(2), reference, "Points distributed to own user"]
    );
    await c.query("COMMIT");
    const b = await pool.query("SELECT balance FROM subadmins WHERE id=$1", [req.auth.id]);
    res.json({ success: true, distributed: amount, subadmin_balance: b.rows[0].balance });
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}));

app.get("/api/payment-methods", authenticate, requireActive, asyncRoute(async (req, res) => {
  const r = await pool.query(
    "SELECT id,name,label,account,currency,instructions,active FROM subadmin_payment_methods WHERE subadmin_id=$1 ORDER BY id DESC",
    [req.auth.id]
  );
  res.json({ success: true, methods: r.rows });
}));

app.post("/api/payment-methods", authenticate, requireActive, asyncRoute(async (req, res) => {
  const name = text(req.body.name, 80);
  const label = text(req.body.label, 100);
  const account = text(req.body.account, 180);
  const currency = text(req.body.currency || "BDT", 10).toUpperCase();
  const instructions = text(req.body.instructions, 1000);
  if (!name || !account || !/^[A-Z0-9]{2,10}$/.test(currency)) return fail(res, 400, "Invalid payment method.");
  const r = await pool.query(
    "INSERT INTO subadmin_payment_methods(subadmin_id,name,label,account,currency,instructions) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,label,account,currency,instructions,active",
    [req.auth.id, name, label, account, currency, instructions]
  );
  res.status(201).json({ success: true, method: r.rows[0] });
}));

app.patch("/api/payment-methods/:id/status", authenticate, requireActive, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1 || typeof req.body.active !== "boolean") {
    return fail(res, 400, "Invalid payment method status.");
  }
  const r = await pool.query(
    "UPDATE subadmin_payment_methods SET active=$1 WHERE id=$2 AND subadmin_id=$3 RETURNING id,name,label,account,currency,instructions,active",
    [req.body.active, id, req.auth.id]
  );
  if (!r.rows.length) return fail(res, 404, "Payment method not found.");
  res.json({ success: true, method: r.rows[0] });
}));

app.use((req, res) => fail(res, 404, "API endpoint not found."));
app.use((err, req, res, next) => {
  console.error("Sub-Admin API error:", err.message);
  if (err.type === "entity.parse.failed") return fail(res, 400, "Invalid JSON.");
  if (err.message === "Origin not allowed.") return fail(res, 403, "Origin not allowed.");
  if (err.code === "23505") return fail(res, 409, "Record already exists.");
  return fail(res, 500, "Internal server error.");
});

async function start() {
  await initDb();
  await pool.query("SELECT 1");
  app.listen(PORT, "0.0.0.0", () => {
    console.log("GLO 365 Sub-Admin Server listening on " + PORT);
  });
}
start().catch(error => {
  console.error("Startup failed:", error.message);
  process.exit(1);
});

NOT YET IMPLEMENTED
-------------------
- Sub-Admin user registration/login and unique invite links
- Deposit submission and approval/rejection
- Withdrawal submission and approval/rejection
- Support conversation APIs
- Main Admin Dashboard integration
- Main Server balance debit + durable transfer outbox/reconciliation
- End-to-end security, rate limiting, audit logs, automated tests

Do not deploy for live use or process real transactions until these are implemented
and tested against the existing Main Server. This starter does not modify the
existing Main Server database or its users.
