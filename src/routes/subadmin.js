"use strict";

/*
 * GLO 365 — Shared Sub-Admin Service
 * Separate Render Web Service + separate PostgreSQL database.
 *
 * IMPORTANT INTEGRATION BOUNDARY:
 * - This service owns Sub-Admin accounts, their customers, local point
 *   distribution, payment methods, deposit/withdrawal requests and support.
 * - Main Server must call the protected /internal endpoints.
 * - Main Server must debit its own balance using a durable outbox and retry
 *   the same transfer_id until /internal/points/credit confirms it.
 * - Do NOT enable point allocation until that Main Server outbox/debit
 *   integration is implemented and tested. Cross-database transactions
 *   cannot be made atomic by this service alone.
 * - Existing Main Server users/database are never modified here.
 */

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET || "";
const MAIN_SERVER_API_KEY = process.env.MAIN_SERVER_API_KEY || "";

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
if (JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters.");
if (MAIN_SERVER_API_KEY.length < 32) throw new Error("MAIN_SERVER_API_KEY must be at least 32 characters.");

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

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",").map(v => v.trim().replace(/\/+$/, "")).filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin || allowedOrigins.includes(origin.replace(/\/+$/, ""))) return cb(null, true);
    return cb(new Error("Origin not allowed"));
  },
  credentials: true,
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Main-Server-Key"]
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { success: false, message: "Too many login attempts. Try again later." }
});

function fail(res, status, message) {
  return res.status(status).json({ success: false, message });
}
function asyncRoute(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}
function clean(v, max = 255) {
  return typeof v === "string" ? v.trim().slice(0, max) : "";
}
function validUsername(v) {
  return /^[a-z0-9_]{3,30}$/.test(v);
}
function validEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}
function validAmount(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 && n <= 10000000 &&
    Math.round(n * 100) === n * 100;
}
function newRef(prefix) {
  return prefix + "-" + crypto.randomUUID();
}
function requireMainServer(req, res, next) {
  const supplied = req.get("X-Main-Server-Key") || "";
  const a = Buffer.from(supplied);
  const b = Buffer.from(MAIN_SERVER_API_KEY);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return fail(res, 401, "Main Server authentication failed.");
  }
  next();
}
function authenticate(req, res, next) {
  const header = req.get("Authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return fail(res, 401, "Authentication required.");
  try {
    const p = jwt.verify(token, JWT_SECRET, { issuer: "glo365-subadmin" });
    if (!p.id || !["subadmin", "customer"].includes(p.role)) {
      return fail(res, 401, "Invalid session.");
    }
    req.auth = p;
    next();
  } catch {
    return fail(res, 401, "Invalid or expired session.");
  }
}
function onlySubAdmin(req, res, next) {
  if (req.auth.role !== "subadmin") return fail(res, 403, "Sub-Admin access required.");
  next();
}
function onlyCustomer(req, res, next) {
  if (req.auth.role !== "customer") return fail(res, 403, "Customer access required.");
  next();
}
const activeAccount = asyncRoute(async (req, res, next) => {
  const table = req.auth.role === "subadmin" ? "subadmins" : "subadmin_users";
  const q = table === "subadmins"
    ? "SELECT status FROM subadmins WHERE id=$1"
    : "SELECT status FROM subadmin_users WHERE id=$1";
  const r = await pool.query(q, [req.auth.id]);
  if (!r.rows.length) return fail(res, 401, "Account not found.");
  if (r.rows[0].status !== "active") return fail(res, 403, "Account suspended.");
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
      invite_code VARCHAR(40) UNIQUE NOT NULL,
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
      reference VARCHAR(160) UNIQUE NOT NULL,
      description TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS subadmin_user_transactions (
      id BIGSERIAL PRIMARY KEY,
      subadmin_id BIGINT NOT NULL REFERENCES subadmins(id),
      user_id BIGINT NOT NULL REFERENCES subadmin_users(id),
      type VARCHAR(40) NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      reference VARCHAR(160) UNIQUE NOT NULL,
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

    CREATE TABLE IF NOT EXISTS subadmin_deposits (
      id BIGSERIAL PRIMARY KEY,
      subadmin_id BIGINT NOT NULL REFERENCES subadmins(id),
      user_id BIGINT NOT NULL REFERENCES subadmin_users(id),
      payment_method_id BIGINT REFERENCES subadmin_payment_methods(id),
      amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
      transaction_ref VARCHAR(160) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected')),
      admin_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      UNIQUE(subadmin_id, transaction_ref)
    );

    CREATE TABLE IF NOT EXISTS subadmin_withdrawals (
      id BIGSERIAL PRIMARY KEY,
      subadmin_id BIGINT NOT NULL REFERENCES subadmins(id),
      user_id BIGINT NOT NULL REFERENCES subadmin_users(id),
      amount NUMERIC(14,2) NOT NULL CHECK (amount > 0),
      payout_method VARCHAR(80) NOT NULL,
      payout_account VARCHAR(180) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','approved','rejected','paid')),
      admin_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      paid_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS subadmin_support_conversations (
      id BIGSERIAL PRIMARY KEY,
      subadmin_id BIGINT NOT NULL REFERENCES subadmins(id),
      user_id BIGINT NOT NULL REFERENCES subadmin_users(id),
      status VARCHAR(20) NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','closed')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS subadmin_support_messages (
      id BIGSERIAL PRIMARY KEY,
      conversation_id BIGINT NOT NULL REFERENCES subadmin_support_conversations(id) ON DELETE CASCADE,
      sender_role VARCHAR(20) NOT NULL CHECK (sender_role IN ('customer','subadmin')),
      sender_id BIGINT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    DO $$
    DECLARE c RECORD;
    BEGIN
      FOR c IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'subadmin_withdrawals'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) ILIKE '%status%'
      LOOP
        EXECUTE format('ALTER TABLE subadmin_withdrawals DROP CONSTRAINT %I', c.conname);
      END LOOP;
      ALTER TABLE subadmin_withdrawals
        ADD CONSTRAINT subadmin_withdrawals_status_check
        CHECK (status IN ('pending','approved','rejected','paid'));
      ALTER TABLE subadmin_withdrawals
        ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ;
    END $$;

    CREATE INDEX IF NOT EXISTS idx_su_owner ON subadmin_users(subadmin_id);
    CREATE INDEX IF NOT EXISTS idx_sut_owner ON subadmin_user_transactions(subadmin_id,user_id);
    CREATE INDEX IF NOT EXISTS idx_sd_owner ON subadmin_deposits(subadmin_id,status);
    CREATE INDEX IF NOT EXISTS idx_sw_owner ON subadmin_withdrawals(subadmin_id,status);
    CREATE INDEX IF NOT EXISTS idx_ss_owner ON subadmin_support_conversations(subadmin_id,user_id);
  `);
}

app.get("/health", asyncRoute(async (req, res) => {
  await pool.query("SELECT 1");
  res.json({ success: true, service: "GLO 365 Sub-Admin Server", database: "connected" });
}));

/* MAIN SERVER INTERNAL API
 * Main Server must authenticate every request with X-Main-Server-Key.
 */
app.post("/internal/subadmins", requireMainServer, asyncRoute(async (req, res) => {
  const mainId = clean(req.body.main_server_id, 120);
  const username = clean(req.body.username, 30).toLowerCase();
  const email = clean(req.body.email, 255).toLowerCase();
  const password = req.body.password;
  if (!mainId || !validUsername(username) || (email && !validEmail(email)) ||
      typeof password !== "string" || password.length < 10 || password.length > 200) {
    return fail(res, 400, "Invalid Sub-Admin details.");
  }
  const hash = await bcrypt.hash(password, 12);
  const invite = "SA" + crypto.randomBytes(10).toString("hex").toUpperCase();
  const r = await pool.query(`
    INSERT INTO subadmins(main_server_id,username,email,password_hash,invite_code)
    VALUES($1,$2,$3,$4,$5)
    ON CONFLICT(main_server_id) DO UPDATE SET
      username=EXCLUDED.username,email=EXCLUDED.email,
      password_hash=EXCLUDED.password_hash,updated_at=NOW()
    RETURNING id,main_server_id,username,email,invite_code,status,balance,created_at
  `, [mainId, username, email || null, hash, invite]);
  res.status(201).json({ success: true, subadmin: r.rows[0] });
}));

app.patch("/internal/subadmins/:mainId/status", requireMainServer, asyncRoute(async (req, res) => {
  const status = req.body.status;
  if (!["active", "suspended"].includes(status)) return fail(res, 400, "Invalid status.");
  const r = await pool.query(
    "UPDATE subadmins SET status=$1,updated_at=NOW() WHERE main_server_id=$2 RETURNING id,username,status",
    [status, clean(req.params.mainId, 120)]
  );
  if (!r.rows.length) return fail(res, 404, "Sub-Admin not found.");
  res.json({ success: true, subadmin: r.rows[0] });
}));

/* Idempotent receiving endpoint. The Main Server must debit its own wallet
 * first via a durable outbox, then retry this exact transfer_id until success.
 */
app.post("/internal/points/credit", requireMainServer, asyncRoute(async (req, res) => {
  const transferId = clean(req.body.transfer_id, 150);
  const mainId = clean(req.body.main_server_id, 120);
  const amount = Number(req.body.amount);
  if (!transferId || !mainId || !validAmount(amount)) return fail(res, 400, "Invalid transfer.");
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const old = await c.query("SELECT amount FROM main_server_transfers WHERE transfer_id=$1", [transferId]);
    if (old.rows.length) {
      if (Number(old.rows[0].amount) !== amount) {
        await c.query("ROLLBACK");
        return fail(res, 409, "Transfer ID reused with a different amount.");
      }
      await c.query("COMMIT");
      return res.json({ success: true, duplicate: true, transfer_id: transferId });
    }
    const s = await c.query(
      "SELECT id,status FROM subadmins WHERE main_server_id=$1 FOR UPDATE", [mainId]
    );
    if (!s.rows.length) {
      await c.query("ROLLBACK");
      return fail(res, 404, "Sub-Admin not found.");
    }
    if (s.rows[0].status !== "active") {
      await c.query("ROLLBACK");
      return fail(res, 403, "Sub-Admin suspended.");
    }
    const sid = s.rows[0].id;
    await c.query("UPDATE subadmins SET balance=balance+$1,updated_at=NOW() WHERE id=$2",
      [amount.toFixed(2), sid]);
    await c.query("INSERT INTO main_server_transfers(transfer_id,subadmin_id,amount) VALUES($1,$2,$3)",
      [transferId, sid, amount.toFixed(2)]);
    await c.query(
      "INSERT INTO subadmin_wallet_transactions(subadmin_id,type,amount,reference,description) VALUES($1,'main_allocation',$2,$3,$4)",
      [sid, amount.toFixed(2), "MAIN-" + transferId, "Points allocated by Main Admin"]
    );
    const b = await c.query("SELECT balance FROM subadmins WHERE id=$1", [sid]);
    await c.query("COMMIT");
    res.json({ success: true, duplicate: false, credited: amount, balance: b.rows[0].balance });
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}));

/* SUB-ADMIN AUTH */
app.post("/api/auth/login", loginLimiter, asyncRoute(async (req, res) => {
  const username = clean(req.body.username, 30).toLowerCase();
  const password = req.body.password;
  if (!username || typeof password !== "string") return fail(res, 400, "Username and password required.");
  const r = await pool.query("SELECT * FROM subadmins WHERE username=$1", [username]);
  if (!r.rows.length || !(await bcrypt.compare(password, r.rows[0].password_hash))) {
    return fail(res, 401, "Invalid username or password.");
  }
  const u = r.rows[0];
  if (u.status !== "active") return fail(res, 403, "Sub-Admin suspended.");
  const token = jwt.sign({ id: u.id, role: "subadmin" }, JWT_SECRET,
    { expiresIn: "12h", issuer: "glo365-subadmin" });
  res.json({ success: true, token, user: {
    id: u.id, username: u.username, email: u.email, role: "subadmin",
    balance: u.balance, invite_code: u.invite_code
  }});
}));

app.get("/api/auth/me", authenticate, activeAccount, asyncRoute(async (req, res) => {
  if (req.auth.role === "subadmin") {
    const r = await pool.query(
      "SELECT id,username,email,status,balance,invite_code,created_at FROM subadmins WHERE id=$1",
      [req.auth.id]);
    return res.json({ success: true, user: { ...r.rows[0], role: "subadmin" } });
  }
  const r = await pool.query(
    "SELECT id,username,email,status,balance,created_at FROM subadmin_users WHERE id=$1",
    [req.auth.id]);
  res.json({ success: true, user: { ...r.rows[0], role: "customer" } });
}));

/* CUSTOMER SIGNUP BY SUB-ADMIN INVITE CODE.
 * This creates a customer only inside the matching Sub-Admin tenant.
 */
app.post("/api/register", loginLimiter, asyncRoute(async (req, res) => {
  const invite = clean(req.body.invite_code, 40).toUpperCase();
  const username = clean(req.body.username, 30).toLowerCase();
  const email = clean(req.body.email, 255).toLowerCase();
  const password = req.body.password;
  if (!invite || !validUsername(username) || (email && !validEmail(email)) ||
      typeof password !== "string" || password.length < 10 || password.length > 200) {
    return fail(res, 400, "Invalid registration details.");
  }
  const owner = await pool.query(
    "SELECT id FROM subadmins WHERE invite_code=$1 AND status='active'", [invite]);
  if (!owner.rows.length) return fail(res, 404, "Invite link is invalid or inactive.");
  const hash = await bcrypt.hash(password, 12);
  let r;
  try {
    r = await pool.query(
      "INSERT INTO subadmin_users(subadmin_id,username,email,password_hash) VALUES($1,$2,$3,$4) RETURNING id,username,email,status,balance,created_at",
      [owner.rows[0].id, username, email || null, hash]);
  } catch (e) {
    if (e.code === "23505") return fail(res, 409, "Username or email already exists under this Sub-Admin.");
    throw e;
  }
  const token = jwt.sign({ id: r.rows[0].id, role: "customer" }, JWT_SECRET,
    { expiresIn: "12h", issuer: "glo365-subadmin" });
  res.status(201).json({ success: true, token, user: { ...r.rows[0], role: "customer" } });
}));

app.post("/api/customer/login", loginLimiter, asyncRoute(async (req, res) => {
  const username = clean(req.body.username, 30).toLowerCase();
  const password = req.body.password;
  const inviteCode = clean(req.body.invite_code, 40).toUpperCase();
  if (!username || typeof password !== "string") {
    return fail(res, 400, "Username and password required.");
  }

  let r;
  if (inviteCode) {
    r = await pool.query(
      `SELECT u.* FROM subadmin_users u
       JOIN subadmins s ON s.id=u.subadmin_id
       WHERE u.username=$1 AND s.invite_code=$2 AND s.status='active'
       LIMIT 1`,
      [username, inviteCode]
    );
  } else {
    r = await pool.query(
      "SELECT * FROM subadmin_users WHERE username=$1 ORDER BY id ASC LIMIT 2",
      [username]
    );
    if (r.rows.length > 1) {
      return fail(res, 409, "More than one account uses this username. Enter your Sub-Admin invite code.");
    }
  }

  if (!r.rows.length || !(await bcrypt.compare(password, r.rows[0].password_hash))) {
    return fail(res, 401, "Invalid username, password, or invite code.");
  }
  const u = r.rows[0];
  if (u.status !== "active") return fail(res, 403, "Account suspended.");
  const token = jwt.sign({ id: u.id, role: "customer" }, JWT_SECRET,
    { expiresIn: "12h", issuer: "glo365-subadmin" });
  res.json({ success: true, token, user: {
    id: u.id, username: u.username, email: u.email, role: "customer", balance: u.balance
  }});
}));

/* SUB-ADMIN WALLET AND CUSTOMER MANAGEMENT */
app.get("/api/wallet", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const r = await pool.query("SELECT balance FROM subadmins WHERE id=$1", [req.auth.id]);
  res.json({ success: true, currency: "DEMO", is_demo: true, balance: r.rows[0].balance });
}));

app.get("/api/wallet/transactions", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const r = await pool.query(
    "SELECT id,type,amount,reference,description,created_at FROM subadmin_wallet_transactions WHERE subadmin_id=$1 ORDER BY id DESC LIMIT 200",
    [req.auth.id]);
  res.json({ success: true, transactions: r.rows });
}));

app.get("/api/dashboard", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const r = await pool.query(`
    SELECT
      (SELECT balance FROM subadmins WHERE id=$1) AS balance,
      (SELECT COUNT(*) FROM subadmin_users WHERE subadmin_id=$1) AS customer_count,
      (SELECT COALESCE(SUM(amount),0) FROM subadmin_wallet_transactions
        WHERE subadmin_id=$1 AND type='main_allocation') AS total_allocated,
      (SELECT COUNT(*) FROM subadmin_deposits WHERE subadmin_id=$1 AND status='pending') AS pending_deposits,
      (SELECT COUNT(*) FROM subadmin_withdrawals WHERE subadmin_id=$1 AND status='pending') AS pending_withdrawals
  `, [req.auth.id]);
  res.json({ success: true, dashboard: r.rows[0] });
}));

app.get("/api/users", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const r = await pool.query(
    "SELECT id,username,email,status,balance,created_at FROM subadmin_users WHERE subadmin_id=$1 ORDER BY id DESC LIMIT 500",
    [req.auth.id]);
  res.json({ success: true, users: r.rows });
}));

app.patch("/api/users/:id/status", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const status = req.body.status;
  if (!Number.isSafeInteger(id) || id < 1 || !["active", "suspended"].includes(status)) {
    return fail(res, 400, "Invalid request.");
  }
  const r = await pool.query(
    "UPDATE subadmin_users SET status=$1,updated_at=NOW() WHERE id=$2 AND subadmin_id=$3 RETURNING id,username,status",
    [status, id, req.auth.id]);
  if (!r.rows.length) return fail(res, 404, "Customer not found.");
  res.json({ success: true, user: r.rows[0] });
}));

app.post("/api/users/:id/points", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const userId = Number(req.params.id);
  const amount = Number(req.body.amount);
  if (!Number.isSafeInteger(userId) || userId < 1 || !validAmount(amount)) {
    return fail(res, 400, "Invalid point distribution.");
  }
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const owner = await c.query("SELECT balance FROM subadmins WHERE id=$1 FOR UPDATE", [req.auth.id]);
    const customer = await c.query(
      "SELECT id FROM subadmin_users WHERE id=$1 AND subadmin_id=$2 AND status='active' FOR UPDATE",
      [userId, req.auth.id]);
    if (!customer.rows.length) {
      await c.query("ROLLBACK");
      return fail(res, 404, "Customer not found under this Sub-Admin.");
    }
    if (Number(owner.rows[0].balance) < amount) {
      await c.query("ROLLBACK");
      return fail(res, 400, "Insufficient allocated points.");
    }
    const ref = newRef("DIST");
    await c.query("UPDATE subadmins SET balance=balance-$1,updated_at=NOW() WHERE id=$2",
      [amount.toFixed(2), req.auth.id]);
    await c.query("UPDATE subadmin_users SET balance=balance+$1,updated_at=NOW() WHERE id=$2",
      [amount.toFixed(2), userId]);
    await c.query(
      "INSERT INTO subadmin_wallet_transactions(subadmin_id,type,amount,reference,description) VALUES($1,'user_distribution',$2,$3,$4)",
      [req.auth.id, (-amount).toFixed(2), ref, "Points distributed to customer"]);
    await c.query(
      "INSERT INTO subadmin_user_transactions(subadmin_id,user_id,type,amount,reference,description) VALUES($1,$2,'point_credit',$3,$4,$5)",
      [req.auth.id, userId, amount.toFixed(2), ref, "Points received from Sub-Admin"]);
    const b = await c.query("SELECT balance FROM subadmins WHERE id=$1", [req.auth.id]);
    await c.query("COMMIT");
    res.json({ success: true, reference: ref, distributed: amount, subadmin_balance: b.rows[0].balance });
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}));

/* PAYMENT METHODS — each Sub-Admin sees and edits only their own methods */
app.get("/api/payment-methods", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const r = await pool.query(
    "SELECT id,name,label,account,currency,instructions,active FROM subadmin_payment_methods WHERE subadmin_id=$1 ORDER BY id DESC",
    [req.auth.id]);
  res.json({ success: true, methods: r.rows });
}));

app.post("/api/payment-methods", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const name = clean(req.body.name, 80);
  const label = clean(req.body.label, 100);
  const account = clean(req.body.account, 180);
  const currency = clean(req.body.currency || "BDT", 10).toUpperCase();
  const instructions = clean(req.body.instructions, 1000);
  if (!name || !account || !/^[A-Z0-9]{2,10}$/.test(currency)) return fail(res, 400, "Invalid payment method.");
  const r = await pool.query(
    "INSERT INTO subadmin_payment_methods(subadmin_id,name,label,account,currency,instructions) VALUES($1,$2,$3,$4,$5,$6) RETURNING *",
    [req.auth.id, name, label || null, account, currency, instructions || null]);
  res.status(201).json({ success: true, method: r.rows[0] });
}));

app.patch("/api/payment-methods/:id", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return fail(res, 400, "Invalid method ID.");
  const r = await pool.query(
    `UPDATE subadmin_payment_methods SET
      name=COALESCE($1,name), label=COALESCE($2,label),
      account=COALESCE($3,account), instructions=COALESCE($4,instructions),
      active=COALESCE($5,active), currency=COALESCE($6,currency)
     WHERE id=$7 AND subadmin_id=$8
     RETURNING id,name,label,account,currency,instructions,active`,
    [req.body.name ? clean(req.body.name,80) : null,
     req.body.label !== undefined ? clean(req.body.label,100) : null,
     req.body.account ? clean(req.body.account,180) : null,
     req.body.instructions !== undefined ? clean(req.body.instructions,1000) : null,
     typeof req.body.active === "boolean" ? req.body.active : null,
     req.body.currency !== undefined && /^[A-Z0-9]{2,10}$/.test(clean(req.body.currency,10).toUpperCase())
       ? clean(req.body.currency,10).toUpperCase() : null,
     id, req.auth.id]);
  if (!r.rows.length) return fail(res, 404, "Payment method not found.");
  res.json({ success: true, method: r.rows[0] });
}));

/* CUSTOMER DEPOSITS: request goes only to the owning Sub-Admin. */
app.post("/api/customer/deposits", authenticate, onlyCustomer, activeAccount, asyncRoute(async (req, res) => {
  const amount = Number(req.body.amount);
  const methodId = Number(req.body.payment_method_id);
  const transactionRef = clean(req.body.transaction_ref, 160);
  if (!validAmount(amount) || !Number.isSafeInteger(methodId) || methodId < 1 || !transactionRef) {
    return fail(res, 400, "Invalid deposit request.");
  }
  const u = await pool.query("SELECT subadmin_id FROM subadmin_users WHERE id=$1", [req.auth.id]);
  const method = await pool.query(
    "SELECT id FROM subadmin_payment_methods WHERE id=$1 AND subadmin_id=$2 AND active=TRUE",
    [methodId, u.rows[0].subadmin_id]);
  if (!method.rows.length) return fail(res, 400, "Payment method is unavailable.");
  const r = await pool.query(
    "INSERT INTO subadmin_deposits(subadmin_id,user_id,payment_method_id,amount,transaction_ref) VALUES($1,$2,$3,$4,$5) RETURNING id,amount,transaction_ref,status,created_at",
    [u.rows[0].subadmin_id, req.auth.id, methodId, amount.toFixed(2), transactionRef]);
  res.status(201).json({ success: true, deposit: r.rows[0] });
}));

app.get("/api/customer/deposits", authenticate, onlyCustomer, activeAccount, asyncRoute(async (req, res) => {
  const r = await pool.query(
    "SELECT id,amount,transaction_ref,status,admin_note,created_at,reviewed_at FROM subadmin_deposits WHERE user_id=$1 ORDER BY id DESC LIMIT 100",
    [req.auth.id]);
  res.json({ success: true, deposits: r.rows });
}));

app.get("/api/customer/payment-methods", authenticate, onlyCustomer, activeAccount, asyncRoute(async (req, res) => {
  const u = await pool.query("SELECT subadmin_id FROM subadmin_users WHERE id=$1", [req.auth.id]);
  const r = await pool.query(
    "SELECT id,name,label,account,currency,instructions FROM subadmin_payment_methods WHERE subadmin_id=$1 AND active=TRUE ORDER BY id DESC",
    [u.rows[0].subadmin_id]);
  res.json({ success: true, methods: r.rows });
}));

/* Customer withdrawal request reserves points immediately. On rejection,
 * reserved points are returned. On approval, Sub-Admin pays outside this
 * demo-points service and marks the request approved.
 */
app.post("/api/customer/withdrawals", authenticate, onlyCustomer, activeAccount, asyncRoute(async (req, res) => {
  const amount = Number(req.body.amount);
  const method = clean(req.body.payout_method, 80);
  const account = clean(req.body.payout_account, 180);
  if (!validAmount(amount) || !method || !account) return fail(res, 400, "Invalid withdrawal request.");
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const u = await c.query("SELECT subadmin_id,balance FROM subadmin_users WHERE id=$1 FOR UPDATE", [req.auth.id]);
    if (!u.rows.length) {
      await c.query("ROLLBACK");
      return fail(res, 404, "Customer account not found.");
    }
    if (Number(u.rows[0].balance) < amount) {
      await c.query("ROLLBACK");
      return fail(res, 400, "Insufficient points.");
    }
    await c.query("UPDATE subadmin_users SET balance=balance-$1,updated_at=NOW() WHERE id=$2",
      [amount.toFixed(2), req.auth.id]);
    const ref = newRef("WDR");
    const r = await c.query(
      "INSERT INTO subadmin_withdrawals(subadmin_id,user_id,amount,payout_method,payout_account) VALUES($1,$2,$3,$4,$5) RETURNING id,amount,status,created_at",
      [u.rows[0].subadmin_id, req.auth.id, amount.toFixed(2), method, account]);
    await c.query(
      "INSERT INTO subadmin_user_transactions(subadmin_id,user_id,type,amount,reference,description) VALUES($1,$2,'withdrawal_reserved',$3,$4,$5)",
      [u.rows[0].subadmin_id, req.auth.id, (-amount).toFixed(2), ref, "Points reserved for withdrawal request"]);
    await c.query("COMMIT");
    res.status(201).json({ success: true, withdrawal: r.rows[0] });
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}));

app.get("/api/customer/withdrawals", authenticate, onlyCustomer, activeAccount, asyncRoute(async (req, res) => {
  const r = await pool.query(
    "SELECT id,amount,payout_method,payout_account,status,admin_note,created_at,reviewed_at FROM subadmin_withdrawals WHERE user_id=$1 ORDER BY id DESC LIMIT 100",
    [req.auth.id]);
  res.json({ success: true, withdrawals: r.rows });
}));

/* SUB-ADMIN queues and reviews are tenant-scoped. */
app.get("/api/deposits", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const r = await pool.query(
    `SELECT d.*,u.username FROM subadmin_deposits d
     JOIN subadmin_users u ON u.id=d.user_id
     WHERE d.subadmin_id=$1 ORDER BY d.id DESC LIMIT 300`, [req.auth.id]);
  res.json({ success: true, deposits: r.rows });
}));

app.post("/api/deposits/:id/review", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const decision = req.body.status;
  const note = clean(req.body.admin_note, 1000);
  if (!Number.isSafeInteger(id) || id < 1 || !["approved","rejected"].includes(decision)) {
    return fail(res, 400, "Invalid review.");
  }
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const d = await c.query(
      "SELECT * FROM subadmin_deposits WHERE id=$1 AND subadmin_id=$2 FOR UPDATE",
      [id, req.auth.id]);
    if (!d.rows.length) {
      await c.query("ROLLBACK");
      return fail(res, 404, "Deposit not found.");
    }
    if (d.rows[0].status !== "pending") {
      await c.query("ROLLBACK");
      return fail(res, 409, "Deposit already reviewed.");
    }
    if (decision === "approved") {
      await c.query("UPDATE subadmin_users SET balance=balance+$1,updated_at=NOW() WHERE id=$2 AND subadmin_id=$3",
        [d.rows[0].amount, d.rows[0].user_id, req.auth.id]);
      await c.query(
        "INSERT INTO subadmin_user_transactions(subadmin_id,user_id,type,amount,reference,description) VALUES($1,$2,'deposit_credit',$3,$4,$5)",
        [req.auth.id, d.rows[0].user_id, d.rows[0].amount, newRef("DEP"), "Deposit approved by Sub-Admin"]);
    }
    const updated = await c.query(
      "UPDATE subadmin_deposits SET status=$1,admin_note=$2,reviewed_at=NOW() WHERE id=$3 RETURNING id,status,admin_note,reviewed_at",
      [decision, note || null, id]);
    await c.query("COMMIT");
    res.json({ success: true, deposit: updated.rows[0] });
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}));

app.get("/api/withdrawals", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const r = await pool.query(
    `SELECT w.*,u.username FROM subadmin_withdrawals w
     JOIN subadmin_users u ON u.id=w.user_id
     WHERE w.subadmin_id=$1 ORDER BY w.id DESC LIMIT 300`, [req.auth.id]);
  res.json({ success: true, withdrawals: r.rows });
}));

app.post("/api/withdrawals/:id/review", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const decision = req.body.status;
  const note = clean(req.body.admin_note, 1000);
  if (!Number.isSafeInteger(id) || id < 1 || !["approved","rejected"].includes(decision)) {
    return fail(res, 400, "Invalid review.");
  }
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const w = await c.query(
      "SELECT * FROM subadmin_withdrawals WHERE id=$1 AND subadmin_id=$2 FOR UPDATE",
      [id, req.auth.id]);
    if (!w.rows.length) {
      await c.query("ROLLBACK");
      return fail(res, 404, "Withdrawal not found.");
    }
    if (w.rows[0].status !== "pending") {
      await c.query("ROLLBACK");
      return fail(res, 409, "Withdrawal already reviewed.");
    }
    if (decision === "rejected") {
      await c.query("UPDATE subadmin_users SET balance=balance+$1,updated_at=NOW() WHERE id=$2 AND subadmin_id=$3",
        [w.rows[0].amount, w.rows[0].user_id, req.auth.id]);
      await c.query(
        "INSERT INTO subadmin_user_transactions(subadmin_id,user_id,type,amount,reference,description) VALUES($1,$2,'withdrawal_refund',$3,$4,$5)",
        [req.auth.id, w.rows[0].user_id, w.rows[0].amount,
         newRef("WREF"), "Points returned after withdrawal rejection"]);
    }
    const updated = await c.query(
      "UPDATE subadmin_withdrawals SET status=$1,admin_note=$2,reviewed_at=NOW() WHERE id=$3 RETURNING id,status,admin_note,reviewed_at",
      [decision, note || null, id]);
    await c.query("COMMIT");
    res.json({ success: true, withdrawal: updated.rows[0],
      reminder: decision === "approved" ? "Sub-Admin must complete payout using their own funds." : undefined });
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}));

app.post("/api/withdrawals/:id/paid", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const note = clean(req.body.admin_note, 1000);
  if (!Number.isSafeInteger(id) || id < 1) return fail(res, 400, "Invalid withdrawal ID.");

  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const w = await c.query(
      "SELECT id,status FROM subadmin_withdrawals WHERE id=$1 AND subadmin_id=$2 FOR UPDATE",
      [id, req.auth.id]
    );
    if (!w.rows.length) {
      await c.query("ROLLBACK");
      return fail(res, 404, "Withdrawal not found.");
    }
    if (w.rows[0].status !== "approved") {
      await c.query("ROLLBACK");
      return fail(res, 409, "Only an approved withdrawal can be marked paid.");
    }
    const updated = await c.query(
      "UPDATE subadmin_withdrawals SET status='paid',admin_note=COALESCE($1,admin_note),paid_at=NOW() WHERE id=$2 AND subadmin_id=$3 RETURNING id,status,admin_note,reviewed_at,paid_at",
      [note || null, id, req.auth.id]
    );
    await c.query("COMMIT");
    res.json({ success: true, withdrawal: updated.rows[0] });
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  } finally {
    c.release();
  }
}));

/* SUPPORT — each customer can access only their own conversation;
 * Sub-Admin can access only conversations belonging to their tenant.
 */
app.post("/api/customer/support/conversations", authenticate, onlyCustomer, activeAccount, asyncRoute(async (req, res) => {
  const u = await pool.query("SELECT subadmin_id FROM subadmin_users WHERE id=$1", [req.auth.id]);
  let c = await pool.query(
    "SELECT id,status FROM subadmin_support_conversations WHERE user_id=$1 AND status='open' ORDER BY id DESC LIMIT 1",
    [req.auth.id]);
  if (!c.rows.length) {
    c = await pool.query(
      "INSERT INTO subadmin_support_conversations(subadmin_id,user_id) VALUES($1,$2) RETURNING id,status",
      [u.rows[0].subadmin_id, req.auth.id]);
  }
  res.json({ success: true, conversation: c.rows[0] });
}));

app.get("/api/customer/support/messages", authenticate, onlyCustomer, activeAccount, asyncRoute(async (req, res) => {
  const c = await pool.query(
    "SELECT id FROM subadmin_support_conversations WHERE user_id=$1 ORDER BY id DESC LIMIT 1",
    [req.auth.id]);
  if (!c.rows.length) return res.json({ success: true, messages: [] });
  const r = await pool.query(
    "SELECT id,sender_role,sender_id,message,created_at FROM subadmin_support_messages WHERE conversation_id=$1 ORDER BY id ASC",
    [c.rows[0].id]);
  res.json({ success: true, conversation_id: c.rows[0].id, messages: r.rows });
}));

app.post("/api/customer/support/messages", authenticate, onlyCustomer, activeAccount, asyncRoute(async (req, res) => {
  const message = clean(req.body.message, 3000);
  if (!message) return fail(res, 400, "Message is required.");
  const u = await pool.query("SELECT subadmin_id FROM subadmin_users WHERE id=$1", [req.auth.id]);
  let c = await pool.query(
    "SELECT id FROM subadmin_support_conversations WHERE user_id=$1 AND status='open' ORDER BY id DESC LIMIT 1",
    [req.auth.id]);
  if (!c.rows.length) {
    c = await pool.query(
      "INSERT INTO subadmin_support_conversations(subadmin_id,user_id) VALUES($1,$2) RETURNING id",
      [u.rows[0].subadmin_id, req.auth.id]);
  }
  const r = await pool.query(
    "INSERT INTO subadmin_support_messages(conversation_id,sender_role,sender_id,message) VALUES($1,'customer',$2,$3) RETURNING id,sender_role,sender_id,message,created_at",
    [c.rows[0].id, req.auth.id, message]);
  await pool.query("UPDATE subadmin_support_conversations SET updated_at=NOW() WHERE id=$1", [c.rows[0].id]);
  res.status(201).json({ success: true, message: r.rows[0] });
}));

app.get("/api/support/conversations", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const r = await pool.query(
    `SELECT c.id,c.user_id,u.username,c.status,c.created_at,c.updated_at
     FROM subadmin_support_conversations c
     JOIN subadmin_users u ON u.id=c.user_id
     WHERE c.subadmin_id=$1 ORDER BY c.updated_at DESC LIMIT 300`, [req.auth.id]);
  res.json({ success: true, conversations: r.rows });
}));

app.get("/api/support/conversations/:id/messages", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const own = await pool.query(
    "SELECT id FROM subadmin_support_conversations WHERE id=$1 AND subadmin_id=$2",
    [id, req.auth.id]);
  if (!own.rows.length) return fail(res, 404, "Conversation not found.");
  const r = await pool.query(
    "SELECT id,sender_role,sender_id,message,created_at FROM subadmin_support_messages WHERE conversation_id=$1 ORDER BY id ASC",
    [id]);
  res.json({ success: true, messages: r.rows });
}));

app.post("/api/support/conversations/:id/messages", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const message = clean(req.body.message, 3000);
  if (!message) return fail(res, 400, "Message is required.");
  const own = await pool.query(
    "SELECT id,status FROM subadmin_support_conversations WHERE id=$1 AND subadmin_id=$2",
    [id, req.auth.id]);
  if (!own.rows.length) return fail(res, 404, "Conversation not found.");
  if (own.rows[0].status !== "open") return fail(res, 409, "Conversation is closed.");
  const r = await pool.query(
    "INSERT INTO subadmin_support_messages(conversation_id,sender_role,sender_id,message) VALUES($1,'subadmin',$2,$3) RETURNING id,sender_role,sender_id,message,created_at",
    [id, req.auth.id, message]);
  await pool.query("UPDATE subadmin_support_conversations SET updated_at=NOW() WHERE id=$1", [id]);
  res.status(201).json({ success: true, message: r.rows[0] });
}));

app.patch("/api/support/conversations/:id/close", authenticate, onlySubAdmin, activeAccount, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  const r = await pool.query(
    "UPDATE subadmin_support_conversations SET status='closed',updated_at=NOW() WHERE id=$1 AND subadmin_id=$2 RETURNING id,status",
    [id, req.auth.id]);
  if (!r.rows.length) return fail(res, 404, "Conversation not found.");
  res.json({ success: true, conversation: r.rows[0] });
}));

app.use((req, res) => fail(res, 404, "API endpoint not found."));
app.use((err, req, res, next) => {
  console.error("Sub-Admin API error:", err.message);
  if (err.type === "entity.parse.failed") return fail(res, 400, "Invalid JSON.");
  if (err.message === "Origin not allowed") return fail(res, 403, "Origin not allowed.");
  if (err.code === "23505") return fail(res, 409, "Record already exists.");
  return fail(res, 500, "Internal server error.");
});

async function start() {
  await initDb();
  await pool.query("SELECT 1");
  app.listen(PORT, "0.0.0.0", () => {
    console.log("GLO 365 Sub-Admin Server listening on port " + PORT);
  });
}
start().catch(err => {
  console.error("Sub-Admin server startup failed:", err.message);
  process.exit(1);
});

process.on("SIGTERM", async () => {
  await pool.end();
  process.exit(0);
});
