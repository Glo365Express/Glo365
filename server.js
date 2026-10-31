require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const AUTH_COOKIE = "glo365_token";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("ERROR: JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is missing.");
  process.exit(1);
}

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(",").map(x => x.trim()).filter(Boolean)
  : true;

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on("error", error => {
  console.error("Unexpected database error:", error.message);
});


// ==========================================
// COMMON HELPERS
// ==========================================

function sendError(res, status, message) {
  return res.status(status).json({ success: false, message });
}

function asyncRoute(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function cleanText(value, maxLength = 255) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role || "user",
    status: user.status || "active",
    balance: user.balance,
    created_at: user.created_at
  };
}

function createToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "7d", issuer: "glo365" }
  );
}

function setAuthCookie(res, token) {
  res.cookie(AUTH_COOKIE, token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
    maxAge: COOKIE_MAX_AGE
  });
}

function clearAuthCookie(res) {
  res.clearCookie(AUTH_COOKIE, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/"
  });
}

function getCookie(req, name) {
  const header = req.headers.cookie || "";
  const parts = header.split(";");

  for (const part of parts) {
    const index = part.indexOf("=");
    if (index < 0) continue;

    const key = part.slice(0, index).trim();
    if (key === name) {
      return decodeURIComponent(part.slice(index + 1).trim());
    }
  }

  return null;
}

function validUsername(username) {
  return /^[a-z0-9_]{3,30}$/.test(username);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validExternalEventUrl(value, platform) {
  try {
    const url = new URL(value);

    if (url.protocol !== "https:") return false;

    const host = url.hostname.toLowerCase();

    const youtubeHosts = [
      "youtube.com",
      "www.youtube.com",
      "m.youtube.com",
      "youtu.be",
      "www.youtube-nocookie.com"
    ];

    const facebookHosts = [
      "facebook.com",
      "www.facebook.com",
      "m.facebook.com",
      "fb.watch",
      "www.fb.watch"
    ];

    if (platform === "youtube") {
      return youtubeHosts.includes(host);
    }

    if (platform === "facebook") {
      return facebookHosts.includes(host);
    }

    return false;
  } catch {
    return false;
  }
}


// ==========================================
// DATABASE INITIALIZATION
// Existing database records are preserved.
// ==========================================

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(30) UNIQUE NOT NULL,
      email VARCHAR(150) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance NUMERIC(12,2) NOT NULL DEFAULT 1000.00,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS profiles (
      user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      full_name VARCHAR(100) DEFAULT '',
      avatar TEXT DEFAULT '',
      bio VARCHAR(300) DEFAULT '',
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS demo_bets (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      game_name VARCHAR(100) NOT NULL,
      selection VARCHAR(100) NOT NULL,
      amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS demo_results (
      id BIGSERIAL PRIMARY KEY,
      game_name VARCHAR(100) NOT NULL,
      result VARCHAR(100) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user';

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active';

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS referred_by BIGINT REFERENCES users(id);

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS referral_code VARCHAR(30);

    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

    CREATE TABLE IF NOT EXISTS moderator_permissions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS affiliate_commissions (
      id BIGSERIAL PRIMARY KEY,
      affiliate_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      referred_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (amount >= 0),
      description TEXT DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      actor_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      action VARCHAR(100) NOT NULL,
      target_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      details JSONB DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(30) NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      currency VARCHAR(10) NOT NULL DEFAULT 'DEMO',
      description TEXT DEFAULT '',
      reference VARCHAR(100),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_messages (
      id BIGSERIAL PRIMARY KEY,
      text VARCHAR(300) NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS admin_live_events (
      id BIGSERIAL PRIMARY KEY,
      title VARCHAR(80) NOT NULL,
      url TEXT NOT NULL,
      platform VARCHAR(20) NOT NULL
        CHECK (platform IN ('youtube', 'facebook')),
      active BOOLEAN NOT NULL DEFAULT TRUE,
      updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_demo_bets_user ON demo_bets(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_wallet_user ON wallet_transactions(user_id);
    CREATE INDEX IF NOT EXISTS idx_affiliate_user ON affiliate_commissions(affiliate_id);
    CREATE INDEX IF NOT EXISTS idx_admin_messages_active ON admin_messages(active);
    CREATE INDEX IF NOT EXISTS idx_admin_live_events_active ON admin_live_events(active);
  `);

  await pool.query(`
    UPDATE users
    SET referral_code = 'GLO' || id
    WHERE referral_code IS NULL
  `);

  console.log("GLO 365 database initialized.");
}


// ==========================================
// AUDIT LOG
// ==========================================

async function audit(actorId, action, targetUserId = null, details = {}) {
  try {
    await pool.query(
      `INSERT INTO audit_logs
       (actor_id, action, target_user_id, details)
       VALUES ($1, $2, $3, $4)`,
      [actorId || null, action, targetUserId, JSON.stringify(details)]
    );
  } catch (error) {
    console.error("Audit log error:", error.message);
  }
}


// ==========================================
// AUTHENTICATION
// Supports HttpOnly Cookie and Bearer Token.
// ==========================================

async function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || "";

  let token = null;

  if (authHeader.startsWith("Bearer ")) {
    token = authHeader.substring(7).trim();
  }

  if (!token) {
    token = getCookie(req, AUTH_COOKIE);
  }

  if (!token) {
    return sendError(res, 401, "Authentication required.");
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: "glo365"
    });

    const result = await pool.query(
      `SELECT id, username, email, role, status
       FROM users WHERE id = $1`,
      [decoded.id]
    );

    if (!result.rows.length) {
      return sendError(res, 401, "Account not found.");
    }

    const user = result.rows[0];

    if (user.status !== "active") {
      return sendError(res, 403, "Your account is not active.");
    }

    req.user = user;
    next();

  } catch (error) {
    return sendError(res, 401, "Invalid or expired token.");
  }
}


// ==========================================
// ROLE & PERMISSION CHECKS
// ==========================================

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return sendError(res, 403, "Admin access required.");
  }
  next();
}

function requirePermission(permission) {
  return asyncRoute(async (req, res, next) => {
    if (req.user.role === "admin") return next();

    if (req.user.role !== "moderator") {
      return sendError(res, 403, "Permission denied.");
    }

    const result = await pool.query(
      "SELECT permissions FROM moderator_permissions WHERE user_id = $1",
      [req.user.id]
    );

    const permissions = result.rows[0]?.permissions || {};

    if (permissions[permission] !== true) {
      return sendError(res, 403, "You do not have this permission.");
    }

    next();
  });
}


// ==========================================
// BOOTSTRAP FIRST ADMIN
// ==========================================

async function bootstrapAdmin() {
  const username = cleanText(process.env.BOOTSTRAP_ADMIN_USERNAME, 30)
    .toLowerCase();

  const email = cleanText(process.env.BOOTSTRAP_ADMIN_EMAIL, 150)
    .toLowerCase();

  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;

  if (!username && !email && !password) {
    console.log("Admin bootstrap not configured.");
    return;
  }

  if (!username || !email || !password || !validUsername(username) ||
      !validEmail(email) || password.length < 12) {
    throw new Error(
      "Admin bootstrap requires a valid username, email and password of at least 12 characters."
    );
  }

  const existing = await pool.query(
    "SELECT id FROM users WHERE role = 'admin' LIMIT 1"
  );

  if (existing.rows.length) {
    console.log("An admin account already exists. Bootstrap skipped.");
    return;
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `INSERT INTO users
       (username, email, password_hash, role, status, referral_code)
       VALUES ($1, $2, $3, 'admin', 'active', 'GLOADMIN')
       ON CONFLICT DO NOTHING
       RETURNING id`,
      [username, email, passwordHash]
    );

    if (result.rows.length) {
      await client.query(
        "INSERT INTO profiles (user_id) VALUES ($1) ON CONFLICT DO NOTHING",
        [result.rows[0].id]
      );
    }

    await client.query("COMMIT");
    console.log("Admin bootstrap completed if no account conflict occurred.");

  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}


// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "GLO 365 Backend API is running.",
    version: "2.1.0"
  });
});

app.get("/health", asyncRoute(async (req, res) => {
  await pool.query("SELECT 1");

  res.json({
    success: true,
    database: "connected",
    status: "healthy"
  });
}));


// ==========================================
// REGISTER
// POST /api/auth/register
// ==========================================

app.post("/api/auth/register", asyncRoute(async (req, res) => {
  const username = cleanText(req.body.username, 30).toLowerCase();
  const email = cleanText(req.body.email, 150).toLowerCase();
  const password = req.body.password;
  const referralCode = cleanText(req.body.referral_code, 30);

  if (!username || !email || !password) {
    return sendError(res, 400, "Username, email and password are required.");
  }

  if (!validUsername(username)) {
    return sendError(res, 400, "Username must be 3-30 characters using letters, numbers or underscore.");
  }

  if (!validEmail(email)) {
    return sendError(res, 400, "Please enter a valid email address.");
  }

  if (typeof password !== "string" || password.length < 8 || password.length > 128) {
    return sendError(res, 400, "Password must be 8-128 characters.");
  }

  let referrer = null;

  if (referralCode) {
    const ref = await pool.query(
      `SELECT id FROM users
       WHERE referral_code = $1
       AND role = 'affiliate'
       AND status = 'active'`,
      [referralCode]
    );

    if (!ref.rows.length) {
      return sendError(res, 400, "Invalid referral code.");
    }

    referrer = ref.rows[0].id;
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      `INSERT INTO users
       (username, email, password_hash, role, status, referred_by)
       VALUES ($1, $2, $3, 'user', 'active', $4)
       RETURNING id, username, email, role, status, balance, created_at`,
      [username, email, passwordHash, referrer]
    );

    const user = result.rows[0];

    await client.query(
      "INSERT INTO profiles (user_id) VALUES ($1)",
      [user.id]
    );

    const referralCodeForUser = "GLO" + user.id;

    await client.query(
      "UPDATE users SET referral_code = $1 WHERE id = $2",
      [referralCodeForUser, user.id]
    );

    await client.query("COMMIT");

    user.referral_code = referralCodeForUser;

    const token = createToken(user);

    setAuthCookie(res, token);

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      token,
      user
    });

  } catch (error) {
    await client.query("ROLLBACK");

    if (error.code === "23505") {
      return sendError(res, 409, "Username or email already exists.");
    }

    console.error("Register error:", error.message);
    return sendError(res, 500, "Registration failed.");

  } finally {
    client.release();
  }
}));


// ==========================================
// LOGIN
// POST /api/auth/login
// ==========================================

app.post("/api/auth/login", asyncRoute(async (req, res) => {
  const loginValue = cleanText(
    req.body.email || req.body.username || req.body.login,
    150
  ).toLowerCase();

  const password = req.body.password;

  if (!loginValue || typeof password !== "string") {
    return sendError(res, 400, "Login details are required.");
  }

  const result = await pool.query(
    `SELECT * FROM users
     WHERE email = $1 OR username = $1
     LIMIT 1`,
    [loginValue]
  );

  if (!result.rows.length) {
    return sendError(res, 401, "Invalid login details.");
  }

  const user = result.rows[0];

  const validPassword = await bcrypt.compare(
    password,
    user.password_hash
  );

  if (!validPassword) {
    return sendError(res, 401, "Invalid login details.");
  }

  if (user.status !== "active") {
    return sendError(res, 403, "Your account is not active.");
  }

  delete user.password_hash;

  const token = createToken(user);

  setAuthCookie(res, token);

  res.json({
    success: true,
    message: "Login successful.",
    token,
    user: publicUser(user)
  });
}));


// ==========================================
// LOGOUT
// POST /api/auth/logout
// ==========================================

app.post("/api/auth/logout", (req, res) => {
  clearAuthCookie(res);

  res.json({
    success: true,
    message: "Logged out successfully."
  });
});


// ==========================================
// CURRENT USER
// GET /api/auth/me
// ==========================================

app.get("/api/auth/me", authenticateToken, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT u.id, u.username, u.email, u.role, u.status,
            u.balance, u.referral_code, u.created_at,
            p.full_name, p.avatar, p.bio
     FROM users u
     LEFT JOIN profiles p ON p.user_id = u.id
     WHERE u.id = $1`,
    [req.user.id]
  );

  if (!result.rows.length) {
    return sendError(res, 404, "User not found.");
  }

  res.json({ success: true, user: result.rows[0] });
}));


// ==========================================
// PROFILE
// ==========================================

app.get("/api/profile", authenticateToken, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT u.id, u.username, u.email, u.role, u.balance,
            p.full_name, p.avatar, p.bio, p.updated_at
     FROM users u
     LEFT JOIN profiles p ON p.user_id = u.id
     WHERE u.id = $1`,
    [req.user.id]
  );

  res.json({
    success: true,
    profile: result.rows[0] || null
  });
}));

app.get("/api/profile/:username", asyncRoute(async (req, res) => {
  const username = cleanText(req.params.username, 30).toLowerCase();

  const result = await pool.query(
    `SELECT u.id, u.username, u.role,
            p.full_name, p.avatar, p.bio
     FROM users u
     LEFT JOIN profiles p ON p.user_id = u.id
     WHERE u.username = $1 AND u.status = 'active'`,
    [username]
  );

  if (!result.rows.length) {
    return sendError(res, 404, "Profile not found.");
  }

  res.json({ success: true, profile: result.rows[0] });
}));

app.put("/api/profile", authenticateToken, asyncRoute(async (req, res) => {
  const fullName = req.body.full_name;
  const avatar = req.body.avatar;
  const bio = req.body.bio;

  if (
    (fullName !== undefined &&
      (typeof fullName !== "string" || fullName.length > 100)) ||
    (avatar !== undefined &&
      (typeof avatar !== "string" || avatar.length > 200000)) ||
    (bio !== undefined &&
      (typeof bio !== "string" || bio.length > 300))
  ) {
    return sendError(res, 400, "Invalid profile information.");
  }

  const result = await pool.query(
    `INSERT INTO profiles (user_id, full_name, avatar, bio)
     VALUES ($4, COALESCE($1, ''), COALESCE($2, ''), COALESCE($3, ''))
     ON CONFLICT (user_id)
     DO UPDATE SET
       full_name = COALESCE($1, profiles.full_name),
       avatar = COALESCE($2, profiles.avatar),
       bio = COALESCE($3, profiles.bio),
       updated_at = NOW()
     RETURNING *`,
    [
      fullName === undefined ? null : fullName.trim(),
      avatar === undefined ? null : avatar,
      bio === undefined ? null : bio.trim(),
      req.user.id
    ]
  );

  res.json({
    success: true,
    message: "Profile updated.",
    profile: result.rows[0]
  });
}));


// ==========================================
// ADMIN: DASHBOARD
// ==========================================

app.get("/api/admin/dashboard", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const [users, moderators, affiliates, bets] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS total FROM users"),
    pool.query("SELECT COUNT(*)::int AS total FROM users WHERE role = 'moderator'"),
    pool.query("SELECT COUNT(*)::int AS total FROM users WHERE role = 'affiliate'"),
    pool.query("SELECT COUNT(*)::int AS total FROM demo_bets")
  ]);

  res.json({
    success: true,
    dashboard: {
      total_users: users.rows[0].total,
      total_moderators: moderators.rows[0].total,
      total_affiliates: affiliates.rows[0].total,
      total_demo_bets: bets.rows[0].total
    }
  });
}));


// ==========================================
// ADMIN: USERS
// ==========================================

app.get("/api/admin/users", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const search = cleanText(req.query.search, 100);

  const result = await pool.query(
    `SELECT id, username, email, role, status, balance,
            referral_code, created_at
     FROM users
     WHERE ($1 = '' OR username ILIKE '%' || $1 || '%'
            OR email ILIKE '%' || $1 || '%')
     ORDER BY created_at DESC
     LIMIT 200`,
    [search]
  );

  res.json({ success: true, users: result.rows });
}));

app.patch("/api/admin/users/:id/status", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const targetId = Number(req.params.id);
  const status = req.body.status;

  if (!Number.isSafeInteger(targetId) ||
      !["active", "suspended"].includes(status)) {
    return sendError(res, 400, "Invalid user or status.");
  }

  if (targetId === Number(req.user.id)) {
    return sendError(res, 400, "You cannot suspend your own account.");
  }

  const result = await pool.query(
    `UPDATE users SET status = $1, updated_at = NOW()
     WHERE id = $2 AND role <> 'admin'
     RETURNING id, username, status`,
    [status, targetId]
  );

  if (!result.rows.length) {
    return sendError(res, 404, "User not found or protected.");
  }

  await audit(req.user.id, "account_status_changed", targetId, { status });

  res.json({
    success: true,
    message: "Account status updated.",
    user: result.rows[0]
  });
}));

app.patch("/api/admin/users/:id/role", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const targetId = Number(req.params.id);
  const role = req.body.role;

  if (!Number.isSafeInteger(targetId) ||
      !["user", "moderator", "affiliate"].includes(role)) {
    return sendError(res, 400, "Invalid role or user.");
  }

  const result = await pool.query(
    `UPDATE users SET role = $1, updated_at = NOW()
     WHERE id = $2 AND role <> 'admin'
     RETURNING id, username, email, role, status`,
    [role, targetId]
  );

  if (!result.rows.length) {
    return sendError(res, 404, "User not found or protected.");
  }

  if (role === "moderator") {
    await pool.query(
      `INSERT INTO moderator_permissions (user_id, permissions)
       VALUES ($1, '{}'::jsonb)
       ON CONFLICT (user_id) DO NOTHING`,
      [targetId]
    );
  }

  await audit(req.user.id, "role_changed", targetId, { role });

  res.json({
    success: true,
    message: "User role updated.",
    user: result.rows[0]
  });
}));


// ==========================================
// ADMIN: MODERATORS
// ==========================================

app.get("/api/admin/moderators", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT u.id, u.username, u.email, u.status,
            mp.permissions
     FROM users u
     LEFT JOIN moderator_permissions mp ON mp.user_id = u.id
     WHERE u.role = 'moderator'
     ORDER BY u.created_at DESC`
  );

  res.json({ success: true, moderators: result.rows });
}));

app.post("/api/admin/moderators", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const username = cleanText(req.body.username, 30).toLowerCase();

  if (!validUsername(username)) {
    return sendError(res, 400, "Enter a valid username.");
  }

  const result = await pool.query(
    `UPDATE users SET role = 'moderator', updated_at = NOW()
     WHERE username = $1 AND role <> 'admin'
     RETURNING id, username, email, role`,
    [username]
  );

  if (!result.rows.length) {
    return sendError(res, 404, "User not found.");
  }

  await pool.query(
    `INSERT INTO moderator_permissions (user_id, permissions)
     VALUES ($1, '{}'::jsonb)
     ON CONFLICT (user_id) DO NOTHING`,
    [result.rows[0].id]
  );

  await audit(req.user.id, "moderator_added", result.rows[0].id);

  res.json({
    success: true,
    message: "Moderator added.",
    moderator: result.rows[0]
  });
}));

app.put("/api/admin/moderators/:id/permissions",
authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const targetId = Number(req.params.id);
  const permissions = req.body.permissions;

  const allowedPermissions = [
    "manage_users",
    "manage_profiles",
    "manage_results",
    "view_reports",
    "manage_affiliates"
  ];

  if (!Number.isSafeInteger(targetId) ||
      !permissions || typeof permissions !== "object" ||
      Array.isArray(permissions)) {
    return sendError(res, 400, "Invalid permission information.");
  }

  const cleanPermissions = {};

  for (const key of allowedPermissions) {
    cleanPermissions[key] = permissions[key] === true;
  }

  const moderator = await pool.query(
    "SELECT id FROM users WHERE id = $1 AND role = 'moderator'",
    [targetId]
  );

  if (!moderator.rows.length) {
    return sendError(res, 404, "Moderator not found.");
  }

  const result = await pool.query(
    `INSERT INTO moderator_permissions (user_id, permissions)
     VALUES ($1, $2)
     ON CONFLICT (user_id)
     DO UPDATE SET permissions = $2, updated_at = NOW()
     RETURNING *`,
    [targetId, JSON.stringify(cleanPermissions)]
  );

  await audit(req.user.id, "moderator_permissions_updated", targetId);

  res.json({
    success: true,
    message: "Moderator permissions updated.",
    permissions: result.rows[0].permissions
  });
}));

app.delete("/api/admin/moderators/:id", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const targetId = Number(req.params.id);

  const result = await pool.query(
    `UPDATE users SET role = 'user', updated_at = NOW()
     WHERE id = $1 AND role = 'moderator'
     RETURNING id, username, role`,
    [targetId]
  );

  if (!result.rows.length) {
    return sendError(res, 404, "Moderator not found.");
  }

  await pool.query(
    "DELETE FROM moderator_permissions WHERE user_id = $1",
    [targetId]
  );

  await audit(req.user.id, "moderator_removed", targetId);

  res.json({
    success: true,
    message: "Moderator removed.",
    user: result.rows[0]
  });
}));


// ==========================================
// MODERATOR
// ==========================================

app.get("/api/moderator/users", authenticateToken,
requirePermission("manage_users"),
asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, username, role, status, created_at
     FROM users
     ORDER BY created_at DESC
     LIMIT 200`
  );

  res.json({ success: true, users: result.rows });
}));

app.patch("/api/moderator/profiles/:id",
authenticateToken, requirePermission("manage_profiles"),
asyncRoute(async (req, res) => {
  const targetId = Number(req.params.id);

  if (!Number.isSafeInteger(targetId)) {
    return sendError(res, 400, "Invalid user ID.");
  }

  const fullName = req.body.full_name;
  const bio = req.body.bio;

  if (
    (fullName !== undefined &&
      (typeof fullName !== "string" || fullName.length > 100)) ||
    (bio !== undefined &&
      (typeof bio !== "string" || bio.length > 300))
  ) {
    return sendError(res, 400, "Invalid profile information.");
  }

  const result = await pool.query(
    `INSERT INTO profiles (user_id, full_name, bio)
     VALUES ($1, COALESCE($2, ''), COALESCE($3, ''))
     ON CONFLICT (user_id)
     DO UPDATE SET
       full_name = COALESCE($2, profiles.full_name),
       bio = COALESCE($3, profiles.bio),
       updated_at = NOW()
     RETURNING *`,
    [
      targetId,
      fullName === undefined ? null : fullName.trim(),
      bio === undefined ? null : bio.trim()
    ]
  );

  await audit(req.user.id, "moderator_profile_updated", targetId);

  res.json({ success: true, profile: result.rows[0] });
}));


// ==========================================
// AFFILIATE
// ==========================================

app.get("/api/affiliate/me", authenticateToken,
asyncRoute(async (req, res) => {
  if (!["affiliate", "admin"].includes(req.user.role)) {
    return sendError(res, 403, "Affiliate access required.");
  }

  const info = await pool.query(
    "SELECT referral_code FROM users WHERE id = $1",
    [req.user.id]
  );

  const referrals = await pool.query(
    "SELECT COUNT(*)::int AS total FROM users WHERE referred_by = $1",
    [req.user.id]
  );

  const commissions = await pool.query(
    `SELECT COALESCE(SUM(amount), 0) AS total,
            COUNT(*)::int AS entries
     FROM affiliate_commissions
     WHERE affiliate_id = $1`,
    [req.user.id]
  );

  res.json({
    success: true,
    referral_code: info.rows[0]?.referral_code,
    total_referrals: referrals.rows[0].total,
    commissions: commissions.rows[0]
  });
}));

app.get("/api/admin/affiliates", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT u.id, u.username, u.email, u.referral_code,
            COUNT(r.id)::int AS referral_count
     FROM users u
     LEFT JOIN users r ON r.referred_by = u.id
     WHERE u.role = 'affiliate'
     GROUP BY u.id
     ORDER BY u.created_at DESC`
  );

  res.json({ success: true, affiliates: result.rows });
}));

app.post("/api/admin/affiliates/:id/commissions",
authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const affiliateId = Number(req.params.id);
  const amount = Number(req.body.amount);
  const description = cleanText(req.body.description, 300);

  if (!Number.isSafeInteger(affiliateId) ||
      !Number.isFinite(amount) || amount <= 0 || amount > 1000000) {
    return sendError(res, 400, "Invalid commission information.");
  }

  const affiliate = await pool.query(
    "SELECT id FROM users WHERE id = $1 AND role = 'affiliate'",
    [affiliateId]
  );

  if (!affiliate.rows.length) {
    return sendError(res, 404, "Affiliate not found.");
  }

  const referredUserId = req.body.referred_user_id || affiliateId;

  const referredUser = await pool.query(
    "SELECT id FROM users WHERE id = $1",
    [referredUserId]
  );

  if (!referredUser.rows.length) {
    return sendError(res, 400, "Referred user not found.");
  }

  const result = await pool.query(
    `INSERT INTO affiliate_commissions
     (affiliate_id, referred_user_id, amount, description, status)
     VALUES ($1, $2, $3, $4, 'pending')
     RETURNING *`,
    [affiliateId, referredUserId, amount, description]
  );

  await audit(req.user.id, "affiliate_commission_recorded", affiliateId);

  res.status(201).json({
    success: true,
    commission: result.rows[0]
  });
}));


// ==========================================
// ADMIN MESSAGE MANAGEMENT
// GET/POST /api/admin/messages
// ==========================================

app.get("/api/admin/messages", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, text, active, updated_by, updated_at
     FROM admin_messages
     ORDER BY updated_at DESC
     LIMIT 50`
  );

  res.json({
    success: true,
    messages: result.rows
  });
}));

app.post("/api/admin/messages", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const message = cleanText(req.body.text, 300);

  if (!message) {
    return sendError(res, 400, "Message is required.");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(
      "UPDATE admin_messages SET active = FALSE WHERE active = TRUE"
    );

    const result = await client.query(
      `INSERT INTO admin_messages (text, active, updated_by)
       VALUES ($1, TRUE, $2)
       RETURNING id, text, active, updated_at`,
      [message, req.user.id]
    );

    await client.query("COMMIT");

    await audit(req.user.id, "admin_message_published", null, {
      message_id: result.rows[0].id
    });

    res.status(201).json({
      success: true,
      message: "Admin message published.",
      data: result.rows[0]
    });

  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

app.post("/api/admin/messages/disable", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  await pool.query(
    "UPDATE admin_messages SET active = FALSE WHERE active = TRUE"
  );

  await audit(req.user.id, "admin_message_disabled");

  res.json({
    success: true,
    message: "Admin message disabled."
  });
}));

app.get("/api/public/admin-message", asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, text, active, updated_at
     FROM admin_messages
     WHERE active = TRUE
     ORDER BY updated_at DESC
     LIMIT 1`
  );

  res.json({
    success: true,
    message: result.rows[0] || null
  });
}));


// ==========================================
// LIVE EVENT MANAGEMENT
// ==========================================

app.get("/api/admin/live-event", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, title, url, platform, active, updated_at
     FROM admin_live_events
     ORDER BY updated_at DESC
     LIMIT 1`
  );

  res.json({
    success: true,
    event: result.rows[0] || null
  });
}));

app.post("/api/admin/live-event", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const title = cleanText(req.body.title, 80);
  const url = cleanText(req.body.url, 1000);
  const platform = cleanText(req.body.platform, 20).toLowerCase();

  if (!title || !url) {
    return sendError(res, 400, "Event title and URL are required.");
  }

  if (!["youtube", "facebook"].includes(platform)) {
    return sendError(res, 400, "Platform must be YouTube or Facebook.");
  }

  if (!validExternalEventUrl(url, platform)) {
    return sendError(res, 400, "Please enter a valid HTTPS URL for the selected platform.");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(
      "UPDATE admin_live_events SET active = FALSE WHERE active = TRUE"
    );

    const result = await client.query(
      `INSERT INTO admin_live_events
       (title, url, platform, active, updated_by)
       VALUES ($1, $2, $3, TRUE, $4)
       RETURNING id, title, url, platform, active, updated_at`,
      [title, url, platform, req.user.id]
    );

    await client.query("COMMIT");

    await audit(req.user.id, "live_event_started", null, {
      event_id: result.rows[0].id,
      platform
    });

    res.status(201).json({
      success: true,
      message: "Live event published.",
      event: result.rows[0]
    });

  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

app.post("/api/admin/live-event/disable",
authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  await pool.query(
    "UPDATE admin_live_events SET active = FALSE WHERE active = TRUE"
  );

  await audit(req.user.id, "live_event_disabled");

  res.json({
    success: true,
    message: "Live event disabled."
  });
}));

app.get("/api/public/live-event", asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, title, url, platform, active, updated_at
     FROM admin_live_events
     WHERE active = TRUE
     ORDER BY updated_at DESC
     LIMIT 1`
  );

  res.json({
    success: true,
    event: result.rows[0] || null
  });
}));


// ==========================================
// DEMO WALLET
// TEST CREDIT ONLY - NOT REAL MONEY
// ==========================================

app.get("/api/wallet", authenticateToken,
asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT balance FROM users WHERE id = $1",
    [req.user.id]
  );

  res.json({
    success: true,
    currency: "DEMO",
    is_demo: true,
    balance: result.rows[0].balance
  });
}));

app.get("/api/wallet/transactions", authenticateToken,
asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, type, amount, currency, description, reference, created_at
     FROM wallet_transactions
     WHERE user_id = $1
     ORDER BY created_at DESC
     LIMIT 100`,
    [req.user.id]
  );

  res.json({
    success: true,
    currency: "DEMO",
    transactions: result.rows
  });
}));


// ==========================================
// CREATE DEMO BET
// ==========================================

app.post("/api/demo/bets", authenticateToken,
asyncRoute(async (req, res) => {
  const gameName = cleanText(req.body.game_name, 100);
  const selection = cleanText(req.body.selection, 100);
  const amount = Number(req.body.amount);

  if (!gameName || !selection ||
      !Number.isFinite(amount) || amount <= 0 || amount > 100000) {
    return sendError(res, 400, "Invalid demo bet information.");
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const userResult = await client.query(
      "SELECT balance FROM users WHERE id = $1 FOR UPDATE",
      [req.user.id]
    );

    if (!userResult.rows.length) {
      await client.query("ROLLBACK");
      return sendError(res, 404, "User not found.");
    }

    if (Number(userResult.rows[0].balance) < amount) {
      await client.query("ROLLBACK");
      return sendError(res, 400, "Insufficient demo balance.");
    }

    await client.query(
      "UPDATE users SET balance = balance - $1 WHERE id = $2",
      [amount, req.user.id]
    );

    const betResult = await client.query(
      `INSERT INTO demo_bets
       (user_id, game_name, selection, amount)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [req.user.id, gameName, selection, amount]
    );

    await client.query(
      `INSERT INTO wallet_transactions
       (user_id, type, amount, currency, description, reference)
       VALUES ($1, 'demo_bet', $2, 'DEMO', $3, $4)`,
      [
        req.user.id,
        -amount,
        "Demo test entry",
        "BET-" + betResult.rows[0].id
      ]
    );

    await client.query("COMMIT");

    res.status(201).json({
      success: true,
      message: "Demo bet created.",
      bet: betResult.rows[0]
    });

  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Demo bet error:", error.message);
    return sendError(res, 500, "Could not create demo bet.");

  } finally {
    client.release();
  }
}));

app.get("/api/demo/bets", authenticateToken,
asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, game_name, selection, amount, status, created_at
     FROM demo_bets
     WHERE user_id = $1
     ORDER BY created_at DESC
     LIMIT 100`,
    [req.user.id]
  );

  res.json({ success: true, bets: result.rows });
}));


// ==========================================
// DEMO RESULTS
// ==========================================

app.get("/api/results", asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, game_name, result, created_at
     FROM demo_results
     ORDER BY created_at DESC
     LIMIT 100`
  );

  res.json({ success: true, results: result.rows });
}));

app.post("/api/admin/results", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const gameName = cleanText(req.body.game_name, 100);
  const resultValue = cleanText(req.body.result, 100);

  if (!gameName || !resultValue) {
    return sendError(res, 400, "Game name and result are required.");
  }

  const result = await pool.query(
    `INSERT INTO demo_results (game_name, result)
     VALUES ($1, $2)
     RETURNING *`,
    [gameName, resultValue]
  );

  await audit(req.user.id, "demo_result_published", null, {
    result_id: result.rows[0].id
  });

  res.status(201).json({
    success: true,
    message: "Demo result published.",
    result: result.rows[0]
  });
}));


// ==========================================
// ADMIN: AUDIT LOGS
// ==========================================

app.get("/api/admin/audit-logs", authenticateToken, requireAdmin,
asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, actor_id, action, target_user_id, details, created_at
     FROM audit_logs
     ORDER BY created_at DESC
     LIMIT 200`
  );

  res.json({ success: true, logs: result.rows });
}));


// ==========================================
// 404
// ==========================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found."
  });
});


// ==========================================
// GLOBAL ERROR HANDLER
// ==========================================

app.use((error, req, res, next) => {
  console.error("Server error:", error.message);

  if (error.type === "entity.parse.failed") {
    return sendError(res, 400, "Invalid JSON request.");
  }

  res.status(500).json({
    success: false,
    message: "Internal server error."
  });
});


// ==========================================
// START SERVER
// ==========================================

async function startServer() {
  try {
    await initializeDatabase();
    await bootstrapAdmin();

    app.listen(PORT, "0.0.0.0", () => {
      console.log("GLO 365 API v2.1.0 running on port " + PORT);
    });

  } catch (error) {
    console.error("Server startup failed:", error.message);
    process.exit(1);
  }
}

startServer();