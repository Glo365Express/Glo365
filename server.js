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
    const DRAW_LOCK_MINUTES = 45;

    // Only this username can ever have the admin role.
    const PRIMARY_ADMIN_USERNAME = "adminglo365";

    if (!JWT_SECRET || JWT_SECRET.length < 32) {
      console.error("ERROR: JWT_SECRET must be at least 32 characters.");
      process.exit(1);
    }

    if (!DATABASE_URL) {
      console.error("ERROR: DATABASE_URL is missing.");
      process.exit(1);
    }

    const allowedOrigins = (process.env.FRONTEND_URL || "")
      .split(",")
      .map(x => x.trim().replace(/\/+$/, ""))
      .filter(Boolean);

    if (process.env.NODE_ENV === "production" && !allowedOrigins.length) {
      console.error("ERROR: FRONTEND_URL must be configured in production.");
      process.exit(1);
    }

    app.disable("x-powered-by");
    app.use(express.json({ limit: "1mb" }));

    // ==========================================
    // CORS SECURITY
    // ==========================================

    app.use(cors({
      origin: (origin, callback) => {
        if (!origin) return callback(null, true);

        if (allowedOrigins.includes(origin.replace(/\/+$/, ""))) {
          return callback(null, true);
        }

        if (
          process.env.NODE_ENV !== "production" &&
          [
            "http://localhost:3000",
            "http://localhost:5500",
            "http://127.0.0.1:5500"
          ].includes(origin)
        ) {
          return callback(null, true);
        }

        return callback(new Error("Origin not allowed."));
      },
      credentials: true,
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization"]
    }));

    app.use((req, res, next) => {
      const origin = req.headers.origin;

      if (!origin) return next();

      const normalizedOrigin = origin.replace(/\/+$/, "");

      const localAllowed =
        process.env.NODE_ENV !== "production" &&
        [
          "http://localhost:3000",
          "http://localhost:5500",
          "http://127.0.0.1:5500"
        ].includes(origin);

      if (!allowedOrigins.includes(normalizedOrigin) && !localAllowed) {
        return res.status(403).json({
          success: false,
          message: "Origin not allowed."
        });
      }

      next();
    });

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
      return res.status(status).json({
        success: false,
        message
      });
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
        {
          id: user.id,
          username: user.username
        },
        JWT_SECRET,
        {
          expiresIn: "7d",
          issuer: "glo365"
        }
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

      for (const part of header.split(";")) {
        const index = part.indexOf("=");
        if (index < 0) continue;

        const key = part.slice(0, index).trim();

        if (key === name) {
          try {
            return decodeURIComponent(part.slice(index + 1).trim());
          } catch {
            return null;
          }
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

    function validId(value) {
      const id = Number(value);

      return Number.isSafeInteger(id) && id > 0
        ? id
        : null;
    }

    // ==========================================
    // DRAW DATE VALIDATION
    // ==========================================

    function validDrawDate(value) {
      if (typeof value !== "string" || !value.trim()) {
        return false;
      }

      return Number.isFinite(Date.parse(value));
    }

    async function getCurrentDraw(client = pool) {
      const result = await client.query(
        `SELECT id, draw_number, draw_at, updated_by, updated_at
         FROM draw_settings
         WHERE id = 1
         LIMIT 1`
      );

      return result.rows[0] || null;
    }

    function isDrawBettingLocked(draw) {
      if (!draw || !draw.draw_at) return true;

      const drawTime = new Date(draw.draw_at).getTime();

      if (!Number.isFinite(drawTime)) return true;

      return drawTime - Date.now() <= DRAW_LOCK_MINUTES * 60 * 1000;
    }

    // ==========================================
    // 3UP AMOUNT VALIDATION HELPERS
    // ==========================================

    function amountToCents(value) {
      if (value === "" || value === null || value === undefined) return 0;

      const number = Number(value);

      if (
        !Number.isFinite(number) ||
        number < 0 ||
        number > 100000 ||
        Math.round(number * 100) !== number * 100
      ) {
        return null;
      }

      return Math.round(number * 100);
    }

    function centsToAmount(cents) {
      return (cents / 100).toFixed(2);
    }

    // ==========================================
    // DATABASE INITIALIZATION
    // Existing records are preserved.
    // ==========================================

    async function initializeDatabase() {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id BIGSERIAL PRIMARY KEY,
          username VARCHAR(30) UNIQUE NOT NULL,
          email VARCHAR(150) UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          balance NUMERIC(12,2) NOT NULL DEFAULT 100.00,
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

        -- New structured draw results. Legacy demo_results are left untouched.
        CREATE TABLE IF NOT EXISTS draw_results (
          id BIGSERIAL PRIMARY KEY,
          draw_date DATE NOT NULL UNIQUE,
          first_prize VARCHAR(6) NOT NULL,
          last_two VARCHAR(2) NOT NULL,
          front_three JSONB NOT NULL DEFAULT '[]'::jsonb,
          published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL
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

        -- Manual deposit review and payment-method library. Existing wallet data is preserved.
        CREATE TABLE IF NOT EXISTS payment_methods (
          id BIGSERIAL PRIMARY KEY,
          preset VARCHAR(40) NOT NULL DEFAULT 'Custom',
          name VARCHAR(60) NOT NULL,
          label VARCHAR(60) NOT NULL DEFAULT '',
          account VARCHAR(150) NOT NULL DEFAULT '',
          currency VARCHAR(10) NOT NULL DEFAULT 'BDT',
          instructions TEXT NOT NULL DEFAULT '',
          active BOOLEAN NOT NULL DEFAULT TRUE,
          created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
          updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS deposit_requests (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          payment_method_id BIGINT REFERENCES payment_methods(id) ON DELETE SET NULL,
          method VARCHAR(60) NOT NULL,
          payment_account VARCHAR(150) NOT NULL DEFAULT '',
          currency VARCHAR(10) NOT NULL DEFAULT 'BDT',
          amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
          sender_account VARCHAR(150) NOT NULL DEFAULT '',
          transaction_id VARCHAR(150) NOT NULL,
          status VARCHAR(20) NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending','approved','rejected')),
          credited_points NUMERIC(12,2),
          rejection_reason VARCHAR(200) NOT NULL DEFAULT '',
          reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
          reviewed_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_deposit_requests_status_date
          ON deposit_requests(status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_deposit_requests_user_date
          ON deposit_requests(user_id, created_at DESC);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_deposit_transaction_unique
          ON deposit_requests(LOWER(transaction_id));


        -- Withdrawal requests are stored server-side; review changes status only.
        CREATE TABLE IF NOT EXISTS withdrawal_requests (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
          method VARCHAR(80) NOT NULL,
          account VARCHAR(180) NOT NULL,
          status VARCHAR(20) NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending','approved','rejected')),
          reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
          reviewed_at TIMESTAMPTZ,
          rejection_reason VARCHAR(200) NOT NULL DEFAULT '',
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_status_date
          ON withdrawal_requests(status, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_withdrawal_requests_user_date
          ON withdrawal_requests(user_id, created_at DESC);

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

        CREATE TABLE IF NOT EXISTS draw_settings (
          id SMALLINT PRIMARY KEY CHECK (id = 1),
          draw_number VARCHAR(50) NOT NULL DEFAULT '',
          draw_at TIMESTAMPTZ,
          updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
          updated_at TIMESTAMPTZ DEFAULT NOW()
        );

        INSERT INTO draw_settings (id, draw_number)
        VALUES (1, '')
        ON CONFLICT (id) DO NOTHING;

        -- Dedicated 3UP records; existing Single/game records are untouched.
        CREATE TABLE IF NOT EXISTS demo_3up_bets (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          draw_number VARCHAR(50) NOT NULL DEFAULT '',
          rows JSONB NOT NULL,
          total_amount NUMERIC(12,2) NOT NULL CHECK (total_amount > 0),
          discount_percent NUMERIC(5,2) NOT NULL DEFAULT 0
            CHECK (discount_percent BETWEEN 0 AND 100),
          discount_amount NUMERIC(12,2) NOT NULL DEFAULT 0
            CHECK (discount_amount >= 0),
          payable_amount NUMERIC(12,2) NOT NULL CHECK (payable_amount > 0),
          status VARCHAR(20) NOT NULL DEFAULT 'pending',
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS demo_3up_settings (
          id SMALLINT PRIMARY KEY CHECK (id = 1),
          discount_percent NUMERIC(5,2) NOT NULL DEFAULT 0
            CHECK (discount_percent BETWEEN 0 AND 100),
          updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
          updated_at TIMESTAMPTZ DEFAULT NOW()
        );

        INSERT INTO demo_3up_settings (id, discount_percent)
        VALUES (1, 0)
        ON CONFLICT (id) DO NOTHING;

        -- Dedicated 6UP demo records; existing games and 3UP data are untouched.
        CREATE TABLE IF NOT EXISTS demo_6up_bets (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          draw_number VARCHAR(50) NOT NULL DEFAULT '',
          rows JSONB NOT NULL,
          total_amount NUMERIC(12,2) NOT NULL CHECK (total_amount > 0),
          discount_percent NUMERIC(5,2) NOT NULL DEFAULT 0
            CHECK (discount_percent BETWEEN 0 AND 100),
          discount_amount NUMERIC(12,2) NOT NULL DEFAULT 0
            CHECK (discount_amount >= 0),
          payable_amount NUMERIC(12,2) NOT NULL CHECK (payable_amount > 0),
          status VARCHAR(20) NOT NULL DEFAULT 'pending',
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS demo_6up_settings (
          id SMALLINT PRIMARY KEY CHECK (id = 1),
          discount_percent NUMERIC(5,2) NOT NULL DEFAULT 0
            CHECK (discount_percent BETWEEN 0 AND 100),
          updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
          updated_at TIMESTAMPTZ DEFAULT NOW()
        );

        INSERT INTO demo_6up_settings (id, discount_percent)
        VALUES (1, 0)
        ON CONFLICT (id) DO NOTHING;

        ALTER TABLE demo_bets ADD COLUMN IF NOT EXISTS draw_date DATE;
        ALTER TABLE demo_bets ADD COLUMN IF NOT EXISTS result_id BIGINT REFERENCES draw_results(id) ON DELETE SET NULL;
        ALTER TABLE demo_3up_bets ADD COLUMN IF NOT EXISTS draw_date DATE;
        ALTER TABLE demo_3up_bets ADD COLUMN IF NOT EXISTS result_id BIGINT REFERENCES draw_results(id) ON DELETE SET NULL;
        ALTER TABLE demo_6up_bets ADD COLUMN IF NOT EXISTS draw_date DATE;
        ALTER TABLE demo_6up_bets ADD COLUMN IF NOT EXISTS result_id BIGINT REFERENCES draw_results(id) ON DELETE SET NULL;
        CREATE INDEX IF NOT EXISTS idx_draw_results_date ON draw_results(draw_date DESC);
        CREATE INDEX IF NOT EXISTS idx_demo_bets_draw_date ON demo_bets(draw_date, status);
        CREATE INDEX IF NOT EXISTS idx_demo_3up_draw_date ON demo_3up_bets(draw_date, status);
        CREATE INDEX IF NOT EXISTS idx_demo_6up_draw_date ON demo_6up_bets(draw_date, status);

        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_demo_bets_user ON demo_bets(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_wallet_user ON wallet_transactions(user_id);
        CREATE INDEX IF NOT EXISTS idx_affiliate_user ON affiliate_commissions(affiliate_id);
        CREATE INDEX IF NOT EXISTS idx_affiliate_referred_user ON affiliate_commissions(referred_user_id);
        CREATE INDEX IF NOT EXISTS idx_admin_messages_active ON admin_messages(active);
        CREATE INDEX IF NOT EXISTS idx_admin_live_events_active ON admin_live_events(active);
        CREATE INDEX IF NOT EXISTS idx_draw_settings_time ON draw_settings(draw_at);
        CREATE INDEX IF NOT EXISTS idx_demo_3up_user
          ON demo_3up_bets(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_demo_6up_user
          ON demo_6up_bets(user_id, created_at DESC);
      `);

      // Apply the 100-point default to the EXISTING PostgreSQL users table too.
      // CREATE TABLE IF NOT EXISTS does not update defaults on an existing table.
      // This changes only the default for future accounts; existing balances stay untouched.
      await pool.query(`
        ALTER TABLE users
        ALTER COLUMN balance SET DEFAULT 100.00
      `);

      // Keep existing accounts and their data.
      // Any previous admin other than the permanent owner becomes a normal user.
      await pool.query(`
        UPDATE users
        SET role = 'user',
            updated_at = NOW()
        WHERE role = 'admin'
          AND username <> 'adminglo365'
      `);

      // Restore the permanent owner's active/admin status if the account exists.
      await pool.query(`
        UPDATE users
        SET role = 'admin',
            status = 'active',
            updated_at = NOW()
        WHERE username = 'adminglo365'
      `);

      await pool.query(`
        UPDATE users
        SET referral_code = 'GLO' || id
        WHERE referral_code IS NULL
      `);

      // At most one admin can exist.
      await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_single_admin
        ON users (role)
        WHERE role = 'admin'
      `);

      // Live Support tables. CREATE IF NOT EXISTS preserves existing application data.
      await pool.query(`
        CREATE TABLE IF NOT EXISTS support_conversations (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS support_messages (
          id BIGSERIAL PRIMARY KEY,
          conversation_id BIGINT NOT NULL REFERENCES support_conversations(id) ON DELETE CASCADE,
          sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          sender_role VARCHAR(10) NOT NULL CHECK (sender_role IN ('user','admin')),
          message TEXT NOT NULL CHECK (char_length(message) BETWEEN 1 AND 5000),
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_support_messages_conversation
          ON support_messages(conversation_id, created_at, id);
        CREATE INDEX IF NOT EXISTS idx_support_conversations_updated
          ON support_conversations(updated_at DESC);
      `);

      console.log("GLO 365 database initialized.");
    }

    // ==========================================
    // PRIMARY ADMIN DATABASE PROTECTION
    // Install after bootstrap so initial promotion can happen.
    // ==========================================

    async function installPrimaryAdminProtection() {
      await pool.query(`
        CREATE OR REPLACE FUNCTION glo365_protect_primary_admin()
        RETURNS TRIGGER AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            IF OLD.username = 'adminglo365' AND OLD.role = 'admin' THEN
              RAISE EXCEPTION 'Primary Admin account cannot be deleted.';
            END IF;

            RETURN OLD;
          END IF;

          IF NEW.role = 'admin' AND NEW.username <> 'adminglo365' THEN
            RAISE EXCEPTION 'Only adminglo365 can have the admin role.';
          END IF;

          IF OLD.username = 'adminglo365' AND OLD.role = 'admin' THEN
            IF NEW.username <> 'adminglo365'
               OR NEW.role <> 'admin'
               OR NEW.status <> 'active' THEN
              RAISE EXCEPTION 'Primary Admin account is protected.';
            END IF;
          END IF;

          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;

        DROP TRIGGER IF EXISTS trg_glo365_protect_primary_admin ON users;

        CREATE TRIGGER trg_glo365_protect_primary_admin
        BEFORE UPDATE OR DELETE ON users
        FOR EACH ROW
        EXECUTE FUNCTION glo365_protect_primary_admin();

        DROP TRIGGER IF EXISTS trg_glo365_only_primary_admin_insert ON users;

        CREATE TRIGGER trg_glo365_only_primary_admin_insert
        BEFORE INSERT ON users
        FOR EACH ROW
        WHEN (NEW.role = 'admin')
        EXECUTE FUNCTION glo365_protect_primary_admin();
      `);
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
          [
            actorId || null,
            action,
            targetUserId,
            JSON.stringify(details)
          ]
        );
      } catch (error) {
        console.error("Audit log error:", error.message);
      }
    }

    // ==========================================
    // AUTHENTICATION
    // ==========================================

    async function authenticateToken(req, res, next) {
      const authHeader = req.headers.authorization || "";
      let token = null;

      if (authHeader.startsWith("Bearer ")) {
        token = authHeader.substring(7).trim();
      }

      if (!token) token = getCookie(req, AUTH_COOKIE);

      if (!token) {
        return sendError(res, 401, "Authentication required.");
      }

      let decoded;

      try {
        decoded = jwt.verify(token, JWT_SECRET, {
          issuer: "glo365"
        });
      } catch {
        return sendError(res, 401, "Invalid or expired token.");
      }

      try {
        const result = await pool.query(
          `SELECT id, username, email, role, status
           FROM users
           WHERE id = $1`,
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
        return next();

      } catch (error) {
        console.error("Authentication database error:", error.message);

        return sendError(
          res,
          500,
          "Authentication service temporarily unavailable."
        );
      }
    }

    // ==========================================
    // ROLE & PERMISSION CHECKS
    // ==========================================

    function isPrimaryAdmin(user) {
      return Boolean(
        user &&
        user.role === "admin" &&
        user.username === PRIMARY_ADMIN_USERNAME
      );
    }

    function requireAdmin(req, res, next) {
      if (!isPrimaryAdmin(req.user)) {
        return sendError(res, 403, "Primary Admin access required.");
      }

      next();
    }

    function requirePermission(permission) {
      return asyncRoute(async (req, res, next) => {
        if (isPrimaryAdmin(req.user)) return next();

        if (req.user.role !== "moderator") {
          return sendError(res, 403, "Permission denied.");
        }

        const result = await pool.query(
          `SELECT permissions
           FROM moderator_permissions
           WHERE user_id = $1`,
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
    // BOOTSTRAP SINGLE PRIMARY ADMIN
    // ==========================================

    async function bootstrapAdmin() {
      const username = PRIMARY_ADMIN_USERNAME;

      const email = cleanText(
        process.env.BOOTSTRAP_ADMIN_EMAIL,
        150
      ).toLowerCase();

      const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;

      const existing = await pool.query(
        `SELECT id, username
         FROM users
         WHERE username = $1
         LIMIT 1`,
        [username]
      );

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        let adminId;

        // Demote all previous admin accounts first.
        await client.query(
          `UPDATE users
           SET role = 'user',
               updated_at = NOW()
           WHERE role = 'admin'
             AND username <> $1`,
          [username]
        );

        if (existing.rows.length) {
          adminId = existing.rows[0].id;

          // Existing owner's password and email are preserved.
          await client.query(
            `UPDATE users
             SET role = 'admin',
                 status = 'active',
                 updated_at = NOW()
             WHERE id = $1`,
            [adminId]
          );

        } else {
          if (
            !email ||
            !validEmail(email) ||
            typeof password !== "string" ||
            password.length < 12 ||
            password.length > 128
          ) {
            throw new Error(
              "Primary Admin does not exist. Set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD (minimum 12 characters) in Render."
            );
          }

          const emailOwner = await client.query(
            "SELECT id FROM users WHERE email = $1 LIMIT 1",
            [email]
          );

          if (emailOwner.rows.length) {
            throw new Error(
              "BOOTSTRAP_ADMIN_EMAIL is already used by another account."
            );
          }

          const passwordHash = await bcrypt.hash(password, 12);

          const created = await client.query(
            `INSERT INTO users
             (username, email, password_hash, role, status, referral_code)
             VALUES ($1, $2, $3, 'admin', 'active', 'GLOADMIN')
             RETURNING id`,
            [username, email, passwordHash]
          );

          adminId = created.rows[0].id;

          await client.query(
            `INSERT INTO profiles (user_id)
             VALUES ($1)
             ON CONFLICT (user_id) DO NOTHING`,
            [adminId]
          );
        }

        await client.query(
          `DELETE FROM moderator_permissions
           WHERE user_id = $1`,
          [adminId]
        );

        await client.query("COMMIT");

        console.log("Single Primary Admin ready: adminglo365.");

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
        version: "2.6.0"
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
        return sendError(
          res,
          400,
          "Username must be 3-30 characters using letters, numbers or underscore."
        );
      }

      if (!validEmail(email)) {
        return sendError(res, 400, "Please enter a valid email address.");
      }

      if (username === PRIMARY_ADMIN_USERNAME) {
        return sendError(res, 409, "This username is reserved.");
      }

      if (
        typeof password !== "string" ||
        password.length < 8 ||
        password.length > 128
      ) {
        return sendError(res, 400, "Password must be 8-128 characters.");
      }

      let referrer = null;

      if (referralCode) {
        const ref = await pool.query(
          `SELECT id
           FROM users
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
        `SELECT *
         FROM users
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
    // ==========================================

    app.get(
      "/api/auth/me",
      authenticateToken,
      asyncRoute(async (req, res) => {
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

        res.json({
          success: true,
          user: result.rows[0]
        });
      })
    );

    // ==========================================
    // PROFILE
    // ==========================================

    app.get(
      "/api/profile",
      authenticateToken,
      asyncRoute(async (req, res) => {
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
      })
    );

    app.get(
      "/api/profile/:username",
      asyncRoute(async (req, res) => {
        const username = cleanText(req.params.username, 30).toLowerCase();

        const result = await pool.query(
          `SELECT u.id, u.username, u.role,
                  p.full_name, p.avatar, p.bio
           FROM users u
           LEFT JOIN profiles p ON p.user_id = u.id
           WHERE u.username = $1
             AND u.status = 'active'`,
          [username]
        );

        if (!result.rows.length) {
          return sendError(res, 404, "Profile not found.");
        }

        res.json({
          success: true,
          profile: result.rows[0]
        });
      })
    );

    app.put(
      "/api/profile",
      authenticateToken,
      asyncRoute(async (req, res) => {
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
      })
    );

    // ==========================================
    // ADMIN: DRAW SETTINGS
    // ==========================================

    app.get(
      "/api/admin/draw-settings",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const drawSettings = await getCurrentDraw();

        res.json({
          success: true,
          drawSettings
        });
      })
    );

    app.put(
      "/api/admin/draw-settings",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const drawNumber = cleanText(req.body.draw_number, 50);
        const drawAt = req.body.draw_at;

        if (!drawNumber) {
          return sendError(res, 400, "Draw Number is required.");
        }

        if (!validDrawDate(drawAt)) {
          return sendError(res, 400, "A valid Draw Date and Time is required.");
        }

        const drawTimestamp = new Date(drawAt);

        if (drawTimestamp.getTime() <= Date.now()) {
          return sendError(
            res,
            400,
            "Draw Date and Time must be in the future."
          );
        }

        const client = await pool.connect();

        try {
          await client.query("BEGIN");

          const result = await client.query(
            `INSERT INTO draw_settings
             (id, draw_number, draw_at, updated_by, updated_at)
             VALUES (1, $1, $2, $3, NOW())
             ON CONFLICT (id)
             DO UPDATE SET
               draw_number = EXCLUDED.draw_number,
               draw_at = EXCLUDED.draw_at,
               updated_by = EXCLUDED.updated_by,
               updated_at = NOW()
             RETURNING id, draw_number, draw_at, updated_by, updated_at`,
            [
              drawNumber,
              drawTimestamp.toISOString(),
              req.user.id
            ]
          );

          await client.query("COMMIT");

          await audit(
            req.user.id,
            "draw_schedule_updated",
            null,
            {
              draw_number: drawNumber,
              draw_at: drawTimestamp.toISOString()
            }
          );

          res.json({
            success: true,
            message: "Draw Schedule saved successfully.",
            drawSettings: result.rows[0]
          });

        } catch (error) {
          await client.query("ROLLBACK");
          throw error;
        } finally {
          client.release();
        }
      })
    );

    // ==========================================
    // PUBLIC DRAW SETTINGS
    // ==========================================

    app.get(
      "/api/public/draw-settings",
      asyncRoute(async (req, res) => {
        const drawSettings = await getCurrentDraw();

        res.json({
          success: true,
          drawSettings,
          betting_locked: isDrawBettingLocked(drawSettings),
          lock_minutes: DRAW_LOCK_MINUTES
        });
      })
    );

    // ==========================================
    // ADMIN: DASHBOARD
    // ==========================================

    app.get(
      "/api/admin/dashboard",
      authenticateToken,
      requireAdmin,
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
      })
    );

    // ==========================================
    // ADMIN: USERS
    // ==========================================

    app.get(
      "/api/admin/users",
      authenticateToken,
      requireAdmin,
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

        res.json({
          success: true,
          users: result.rows
        });
      })
    );

    app.patch(
      "/api/admin/users/:id/status",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const targetId = validId(req.params.id);
        const status = req.body.status;

        if (!targetId || !["active", "suspended"].includes(status)) {
          return sendError(res, 400, "Invalid user or status.");
        }

        if (targetId === Number(req.user.id)) {
          return sendError(res, 400, "You cannot suspend your own account.");
        }

        const result = await pool.query(
          `UPDATE users
           SET status = $1, updated_at = NOW()
           WHERE id = $2
             AND role <> 'admin'
             AND username <> $3
           RETURNING id, username, status`,
          [status, targetId, PRIMARY_ADMIN_USERNAME]
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
      })
    );

    app.patch(
      "/api/admin/users/:id/role",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const targetId = validId(req.params.id);
        const role = req.body.role;

        if (
          !targetId ||
          !["user", "moderator", "affiliate"].includes(role)
        ) {
          return sendError(res, 400, "Invalid role or user.");
        }

        const result = await pool.query(
          `UPDATE users
           SET role = $1, updated_at = NOW()
           WHERE id = $2
             AND role <> 'admin'
             AND username <> $3
           RETURNING id, username, email, role, status`,
          [role, targetId, PRIMARY_ADMIN_USERNAME]
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
        } else {
          await pool.query(
            "DELETE FROM moderator_permissions WHERE user_id = $1",
            [targetId]
          );
        }

        await audit(req.user.id, "role_changed", targetId, { role });

        res.json({
          success: true,
          message: "User role updated.",
          user: result.rows[0]
        });
      })
    );

    // ==========================================
    // ADMIN: MODERATORS
    // ==========================================

    app.get(
      "/api/admin/moderators",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const result = await pool.query(
          `SELECT u.id, u.username, u.email, u.status,
                  mp.permissions
           FROM users u
           LEFT JOIN moderator_permissions mp ON mp.user_id = u.id
           WHERE u.role = 'moderator'
           ORDER BY u.created_at DESC`
        );

        res.json({
          success: true,
          moderators: result.rows
        });
      })
    );

    app.post(
      "/api/admin/moderators",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const username = cleanText(req.body.username, 30).toLowerCase();

        if (!validUsername(username)) {
          return sendError(res, 400, "Enter a valid username.");
        }

        if (username === PRIMARY_ADMIN_USERNAME) {
          return sendError(res, 403, "Primary Admin cannot become a moderator.");
        }

        const result = await pool.query(
          `UPDATE users
           SET role = 'moderator', updated_at = NOW()
           WHERE username = $1
             AND role <> 'admin'
             AND username <> $2
           RETURNING id, username, email, role`,
          [username, PRIMARY_ADMIN_USERNAME]
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
      })
    );

    app.put(
      "/api/admin/moderators/:id/permissions",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const targetId = validId(req.params.id);
        const permissions = req.body.permissions;

        const allowedPermissions = [
          "manage_users",
          "manage_profiles",
          "manage_results",
          "view_reports",
          "manage_affiliates"
        ];

        if (
          !targetId ||
          !permissions ||
          typeof permissions !== "object" ||
          Array.isArray(permissions)
        ) {
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
           DO UPDATE SET
             permissions = $2,
             updated_at = NOW()
           RETURNING *`,
          [targetId, JSON.stringify(cleanPermissions)]
        );

        await audit(
          req.user.id,
          "moderator_permissions_updated",
          targetId,
          { permissions: cleanPermissions }
        );

        res.json({
          success: true,
          message: "Moderator permissions updated.",
          permissions: result.rows[0].permissions
        });
      })
    );

    app.delete(
      "/api/admin/moderators/:id",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const targetId = validId(req.params.id);

        if (!targetId) {
          return sendError(res, 400, "Invalid moderator ID.");
        }

        const result = await pool.query(
          `UPDATE users
           SET role = 'user', updated_at = NOW()
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
      })
    );

    // ==========================================
    // MODERATOR: EXISTING PERMISSIONS
    // ==========================================

    app.get(
      "/api/moderator/users",
      authenticateToken,
      requirePermission("manage_users"),
      asyncRoute(async (req, res) => {
        const result = await pool.query(
          `SELECT id, username, role, status, created_at
           FROM users
           ORDER BY created_at DESC
           LIMIT 200`
        );

        res.json({
          success: true,
          users: result.rows
        });
      })
    );

    app.patch(
      "/api/moderator/profiles/:id",
      authenticateToken,
      requirePermission("manage_profiles"),
      asyncRoute(async (req, res) => {
        const targetId = validId(req.params.id);

        if (!targetId) {
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

        res.json({
          success: true,
          profile: result.rows[0]
        });
      })
    );

    // ==========================================
    // AFFILIATE: SELF DASHBOARD
    // ==========================================

    app.get(
      "/api/affiliate/me",
      authenticateToken,
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
      })
    );

    // ==========================================
    // AFFILIATE MANAGEMENT HELPERS
    // ==========================================

    async function getAffiliateList(res) {
      const result = await pool.query(
        `SELECT u.id, u.username, u.email, u.status,
                u.referral_code, u.created_at,
                COUNT(r.id)::int AS referral_count
         FROM users u
         LEFT JOIN users r ON r.referred_by = u.id
         WHERE u.role = 'affiliate'
         GROUP BY u.id
         ORDER BY u.created_at DESC`
      );

      res.json({
        success: true,
        affiliates: result.rows
      });
    }

    async function createAffiliateCommission(req, res) {
      const affiliateId = validId(req.params.id);
      const referredUserId = validId(req.body.referred_user_id);
      const amount = Number(req.body.amount);
      const description = cleanText(req.body.description, 300);

      if (
        !affiliateId ||
        !referredUserId ||
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > 1000000
      ) {
        return sendError(
          res,
          400,
          "Affiliate, referred user and valid commission amount are required."
        );
      }

      if (affiliateId === referredUserId) {
        return sendError(
          res,
          400,
          "An affiliate cannot be their own referred user."
        );
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const affiliate = await client.query(
          `SELECT id FROM users
           WHERE id = $1
             AND role = 'affiliate'
             AND status = 'active'
           FOR UPDATE`,
          [affiliateId]
        );

        if (!affiliate.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 404, "Active affiliate not found.");
        }

        const referredUser = await client.query(
          `SELECT id FROM users
           WHERE id = $1
             AND referred_by = $2
             AND role = 'user'
           FOR UPDATE`,
          [referredUserId, affiliateId]
        );

        if (!referredUser.rows.length) {
          await client.query("ROLLBACK");

          return sendError(
            res,
            400,
            "This user is not referred by the selected affiliate."
          );
        }

        const duplicate = await client.query(
          `SELECT id FROM affiliate_commissions
           WHERE affiliate_id = $1
             AND referred_user_id = $2
           LIMIT 1`,
          [affiliateId, referredUserId]
        );

        if (duplicate.rows.length) {
          await client.query("ROLLBACK");

          return sendError(
            res,
            409,
            "A commission record already exists for this referred user."
          );
        }

        const result = await client.query(
          `INSERT INTO affiliate_commissions
           (affiliate_id, referred_user_id, amount, description, status)
           VALUES ($1, $2, $3, $4, 'pending')
           RETURNING *`,
          [affiliateId, referredUserId, amount, description]
        );

        await client.query("COMMIT");

        await audit(
          req.user.id,
          "affiliate_commission_recorded",
          referredUserId,
          {
            affiliate_id: affiliateId,
            commission_id: result.rows[0].id,
            amount
          }
        );

        return res.status(201).json({
          success: true,
          message: "Commission created successfully.",
          commission: result.rows[0]
        });

      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }

    async function updateAffiliateCommissionStatus(req, res) {
      const commissionId = validId(req.params.id);
      const status = cleanText(req.body.status, 20).toLowerCase();

      if (
        !commissionId ||
        !["pending", "approved", "rejected"].includes(status)
      ) {
        return sendError(
          res,
          400,
          "Invalid commission ID or status. Use pending, approved or rejected."
        );
      }

      const result = await pool.query(
        `UPDATE affiliate_commissions
         SET status = $1
         WHERE id = $2
         RETURNING *`,
        [status, commissionId]
      );

      if (!result.rows.length) {
        return sendError(res, 404, "Commission not found.");
      }

      await audit(
        req.user.id,
        "affiliate_commission_status_changed",
        result.rows[0].referred_user_id,
        {
          commission_id: commissionId,
          affiliate_id: result.rows[0].affiliate_id,
          status
        }
      );

      res.json({
        success: true,
        message: "Commission status updated.",
        commission: result.rows[0]
      });
    }

    async function getAffiliateCommissions(res, affiliateId = null) {
      const result = await pool.query(
        `SELECT c.id, c.affiliate_id, c.referred_user_id,
                c.amount, c.description, c.status, c.created_at,
                a.username AS affiliate_username,
                r.username AS referred_username
         FROM affiliate_commissions c
         JOIN users a ON a.id = c.affiliate_id
         JOIN users r ON r.id = c.referred_user_id
         WHERE ($1::bigint IS NULL OR c.affiliate_id = $1)
         ORDER BY c.created_at DESC
         LIMIT 300`,
        [affiliateId]
      );

      res.json({
        success: true,
        commissions: result.rows
      });
    }

    // ==========================================
    // ADMIN: AFFILIATE MANAGEMENT
    // ==========================================

    app.get(
      "/api/admin/affiliates",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        await getAffiliateList(res);
      })
    );

    app.get(
      "/api/admin/affiliates/commissions",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        await getAffiliateCommissions(res);
      })
    );

    app.post(
      "/api/admin/affiliates/:id/commissions",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        await createAffiliateCommission(req, res);
      })
    );

    app.patch(
      "/api/admin/commissions/:id/status",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        await updateAffiliateCommissionStatus(req, res);
      })
    );

    // ==========================================
    // MODERATOR: AFFILIATE MANAGEMENT
    // ==========================================

    app.get(
      "/api/moderator/affiliates",
      authenticateToken,
      requirePermission("manage_affiliates"),
      asyncRoute(async (req, res) => {
        await getAffiliateList(res);
      })
    );

    app.get(
      "/api/moderator/affiliates/commissions",
      authenticateToken,
      requirePermission("manage_affiliates"),
      asyncRoute(async (req, res) => {
        const affiliateId = validId(req.query.affiliate_id);
        await getAffiliateCommissions(res, affiliateId);
      })
    );

    app.post(
      "/api/moderator/affiliates/:id/commissions",
      authenticateToken,
      requirePermission("manage_affiliates"),
      asyncRoute(async (req, res) => {
        await createAffiliateCommission(req, res);
      })
    );

    app.patch(
      "/api/moderator/commissions/:id/status",
      authenticateToken,
      requirePermission("manage_affiliates"),
      asyncRoute(async (req, res) => {
        await updateAffiliateCommissionStatus(req, res);
      })
    );

    // ==========================================
    // ADMIN MESSAGE MANAGEMENT
    // ==========================================

    app.get(
      "/api/admin/messages",
      authenticateToken,
      requireAdmin,
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
      })
    );

    app.post(
      "/api/admin/messages",
      authenticateToken,
      requireAdmin,
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

          await audit(
            req.user.id,
            "admin_message_published",
            null,
            { message_id: result.rows[0].id }
          );

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
      })
    );

    app.post(
      "/api/admin/messages/disable",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        await pool.query(
          "UPDATE admin_messages SET active = FALSE WHERE active = TRUE"
        );

        await audit(req.user.id, "admin_message_disabled");

        res.json({
          success: true,
          message: "Admin message disabled."
        });
      })
    );

    app.get(
      "/api/public/admin-message",
      asyncRoute(async (req, res) => {
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
      })
    );

    // ==========================================
    // LIVE EVENT MANAGEMENT
    // ==========================================

    app.get(
      "/api/admin/live-event",
      authenticateToken,
      requireAdmin,
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
      })
    );

    app.post(
      "/api/admin/live-event",
      authenticateToken,
      requireAdmin,
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
          return sendError(
            res,
            400,
            "Please enter a valid HTTPS URL for the selected platform."
          );
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

          await audit(
            req.user.id,
            "live_event_started",
            null,
            {
              event_id: result.rows[0].id,
              platform
            }
          );

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
      })
    );

    app.post(
      "/api/admin/live-event/disable",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        await pool.query(
          "UPDATE admin_live_events SET active = FALSE WHERE active = TRUE"
        );

        await audit(req.user.id, "live_event_disabled");

        res.json({
          success: true,
          message: "Live event disabled."
        });
      })
    );

    app.get(
      "/api/public/live-event",
      asyncRoute(async (req, res) => {
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
      })
    );

    // ==========================================
    // PAYMENT METHODS & MANUAL DEPOSIT MANAGEMENT
    // Wallet credits are DEMO points; admin must manually verify transfers.
    // ==========================================

    app.get("/api/admin/payment-methods", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const q = cleanText(req.query.q, 150).toLowerCase();
      if (!q) return res.json({ success: true, methods: [] });
      const result = await pool.query(
        `SELECT id, preset, name, label, account, currency, instructions,
                active, created_at, updated_at
         FROM payment_methods
         WHERE LOWER(CONCAT_WS(' ', name, label, account, currency, instructions, id::text)) LIKE $1
         ORDER BY updated_at DESC LIMIT 100`, [`%${q}%`]
      );
      res.json({ success: true, methods: result.rows });
    }));

    app.post("/api/admin/payment-methods", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const preset = cleanText(req.body.preset || "Custom", 40);
      const name = cleanText(req.body.name, 60);
      const label = cleanText(req.body.label, 60);
      const account = cleanText(req.body.account, 150);
      const currency = cleanText(req.body.currency || "BDT", 10).toUpperCase();
      const instructions = cleanText(req.body.instructions, 1000);
      const active = req.body.active !== false;
      if (!name || !/^[A-Z0-9]{2,10}$/.test(currency)) return sendError(res, 400, "Invalid payment method details.");
      const result = await pool.query(
        `INSERT INTO payment_methods (preset,name,label,account,currency,instructions,active,created_by,updated_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8) RETURNING *`,
        [preset,name,label,account,currency,instructions,active,req.user.id]
      );
      await audit(req.user.id, "payment_method_created", null, { method_id: result.rows[0].id, name });
      res.status(201).json({ success: true, method: result.rows[0] });
    }));

    app.put("/api/admin/payment-methods/:id", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const id = Number(req.params.id);
      const preset = cleanText(req.body.preset || "Custom", 40);
      const name = cleanText(req.body.name, 60);
      const label = cleanText(req.body.label, 60);
      const account = cleanText(req.body.account, 150);
      const currency = cleanText(req.body.currency || "BDT", 10).toUpperCase();
      const instructions = cleanText(req.body.instructions, 1000);
      const active = req.body.active !== false;
      if (!Number.isSafeInteger(id) || id < 1 || !name || !/^[A-Z0-9]{2,10}$/.test(currency)) return sendError(res, 400, "Invalid payment method details.");
      const result = await pool.query(
        `UPDATE payment_methods SET preset=$1,name=$2,label=$3,account=$4,currency=$5,
         instructions=$6,active=$7,updated_by=$8,updated_at=NOW() WHERE id=$9 RETURNING *`,
        [preset,name,label,account,currency,instructions,active,req.user.id,id]
      );
      if (!result.rows.length) return sendError(res, 404, "Payment method not found.");
      await audit(req.user.id, "payment_method_updated", null, { method_id: id });
      res.json({ success: true, method: result.rows[0] });
    }));

    app.patch("/api/admin/payment-methods/:id/status", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const id = Number(req.params.id);
      if (!Number.isSafeInteger(id) || id < 1 || typeof req.body.active !== "boolean") return sendError(res, 400, "Invalid method status.");
      const result = await pool.query(
        `UPDATE payment_methods SET active=$1,updated_by=$2,updated_at=NOW() WHERE id=$3 RETURNING *`,
        [req.body.active,req.user.id,id]
      );
      if (!result.rows.length) return sendError(res, 404, "Payment method not found.");
      res.json({ success: true, method: result.rows[0] });
    }));

    app.delete("/api/admin/payment-methods/:id", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const id = Number(req.params.id);
      if (!Number.isSafeInteger(id) || id < 1) return sendError(res, 400, "Invalid method ID.");
      const result = await pool.query("DELETE FROM payment_methods WHERE id=$1 RETURNING id", [id]);
      if (!result.rows.length) return sendError(res, 404, "Payment method not found.");
      res.json({ success: true, message: "Payment method deleted." });
    }));

    app.get("/api/public/payment-methods", asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id,preset,name,label,account,currency,instructions
         FROM payment_methods WHERE active=TRUE ORDER BY name, id`
      );
      res.json({ success: true, methods: result.rows });
    }));

    // Authenticated user's own deposit history. Never expose another user's requests.
    app.get("/api/deposits/me", authenticateToken, asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id,payment_method_id,method,payment_account,currency,amount,
                sender_account,transaction_id,status,credited_points,rejection_reason,created_at,reviewed_at
         FROM deposit_requests WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
        [req.user.id]
      );
      res.json({ success:true, requests:result.rows });
    }));

    // User-side request endpoint; transaction reference is unique across requests.
    app.post("/api/deposits", authenticateToken, asyncRoute(async (req, res) => {
      const methodId = Number(req.body.payment_method_id);
      const amount = Number(req.body.amount);
      const sender = cleanText(req.body.sender_account, 150);
      const transactionId = cleanText(req.body.transaction_id, 150);
      if (!Number.isSafeInteger(methodId) || methodId < 1 || !Number.isFinite(amount) || amount <= 0 || amount > 10000000 || !sender || !transactionId) {
        return sendError(res, 400, "Invalid deposit request.");
      }
      const methodResult = await pool.query(
        `SELECT id,name,account,currency FROM payment_methods WHERE id=$1 AND active=TRUE`, [methodId]
      );
      if (!methodResult.rows.length) return sendError(res, 400, "Payment method is unavailable.");
      const method = methodResult.rows[0];
      try {
        const result = await pool.query(
          `INSERT INTO deposit_requests (user_id,payment_method_id,method,payment_account,currency,amount,sender_account,transaction_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,status,created_at`,
          [req.user.id,method.id,method.name,method.account,method.currency,amount.toFixed(2),sender,transactionId]
        );
        res.status(201).json({ success: true, request: result.rows[0] });
      } catch (error) {
        if (error.code === "23505") return sendError(res, 409, "This transaction ID has already been submitted.");
        throw error;
      }
    }));

    app.get("/api/admin/deposits", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const status = cleanText(req.query.status || "all", 20).toLowerCase();
      const search = cleanText(req.query.search, 150).toLowerCase();
      const params = [];
      let where = "TRUE";
      if (["pending","approved","rejected"].includes(status)) { params.push(status); where += ` AND d.status=$${params.length}`; }
      if (search) { params.push(`%${search}%`); where += ` AND LOWER(CONCAT_WS(' ',u.username,d.id::text,d.transaction_id,d.method)) LIKE $${params.length}`; }
      const [items, counts] = await Promise.all([
        pool.query(
          `SELECT d.id,d.user_id,u.username,d.method,d.payment_account,d.currency,d.amount,
                  d.sender_account,d.transaction_id,d.status,d.credited_points,d.rejection_reason,
                  d.reviewed_at,admin.username AS reviewed_by,d.created_at
           FROM deposit_requests d JOIN users u ON u.id=d.user_id
           LEFT JOIN users admin ON admin.id=d.reviewed_by
           WHERE ${where} ORDER BY d.created_at DESC LIMIT 500`, params
        ),
        pool.query(`SELECT COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE status='pending')::int AS pending,
          COUNT(*) FILTER (WHERE status='approved')::int AS approved,
          COUNT(*) FILTER (WHERE status='rejected')::int AS rejected FROM deposit_requests`)
      ]);
      res.json({ success: true, requests: items.rows, stats: counts.rows[0] });
    }));

    app.post("/api/admin/deposits/:id/approve", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const id = Number(req.params.id);
      const points = Number(req.body.points);
      if (!Number.isSafeInteger(id) || id < 1 || !Number.isFinite(points) || points <= 0 || points > 10000000 || Math.round(points*100)!==points*100) {
        return sendError(res, 400, "Enter valid points to credit.");
      }
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const found = await client.query("SELECT * FROM deposit_requests WHERE id=$1 FOR UPDATE", [id]);
        if (!found.rows.length) { await client.query("ROLLBACK"); return sendError(res,404,"Deposit request not found."); }
        const request = found.rows[0];
        if (request.status !== "pending") { await client.query("ROLLBACK"); return sendError(res,409,"This request has already been reviewed."); }
        const user = await client.query("SELECT balance FROM users WHERE id=$1 FOR UPDATE", [request.user_id]);
        if (!user.rows.length) { await client.query("ROLLBACK"); return sendError(res,404,"User not found."); }
        const balance = Number(user.rows[0].balance);
        const newBalance = Number((balance + points).toFixed(2));
        if (!Number.isFinite(newBalance) || newBalance > 9999999999.99) { await client.query("ROLLBACK"); return sendError(res,400,"Wallet balance limit exceeded."); }
        await client.query("UPDATE users SET balance=$1,updated_at=NOW() WHERE id=$2", [newBalance,request.user_id]);
        await client.query(
          `INSERT INTO wallet_transactions (user_id,type,amount,currency,description,reference)
           VALUES ($1,'deposit_credit',$2,'DEMO',$3,$4)`,
          [request.user_id,points,"Admin-approved deposit points","DEP-"+id]
        );
        const updated = await client.query(
          `UPDATE deposit_requests SET status='approved',credited_points=$1,reviewed_by=$2,reviewed_at=NOW()
           WHERE id=$3 AND status='pending' RETURNING *`, [points,req.user.id,id]
        );
        if (!updated.rows.length) throw new Error("Deposit approval state changed unexpectedly.");
        await client.query("COMMIT");
        await audit(req.user.id,"deposit_approved",request.user_id,{deposit_id:id,credited_points:points});
        res.json({ success:true, request:updated.rows[0], new_balance:newBalance });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally { client.release(); }
    }));

    app.post("/api/admin/deposits/:id/reject", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const id = Number(req.params.id);
      const reason = cleanText(req.body.reason,200);
      if (!Number.isSafeInteger(id) || id < 1 || !reason) return sendError(res,400,"A rejection reason is required.");
      const result = await pool.query(
        `UPDATE deposit_requests SET status='rejected',rejection_reason=$1,reviewed_by=$2,reviewed_at=NOW()
         WHERE id=$3 AND status='pending' RETURNING *`, [reason,req.user.id,id]
      );
      if (!result.rows.length) return sendError(res,409,"Request not found or already reviewed.");
      await audit(req.user.id,"deposit_rejected",result.rows[0].user_id,{deposit_id:id,reason});
      res.json({ success:true, request:result.rows[0] });
    }));

    // ==========================================
    // WITHDRAWAL REQUESTS (SERVER-SIDE DEMO REVIEW)
    // Approval/rejection changes request status only; no real payment is sent.
    // ==========================================

    app.post("/api/withdrawals", authenticateToken, asyncRoute(async (req, res) => {
      const amount = Number(req.body.amount);
      const method = cleanText(req.body.method, 80);
      const account = cleanText(req.body.account, 180);
      if (!Number.isFinite(amount) || amount <= 0 || amount > 10000000 || Math.round(amount * 100) !== amount * 100 || !method || !account) {
        return sendError(res, 400, "Enter a valid withdrawal amount, method and account.");
      }

      // Lock the user's wallet row and validate pending reservations server-side.
      // This prevents concurrent requests from exceeding the available DEMO balance.
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const walletResult = await client.query(
          "SELECT balance,status FROM users WHERE id=$1 FOR UPDATE",
          [req.user.id]
        );
        if (!walletResult.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 404, "User not found.");
        }
        if (String(walletResult.rows[0].status || "active").toLowerCase() !== "active") {
          await client.query("ROLLBACK");
          return sendError(res, 403, "Your account is not active.");
        }
        const pendingResult = await client.query(
          "SELECT COALESCE(SUM(amount),0) AS reserved FROM withdrawal_requests WHERE user_id=$1 AND status='pending'",
          [req.user.id]
        );
        const balance = Number(walletResult.rows[0].balance || 0);
        const reserved = Number(pendingResult.rows[0].reserved || 0);
        const available = Math.max(0, balance - reserved);
        if (amount > available) {
          await client.query("ROLLBACK");
          return sendError(res, 400, "Insufficient available DEMO points.");
        }
        const result = await client.query(
          `INSERT INTO withdrawal_requests (user_id,amount,method,account)
           VALUES ($1,$2,$3,$4)
           RETURNING id,amount,method,account,status,created_at`,
          [req.user.id, amount.toFixed(2), method, account]
        );
        await client.query("COMMIT");
        res.status(201).json({ success:true, request:result.rows[0], available_balance:Number((available-amount).toFixed(2)) });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }));

    app.get("/api/withdrawals/me", authenticateToken, asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id,amount,method,account,status,rejection_reason,created_at,reviewed_at
         FROM withdrawal_requests WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
        [req.user.id]
      );
      res.json({ success:true, requests:result.rows });
    }));

    app.get("/api/admin/withdrawals", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const status = cleanText(req.query.status || "all", 20).toLowerCase();
      const search = cleanText(req.query.search, 150).toLowerCase();
      const params = [];
      let where = "TRUE";
      if (["pending","approved","rejected"].includes(status)) {
        params.push(status); where += ` AND w.status=$${params.length}`;
      }
      if (search) {
        params.push(`%${search}%`);
        where += ` AND LOWER(CONCAT_WS(' ',u.username,w.id::text,w.method,w.account)) LIKE $${params.length}`;
      }
      const [items, counts] = await Promise.all([
        pool.query(
          `SELECT w.id,w.user_id,u.username,w.amount,w.method,w.account,w.status,
                  w.created_at,w.reviewed_at,w.rejection_reason,admin.username AS reviewed_by
           FROM withdrawal_requests w JOIN users u ON u.id=w.user_id
           LEFT JOIN users admin ON admin.id=w.reviewed_by
           WHERE ${where} ORDER BY w.created_at DESC LIMIT 500`, params
        ),
        pool.query(`SELECT COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE status='pending')::int AS pending,
          COUNT(*) FILTER (WHERE status='approved')::int AS approved,
          COUNT(*) FILTER (WHERE status='rejected')::int AS rejected
          FROM withdrawal_requests`)
      ]);
      res.json({ success:true, requests:items.rows, stats:counts.rows[0] });
    }));

    app.post("/api/admin/withdrawals/:id/approve", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id < 1) {
        return sendError(res, 400, "Invalid withdrawal request ID.");
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        // Lock the request first so concurrent approvals cannot debit twice.
        const found = await client.query(
          `SELECT *
           FROM withdrawal_requests
           WHERE id = $1
           FOR UPDATE`,
          [id]
        );

        if (!found.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 404, "Withdrawal request not found.");
        }

        const request = found.rows[0];

        if (request.status !== "pending") {
          await client.query("ROLLBACK");
          return sendError(res, 409, "This request has already been reviewed.");
        }

        const amount = Number(request.amount);

        if (
          !Number.isFinite(amount) ||
          amount <= 0 ||
          Math.round(amount * 100) !== amount * 100
        ) {
          await client.query("ROLLBACK");
          return sendError(res, 400, "The withdrawal amount is invalid.");
        }

        // Lock the wallet row and ensure the reserved points still exist.
        const walletResult = await client.query(
          `SELECT balance, status
           FROM users
           WHERE id = $1
           FOR UPDATE`,
          [request.user_id]
        );

        if (!walletResult.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 404, "Withdrawal user's account was not found.");
        }

        if (String(walletResult.rows[0].status || "active").toLowerCase() !== "active") {
          await client.query("ROLLBACK");
          return sendError(res, 403, "The user's account is not active.");
        }

        const currentBalance = Number(walletResult.rows[0].balance || 0);

        if (!Number.isFinite(currentBalance) || currentBalance < amount) {
          await client.query("ROLLBACK");
          return sendError(
            res,
            409,
            "Insufficient DEMO points in the wallet. The pending withdrawal remains unchanged."
          );
        }

        const newBalance = Number((currentBalance - amount).toFixed(2));

        // Deduct points and write the wallet ledger entry in this same transaction.
        await client.query(
          `UPDATE users
           SET balance = $1,
               updated_at = NOW()
           WHERE id = $2`,
          [newBalance.toFixed(2), request.user_id]
        );

        await client.query(
          `INSERT INTO wallet_transactions
           (user_id, type, amount, currency, description, reference)
           VALUES ($1, 'withdrawal_debit', $2, 'DEMO', $3, $4)`,
          [
            request.user_id,
            (-amount).toFixed(2),
            "Admin-approved demo withdrawal",
            "WD-" + id
          ]
        );

        const updated = await client.query(
          `UPDATE withdrawal_requests
           SET status = 'approved',
               reviewed_by = $1,
               reviewed_at = NOW()
           WHERE id = $2
             AND status = 'pending'
           RETURNING *`,
          [req.user.id, id]
        );

        if (!updated.rows.length) {
          throw new Error("Withdrawal approval state changed unexpectedly.");
        }

        await client.query("COMMIT");

        await audit(
          req.user.id,
          "withdrawal_approved",
          request.user_id,
          {
            withdrawal_id: id,
            amount,
            new_balance: newBalance
          }
        );

        res.json({
          success: true,
          request: updated.rows[0],
          new_balance: newBalance,
          message: "Approved successfully. DEMO points were deducted from the wallet. No real payment was sent."
        });

      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    }));

    app.post("/api/admin/withdrawals/:id/reject", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const id = Number(req.params.id);
      const reason = cleanText(req.body.reason || "Rejected by admin",200);
      if (!Number.isSafeInteger(id) || id < 1) return sendError(res,400,"Invalid withdrawal request ID.");
      const result = await pool.query(
        `UPDATE withdrawal_requests SET status='rejected',rejection_reason=$1,reviewed_by=$2,reviewed_at=NOW()
         WHERE id=$3 AND status='pending' RETURNING *`,[reason,req.user.id,id]
      );
      if (!result.rows.length) return sendError(res,409,"Request not found or already reviewed.");
      await audit(req.user.id,"withdrawal_rejected",result.rows[0].user_id,{withdrawal_id:id,reason});
      res.json({success:true,request:result.rows[0]});
    }));

    // ==========================================
    // DEMO WALLET
    // TEST CREDIT ONLY - NOT REAL MONEY
    // ==========================================

    app.get(
      "/api/wallet",
      authenticateToken,
      asyncRoute(async (req, res) => {
        const result = await pool.query(
          "SELECT balance FROM users WHERE id = $1",
          [req.user.id]
        );

        if (!result.rows.length) {
          return sendError(res, 404, "User not found.");
        }

        res.json({
          success: true,
          currency: "DEMO",
          is_demo: true,
          balance: result.rows[0].balance
        });
      })
    );

    app.get(
      "/api/wallet/transactions",
      authenticateToken,
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
      })
    );

    // ==========================================
    // CREATE DEMO BET
    // SERVER ENFORCES THE 45-MINUTE DRAW LOCK
    // ==========================================

    app.post(
      "/api/demo/bets",
      authenticateToken,
      asyncRoute(async (req, res) => {
        const gameName = cleanText(req.body.game_name, 100);
        const selection = cleanText(req.body.selection, 100);
        const amount = Number(req.body.amount);

        if (
          !gameName ||
          !selection ||
          !Number.isFinite(amount) ||
          amount <= 0 ||
          amount > 100000
        ) {
          return sendError(res, 400, "Invalid demo bet information.");
        }

        const client = await pool.connect();

        try {
          await client.query("BEGIN");

          const drawResult = await client.query(
            `SELECT id, draw_number, draw_at
             FROM draw_settings
             WHERE id = 1
             FOR SHARE`
          );

          const draw = drawResult.rows[0] || null;

          if (isDrawBettingLocked(draw)) {
            await client.query("ROLLBACK");

            return sendError(
              res,
              403,
              "Betting is closed. The draw is missing or within the 45-minute cutoff."
            );
          }

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
             (user_id, game_name, selection, amount, draw_date)
             VALUES ($1, $2, $3, $4, ($5::timestamptz AT TIME ZONE 'Asia/Dhaka')::date)
             RETURNING *`,
            [req.user.id, gameName, selection, amount, draw.draw_at]
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
      })
    );

    app.get(
      "/api/demo/bets",
      authenticateToken,
      asyncRoute(async (req, res) => {
        const result = await pool.query(
          `SELECT id, game_name, selection, amount, status, created_at
           FROM demo_bets
           WHERE user_id = $1
           ORDER BY created_at DESC
           LIMIT 100`,
          [req.user.id]
        );

        res.json({
          success: true,
          bets: result.rows
        });
      })
    );

    // ==========================================
    // 3UP API
    // Dedicated endpoints and tables; demo points only.
    // ==========================================

    // Public 3UP settings used by the 3UP page.
    app.get(
      "/api/public/3up-settings",
      asyncRoute(async (req, res) => {
        const [draw, settings] = await Promise.all([
          getCurrentDraw(),
          pool.query(
            `SELECT discount_percent, updated_at
             FROM demo_3up_settings
             WHERE id = 1`
          )
        ]);

        res.json({
          success: true,
          drawSettings: draw,
          discount_percent: Number(settings.rows[0]?.discount_percent || 0),
          betting_locked: isDrawBettingLocked(draw),
          lock_minutes: DRAW_LOCK_MINUTES,
          currency: "DEMO",
          is_demo: true
        });
      })
    );

    // Primary Admin reads 3UP discount settings.
    app.get(
      "/api/admin/3up-settings",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const result = await pool.query(
          `SELECT discount_percent, updated_by, updated_at
           FROM demo_3up_settings
           WHERE id = 1`
        );

        res.json({
          success: true,
          settings: result.rows[0] || {
            discount_percent: "0.00"
          }
        });
      })
    );

    // Primary Admin changes the server-side discount.
    app.put(
      "/api/admin/3up-settings",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const rawDiscount = req.body.discount_percent;
        const discount = Number(rawDiscount);

        if (
          rawDiscount === "" ||
          rawDiscount === null ||
          rawDiscount === undefined ||
          !Number.isFinite(discount) ||
          discount < 0 ||
          discount > 100 ||
          Math.round(discount * 100) !== discount * 100
        ) {
          return sendError(
            res,
            400,
            "Discount must be a number from 0 to 100 with up to 2 decimal places."
          );
        }

        const result = await pool.query(
          `INSERT INTO demo_3up_settings
           (id, discount_percent, updated_by, updated_at)
           VALUES (1, $1, $2, NOW())
           ON CONFLICT (id)
           DO UPDATE SET
             discount_percent = EXCLUDED.discount_percent,
             updated_by = EXCLUDED.updated_by,
             updated_at = NOW()
           RETURNING discount_percent, updated_by, updated_at`,
          [discount, req.user.id]
        );

        await audit(
          req.user.id,
          "3up_discount_updated",
          null,
          { discount_percent: discount }
        );

        res.json({
          success: true,
          message: "3UP discount settings saved.",
          settings: result.rows[0]
        });
      })
    );

    // Submit 3UP demo entries. Client cannot choose its own discount.
    app.post(
      "/api/demo/3up/bets",
      authenticateToken,
      asyncRoute(async (req, res) => {
        const inputRows = req.body.rows;

        if (
          !Array.isArray(inputRows) ||
          inputRows.length < 1 ||
          inputRows.length > 50
        ) {
          return sendError(res, 400, "Submit between 1 and 50 3UP rows.");
        }

        let totalCents = 0;
        const cleanRows = [];

        for (let index = 0; index < inputRows.length; index++) {
          const row = inputRows[index];

          if (!row || typeof row !== "object" || Array.isArray(row)) {
            return sendError(res, 400, `Invalid 3UP row at position ${index + 1}.`);
          }

          const number = String(row.number ?? "").trim();

          if (!/^\d{3}$/.test(number)) {
            return sendError(
              res,
              400,
              `Row ${index + 1}: number must contain exactly 3 digits.`
            );
          }

          const straightCents = amountToCents(row.straight);
          const rumbleCents = amountToCents(row.rumble);

          if (straightCents === null || rumbleCents === null) {
            return sendError(
              res,
              400,
              `Row ${index + 1}: D/R amounts must be non-negative numbers with up to 2 decimals.`
            );
          }

          if (straightCents + rumbleCents <= 0) {
            return sendError(
              res,
              400,
              `Row ${index + 1}: enter a Straight or Rumble amount.`
            );
          }

          totalCents += straightCents + rumbleCents;

          if (totalCents > 10000000) {
            return sendError(res, 400, "Total 3UP amount cannot exceed 100000 DEMO points.");
          }

          cleanRows.push({
            number,
            straight: centsToAmount(straightCents),
            rumble: centsToAmount(rumbleCents)
          });
        }

        const client = await pool.connect();

        try {
          await client.query("BEGIN");

          // Lock the draw row while checking the cutoff to avoid schedule races.
          const drawResult = await client.query(
            `SELECT id, draw_number, draw_at
             FROM draw_settings
             WHERE id = 1
             FOR SHARE`
          );

          const draw = drawResult.rows[0] || null;

          if (isDrawBettingLocked(draw)) {
            await client.query("ROLLBACK");

            return sendError(
              res,
              403,
              "3UP entries are closed. The draw is missing or within the 45-minute cutoff."
            );
          }

          const settingsResult = await client.query(
            `SELECT discount_percent
             FROM demo_3up_settings
             WHERE id = 1`
          );

          const discountPercent = Number(
            settingsResult.rows[0]?.discount_percent || 0
          );

          const discountCents = Math.round(
            totalCents * discountPercent / 100
          );

          const payableCents = totalCents - discountCents;

          if (payableCents <= 0) {
            await client.query("ROLLBACK");
            return sendError(res, 400, "Payable amount must be greater than zero.");
          }

          const userResult = await client.query(
            `SELECT balance
             FROM users
             WHERE id = $1
             FOR UPDATE`,
            [req.user.id]
          );

          if (!userResult.rows.length) {
            await client.query("ROLLBACK");
            return sendError(res, 404, "User not found.");
          }

          const balanceCents = Math.round(
            Number(userResult.rows[0].balance) * 100
          );

          if (balanceCents < payableCents) {
            await client.query("ROLLBACK");
            return sendError(res, 400, "Insufficient demo balance.");
          }

          await client.query(
            `UPDATE users
             SET balance = balance - $1,
                 updated_at = NOW()
             WHERE id = $2`,
            [centsToAmount(payableCents), req.user.id]
          );

          const betResult = await client.query(
            `INSERT INTO demo_3up_bets
             (user_id, draw_number, rows, total_amount,
              discount_percent, discount_amount, payable_amount, draw_date)
             VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7,
                     ($8::timestamptz AT TIME ZONE 'Asia/Dhaka')::date)
             RETURNING id, user_id, draw_number, rows, total_amount,
                       discount_percent, discount_amount, payable_amount,
                       status, created_at`,
            [
              req.user.id,
              draw.draw_number || "",
              JSON.stringify(cleanRows),
              centsToAmount(totalCents),
              discountPercent,
              centsToAmount(discountCents),
              centsToAmount(payableCents),
              draw.draw_at
            ]
          );

          await client.query(
            `INSERT INTO wallet_transactions
             (user_id, type, amount, currency, description, reference)
             VALUES ($1, 'demo_3up_bet', $2, 'DEMO', $3, $4)`,
            [
              req.user.id,
              -Number(centsToAmount(payableCents)),
              "3UP Demo Entry",
              "3UP-" + betResult.rows[0].id
            ]
          );

          const updatedBalance = await client.query(
            "SELECT balance FROM users WHERE id = $1",
            [req.user.id]
          );

          await client.query("COMMIT");

          res.status(201).json({
            success: true,
            message: "3UP demo entry submitted successfully.",
            currency: "DEMO",
            is_demo: true,
            bet: betResult.rows[0],
            balance: updatedBalance.rows[0].balance
          });

        } catch (error) {
          await client.query("ROLLBACK");
          console.error("3UP demo entry error:", error.message);
          return sendError(res, 500, "Could not submit 3UP demo entry.");
        } finally {
          client.release();
        }
      })
    );

    // Each user can see only their own 3UP entries.
    app.get(
      "/api/demo/3up/bets",
      authenticateToken,
      asyncRoute(async (req, res) => {
        const result = await pool.query(
          `SELECT id, draw_number, rows, total_amount,
                  discount_percent, discount_amount, payable_amount,
                  status, created_at
           FROM demo_3up_bets
           WHERE user_id = $1
           ORDER BY created_at DESC
           LIMIT 100`,
          [req.user.id]
        );

        res.json({
          success: true,
          currency: "DEMO",
          bets: result.rows
        });
      })
    );

    // ==========================================
    // 6UP DEMO SETTINGS & ENTRIES
    // ==========================================

    // Public settings: draw schedule and server-controlled discount.
    app.get(
      "/api/public/6up-settings",
      asyncRoute(async (req, res) => {
        const [drawSettings, settingsResult] = await Promise.all([
          getCurrentDraw(),
          pool.query(
            `SELECT discount_percent
             FROM demo_6up_settings
             WHERE id = 1`
          )
        ]);

        res.json({
          success: true,
          drawSettings,
          discount_percent: Number(
            settingsResult.rows[0]?.discount_percent || 0
          ),
          betting_locked: isDrawBettingLocked(drawSettings),
          lock_minutes: DRAW_LOCK_MINUTES,
          currency: "DEMO",
          is_demo: true
        });
      })
    );

    // Primary Admin reads 6UP discount settings.
    app.get(
      "/api/admin/6up-settings",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const result = await pool.query(
          `SELECT discount_percent, updated_by, updated_at
           FROM demo_6up_settings
           WHERE id = 1`
        );

        res.json({
          success: true,
          settings: result.rows[0] || { discount_percent: "0.00" }
        });
      })
    );

    // Primary Admin changes the server-side 6UP discount.
    app.put(
      "/api/admin/6up-settings",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const rawDiscount = req.body.discount_percent;
        const discount = Number(rawDiscount);

        if (
          rawDiscount === "" ||
          rawDiscount === null ||
          rawDiscount === undefined ||
          !Number.isFinite(discount) ||
          discount < 0 ||
          discount > 100 ||
          Math.round(discount * 100) !== discount * 100
        ) {
          return sendError(
            res,
            400,
            "Discount must be a number from 0 to 100 with up to 2 decimal places."
          );
        }

        const result = await pool.query(
          `INSERT INTO demo_6up_settings
           (id, discount_percent, updated_by, updated_at)
           VALUES (1, $1, $2, NOW())
           ON CONFLICT (id)
           DO UPDATE SET
             discount_percent = EXCLUDED.discount_percent,
             updated_by = EXCLUDED.updated_by,
             updated_at = NOW()
           RETURNING discount_percent, updated_by, updated_at`,
          [discount, req.user.id]
        );

        await audit(
          req.user.id,
          "6up_discount_updated",
          null,
          { discount_percent: discount }
        );

        res.json({
          success: true,
          message: "6UP discount settings saved.",
          settings: result.rows[0]
        });
      })
    );

    // Submit 6UP demo entries. Discount and payable amount are calculated here.
    app.post(
      "/api/demo/6up/bets",
      authenticateToken,
      asyncRoute(async (req, res) => {
        const inputRows = req.body.rows;

        if (
          !Array.isArray(inputRows) ||
          inputRows.length < 1 ||
          inputRows.length > 50
        ) {
          return sendError(res, 400, "Submit between 1 and 50 6UP rows.");
        }

        let totalCents = 0;
        const cleanRows = [];

        for (let index = 0; index < inputRows.length; index++) {
          const row = inputRows[index];

          if (!row || typeof row !== "object" || Array.isArray(row)) {
            return sendError(res, 400, `Invalid 6UP row at position ${index + 1}.`);
          }

          const number = String(row.number ?? "").trim();

          if (!/^\d{6}$/.test(number)) {
            return sendError(
              res,
              400,
              `Row ${index + 1}: number must contain exactly 6 digits.`
            );
          }

          const straightCents = amountToCents(row.straight);
          const rumbleCents = amountToCents(row.rumble);

          if (straightCents === null || rumbleCents === null) {
            return sendError(
              res,
              400,
              `Row ${index + 1}: D/R amounts must be non-negative numbers with up to 2 decimals.`
            );
          }

          if (straightCents + rumbleCents <= 0) {
            return sendError(
              res,
              400,
              `Row ${index + 1}: enter a Straight or Rumble amount.`
            );
          }

          totalCents += straightCents + rumbleCents;

          if (totalCents > 10000000) {
            return sendError(res, 400, "Total 6UP amount cannot exceed 100000 DEMO points.");
          }

          cleanRows.push({
            number,
            straight: centsToAmount(straightCents),
            rumble: centsToAmount(rumbleCents)
          });
        }

        const client = await pool.connect();

        try {
          await client.query("BEGIN");

          // Keep the same authoritative draw cutoff as the 3UP endpoint.
          const drawResult = await client.query(
            `SELECT id, draw_number, draw_at
             FROM draw_settings
             WHERE id = 1
             FOR SHARE`
          );

          const draw = drawResult.rows[0] || null;

          if (isDrawBettingLocked(draw)) {
            await client.query("ROLLBACK");
            return sendError(
              res,
              403,
              "6UP entries are closed. The draw is missing or within the 45-minute cutoff."
            );
          }

          const settingsResult = await client.query(
            `SELECT discount_percent
             FROM demo_6up_settings
             WHERE id = 1`
          );

          const discountPercent = Number(
            settingsResult.rows[0]?.discount_percent || 0
          );
          const discountCents = Math.round(totalCents * discountPercent / 100);
          const payableCents = totalCents - discountCents;

          if (payableCents <= 0) {
            await client.query("ROLLBACK");
            return sendError(res, 400, "Payable amount must be greater than zero.");
          }

          const userResult = await client.query(
            `SELECT balance
             FROM users
             WHERE id = $1
             FOR UPDATE`,
            [req.user.id]
          );

          if (!userResult.rows.length) {
            await client.query("ROLLBACK");
            return sendError(res, 404, "User not found.");
          }

          const balanceCents = Math.round(Number(userResult.rows[0].balance) * 100);

          if (balanceCents < payableCents) {
            await client.query("ROLLBACK");
            return sendError(res, 400, "Insufficient demo balance.");
          }

          await client.query(
            `UPDATE users
             SET balance = balance - $1,
                 updated_at = NOW()
             WHERE id = $2`,
            [centsToAmount(payableCents), req.user.id]
          );

          const betResult = await client.query(
            `INSERT INTO demo_6up_bets
             (user_id, draw_number, rows, total_amount,
              discount_percent, discount_amount, payable_amount, draw_date)
             VALUES ($1, $2, $3::jsonb, $4, $5, $6, $7,
                     ($8::timestamptz AT TIME ZONE 'Asia/Dhaka')::date)
             RETURNING id, user_id, draw_number, rows, total_amount,
                       discount_percent, discount_amount, payable_amount,
                       status, created_at`,
            [
              req.user.id,
              draw.draw_number || "",
              JSON.stringify(cleanRows),
              centsToAmount(totalCents),
              discountPercent,
              centsToAmount(discountCents),
              centsToAmount(payableCents),
              draw.draw_at
            ]
          );

          await client.query(
            `INSERT INTO wallet_transactions
             (user_id, type, amount, currency, description, reference)
             VALUES ($1, 'demo_6up_bet', $2, 'DEMO', $3, $4)`,
            [
              req.user.id,
              -Number(centsToAmount(payableCents)),
              "6UP Demo Entry",
              "6UP-" + betResult.rows[0].id
            ]
          );

          const updatedBalance = await client.query(
            "SELECT balance FROM users WHERE id = $1",
            [req.user.id]
          );

          await client.query("COMMIT");

          res.status(201).json({
            success: true,
            message: "6UP demo entry submitted successfully.",
            currency: "DEMO",
            is_demo: true,
            bet: betResult.rows[0],
            balance: updatedBalance.rows[0].balance
          });
        } catch (error) {
          await client.query("ROLLBACK");
          console.error("6UP demo entry error:", error.message);
          return sendError(res, 500, "Could not submit 6UP demo entry.");
        } finally {
          client.release();
        }
      })
    );

    // Each user can see only their own 6UP entries.
    app.get(
      "/api/demo/6up/bets",
      authenticateToken,
      asyncRoute(async (req, res) => {
        const result = await pool.query(
          `SELECT id, draw_number, rows, total_amount,
                  discount_percent, discount_amount, payable_amount,
                  status, created_at
           FROM demo_6up_bets
           WHERE user_id = $1
           ORDER BY created_at DESC
           LIMIT 100`,
          [req.user.id]
        );

        res.json({
          success: true,
          currency: "DEMO",
          bets: result.rows
        });
      })
    );

    // ==========================================
    // STRUCTURED DRAW RESULTS + SERVER SETTLEMENT
    // ==========================================

    function resultMatches(game, selection, result) {
      const g = String(game || "").toLowerCase().replace(/[\s_-]/g, "");
      const n = String(selection || "").trim();
      const first = String(result.first_prize || "").padStart(6, "0");
      const last = String(result.last_two || "").padStart(2, "0");
      const fronts = Array.isArray(result.front_three) ? result.front_three : [];
      if (g.includes("single")) return /^\d$/.test(n) && n === first.slice(-1);
      if (g === "2d" || g.includes("2d")) return /^\d{1,2}$/.test(n) && n.padStart(2, "0") === last;
      if (g.includes("3up")) return /^\d{1,3}$/.test(n) && fronts.includes(n.padStart(3, "0"));
      if (g.includes("6up")) return /^\d{1,6}$/.test(n) && n.padStart(6, "0") === first;
      return false;
    }

    async function settleDrawBets(client, result) {
      let checked = 0, won = 0, lost = 0;
      const singleRows = await client.query(
        `SELECT id, game_name, selection FROM demo_bets
         WHERE draw_date = $1 AND LOWER(status) NOT IN ('win','won','loss','lose','lost','cancelled','canceled')
         FOR UPDATE`, [result.draw_date]
      );
      for (const bet of singleRows.rows) {
        const isWin = resultMatches(bet.game_name, bet.selection, result);
        await client.query(`UPDATE demo_bets SET status=$1, result_id=$2 WHERE id=$3`, [isWin ? 'win' : 'loss', result.id, bet.id]);
        checked++; if (isWin) won++; else lost++;
      }

      for (const [table, game] of [['demo_3up_bets','3up'], ['demo_6up_bets','6up']]) {
        const rows = await client.query(
          `SELECT id, rows FROM ${table}
           WHERE draw_date=$1 AND LOWER(status) NOT IN ('win','won','loss','lose','lost','cancelled','canceled')
           FOR UPDATE`, [result.draw_date]
        );
        for (const bet of rows.rows) {
          const selections = Array.isArray(bet.rows) ? bet.rows : [];
          const isWin = selections.some(row => {
            const n = String(row.number || '').trim();
            return game === '3up'
              ? /^\d{3}$/.test(n) && result.front_three.includes(n)
              : /^\d{6}$/.test(n) && n === result.first_prize;
          });
          await client.query(`UPDATE ${table} SET status=$1, result_id=$2 WHERE id=$3`, [isWin ? 'win' : 'loss', result.id, bet.id]);
          checked++; if (isWin) won++; else lost++;
        }
      }
      return { checked, won, lost };
    }

    app.get('/api/results', asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id, TO_CHAR(draw_date, 'YYYY-MM-DD') AS date,
                first_prize AS "firstPrize", last_two AS "lastTwo",
                front_three AS "frontThree", published_at AS "publishedAt",
                updated_at AS "updatedAt"
         FROM draw_results ORDER BY draw_date DESC LIMIT 100`
      );
      res.json({ success: true, results: result.rows });
    }));

    app.get('/api/admin/results', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id, TO_CHAR(draw_date, 'YYYY-MM-DD') AS date,
                first_prize AS "firstPrize", last_two AS "lastTwo",
                front_three AS "frontThree", published_at AS "publishedAt",
                updated_at AS "updatedAt"
         FROM draw_results ORDER BY draw_date DESC LIMIT 100`
      );
      res.json({ success: true, results: result.rows });
    }));

    app.post('/api/admin/results', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const date = String(req.body.drawDate || req.body.date || '').trim();
      const firstRaw = String(req.body.firstPrize ?? '').trim();
      const lastRaw = String(req.body.lastTwo ?? '').trim();
      const frontRaw = req.body.frontThree;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^\d{1,6}$/.test(firstRaw) || !/^\d{1,2}$/.test(lastRaw)) {
        return sendError(res, 400, 'Enter a valid Draw Date, First Prize and Last Two.');
      }
      const fronts = Array.isArray(frontRaw)
        ? frontRaw.map(x => String(x).trim())
        : String(frontRaw || '').split(',').map(x => x.trim()).filter(Boolean);
      if (fronts.some(x => !/^\d{3}$/.test(x))) return sendError(res, 400, 'Every Front Three number must contain exactly 3 digits.');
      const uniqueFronts = [...new Set(fronts)];
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const saved = await client.query(
          `INSERT INTO draw_results
           (draw_date, first_prize, last_two, front_three, published_at, updated_at, updated_by)
           VALUES ($1::date, $2, $3, $4::jsonb, NOW(), NOW(), $5)
           ON CONFLICT (draw_date) DO UPDATE SET
             first_prize=EXCLUDED.first_prize, last_two=EXCLUDED.last_two,
             front_three=EXCLUDED.front_three, updated_at=NOW(), updated_by=EXCLUDED.updated_by
           RETURNING id, TO_CHAR(draw_date, 'YYYY-MM-DD') AS date,
             first_prize AS "firstPrize", last_two AS "lastTwo", front_three AS "frontThree",
             published_at AS "publishedAt", updated_at AS "updatedAt"`,
          [date, firstRaw.padStart(6,'0'), lastRaw.padStart(2,'0'), JSON.stringify(uniqueFronts), req.user.id]
        );
        const result = saved.rows[0];
        // On re-publish, retain the original published_at timestamp.
        const settled = await settleDrawBets(client, { ...result, draw_date: date, first_prize: result.firstPrize, last_two: result.lastTwo, front_three: result.frontThree });
        await client.query('COMMIT');
        await audit(req.user.id, 'draw_result_published', null, { result_id: result.id, draw_date: date, ...settled });
        res.status(201).json({ success: true, message: 'Result published and bets settled.', result, settlement: settled });
      } catch (error) {
        await client.query('ROLLBACK');
        console.error('Draw result publish error:', error.message);
        return sendError(res, 500, 'Could not publish or settle this result.');
      } finally { client.release(); }
    }));

    // Submission-number report: hide entries submitted before publication once 72h have elapsed.
    app.get('/api/admin/number-reports', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const result = await pool.query(`
        SELECT 'single' AS game, b.id, b.game_name, b.selection AS number, b.amount,
               b.status, b.draw_date, b.created_at, u.username
        FROM demo_bets b JOIN users u ON u.id=b.user_id
        LEFT JOIN draw_results r ON r.draw_date=b.draw_date
        WHERE r.id IS NULL OR b.created_at >= r.published_at OR NOW() < r.published_at + INTERVAL '72 hours'
        UNION ALL
        SELECT '3up', b.id, '3UP', row_item->>'number',
               COALESCE((row_item->>'straight')::numeric,0)+COALESCE((row_item->>'rumble')::numeric,0),
               b.status, b.draw_date, b.created_at, u.username
        FROM demo_3up_bets b JOIN users u ON u.id=b.user_id
        CROSS JOIN LATERAL jsonb_array_elements(b.rows) row_item
        LEFT JOIN draw_results r ON r.draw_date=b.draw_date
        WHERE r.id IS NULL OR b.created_at >= r.published_at OR NOW() < r.published_at + INTERVAL '72 hours'
        UNION ALL
        SELECT '6up', b.id, '6UP', row_item->>'number',
               COALESCE((row_item->>'straight')::numeric,0)+COALESCE((row_item->>'rumble')::numeric,0),
               b.status, b.draw_date, b.created_at, u.username
        FROM demo_6up_bets b JOIN users u ON u.id=b.user_id
        CROSS JOIN LATERAL jsonb_array_elements(b.rows) row_item
        LEFT JOIN draw_results r ON r.draw_date=b.draw_date
        WHERE r.id IS NULL OR b.created_at >= r.published_at OR NOW() < r.published_at + INTERVAL '72 hours'
        ORDER BY created_at DESC LIMIT 1000
      `);
      res.json({ success: true, reports: result.rows });
    }));

    // ==========================================
    // ADMIN: AUDIT LOGS
    // ==========================================

    app.get(
      "/api/admin/audit-logs",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const result = await pool.query(
          `SELECT id, actor_id, action, target_user_id, details, created_at
           FROM audit_logs
           ORDER BY created_at DESC
           LIMIT 200`
        );

        res.json({
          success: true,
          logs: result.rows
        });
      })
    );

    // ==========================================
    // 404
    // ==========================================

    // ==========================================
    // LIVE SUPPORT
    // Users can open a conversation by sending the first message.
    // Only the primary admin can reply, and only after a user message exists.
    // ==========================================

    function normalizeSupportMessage(row) {
      return {
        id: row.id,
        conversation_id: row.conversation_id,
        sender_id: row.sender_id,
        sender_role: row.sender_role,
        message: row.message,
        created_at: row.created_at
      };
    }

    app.get("/api/support/messages", authenticateToken, asyncRoute(async (req, res) => {
      let userId;
      if (isPrimaryAdmin(req.user)) {
        userId = req.query.user_id;
        if (!userId) return sendError(res, 400, "user_id is required for Admin.");
      } else {
        userId = req.user.id;
      }

      const conversation = await pool.query(
        `SELECT id, user_id, created_at, updated_at
         FROM support_conversations WHERE user_id = $1`, [userId]
      );
      if (!conversation.rows.length) {
        return res.json({ success: true, conversation: null, messages: [] });
      }
      const conv = conversation.rows[0];
      const result = await pool.query(
        `SELECT id, conversation_id, sender_id, sender_role, message, created_at
         FROM support_messages WHERE conversation_id = $1
         ORDER BY created_at ASC, id ASC`, [conv.id]
      );
      return res.json({ success: true, conversation: conv, messages: result.rows.map(normalizeSupportMessage) });
    }));

    app.post("/api/support/messages", authenticateToken, asyncRoute(async (req, res) => {
      const message = typeof req.body.message === "string" ? req.body.message.trim() : "";
      if (!message || message.length > 5000) {
        return sendError(res, 400, "Message must contain 1 to 5000 characters.");
      }

      const adminSending = isPrimaryAdmin(req.user);
      const targetUserId = adminSending ? req.body.user_id : req.user.id;
      if (adminSending && !targetUserId) {
        return sendError(res, 400, "user_id is required when Admin replies.");
      }

      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        let conversation;
        if (adminSending) {
          const found = await client.query(
            `SELECT id, user_id FROM support_conversations
             WHERE user_id = $1 FOR UPDATE`, [targetUserId]
          );
          if (!found.rows.length) {
            await client.query("ROLLBACK");
            return sendError(res, 404, "The user has not started a support conversation.");
          }
          conversation = found.rows[0];
          const firstUserMessage = await client.query(
            `SELECT id FROM support_messages
             WHERE conversation_id = $1 AND sender_role = 'user' LIMIT 1`, [conversation.id]
          );
          if (!firstUserMessage.rows.length) {
            await client.query("ROLLBACK");
            return sendError(res, 403, "Admin can reply only after the user sends a message.");
          }
        } else {
          const created = await client.query(
            `INSERT INTO support_conversations (user_id) VALUES ($1)
             ON CONFLICT (user_id) DO UPDATE SET updated_at = NOW()
             RETURNING id, user_id`, [req.user.id]
          );
          conversation = created.rows[0];
          await client.query(
            `SELECT id FROM support_conversations WHERE id = $1 FOR UPDATE`, [conversation.id]
          );
        }

        const inserted = await client.query(
          `INSERT INTO support_messages
             (conversation_id, sender_id, sender_role, message)
           VALUES ($1, $2, $3, $4)
           RETURNING id, conversation_id, sender_id, sender_role, message, created_at`,
          [conversation.id, req.user.id, adminSending ? "admin" : "user", message]
        );
        await client.query(
          `UPDATE support_conversations SET updated_at = NOW() WHERE id = $1`, [conversation.id]
        );
        await client.query("COMMIT");
        return res.status(201).json({ success: true, message: normalizeSupportMessage(inserted.rows[0]) });
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    }));

    app.get("/api/admin/support/conversations", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const result = await pool.query(
        
