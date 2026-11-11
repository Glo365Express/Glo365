    require("dotenv").config();

    const express = require("express");
    const cors = require("cors");
    const bcrypt = require("bcryptjs");
    const jwt = require("jsonwebtoken");
    const crypto = require("crypto");

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

    const pool = require("./src/config/database");

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

    function validPassword(password) {
      return typeof password === "string" && password.length >= 6 && password.length <= 16;
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

        -- Millionaire is intentionally isolated from Single/2D/3UP/6UP settlement.
        CREATE TABLE IF NOT EXISTS millionaire_draws (
          id BIGSERIAL PRIMARY KEY,
          draw_date DATE NOT NULL UNIQUE,
          draw_number VARCHAR(40) NOT NULL UNIQUE,
          draw_at TIMESTAMPTZ NOT NULL,
          result VARCHAR(3),
          published_at TIMESTAMPTZ,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
          CHECK (result IS NULL OR result ~ '^[0-9]{3}$')
        );
        CREATE TABLE IF NOT EXISTS millionaire_bets (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          draw_id BIGINT NOT NULL REFERENCES millionaire_draws(id) ON DELETE RESTRICT,
          selection VARCHAR(3) NOT NULL CHECK (selection ~ '^[0-9]{3}$'),
          amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
          status VARCHAR(20) NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending','win','loss')),
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_millionaire_bets_user_date
          ON millionaire_bets(user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_millionaire_bets_draw
          ON millionaire_bets(draw_id, status);


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

        ALTER TABLE users
          ADD COLUMN IF NOT EXISTS commission_rate NUMERIC(5,2) NOT NULL DEFAULT 0
          CHECK (commission_rate BETWEEN 0 AND 100);

        CREATE TABLE IF NOT EXISTS affiliate_loss_commissions (
          id BIGSERIAL PRIMARY KEY,
          affiliate_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          referred_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          source_table VARCHAR(40) NOT NULL,
          source_bet_id BIGINT NOT NULL,
          loss_points NUMERIC(12,2) NOT NULL CHECK (loss_points > 0),
          commission_rate NUMERIC(5,2) NOT NULL CHECK (commission_rate BETWEEN 0 AND 100),
          commission_amount NUMERIC(12,2) NOT NULL CHECK (commission_amount >= 0),
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          UNIQUE(source_table, source_bet_id)
        );
        CREATE INDEX IF NOT EXISTS idx_affiliate_loss_affiliate_date
          ON affiliate_loss_commissions(affiliate_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_affiliate_loss_user
          ON affiliate_loss_commissions(referred_user_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS audit_logs (
          id BIGSERIAL PRIMARY KEY,
          actor_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
          action VARCHAR(100) NOT NULL,
          target_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
          details JSONB DEFAULT '{}'::jsonb,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS user_verifications (
          id BIGSERIAL PRIMARY KEY,
          user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
          legal_name_enc TEXT NOT NULL,
          document_type VARCHAR(10) NOT NULL CHECK (document_type IN ('NID','PASSPORT')),
          document_number_enc TEXT NOT NULL,
          phone_enc TEXT NOT NULL,
          email_enc TEXT NOT NULL,
          status VARCHAR(20) NOT NULL DEFAULT 'verified' CHECK (status IN ('verified','corrected')),
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL
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


        -- Withdrawal requests are stored server-side; points are debited on submission and refunded only on rejection.
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
          points_deducted BOOLEAN NOT NULL DEFAULT FALSE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE withdrawal_requests
          ADD COLUMN IF NOT EXISTS points_deducted BOOLEAN NOT NULL DEFAULT FALSE;
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
        CREATE INDEX IF NOT EXISTS idx_millionaire_draw_date ON millionaire_draws(draw_date DESC);
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
          user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          status VARCHAR(12) NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
          closed_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        ALTER TABLE support_conversations ADD COLUMN IF NOT EXISTS status VARCHAR(12) NOT NULL DEFAULT 'open';
        ALTER TABLE support_conversations ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ;
        ALTER TABLE support_conversations DROP CONSTRAINT IF EXISTS support_conversations_user_id_key;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_support_one_open_conversation_per_user
          ON support_conversations(user_id) WHERE status = 'open';
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

    app.get("/api/auth/username-availability", asyncRoute(async (req, res) => {
      const username = cleanText(req.query.username, 30).toLowerCase();
      if (!validUsername(username) || username === PRIMARY_ADMIN_USERNAME) {
        return res.json({ success: true, available: false, valid: false });
      }
      const result = await pool.query(
        "SELECT 1 FROM users WHERE username = $1 LIMIT 1", [username]
      );
      return res.json({ success: true, available: result.rows.length === 0, valid: true });
    }));

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

      if (!validPassword(password)) {
        return sendError(res, 400, "Password must be 6-16 characters.");
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
    // CHANGE LOGIN PASSWORD
    // ==========================================

    app.post("/api/auth/change-password", authenticateToken, asyncRoute(async (req, res) => {
      const currentPassword = req.body.current_password;
      const newPassword = req.body.new_password;
      if (typeof currentPassword !== "string" || !currentPassword) {
        return sendError(res, 400, "Current password is required.");
      }
      if (!validPassword(newPassword)) {
        return sendError(res, 400, "New password must be 6-16 characters.");
      }
      const found = await pool.query(
        "SELECT password_hash FROM users WHERE id = $1 LIMIT 1", [req.user.id]
      );
      if (!found.rows.length) return sendError(res, 404, "Account not found.");
      const matches = await bcrypt.compare(currentPassword, found.rows[0].password_hash);
      if (!matches) return sendError(res, 401, "Current password is incorrect.");
      const passwordHash = await bcrypt.hash(newPassword, 12);
      await pool.query(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
        [passwordHash, req.user.id]
      );
      clearAuthCookie(res);
      return res.json({ success: true, message: "Password changed. Please log in again." });
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
    // PRIVATE IDENTITY VERIFICATION HELPERS
    // ==========================================

    function verificationKey() {
      const raw = process.env.VERIFICATION_ENCRYPTION_KEY || "";
      let key;
      if (/^[a-f0-9]{64}$/i.test(raw)) key = Buffer.from(raw, "hex");
      else {
        try { key = Buffer.from(raw, "base64"); } catch { key = null; }
      }
      if (!key || key.length !== 32) {
        throw new Error("VERIFICATION_ENCRYPTION_KEY must be a 32-byte key (64 hex characters or base64).");
      }
      return key;
    }

    function encryptVerificationValue(value) {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", verificationKey(), iv);
      const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
      return [iv.toString("base64"), cipher.getAuthTag().toString("base64"), encrypted.toString("base64")].join(".");
    }

    function decryptVerificationValue(value) {
      const parts = String(value || "").split(".");
      if (parts.length !== 3) throw new Error("Invalid encrypted verification value.");
      const decipher = crypto.createDecipheriv("aes-256-gcm", verificationKey(), Buffer.from(parts[0], "base64"));
      decipher.setAuthTag(Buffer.from(parts[1], "base64"));
      return Buffer.concat([decipher.update(Buffer.from(parts[2], "base64")), decipher.final()]).toString("utf8");
    }

    function maskValue(value, visibleStart = 1, visibleEnd = 2) {
      const chars = Array.from(String(value || ""));
      if (chars.length <= visibleStart + visibleEnd) return "*".repeat(Math.max(4, chars.length));
      return chars.slice(0, visibleStart).join("") + "*".repeat(Math.min(10, chars.length - visibleStart - visibleEnd)) + chars.slice(-visibleEnd).join("");
    }

    function verificationPublicView(row) {
      const name = decryptVerificationValue(row.legal_name_enc);
      const documentNumber = decryptVerificationValue(row.document_number_enc);
      const phone = decryptVerificationValue(row.phone_enc);
      const email = decryptVerificationValue(row.email_enc);
      const words = name.split(/\s+/).filter(Boolean);
      const maskedName = words.map(w => w.length < 3 ? "*".repeat(w.length) : w[0] + "*".repeat(Math.min(6, w.length - 1))).join(" ");
      return {
        status: row.status,
        legal_name: maskedName,
        document_type: row.document_type,
        document_number: maskValue(documentNumber, 1, 2),
        phone: maskValue(phone, 3, 2),
        email: maskValue(email, 1, Math.min(10, (email.split("@")[1] || "").length + 1)),
        created_at: row.created_at,
        updated_at: row.updated_at
      };
    }

    function validateVerificationInput(body) {
      const legalName = cleanText(body.legal_name, 120);
      const documentType = cleanText(body.document_type, 10).toUpperCase();
      const documentNumber = cleanText(body.document_number, 40).replace(/\s+/g, "").toUpperCase();
      const phone = cleanText(body.phone, 25).replace(/[\s()-]/g, "");
      const email = cleanText(body.email, 150).toLowerCase();
      if (legalName.length < 3 || !/^[\p{L}][\p{L} .'-]{1,118}$/u.test(legalName)) return { error: "Enter your full legal name." };
      if (!["NID", "PASSPORT"].includes(documentType)) return { error: "Select NID or Passport." };
      if (!/^[A-Z0-9-]{5,40}$/.test(documentNumber)) return { error: "Enter a valid document number format." };
      if (!/^\+?[0-9]{8,15}$/.test(phone)) return { error: "Enter a valid phone number." };
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { error: "Enter a valid email address." };
      return { legalName, documentType, documentNumber, phone, email };
    }

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
    // USER IDENTITY VERIFICATION (ONE-TIME SUBMISSION)
    // ==========================================

    app.get("/api/verification/me", authenticateToken, asyncRoute(async (req, res) => {
      const result = await pool.query("SELECT * FROM user_verifications WHERE user_id = $1", [req.user.id]);
      if (!result.rows.length) return res.json({ success: true, submitted: false, verification: null });
      return res.json({ success: true, submitted: true, verification: verificationPublicView(result.rows[0]) });
    }));

    app.post("/api/verification", authenticateToken, asyncRoute(async (req, res) => {
      let values;
      try { values = validateVerificationInput(req.body || {}); }
      catch (error) { console.error("Verification validation error:", error.message); return sendError(res, 503, "Verification service is not configured securely."); }
      if (values.error) return sendError(res, 400, values.error);
      let encrypted;
      try {
        encrypted = [encryptVerificationValue(values.legalName), encryptVerificationValue(values.documentNumber), encryptVerificationValue(values.phone), encryptVerificationValue(values.email)];
      } catch (error) {
        console.error("Verification encryption configuration error:", error.message);
        return sendError(res, 503, "Verification service is temporarily unavailable.");
      }
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const inserted = await client.query(
          `INSERT INTO user_verifications (user_id, legal_name_enc, document_type, document_number_enc, phone_enc, email_enc, status)
           VALUES ($1,$2,$3,$4,$5,$6,'verified')
           ON CONFLICT (user_id) DO NOTHING RETURNING *`,
          [req.user.id, encrypted[0], values.documentType, encrypted[1], encrypted[2], encrypted[3]]
        );
        if (!inserted.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 409, "Verification details have already been submitted and cannot be changed.");
        }
        await client.query(
          `INSERT INTO audit_logs (actor_id, action, target_user_id, details) VALUES ($1,'verification.submitted',$1,$2::jsonb)`,
          [req.user.id, JSON.stringify({ document_type: values.documentType, status: "verified" })]
        );
        await client.query("COMMIT");
        return res.status(201).json({ success: true, message: "Your details have been securely submitted.", verification: verificationPublicView(inserted.rows[0]) });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally { client.release(); }
    }));

    // Primary Admin verification queue (masked values only; no decryption).
    app.get("/api/admin/verifications", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT v.user_id, u.username, v.document_type, v.status, v.created_at, v.updated_at
         FROM user_verifications v JOIN users u ON u.id = v.user_id
         ORDER BY v.created_at DESC LIMIT 500`
      );
      return res.json({ success: true, verifications: result.rows });
    }));

    // Primary Admin only. Full identity data is decrypted only for this endpoint.
    app.get("/api/admin/verifications/:userId", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const userId = String(req.params.userId || "");
      if (!/^\d+$/.test(userId)) return sendError(res, 400, "Invalid user ID.");
      const result = await pool.query(
        `SELECT v.*, u.username FROM user_verifications v JOIN users u ON u.id = v.user_id WHERE v.user_id = $1`, [userId]
      );
      if (!result.rows.length) return sendError(res, 404, "Verification record not found.");
      const row = result.rows[0];
      const full = {
        user_id: row.user_id, username: row.username,
        legal_name: decryptVerificationValue(row.legal_name_enc), document_type: row.document_type,
        document_number: decryptVerificationValue(row.document_number_enc),
        phone: decryptVerificationValue(row.phone_enc), email: decryptVerificationValue(row.email_enc),
        status: row.status, created_at: row.created_at, updated_at: row.updated_at
      };
      await pool.query(
        `INSERT INTO audit_logs (actor_id, action, target_user_id, details) VALUES ($1,'verification.admin_viewed',$2,$3::jsonb)`,
        [req.user.id, userId, JSON.stringify({ fields: ["legal_name", "document_number", "phone", "email"] })]
      );
      return res.json({ success: true, verification: full });
    }));

    app.patch("/api/admin/verifications/:userId", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const userId = String(req.params.userId || "");
      if (!/^\d+$/.test(userId)) return sendError(res, 400, "Invalid user ID.");
      const current = await pool.query("SELECT * FROM user_verifications WHERE user_id = $1", [userId]);
      if (!current.rows.length) return sendError(res, 404, "Verification record not found.");
      const old = current.rows[0];
      const merged = {
        legal_name: req.body.legal_name === undefined ? decryptVerificationValue(old.legal_name_enc) : req.body.legal_name,
        document_type: req.body.document_type === undefined ? old.document_type : req.body.document_type,
        document_number: req.body.document_number === undefined ? decryptVerificationValue(old.document_number_enc) : req.body.document_number,
        phone: req.body.phone === undefined ? decryptVerificationValue(old.phone_enc) : req.body.phone,
        email: req.body.email === undefined ? decryptVerificationValue(old.email_enc) : req.body.email
      };
      const values = validateVerificationInput({ legal_name: merged.legal_name, document_type: merged.document_type, document_number: merged.document_number, phone: merged.phone, email: merged.email });
      if (values.error) return sendError(res, 400, values.error);
      const encrypted = [encryptVerificationValue(values.legalName), encryptVerificationValue(values.documentNumber), encryptVerificationValue(values.phone), encryptVerificationValue(values.email)];
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          `UPDATE user_verifications SET legal_name_enc=$1, document_type=$2, document_number_enc=$3, phone_enc=$4, email_enc=$5, status='corrected', updated_at=NOW(), updated_by=$6 WHERE user_id=$7`,
          [encrypted[0], values.documentType, encrypted[1], encrypted[2], encrypted[3], req.user.id, userId]
        );
        await client.query(
          `INSERT INTO audit_logs (actor_id, action, target_user_id, details) VALUES ($1,'verification.admin_corrected',$2,$3::jsonb)`,
          [req.user.id, userId, JSON.stringify({ fields: Object.keys(req.body || {}).filter(k => ["legal_name","document_type","document_number","phone","email"].includes(k)) })]
        );
        await client.query("COMMIT");
      } catch (error) { await client.query("ROLLBACK"); throw error; }
      finally { client.release(); }
      return res.json({ success: true, message: "Verification details corrected by Admin." });
    }));

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
          `SELECT COALESCE(SUM(commission_amount), 0) AS total,
                  COUNT(*)::int AS entries,
                  COALESCE(SUM(loss_points), 0) AS total_loss_points
           FROM affiliate_loss_commissions
           WHERE affiliate_id = $1`,
          [req.user.id]
        );
        const rate = await pool.query(
          `SELECT commission_rate FROM users WHERE id = $1 AND role = 'affiliate'`,
          [req.user.id]
        );

        res.json({
          success: true,
          referral_code: info.rows[0]?.referral_code,
          total_referrals: referrals.rows[0].total,
          commission_rate: rate.rows[0]?.commission_rate || 0,
          commissions: commissions.rows[0]
        });
      })
    );

    app.get(
      "/api/affiliate/users",
      authenticateToken,
      asyncRoute(async (req, res) => {
        if (req.user.role !== "affiliate") {
          return sendError(res, 403, "Affiliate access required.");
        }
        const result = await pool.query(
          `SELECT id, username, created_at, status
           FROM users
           WHERE referred_by = $1 AND role = 'user'
           ORDER BY created_at DESC
           LIMIT 1000`,
          [req.user.id]
        );
        res.json({ success: true, users: result.rows, total: result.rows.length });
      })
    );

    app.get(
      "/api/affiliate/commissions",
      authenticateToken,
      asyncRoute(async (req, res) => {
        if (req.user.role !== "affiliate") {
          return sendError(res, 403, "Affiliate access required.");
        }
        const result = await pool.query(
          `SELECT c.id, c.referred_user_id, u.username AS referred_username,
                  c.source_table, c.source_bet_id, c.loss_points,
                  c.commission_rate, c.commission_amount, c.created_at
           FROM affiliate_loss_commissions c
           JOIN users u ON u.id = c.referred_user_id
           WHERE c.affiliate_id = $1
           ORDER BY c.created_at DESC
           LIMIT 500`,
          [req.user.id]
        );
        res.json({ success: true, commissions: result.rows });
      })
    );

    // ==========================================
    // AFFILIATE MANAGEMENT HELPERS
    // ==========================================

    async function getAffiliateList(res) {
      const result = await pool.query(
        `SELECT u.id, u.username, u.email, u.status,
                u.referral_code, u.commission_rate, u.created_at,
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

    app.post(
      "/api/admin/affiliates",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const username = cleanText(req.body.username, 30).toLowerCase();
        const email = cleanText(req.body.email, 150).toLowerCase();
        const password = req.body.password;
        const rate = Number(req.body.commission_rate);
        if (!validUsername(username) || !validEmail(email)) {
          return sendError(res, 400, "Enter a valid username and email address.");
        }
        if (username === PRIMARY_ADMIN_USERNAME) {
          return sendError(res, 400, "This username is reserved.");
        }
        if (!validPassword(password)) {
          return sendError(res, 400, "Password must be 6-16 characters.");
        }
        if (!Number.isFinite(rate) || rate < 0 || rate > 100) {
          return sendError(res, 400, "Commission rate must be between 0 and 100.");
        }
        const passwordHash = await bcrypt.hash(password, 12);
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const created = await client.query(
            `INSERT INTO users (username,email,password_hash,role,status,commission_rate)
             VALUES ($1,$2,$3,'affiliate','active',$4)
             RETURNING id,username,email,role,status,commission_rate,created_at`,
            [username,email,passwordHash,rate]
          );
          const affiliate = created.rows[0];
          const code = "GLOAF" + affiliate.id;
          await client.query("UPDATE users SET referral_code=$1 WHERE id=$2", [code,affiliate.id]);
          await client.query("INSERT INTO profiles (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING", [affiliate.id]);
          await client.query("COMMIT");
          affiliate.referral_code = code;
          await audit(req.user.id, "affiliate_account_created", affiliate.id, { commission_rate: rate });
          return res.status(201).json({ success:true, message:"Affiliate account created.", affiliate });
        } catch (error) {
          await client.query("ROLLBACK");
          if (error.code === "23505") return sendError(res, 409, "Username or email already exists.");
          throw error;
        } finally { client.release(); }
      })
    );

    app.patch(
      "/api/admin/affiliates/:id/rate",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const id = validId(req.params.id);
        const rate = Number(req.body.commission_rate);
        if (!id || !Number.isFinite(rate) || rate < 0 || rate > 100) {
          return sendError(res, 400, "Valid affiliate ID and commission rate (0-100) are required.");
        }
        const result = await pool.query(
          `UPDATE users SET commission_rate=$1, updated_at=NOW()
           WHERE id=$2 AND role='affiliate'
           RETURNING id,username,email,status,commission_rate,referral_code`,
          [rate,id]
        );
        if (!result.rows.length) return sendError(res, 404, "Affiliate not found.");
        await audit(req.user.id, "affiliate_commission_rate_updated", id, { commission_rate: rate });
        res.json({ success:true, affiliate:result.rows[0] });
      })
    );

    app.patch(
      "/api/admin/affiliates/:id/status",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const id = validId(req.params.id);
        const status = cleanText(req.body.status, 20).toLowerCase();
        if (!id || !["active","suspended"].includes(status)) {
          return sendError(res, 400, "Status must be active or suspended.");
        }
        const result = await pool.query(
          `UPDATE users SET status=$1, updated_at=NOW()
           WHERE id=$2 AND role='affiliate'
           RETURNING id,username,email,status,commission_rate`,
          [status,id]
        );
        if (!result.rows.length) return sendError(res, 404, "Affiliate not found.");
        await audit(req.user.id, "affiliate_status_updated", id, { status });
        res.json({ success:true, affiliate:result.rows[0] });
      })
    );

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

    // Admin view of automatically calculated loss-point commissions only.
    app.get(
      "/api/admin/affiliates/loss-commissions",
      authenticateToken,
      requireAdmin,
      asyncRoute(async (req, res) => {
        const result = await pool.query(
          `SELECT c.id, c.affiliate_id, c.referred_user_id,
                  a.username AS affiliate_username,
                  u.username AS referred_username,
                  c.source_table, c.source_bet_id, c.loss_points,
                  c.commission_rate, c.commission_amount, c.created_at
           FROM affiliate_loss_commissions c
           JOIN users a ON a.id = c.affiliate_id
           JOIN users u ON u.id = c.referred_user_id
           ORDER BY c.created_at DESC
           LIMIT 500`
        );
        res.json({ success: true, commissions: result.rows });
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
        UNION ALL
        SELECT 'millionaire', b.id, 'Millionaire', b.selection, b.amount,
               b.status, d.draw_date, b.created_at, u.username
        FROM millionaire_bets b
        JOIN millionaire_draws d ON d.id=b.draw_id
        JOIN users u ON u.id=b.user_id
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
    // ==========================================
    // MODULAR ROUTE REGISTRATION
    // ==========================================

    const registerDepositRoutes = require("./src/routes/deposit");
    const registerWithdrawalRoutes = require("./src/routes/withdrawal");
    const { registerWalletRoutes } = require("./src/routes/wallet");
    const registerDailyMillionaireRoutes = require("./src/games/daily-millionaire");
    const registerResultsRoutes = require("./src/games/results");
    const registerThailandRoutes = require("./src/games/thailand");
    const registerThailand3UpRoutes = require("./src/games/thailand/3up");
    const registerThailand6UpRoutes = require("./src/games/thailand/6up");
    const registerSingaporeRoutes = require("./src/games/singapore");
    const registerMalaysiaRoutes = require("./src/games/malaysia");

    const routeDependencies = {
      pool,
      authenticateToken,
      requireAdmin,
      asyncRoute,
      cleanText,
      sendError,
      audit,
      getCurrentDraw,
      isDrawBettingLocked,
      DRAW_LOCK_MINUTES
    };

    registerDepositRoutes({ app, ...routeDependencies });
    registerWithdrawalRoutes(app, routeDependencies);
    registerWalletRoutes(app, routeDependencies);
    registerDailyMillionaireRoutes(app, routeDependencies);
    registerThailandRoutes(app, routeDependencies);
    registerThailand3UpRoutes({ app, ...routeDependencies });
    registerThailand6UpRoutes({ app, ...routeDependencies });
    const initializeSingaporeRoutes = registerSingaporeRoutes(app, routeDependencies);
    const initializeMalaysiaRoutes = registerMalaysiaRoutes(app, routeDependencies);
    registerResultsRoutes(app, routeDependencies);

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
        `SELECT id, user_id, status, created_at, updated_at, closed_at
         FROM support_conversations WHERE user_id = $1 AND status = 'open'
         ORDER BY id DESC LIMIT 1`, [userId]
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
             WHERE user_id = $1 AND status = 'open' ORDER BY id DESC LIMIT 1 FOR UPDATE`, [targetUserId]
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
            `INSERT INTO support_conversations (user_id, status) VALUES ($1, 'open')
             ON CONFLICT (user_id) WHERE status = 'open'
             DO UPDATE SET updated_at = NOW()
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

    // Admin Close permanently deletes this conversation and its messages (CASCADE).
    // A later user message starts a brand-new conversation with no chat history.
    app.delete("/api/admin/support/conversations/:id", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const id = String(req.params.id || "");
      if (!/^\d+$/.test(id)) return sendError(res, 400, "Invalid conversation ID.");
      const deleted = await pool.query(
        "DELETE FROM support_conversations WHERE id = $1 AND status = 'open' RETURNING id",
        [id]
      );
      if (!deleted.rows.length) return sendError(res, 404, "Open conversation not found.");
      return res.json({ success: true, message: "Conversation and its messages have been deleted." });
    }));

    app.get("/api/admin/support/conversations", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT c.id, c.user_id, c.status, u.username, u.email, c.created_at, c.updated_at,
                (SELECT m.message FROM support_messages m
                 WHERE m.conversation_id = c.id
                 ORDER BY m.created_at DESC, m.id DESC LIMIT 1) AS last_message,
                (SELECT m.sender_role FROM support_messages m
                 WHERE m.conversation_id = c.id
                 ORDER BY m.created_at DESC, m.id DESC LIMIT 1) AS last_sender_role
         FROM support_conversations c
         JOIN users u ON u.id = c.user_id
         WHERE c.status = 'open'
         ORDER BY c.updated_at DESC, c.id DESC`
      );
      return res.json({ success: true, conversations: result.rows });
    }));

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

      if (error.message === "Origin not allowed.") {
        return sendError(res, 403, "Origin not allowed.");
      }

      if (error.code === "23505") {
        return sendError(res, 409, "A record with this information already exists.");
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

        // Initialize Singapore-specific tables after the shared users table exists.
        await initializeSingaporeRoutes();

        // Initialize Malaysia-specific tables after the shared users table exists.
        await initializeMalaysiaRoutes();

        await bootstrapAdmin();

        await installPrimaryAdminProtection();

        app.listen(PORT, "0.0.0.0", () => {
          console.log(
            "GLO 365 API v2.6.0 running on port " + PORT
          );
          console.log("Primary Admin username: adminglo365");
        });

      } catch (error) {
        console.error("Server startup failed:", error.message);
        process.exit(1);
      }
    }

    startServer();