"use strict";

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_USERNAME = "adminglo365";
const LOCK_MINUTES = 45;
const MAX_BET = 100000;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
  process.exit(1);
}

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map(x => x.trim().replace(/\/+$/, ""))
  .filter(Boolean);

if (process.env.NODE_ENV === "production" && !allowedOrigins.length) {
  console.error("FRONTEND_URL is required in production.");
  process.exit(1);
}

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);

    const normalized = origin.replace(/\/+$/, "");

    if (allowedOrigins.includes(normalized)) {
      return callback(null, true);
    }

    if (
      process.env.NODE_ENV !== "production" &&
      ["http://localhost:3000", "http://localhost:5500",
       "http://127.0.0.1:5500"].includes(origin)
    ) {
      return callback(null, true);
    }

    return callback(new Error("Origin not allowed."));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.PGSSL === "false"
    ? false
    : { rejectUnauthorized: false },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

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

function validGame(game) {
  return ["2D", "3D", "4D", "649"].includes(
    String(game || "").toUpperCase()
  );
}

function normalizeGame(game) {
  return String(game || "").toUpperCase();
}

function validAmount(value) {
  const amount = Number(value);

  return Number.isFinite(amount) &&
    amount > 0 &&
    amount <= MAX_BET &&
    Math.round(amount * 100) === amount * 100
    ? amount
    : null;
}

function validateSelections(game, selections) {
  if (!Array.isArray(selections) || selections.length < 1 ||
      selections.length > 50) {
    return false;
  }

  if (game === "649") {
    return selections.every(item => {
      if (!Array.isArray(item) || item.length !== 6) return false;

      const nums = item.map(Number);

      return nums.every(n =>
        Number.isInteger(n) && n >= 1 && n <= 49
      ) && new Set(nums).size === 6;
    });
  }

  const digits = Number(game);

  return selections.every(item =>
    typeof item === "string" &&
    new RegExp(`^[0-9]{${digits}}$`).test(item)
  );
}

function getLockStatus(drawAt, enabled) {
  if (!enabled || !drawAt) return true;

  const drawTime = new Date(drawAt).getTime();

  if (!Number.isFinite(drawTime)) return true;

  return drawTime - Date.now() <= LOCK_MINUTES * 60 * 1000;
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS singapore_game_settings (
      game VARCHAR(10) PRIMARY KEY,
      draw_number VARCHAR(50) NOT NULL DEFAULT '',
      draw_at TIMESTAMPTZ,
      prize_rate NUMERIC(12,2) NOT NULL DEFAULT 0,
      betting_enabled BOOLEAN NOT NULL DEFAULT FALSE,
      updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS singapore_bets (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      game VARCHAR(10) NOT NULL
        CHECK (game IN ('2D','3D','4D','649')),
      draw_number VARCHAR(50) NOT NULL,
      draw_at TIMESTAMPTZ NOT NULL,
      selections JSONB NOT NULL,
      amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
      prize_rate NUMERIC(12,2) NOT NULL DEFAULT 0,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_singapore_bets_user
      ON singapore_bets(user_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_singapore_bets_game_draw
      ON singapore_bets(game, draw_number);

    CREATE INDEX IF NOT EXISTS idx_singapore_settings_draw
      ON singapore_game_settings(draw_at);
  `);

  await pool.query(`
    INSERT INTO singapore_game_settings
      (game, betting_enabled)
    VALUES
      ('2D', FALSE),
      ('3D', FALSE),
      ('4D', FALSE),
      ('649', FALSE)
    ON CONFLICT (game) DO NOTHING
  `);

  console.log("Singapore Games database ready.");
}

async function authenticateToken(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.substring(7).trim()
    : null;

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
       WHERE id = $1
       LIMIT 1`,
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
    next(error);
  }
}

function requireAdmin(req, res, next) {
  if (
    req.user.role !== "admin" ||
    req.user.username !== ADMIN_USERNAME
  ) {
    return sendError(res, 403, "Primary Admin access required.");
  }

  next();
}

async function getSettings(game) {
  const result = await pool.query(
    `SELECT game, draw_number, draw_at, prize_rate,
            betting_enabled, updated_at
     FROM singapore_game_settings
     WHERE game = $1`,
    [game]
  );

  return result.rows[0] || null;
}

function publicSettings(row) {
  if (!row) return null;

  return {
    game: row.game,
    draw_number: row.draw_number,
    draw_at: row.draw_at,
    prize_rate: Number(row.prize_rate),
    betting_enabled: row.betting_enabled,
    betting_locked: getLockStatus(
      row.draw_at,
      row.betting_enabled
    ),
    lock_minutes: LOCK_MINUTES,
    updated_at: row.updated_at
  };
}

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    service: "GLO 365 Singapore Games",
    status: "online"
  });
});

app.get("/api/singapore/games", (req, res) => {
  res.json({
    success: true,
    games: [
      { id: "2D", name: "2D NUMBER" },
      { id: "3D", name: "3D NUMBER" },
      { id: "4D", name: "4D NUMBER" },
      { id: "649", name: "6/49 NUMBER" }
    ]
  });
});

app.get("/api/singapore/settings/:game",
  asyncRoute(async (req, res) => {
    const game = normalizeGame(req.params.game);

    if (!validGame(game)) {
      return sendError(res, 400, "Invalid game.");
    }

    const row = await getSettings(game);

    res.json({
      success: true,
      settings: publicSettings(row)
    });
  })
);

app.get("/api/singapore/settings",
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT game, draw_number, draw_at, prize_rate,
              betting_enabled, updated_at
       FROM singapore_game_settings
       ORDER BY game`
    );

    res.json({
      success: true,
      settings: result.rows.map(publicSettings)
    });
  })
);

app.get("/api/singapore/me",
  authenticateToken,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT id, username, balance
       FROM users
       WHERE id = $1`,
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

app.post("/api/singapore/bets",
  authenticateToken,
  asyncRoute(async (req, res) => {
    const game = normalizeGame(req.body.game);
    const amount = validAmount(req.body.amount);
    const selections = req.body.selections;

    if (!validGame(game)) {
      return sendError(res, 400, "Invalid game.");
    }

    if (!amount) {
      return sendError(res, 400, "Invalid bet amount.");
    }

    if (!validateSelections(game, selections)) {
      return sendError(res, 400, "Invalid number selection.");
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const settingsResult = await client.query(
        `SELECT game, draw_number, draw_at, prize_rate,
                betting_enabled
         FROM singapore_game_settings
         WHERE game = $1
         FOR UPDATE`,
        [game]
      );

      if (!settingsResult.rows.length) {
        await client.query("ROLLBACK");
        return sendError(res, 404, "Game settings not found.");
      }

      const settings = settingsResult.rows[0];

      if (
        getLockStatus(settings.draw_at, settings.betting_enabled)
      ) {
        await client.query("ROLLBACK");
        return sendError(res, 403, "Betting is currently closed.");
      }

      if (!settings.draw_number || !settings.draw_at) {
        await client.query("ROLLBACK");
        return sendError(res, 400, "Draw is not configured.");
      }

      const debit = await client.query(
        `UPDATE users
         SET balance = balance - $1
         WHERE id = $2
           AND status = 'active'
           AND balance >= $1
         RETURNING balance`,
        [amount, req.user.id]
      );

      if (!debit.rows.length) {
        await client.query("ROLLBACK");
        return sendError(res, 400, "Insufficient points.");
      }

      const betResult = await client.query(
        `INSERT INTO singapore_bets
         (user_id, game, draw_number, draw_at,
          selections, amount, prize_rate)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)
         RETURNING id, game, draw_number, draw_at,
                   selections, amount, prize_rate,
                   status, created_at`,
        [
          req.user.id,
          game,
          settings.draw_number,
          settings.draw_at,
          JSON.stringify(selections),
          amount,
          settings.prize_rate
        ]
      );

      await client.query(
        `INSERT INTO wallet_transactions
         (user_id, type, amount, currency, description, reference)
         VALUES ($1, $2, $3, 'DEMO', $4, $5)`,
        [
          req.user.id,
          "singapore_bet",
          amount,
          `Singapore ${game} demo points bet`,
          `SG-${betResult.rows[0].id}`
        ]
      );

      await client.query("COMMIT");

      res.status(201).json({
        success: true,
        message: "Bet placed successfully.",
        bet: betResult.rows[0],
        balance: debit.rows[0].balance
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  })
);

app.get("/api/singapore/bets",
  authenticateToken,
  asyncRoute(async (req, res) => {
    const limit = Math.min(
      Math.max(Number(req.query.limit) || 30, 1),
      100
    );

    const result = await pool.query(
      `SELECT id, game, draw_number, draw_at,
              selections, amount, prize_rate,
              status, created_at
       FROM singapore_bets
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [req.user.id, limit]
    );

    res.json({
      success: true,
      bets: result.rows
    });
  })
);

app.get("/api/admin/singapore/settings",
  authenticateToken,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT game, draw_number, draw_at, prize_rate,
              betting_enabled, updated_by, updated_at
       FROM singapore_game_settings
       ORDER BY game`
    );

    res.json({
      success: true,
      settings: result.rows.map(publicSettings)
    });
  })
);

app.put("/api/admin/singapore/settings/:game",
  authenticateToken,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const game = normalizeGame(req.params.game);
    const drawNumber = String(req.body.draw_number || "").trim();
    const drawAt = req.body.draw_at;
    const prizeRate = Number(req.body.prize_rate);
    const bettingEnabled = req.body.betting_enabled;

    if (!validGame(game)) {
      return sendError(res, 400, "Invalid game.");
    }

    if (!drawNumber || drawNumber.length > 50) {
      return sendError(res, 400, "Invalid draw number.");
    }

    if (
      typeof drawAt !== "string" ||
      !Number.isFinite(Date.parse(drawAt)) ||
      Date.parse(drawAt) <= Date.now()
    ) {
      return sendError(res, 400, "Draw date must be in the future.");
    }

    if (
      !Number.isFinite(prizeRate) ||
      prizeRate < 0 ||
      prizeRate > 100000
    ) {
      return sendError(res, 400, "Invalid prize rate.");
    }

    if (typeof bettingEnabled !== "boolean") {
      return sendError(res, 400, "Invalid betting status.");
    }

    const result = await pool.query(
      `INSERT INTO singapore_game_settings
       (game, draw_number, draw_at, prize_rate,
        betting_enabled, updated_by, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW())
       ON CONFLICT (game)
       DO UPDATE SET
         draw_number = EXCLUDED.draw_number,
         draw_at = EXCLUDED.draw_at,
         prize_rate = EXCLUDED.prize_rate,
         betting_enabled = EXCLUDED.betting_enabled,
         updated_by = EXCLUDED.updated_by,
         updated_at = NOW()
       RETURNING game, draw_number, draw_at, prize_rate,
                 betting_enabled, updated_by, updated_at`,
      [
        game,
        drawNumber,
        new Date(drawAt).toISOString(),
        prizeRate,
        bettingEnabled,
        req.user.id
      ]
    );

    res.json({
      success: true,
      message: "Singapore game settings saved.",
      settings: publicSettings(result.rows[0])
    });
  })
);

app.get("/api/admin/singapore/bets",
  authenticateToken,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const game = req.query.game
      ? normalizeGame(req.query.game)
      : null;

    if (game && !validGame(game)) {
      return sendError(res, 400, "Invalid game.");
    }

    const limit = Math.min(
      Math.max(Number(req.query.limit) || 100, 1),
      500
    );

    const result = await pool.query(
      `SELECT b.id, b.user_id, u.username, b.game,
              b.draw_number, b.draw_at, b.selections,
              b.amount, b.prize_rate, b.status, b.created_at
       FROM singapore_bets b
       JOIN users u ON u.id = b.user_id
       WHERE ($1::varchar IS NULL OR b.game = $1)
       ORDER BY b.created_at DESC
       LIMIT $2`,
      [game, limit]
    );

    res.json({
      success: true,
      bets: result.rows
    });
  })
);

app.get("/api/admin/singapore/summary",
  authenticateToken,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const result = await pool.query(`
      SELECT
        COUNT(*)::int AS total_bets,
        COALESCE(SUM(amount), 0) AS total_points,
        COUNT(DISTINCT user_id)::int AS total_users
      FROM singapore_bets
    `);

    res.json({
      success: true,
      summary: result.rows[0]
    });
  })
);

app.use((req, res) => {
  sendError(res, 404, "API route not found.");
});

app.use((error, req, res, next) => {
  console.error("Singapore API error:", error.message);

  if (res.headersSent) return next(error);

  sendError(res, 500, "Server error. Please try again later.");
});

async function startServer() {
  try {
    await pool.query("SELECT 1");
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`Singapore Games API running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Singapore server startup failed:", error);
    process.exit(1);
  }
}

process.on("SIGTERM", async () => {
  await pool.end();
  process.exit(0);
});

startServer();
