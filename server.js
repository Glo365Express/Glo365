require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

app.use(express.json({ limit: "1mb" }));

app.use(cors({
  origin: process.env.FRONTEND_URL
    ? process.env.FRONTEND_URL.split(",").map(url => url.trim())
    : true
}));

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET) {
  console.error("ERROR: JWT_SECRET environment variable is missing.");
  process.exit(1);
}

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL environment variable is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

// ==========================================
// DATABASE INITIALIZATION
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
  `);

  console.log("Database initialized successfully.");
}

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "GLO 365 Backend API is running.",
    version: "1.0.0"
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      success: true,
      database: "connected",
      status: "healthy"
    });
  } catch (error) {
    res.status(503).json({
      success: false,
      database: "disconnected",
      status: "unhealthy"
    });
  }
});

// ==========================================
// AUTHENTICATION MIDDLEWARE
// ==========================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authentication required."
    });
  }

  const token = authHeader.substring(7);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token."
    });
  }
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// ==========================================
// REGISTER
// POST /api/auth/register
// ==========================================

app.post("/api/auth/register", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Username, email and password are required."
      });
    }

    const cleanUsername = String(username).trim().toLowerCase();
    const cleanEmail = String(email).trim().toLowerCase();

    if (!/^[a-z0-9_]{3,30}$/.test(cleanUsername)) {
      return res.status(400).json({
        success: false,
        message: "Username must be 3-30 characters using letters, numbers or underscore."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address."
      });
    }

    if (typeof password !== "string" || password.length < 8 || password.length > 128) {
      return res.status(400).json({
        success: false,
        message: "Password must be 8-128 characters."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, balance, created_at`,
      [cleanUsername, cleanEmail, passwordHash]
    );

    const user = result.rows[0];

    await pool.query(
      "INSERT INTO profiles (user_id) VALUES ($1)",
      [user.id]
    );

    const token = createToken(user);

    res.status(201).json({
      success: true,
      message: "Account created successfully.",
      token,
      user
    });

  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        success: false,
        message: "Username or email already exists."
      });
    }

    console.error("Register error:", error.message);

    res.status(500).json({
      success: false,
      message: "Registration failed."
    });
  }
});

// ==========================================
// LOGIN
// POST /api/auth/login
// ==========================================

app.post("/api/auth/login", async (req, res) => {
  const { email, username, password } = req.body;

  try {
    const loginValue = String(email || username || "")
      .trim()
      .toLowerCase();

    if (!loginValue || !password) {
      return res.status(400).json({
        success: false,
        message: "Login details are required."
      });
    }

    const result = await pool.query(
      `SELECT * FROM users
       WHERE email = $1 OR username = $1
       LIMIT 1`,
      [loginValue]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid login details."
      });
    }

    const token = createToken(user);

    delete user.password_hash;

    res.json({
      success: true,
      message: "Login successful.",
      token,
      user
    });

  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
      success: false,
      message: "Login failed."
    });
  }
});

// ==========================================
// CURRENT USER
// GET /api/auth/me
// ==========================================

app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         u.id,
         u.username,
         u.email,
         u.balance,
         u.created_at,
         p.full_name,
         p.avatar,
         p.bio
       FROM users u
       LEFT JOIN profiles p ON p.user_id = u.id
       WHERE u.id = $1`,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        success: false,
        message: "User not found."
      });
    }

    res.json({
      success: true,
      user: result.rows[0]
    });

  } catch (error) {
    console.error("Me error:", error.message);

    res.status(500).json({
      success: false,
      message: "Could not load user."
    });
  }
});

// ==========================================
// PROFILE
// GET /api/profile
// ==========================================

app.get("/api/profile", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         u.id,
         u.username,
         u.email,
         u.balance,
         p.full_name,
         p.avatar,
         p.bio
       FROM users u
       LEFT JOIN profiles p ON p.user_id = u.id
       WHERE u.id = $1`,
      [req.user.id]
    );

    res.json({
      success: true,
      profile: result.rows[0] || null
    });

  } catch (error) {
    console.error("Profile error:", error.message);

    res.status(500).json({
      success: false,
      message: "Could not load profile."
    });
  }
});

// ==========================================
// UPDATE PROFILE
// PUT /api/profile
// ==========================================

app.put("/api/profile", authenticateToken, async (req, res) => {
  const { full_name, avatar, bio } = req.body;

  try {
    if (
      (full_name !== undefined && (typeof full_name !== "string" || full_name.length > 100)) ||
      (avatar !== undefined && (typeof avatar !== "string" || avatar.length > 200000)) ||
      (bio !== undefined && (typeof bio !== "string" || bio.length > 300))
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid profile information."
      });
    }

    const result = await pool.query(
      `UPDATE profiles
       SET
         full_name = COALESCE($1, full_name),
         avatar = COALESCE($2, avatar),
         bio = COALESCE($3, bio),
         updated_at = NOW()
       WHERE user_id = $4
       RETURNING *`,
      [
        full_name === undefined ? null : full_name.trim(),
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

  } catch (error) {
    console.error("Update profile error:", error.message);

    res.status(500).json({
      success: false,
      message: "Profile update failed."
    });
  }
});

// ==========================================
// DEMO WALLET
// GET /api/wallet
// ==========================================

app.get("/api/wallet", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT balance FROM users WHERE id = $1",
      [req.user.id]
    );

    res.json({
      success: true,
      currency: "DEMO",
      balance: result.rows[0].balance
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Could not load demo wallet."
    });
  }
});

// ==========================================
// CREATE DEMO BET
// POST /api/demo/bets
// ==========================================

app.post("/api/demo/bets", authenticateToken, async (req, res) => {
  const { game_name, selection, amount } = req.body;

  const betAmount = Number(amount);

  if (
    typeof game_name !== "string" ||
    typeof selection !== "string" ||
    !game_name.trim() ||
    !selection.trim() ||
    game_name.length > 100 ||
    selection.length > 100 ||
    !Number.isFinite(betAmount) ||
    betAmount <= 0 ||
    betAmount > 100000
  ) {
    return res.status(400).json({
      success: false,
      message: "Invalid demo bet information."
    });
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

      return res.status(404).json({
        success: false,
        message: "User not found."
      });
    }

    if (Number(userResult.rows[0].balance) < betAmount) {
      await client.query("ROLLBACK");

      return res.status(400).json({
        success: false,
        message: "Insufficient demo balance."
      });
    }

    await client.query(
      "UPDATE users SET balance = balance - $1 WHERE id = $2",
      [betAmount, req.user.id]
    );

    const betResult = await client.query(
      `INSERT INTO demo_bets
       (user_id, game_name, selection, amount)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [
        req.user.id,
        game_name.trim(),
        selection.trim(),
        betAmount
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

    res.status(500).json({
      success: false,
      message: "Could not create demo bet."
    });

  } finally {
    client.release();
  }
});

// ==========================================
// DEMO BET HISTORY
// GET /api/demo/bets
// ==========================================

app.get("/api/demo/bets", authenticateToken, async (req, res) => {
  try {
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

  } catch (error) {
    console.error("Bet history error:", error.message);

    res.status(500).json({
      success: false,
      message: "Could not load demo bet history."
    });
  }
});

// ==========================================
// DEMO RESULTS
// GET /api/results
// ==========================================

app.get("/api/results", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, game_name, result, created_at
       FROM demo_results
       ORDER BY created_at DESC
       LIMIT 100`
    );

    res.json({
      success: true,
      results: result.rows
    });

  } catch (error) {
    console.error("Results error:", error.message);

    res.status(500).json({
      success: false,
      message: "Could not load results."
    });
  }
});

// ==========================================
// 404 HANDLER
// ==========================================

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found."
  });
});

// ==========================================
// ERROR HANDLER
// ==========================================

app.use((error, req, res, next) => {
  console.error("Server error:", error.message);

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

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`GLO 365 API running on port ${PORT}`);
    });

  } catch (error) {
    console.error("Server startup failed:", error.message);
    process.exit(1);
  }
}

startServer();