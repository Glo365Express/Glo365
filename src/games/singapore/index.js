// GLO 365 Singapore Games module
// Mounted inside the existing GLO 365 API. Do not deploy as a separate server.

module.exports = function registerSingaporeRoutes(app, deps) {
  const {
    pool,
    authenticateToken,
    requireAdmin,
    asyncRoute,
    cleanText,
    sendError,
    audit
  } = deps;

  const GAMES = ["2D", "3D", "4D", "649"];
  const LOCK_MINUTES = 45;
  const MAX_AMOUNT = 100000;

  function normalizeGame(value) {
    return String(value || "").trim().toUpperCase();
  }

  function isValidGame(value) {
    return GAMES.includes(normalizeGame(value));
  }

  function amountOrNull(value) {
    const amount = Number(value);
    if (!Number.isFinite(amount) || amount <= 0 || amount > MAX_AMOUNT ||
        Math.round(amount * 100) !== amount * 100) return null;
    return amount;
  }

  function validSelections(game, selections) {
    if (!Array.isArray(selections) || selections.length < 1 ||
        selections.length > 50) return false;

    if (game === "649") {
      return selections.every(row => {
        if (!Array.isArray(row) || row.length !== 6) return false;
        const numbers = row.map(Number);
        return numbers.every(n => Number.isInteger(n) && n >= 1 && n <= 49) &&
          new Set(numbers).size === 6;
      });
    }

    const digits = Number(game[0]);
    const pattern = new RegExp(`^[0-9]{${digits}}$`);
    return selections.every(value =>
      typeof value === "string" && pattern.test(value)
    );
  }

  function isLocked(settings) {
    if (!settings || !settings.draw_at || !settings.betting_enabled) return true;
    const drawTime = new Date(settings.draw_at).getTime();
    return !Number.isFinite(drawTime) ||
      drawTime - Date.now() <= LOCK_MINUTES * 60 * 1000;
  }

  function publicSettings(row) {
    if (!row) return null;
    return {
      game: row.game,
      draw_number: row.draw_number,
      draw_at: row.draw_at,
      prize_rate: Number(row.prize_rate),
      betting_enabled: row.betting_enabled,
      betting_locked: isLocked(row),
      lock_minutes: LOCK_MINUTES,
      updated_at: row.updated_at
    };
  }

  async function getSettings(client, game) {
    const result = await client.query(
      `SELECT game, draw_number, draw_at, prize_rate,
              betting_enabled, updated_by, updated_at
       FROM singapore_game_settings
       WHERE game = $1`,
      [game]
    );
    return result.rows[0] || null;
  }

  // Called by the main server only after initializeDatabase() has created users.
  async function initializeSingaporeDatabase() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS singapore_game_settings (
        game VARCHAR(10) PRIMARY KEY
          CHECK (game IN ('2D','3D','4D','649')),
        draw_number VARCHAR(50) NOT NULL DEFAULT '',
        draw_at TIMESTAMPTZ,
        prize_rate NUMERIC(12,2) NOT NULL DEFAULT 0
          CHECK (prize_rate >= 0),
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
        status VARCHAR(20) NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending','win','loss','cancelled')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_singapore_bets_user_date
        ON singapore_bets(user_id, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_singapore_bets_game_draw
        ON singapore_bets(game, draw_number);
    `);

    for (const game of GAMES) {
      await pool.query(
        `INSERT INTO singapore_game_settings (game, betting_enabled)
         VALUES ($1, FALSE)
         ON CONFLICT (game) DO NOTHING`,
        [game]
      );
    }

    console.log("Singapore Games database initialized.");
  }

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

  app.get("/api/singapore/settings", asyncRoute(async (req, res) => {
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
  }));

  app.get("/api/singapore/settings/:game", asyncRoute(async (req, res) => {
    const game = normalizeGame(req.params.game);
    if (!isValidGame(game)) {
      return sendError(res, 400, "Invalid Singapore game.");
    }
    const row = await getSettings(pool, game);
    res.json({ success: true, settings: publicSettings(row) });
  }));

  app.get("/api/singapore/me", authenticateToken,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id, username, balance
         FROM users
         WHERE id = $1 AND status = 'active'`,
        [req.user.id]
      );
      if (!result.rows.length) {
        return sendError(res, 404, "User not found.");
      }
      res.json({ success: true, user: result.rows[0] });
    })
  );

  app.post("/api/singapore/bets", authenticateToken,
    asyncRoute(async (req, res) => {
      const game = normalizeGame(req.body.game);
      const amount = amountOrNull(req.body.amount);
      const selections = req.body.selections;

      if (!isValidGame(game)) {
        return sendError(res, 400, "Invalid Singapore game.");
      }
      if (!amount) {
        return sendError(res, 400, "Invalid demo points amount.");
      }
      if (!validSelections(game, selections)) {
        return sendError(res, 400, "Invalid number selection.");
      }

      const client = await pool.connect();
      try {
        await client.query("BEGIN");

        const settings = await getSettings(client, game);
        if (!settings || !settings.draw_number || !settings.draw_at) {
          await client.query("ROLLBACK");
          return sendError(res, 400, "Draw schedule is not configured.");
        }
        if (isLocked(settings)) {
          await client.query("ROLLBACK");
          return sendError(res, 403, "Betting is closed.");
        }

        // Debit balance and create bet/ledger row in one transaction.
        const debit = await client.query(
          `UPDATE users
           SET balance = balance - $1
           WHERE id = $2 AND status = 'active' AND balance >= $1
           RETURNING balance`,
          [amount, req.user.id]
        );
        if (!debit.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 400, "Insufficient demo points or inactive account.");
        }

        const inserted = await client.query(
          `INSERT INTO singapore_bets
           (user_id, game, draw_number, draw_at, selections, amount, prize_rate)
           VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)
           RETURNING id, game, draw_number, draw_at, selections,
                     amount, prize_rate, status, created_at`,
          [
            req.user.id, game, settings.draw_number, settings.draw_at,
            JSON.stringify(selections), amount, settings.prize_rate
          ]
        );

        // GLO 365 wallet_transactions stores the signed ledger amount.
        await client.query(
          `INSERT INTO wallet_transactions
           (user_id, type, amount, currency, description, reference)
           VALUES ($1, 'singapore_bet', $2, 'DEMO', $3, $4)`,
          [
            req.user.id, -amount,
            `Singapore ${game} demo points bet`,
            `SG-${inserted.rows[0].id}`
          ]
        );

        await client.query("COMMIT");

        res.status(201).json({
          success: true,
          message: "Singapore demo bet placed successfully.",
          bet: inserted.rows[0],
          balance: debit.rows[0].balance
        });
      } catch (error) {
        await client.query("ROLLBACK").catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    })
  );

  app.get("/api/singapore/bets", authenticateToken,
    asyncRoute(async (req, res) => {
      const limit = Math.min(Math.max(Number(req.query.limit) || 30, 1), 100);
      const result = await pool.query(
        `SELECT id, game, draw_number, draw_at, selections, amount,
                prize_rate, status, created_at
         FROM singapore_bets
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT $2`,
        [req.user.id, limit]
      );
      res.json({ success: true, bets: result.rows });
    })
  );

  app.get("/api/admin/singapore/settings", authenticateToken, requireAdmin,
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

  app.put("/api/admin/singapore/settings/:game", authenticateToken, requireAdmin,
    asyncRoute(async (req, res) => {
      const game = normalizeGame(req.params.game);
      const drawNumber = cleanText(req.body.draw_number, 50);
      const drawAt = req.body.draw_at;
      const prizeRate = Number(req.body.prize_rate);
      const bettingEnabled = req.body.betting_enabled;

      if (!isValidGame(game)) {
        return sendError(res, 400, "Invalid Singapore game.");
      }
      if (!drawNumber) {
        return sendError(res, 400, "Draw number is required.");
      }
      if (typeof drawAt !== "string" || !Number.isFinite(Date.parse(drawAt)) ||
          Date.parse(drawAt) <= Date.now()) {
        return sendError(res, 400, "Draw date and time must be in the future.");
      }
      if (!Number.isFinite(prizeRate) || prizeRate < 0 || prizeRate > 100000) {
        return sendError(res, 400, "Invalid prize rate.");
      }
      if (typeof bettingEnabled !== "boolean") {
        return sendError(res, 400, "Invalid betting status.");
      }

      const drawTime = new Date(drawAt).toISOString();
      const result = await pool.query(
        `INSERT INTO singapore_game_settings
         (game, draw_number, draw_at, prize_rate, betting_enabled, updated_by, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,NOW())
         ON CONFLICT (game) DO UPDATE SET
           draw_number = EXCLUDED.draw_number,
           draw_at = EXCLUDED.draw_at,
           prize_rate = EXCLUDED.prize_rate,
           betting_enabled = EXCLUDED.betting_enabled,
           updated_by = EXCLUDED.updated_by,
           updated_at = NOW()
         RETURNING game, draw_number, draw_at, prize_rate,
                   betting_enabled, updated_by, updated_at`,
        [game, drawNumber, drawTime, prizeRate, bettingEnabled, req.user.id]
      );

      await audit(req.user.id, "singapore_settings_updated", null, {
        game, draw_number: drawNumber, draw_at: drawTime,
        prize_rate: prizeRate, betting_enabled: bettingEnabled
      });

      res.json({
        success: true,
        message: "Singapore game settings saved.",
        settings: publicSettings(result.rows[0])
      });
    })
  );

  app.get("/api/admin/singapore/bets", authenticateToken, requireAdmin,
    asyncRoute(async (req, res) => {
      const game = req.query.game ? normalizeGame(req.query.game) : null;
      if (game && !isValidGame(game)) {
        return sendError(res, 400, "Invalid Singapore game.");
      }
      const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
      const result = await pool.query(
        `SELECT b.id, b.user_id, u.username, b.game, b.draw_number,
                b.draw_at, b.selections, b.amount, b.prize_rate,
                b.status, b.created_at
         FROM singapore_bets b
         JOIN users u ON u.id = b.user_id
         WHERE ($1::varchar IS NULL OR b.game = $1)
         ORDER BY b.created_at DESC
         LIMIT $2`,
        [game, limit]
      );
      res.json({ success: true, bets: result.rows });
    })
  );

  app.get("/api/admin/singapore/summary", authenticateToken, requireAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(`
        SELECT COUNT(*)::int AS total_bets,
               COALESCE(SUM(amount), 0) AS total_points,
               COUNT(DISTINCT user_id)::int AS total_users
        FROM singapore_bets
      `);
      res.json({ success: true, summary: result.rows[0] });
    })
  );

  console.log("Singapore Games routes registered.");
  return initializeSingaporeDatabase;
};
