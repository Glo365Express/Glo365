
"use strict";

// GLO 365 Malaysia Games + Results Module
// Existing wallet, authentication, betting and settings are preserved.
// Malaysia results support 2D, 3D and 4D.
// Winning bets are settled automatically and paid exactly once.

module.exports = function registerMalaysiaRoutes(app, deps) {

  const {
    pool,
    authenticateToken,
    requireAdmin,
    asyncRoute,
    cleanText,
    sendError,
    audit
  } = deps;

  const GAMES = ["2D", "3D", "4D"];
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

    if (
      !Number.isFinite(amount) ||
      amount <= 0 ||
      amount > MAX_AMOUNT ||
      Math.round(amount * 100) !== amount * 100
    ) {
      return null;
    }

    return amount;
  }

  function validSelections(game, selections) {
    if (
      !Array.isArray(selections) ||
      selections.length < 1 ||
      selections.length > 50
    ) {
      return false;
    }

    const digits = Number(game[0]);
    const pattern = new RegExp(`^[0-9]{${digits}}$`);

    return selections.every(value =>
      typeof value === "string" && pattern.test(value)
    );
  }

  function isLocked(settings) {
    if (
      !settings ||
      !settings.draw_at ||
      !settings.betting_enabled
    ) {
      return true;
    }

    const drawTime = new Date(settings.draw_at).getTime();

    return (
      !Number.isFinite(drawTime) ||
      drawTime - Date.now() <= LOCK_MINUTES * 60 * 1000
    );
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
       FROM malaysia_game_settings
       WHERE game = $1`,
      [game]
    );

    return result.rows[0] || null;
  }

  function normalizeDrawNumber(value) {
    return cleanText(String(value || ""), 50);
  }

  function normalizeWinningNumber(game, value) {
    const digits = Number(game[0]);
    const number = String(value == null ? "" : value).trim();

    if (!new RegExp(`^[0-9]{${digits}}$`).test(number)) {
      return null;
    }

    return number;
  }

  function normalizeSelections(value) {
    if (Array.isArray(value)) return value;

    if (typeof value === "string") {
      try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) ? parsed : [];
      } catch (error) {
        return [];
      }
    }

    return [];
  }

  // ==========================================
  // DATABASE INITIALIZATION
  // ==========================================

  async function initializeMalaysiaDatabase() {

    await pool.query(`

      CREATE TABLE IF NOT EXISTS malaysia_game_settings (

        game VARCHAR(10) PRIMARY KEY
          CHECK (game IN ('2D','3D','4D')),

        draw_number VARCHAR(50) NOT NULL DEFAULT '',

        draw_at TIMESTAMPTZ,

        prize_rate NUMERIC(12,2) NOT NULL DEFAULT 0
          CHECK (prize_rate >= 0),

        betting_enabled BOOLEAN NOT NULL DEFAULT FALSE,

        updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,

        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()

      );

      CREATE TABLE IF NOT EXISTS malaysia_bets (

        id BIGSERIAL PRIMARY KEY,

        user_id BIGINT NOT NULL
          REFERENCES users(id) ON DELETE CASCADE,

        game VARCHAR(10) NOT NULL
          CHECK (game IN ('2D','3D','4D')),

        draw_number VARCHAR(50) NOT NULL,

        draw_at TIMESTAMPTZ NOT NULL,

        selections JSONB NOT NULL,

        amount NUMERIC(12,2) NOT NULL
          CHECK (amount > 0),

        prize_rate NUMERIC(12,2) NOT NULL DEFAULT 0,

        status VARCHAR(20) NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending','win','loss','cancelled')),

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()

      );

      CREATE INDEX IF NOT EXISTS idx_malaysia_bets_user_date
        ON malaysia_bets(user_id, created_at DESC);

      CREATE INDEX IF NOT EXISTS idx_malaysia_bets_game_draw
        ON malaysia_bets(game, draw_number);

      CREATE TABLE IF NOT EXISTS malaysia_results (

        id BIGSERIAL PRIMARY KEY,

        game VARCHAR(10) NOT NULL
          CHECK (game IN ('2D','3D','4D')),

        draw_number VARCHAR(50) NOT NULL,

        winning_number VARCHAR(4) NOT NULL,

        published_by BIGINT REFERENCES users(id) ON DELETE SET NULL,

        published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        UNIQUE(game, draw_number)

      );

      CREATE INDEX IF NOT EXISTS idx_malaysia_results_published
        ON malaysia_results(published_at DESC);

    `);

    for (const game of GAMES) {
      await pool.query(
        `INSERT INTO malaysia_game_settings
         (game, betting_enabled)
         VALUES ($1, FALSE)
         ON CONFLICT (game) DO NOTHING`,
        [game]
      );
    }

    console.log("Malaysia Games and Results database initialized.");
  }

  // ==========================================
  // PUBLIC GAME LIST
  // ==========================================

  app.get("/api/malaysia/games", (req, res) => {
    res.json({
      success: true,
      games: [
        { id: "2D", name: "2D NUMBER" },
        { id: "3D", name: "3D NUMBER" },
        { id: "4D", name: "4D NUMBER" }
      ]
    });
  });

  // ==========================================
  // PUBLIC SETTINGS
  // ==========================================

  app.get(
    "/api/malaysia/settings",
    asyncRoute(async (req, res) => {

      const result = await pool.query(
        `SELECT game, draw_number, draw_at, prize_rate,
                betting_enabled, updated_at
         FROM malaysia_game_settings
         ORDER BY game`
      );

      res.json({
        success: true,
        settings: result.rows.map(publicSettings)
      });
    })
  );

  app.get(
    "/api/malaysia/settings/:game",
    asyncRoute(async (req, res) => {

      const game = normalizeGame(req.params.game);

      if (!isValidGame(game)) {
        return sendError(res, 400, "Invalid Malaysia game.");
      }

      const row = await getSettings(pool, game);

      res.json({
        success: true,
        settings: publicSettings(row)
      });
    })
  );

  // ==========================================
  // PUBLIC MALAYSIA RESULTS
  // ==========================================

  app.get(
    "/api/malaysia/results",
    asyncRoute(async (req, res) => {

      const game = req.query.game
        ? normalizeGame(req.query.game)
        : null;

      if (game && !isValidGame(game)) {
        return sendError(res, 400, "Invalid Malaysia game.");
      }

      const limit = Math.min(
        Math.max(Number(req.query.limit) || 100, 1),
        300
      );

      const result = await pool.query(
        `SELECT id, game, draw_number, winning_number,
                published_at, updated_at
         FROM malaysia_results
         WHERE ($1::varchar IS NULL OR game = $1)
         ORDER BY published_at DESC
         LIMIT $2`,
        [game, limit]
      );

      res.json({
        success: true,
        results: result.rows
      });
    })
  );

  // ==========================================
  // USER ACCOUNT
  // ==========================================

  app.get(
    "/api/malaysia/me",
    authenticateToken,
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

      res.json({
        success: true,
        user: result.rows[0]
      });
    })
  );

  // ==========================================
  // PLACE BET
  // ==========================================

  app.post(
    "/api/malaysia/bets",
    authenticateToken,
    asyncRoute(async (req, res) => {

      const game = normalizeGame(req.body.game);
      const amount = amountOrNull(req.body.amount);
      const selections = req.body.selections;

      if (!isValidGame(game)) {
        return sendError(res, 400, "Invalid Malaysia game.");
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

        const settingsResult = await client.query(
          `SELECT game, draw_number, draw_at, prize_rate,
                  betting_enabled, updated_by, updated_at
           FROM malaysia_game_settings
           WHERE game = $1
           FOR UPDATE`,
          [game]
        );

        const settings = settingsResult.rows[0];

        if (
          !settings ||
          !settings.draw_number ||
          !settings.draw_at
        ) {
          await client.query("ROLLBACK");
          return sendError(
            res,
            400,
            "Draw schedule is not configured."
          );
        }

        if (isLocked(settings)) {
          await client.query("ROLLBACK");
          return sendError(res, 403, "Betting is closed.");
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
          return sendError(
            res,
            400,
            "Insufficient demo points or inactive account."
          );
        }

        const inserted = await client.query(
          `INSERT INTO malaysia_bets
           (user_id, game, draw_number, draw_at,
            selections, amount, prize_rate)
           VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)
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
           VALUES ($1, 'malaysia_bet', $2, 'DEMO', $3, $4)`,
          [
            req.user.id,
            -amount,
            `Malaysia ${game} demo points bet`,
            `MY-${inserted.rows[0].id}`
          ]
        );

        await client.query("COMMIT");

        res.status(201).json({
          success: true,
          message: "Malaysia demo bet placed successfully.",
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

  // ==========================================
  // USER BET HISTORY
  // ==========================================

  app.get(
    "/api/malaysia/bets",
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
         FROM malaysia_bets
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

  // ==========================================
  // ADMIN SETTINGS
  // ==========================================

  app.get(
    "/api/admin/malaysia/settings",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {

      const result = await pool.query(
        `SELECT game, draw_number, draw_at, prize_rate,
                betting_enabled, updated_by, updated_at
         FROM malaysia_game_settings
         ORDER BY game`
      );

      res.json({
        success: true,
        settings: result.rows.map(publicSettings)
      });
    })
  );

  app.put(
    "/api/admin/malaysia/settings/:game",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {

      const game = normalizeGame(req.params.game);

      const drawNumber = cleanText(
        req.body.draw_number,
        50
      );

      const drawAt = req.body.draw_at;
      const prizeRate = Number(req.body.prize_rate);
      const bettingEnabled = req.body.betting_enabled;

      if (!isValidGame(game)) {
        return sendError(res, 400, "Invalid Malaysia game.");
      }

      if (!drawNumber) {
        return sendError(res, 400, "Draw number is required.");
      }

      if (
        typeof drawAt !== "string" ||
        !Number.isFinite(Date.parse(drawAt)) ||
        Date.parse(drawAt) <= Date.now()
      ) {
        return sendError(
          res,
          400,
          "Draw date and time must be in the future."
        );
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

      const drawTime = new Date(drawAt).toISOString();

      const result = await pool.query(
        `INSERT INTO malaysia_game_settings
         (game, draw_number, draw_at, prize_rate,
          betting_enabled, updated_by, updated_at)
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
        [
          game,
          drawNumber,
          drawTime,
          prizeRate,
          bettingEnabled,
          req.user.id
        ]
      );

      await audit(
        req.user.id,
        "malaysia_settings_updated",
        null,
        {
          game,
          draw_number: drawNumber,
          draw_at: drawTime,
          prize_rate: prizeRate,
          betting_enabled: bettingEnabled
        }
      );

      res.json({
        success: true,
        message: "Malaysia game settings saved.",
        settings: publicSettings(result.rows[0])
      });
    })
  );

  // ==========================================
  // MALAYSIA RESULT SETTLEMENT
  // ==========================================

  async function settleMalaysiaResult(client, resultRow) {

    const pending = await client.query(
      `SELECT id, user_id, game, draw_number,
              selections, amount, prize_rate
       FROM malaysia_bets
       WHERE game = $1
         AND draw_number = $2
         AND status = 'pending'
       ORDER BY id
       FOR UPDATE`,
      [resultRow.game, resultRow.draw_number]
    );

    let checked = 0;
    let won = 0;
    let lost = 0;
    let pointsPaid = 0;

    for (const bet of pending.rows) {

      checked++;

      const selections = normalizeSelections(bet.selections);

      const isWinner = selections.includes(
        resultRow.winning_number
      );

      if (isWinner) {

        const amount = Number(bet.amount);
        const rate = Number(bet.prize_rate);

        const reward = Math.round(amount * rate * 100) / 100;

        if (!Number.isFinite(reward) || reward < 0) {
          throw new Error(
            `Invalid reward calculation for Malaysia bet ${bet.id}.`
          );
        }

        // Credit the existing demo wallet.
        const credit = await client.query(
          `UPDATE users
           SET balance = balance + $1
           WHERE id = $2
           RETURNING balance`,
          [reward, bet.user_id]
        );

        if (!credit.rows.length) {
          throw new Error(
            `User not found while settling Malaysia bet ${bet.id}.`
          );
        }

        // Record reward in the existing wallet ledger.
        await client.query(
          `INSERT INTO wallet_transactions
           (user_id, type, amount, currency, description, reference)
           VALUES ($1, 'malaysia_win', $2, 'DEMO', $3, $4)`,
          [
            bet.user_id,
            reward,
            `Malaysia ${bet.game} winning reward`,
            `MY-WIN-${bet.id}`
          ]
        );

        await client.query(
          `UPDATE malaysia_bets
           SET status = 'win'
           WHERE id = $1 AND status = 'pending'`,
          [bet.id]
        );

        won++;
        pointsPaid += reward;

      } else {

        await client.query(
          `UPDATE malaysia_bets
           SET status = 'loss'
           WHERE id = $1 AND status = 'pending'`,
          [bet.id]
        );

        lost++;
      }
    }

    return {
      checked,
      won,
      lost,
      pointsPaid: Math.round(pointsPaid * 100) / 100
    };
  }

  // ==========================================
  // ADMIN: PUBLISH ONE OR MULTIPLE RESULTS
  // ==========================================

  app.post(
    "/api/admin/malaysia/results",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {

      // Supported formats:
      //
      // One result:
      // {
      //   "game": "2D",
      //   "draw_number": "DRAW-100",
      //   "winning_number": "45"
      // }
      //
      // Multiple results:
      // {
      //   "results": [
      //     {"game":"2D","draw_number":"DRAW-100","winning_number":"45"},
      //     {"game":"3D","draw_number":"DRAW-100","winning_number":"678"},
      //     {"game":"4D","draw_number":"DRAW-100","winning_number":"1234"}
      //   ]
      // }

      let inputResults = [];

      if (Array.isArray(req.body.results)) {
        inputResults = req.body.results;
      } else {
        inputResults = [req.body];
      }

      if (
        !inputResults.length ||
        inputResults.length > 3
      ) {
        return sendError(
          res,
          400,
          "Provide one to three Malaysia game results."
        );
      }

      const normalized = [];
      const seenGames = new Set();

      for (const item of inputResults) {

        const game = normalizeGame(item.game);

        if (!isValidGame(game)) {
          return sendError(res, 400, "Invalid Malaysia game.");
        }

        if (seenGames.has(game)) {
          return sendError(
            res,
            400,
            `Duplicate ${game} result in the same request.`
          );
        }

        seenGames.add(game);

        let drawNumber = normalizeDrawNumber(
          item.draw_number || item.drawNumber
        );

        // If draw number is omitted, use the configured game draw.
        if (!drawNumber) {
          const settings = await getSettings(pool, game);
          drawNumber = settings
            ? normalizeDrawNumber(settings.draw_number)
            : "";
        }

        if (!drawNumber) {
          return sendError(
            res,
            400,
            `${game} draw number is not configured.`
          );
        }

        const winningNumber = normalizeWinningNumber(
          game,
          item.winning_number !== undefined
            ? item.winning_number
            : item.winningNumber
        );

        if (!winningNumber) {
          return sendError(
            res,
            400,
            `${game} winning number must contain exactly ${game[0]} digits.`
          );
        }

        normalized.push({
          game,
          draw_number: drawNumber,
          winning_number: winningNumber
        });
      }

      const client = await pool.connect();

      try {

        await client.query("BEGIN");

        const published = [];
        const totals = {
          checked: 0,
          won: 0,
          lost: 0,
          pointsPaid: 0
        };

        for (const item of normalized) {

          // Store or update the published result.
          const saved = await client.query(
            `INSERT INTO malaysia_results
             (game, draw_number, winning_number,
              published_by, published_at, updated_at)
             VALUES ($1,$2,$3,$4,NOW(),NOW())
             ON CONFLICT (game, draw_number)
             DO UPDATE SET
               winning_number = EXCLUDED.winning_number,
               published_by = EXCLUDED.published_by,
               published_at = NOW(),
               updated_at = NOW()
             RETURNING id, game, draw_number,
                       winning_number, published_at, updated_at`,
            [
              item.game,
              item.draw_number,
              item.winning_number,
              req.user.id
            ]
          );

          const resultRow = saved.rows[0];

          // Only pending bets are settled.
          // The transaction and row locks prevent duplicate payouts.
          const settlement = await settleMalaysiaResult(
            client,
            resultRow
          );

          totals.checked += settlement.checked;
          totals.won += settlement.won;
          totals.lost += settlement.lost;
          totals.pointsPaid += settlement.pointsPaid;

          published.push({
            result: resultRow,
            settlement
          });
        }

        await client.query("COMMIT");

        await audit(
          req.user.id,
          "malaysia_results_published",
          null,
          {
            results: normalized,
            settlement: totals
          }
        );

        res.json({
          success: true,
          message: "Malaysia result published successfully.",
          published,
          settlement: {
            checked: totals.checked,
            won: totals.won,
            lost: totals.lost,
            pointsPaid: Math.round(totals.pointsPaid * 100) / 100
          }
        });

      } catch (error) {

        await client.query("ROLLBACK").catch(() => {});
        throw error;

      } finally {

        client.release();
      }
    })
  );

  // ==========================================
  // ADMIN: VIEW PUBLISHED RESULTS
  // ==========================================

  app.get(
    "/api/admin/malaysia/results",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {

      const game = req.query.game
        ? normalizeGame(req.query.game)
        : null;

      if (game && !isValidGame(game)) {
        return sendError(res, 400, "Invalid Malaysia game.");
      }

      const limit = Math.min(
        Math.max(Number(req.query.limit) || 100, 1),
        300
      );

      const result = await pool.query(
        `SELECT r.id, r.game, r.draw_number,
                r.winning_number, r.published_at,
                r.updated_at, u.username AS published_by_username
         FROM malaysia_results r
         LEFT JOIN users u ON u.id = r.published_by
         WHERE ($1::varchar IS NULL OR r.game = $1)
         ORDER BY r.published_at DESC
         LIMIT $2`,
        [game, limit]
      );

      res.json({
        success: true,
        results: result.rows
      });
    })
  );

  // ==========================================
  // ADMIN BET MANAGEMENT
  // ==========================================

  app.get(
    "/api/admin/malaysia/bets",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {

      const game = req.query.game
        ? normalizeGame(req.query.game)
        : null;

      if (game && !isValidGame(game)) {
        return sendError(res, 400, "Invalid Malaysia game.");
      }

      const limit = Math.min(
        Math.max(Number(req.query.limit) || 100, 1),
        500
      );

      const result = await pool.query(
        `SELECT b.id, b.user_id, u.username,
                b.game, b.draw_number, b.draw_at,
                b.selections, b.amount, b.prize_rate,
                b.status, b.created_at
         FROM malaysia_bets b
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

  // ==========================================
  // ADMIN SUMMARY
  // ==========================================

  app.get(
    "/api/admin/malaysia/summary",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {

      const result = await pool.query(`
        SELECT
          COUNT(*)::int AS total_bets,
          COALESCE(SUM(amount), 0) AS total_points,
          COUNT(DISTINCT user_id)::int AS total_users
        FROM malaysia_bets
      `);

      res.json({
        success: true,
        summary: result.rows[0]
      });
    })
  );

  console.log("Malaysia Games and Results routes registered.");

  return initializeMalaysiaDatabase;
};
