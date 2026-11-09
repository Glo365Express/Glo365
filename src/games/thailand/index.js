// GLO 365 - Thailand Shared Single / 2D Demo Bet API
// Keeps the existing shared API paths and database transaction behavior.
// Single and 2D game-specific selection validation is delegated to their modules.
// Register this module exactly once from server.js.

const {
  normalizeSingleSelection,
  isSingleGameName
} = require("./single");

const {
  normalize2DSelection,
  is2DGameName
} = require("./2d");

module.exports = function registerThailandRoutes(app, deps) {
  const {
    pool,
    authenticateToken,
    asyncRoute,
    cleanText,
    sendError,
    isDrawBettingLocked
  } = deps || {};

  const required = {
    pool,
    authenticateToken,
    asyncRoute,
    cleanText,
    sendError,
    isDrawBettingLocked
  };

  for (const [name, value] of Object.entries(required)) {
    if (!value) {
      throw new Error(`Thailand routes: missing dependency "${name}".`);
    }
  }

  app.post(
    "/api/demo/bets",
    authenticateToken,
    asyncRoute(async (req, res) => {
      const gameName = cleanText(req.body.game_name, 100);
      const rawSelection = cleanText(req.body.selection, 100);
      const amount = Number(req.body.amount);

      if (
        !gameName ||
        !rawSelection ||
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > 100000
      ) {
        return sendError(res, 400, "Invalid demo bet information.");
      }

      // This shared endpoint is exclusively for Thailand Single and 2D.
      // Reject unknown game names rather than storing unsupported game bets.
      let selection;

      if (isSingleGameName(gameName)) {
        const normalized = normalizeSingleSelection(rawSelection);

        if (!normalized.valid) {
          return sendError(res, 400, normalized.error);
        }

        selection = normalized.selection;
      } else if (is2DGameName(gameName)) {
        const normalized = normalize2DSelection(rawSelection);

        if (!normalized.valid) {
          return sendError(res, 400, normalized.error);
        }

        selection = normalized.selection;
      } else {
        return sendError(res, 400, "Unsupported Thailand game.");
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
         FROM demo_bets WHERE user_id = $1
         UNION ALL
         SELECT b.id, 'Millionaire' AS game_name, b.selection, b.amount, b.status, b.created_at
         FROM millionaire_bets b WHERE b.user_id = $1
         ORDER BY created_at DESC LIMIT 200`,
        [req.user.id]
      );

      res.json({ success: true, bets: result.rows });
    })
  );
};
