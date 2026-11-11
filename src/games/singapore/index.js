
// GLO 365 Singapore Games module
// Mounted inside the existing GLO 365 API.
// Do not deploy as a separate server.
//
// Result policy:
// 1. New results are saved as drafts.
// 2. Draft results can be edited or deleted.
// 3. Published results are permanently immutable.
// 4. Historical draws can be added using past dates.
// 5. 2D and 3D are derived automatically from the 4D result.

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

  // ---------------------------------------------------------
  // COMMON HELPERS
  // ---------------------------------------------------------

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

  function validDate(value) {
    return typeof value === "string" &&
      /^\d{4}-\d{2}-\d{2}$/.test(value) &&
      !Number.isNaN(Date.parse(value)) &&
      new Date(value).toISOString().slice(0, 10) === value;
  }

  function validDrawNumber(value) {
    return typeof value === "string" &&
      value.trim().length > 0 &&
      value.trim().length <= 50;
  }

  function validFourDigit(value) {
    return typeof value === "string" && /^[0-9]{4}$/.test(value);
  }

  function validSelections(game, selections) {
    if (
      !Array.isArray(selections) ||
      selections.length < 1 ||
      selections.length > 50
    ) {
      return false;
    }

    if (game === "649") {
      return selections.every(row => {
        if (!Array.isArray(row) || row.length !== 6) return false;

        const numbers = row.map(Number);

        return numbers.every(
          n => Number.isInteger(n) && n >= 1 && n <= 49
        ) && new Set(numbers).size === 6;
      });
    }

    const digits = Number(game[0]);
    const pattern = new RegExp(`^[0-9]{${digits}}$`);

    return selections.every(value =>
      typeof value === "string" && pattern.test(value)
    );
  }

  function isLocked(settings) {
    if (!settings || !settings.draw_at || !settings.betting_enabled) {
      return true;
    }

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

  async function writeAudit(userId, action, targetId, details) {
    if (typeof audit === "function") {
      await audit(userId, action, targetId, details);
    }
  }

  function validNumberArray(values, count, min, max) {
    if (!Array.isArray(values) || values.length !== count) {
      return false;
    }

    return values.every(value =>
      Number.isInteger(Number(value)) &&
      Number(value) >= min &&
      Number(value) <= max
    );
  }

  function validPrizeGroups(groups) {
    if (!Array.isArray(groups) || groups.length !== 7) {
      return false;
    }

    const expected = [
      "Match 6",
      "Match 5 + Additional",
      "Match 5",
      "Match 4 + Additional",
      "Match 4",
      "Match 3 + Additional",
      "Match 3"
    ];

    return groups.every((group, index) => {
      if (!group || typeof group !== "object") return false;

      if (group.group !== index + 1) return false;

      if (group.category !== expected[index]) return false;

      if (
        group.amount !== null &&
        group.amount !== undefined &&
        (
          typeof group.amount !== "string" ||
          group.amount.length > 100
        )
      ) {
        return false;
      }

      return true;
    });
  }

  function getDerivedResults(result) {
    if (!result) return null;

    const categories = [
      {
        name: "1st Prize",
        numbers: [result.first_prize]
      },
      {
        name: "2nd Prize",
        numbers: [result.second_prize]
      },
      {
        name: "3rd Prize",
        numbers: [result.third_prize]
      },
      {
        name: "Starter",
        numbers: result.starter_numbers
      },
      {
        name: "Consolation",
        numbers: result.consolation_numbers
      }
    ];

    const seen2D = new Set();
    const seen3D = new Set();

    const derived2D = [];
    const derived3D = [];

    for (const category of categories) {
      const numbers2D = [];
      const numbers3D = [];

      for (const number of category.numbers) {
        if (!validFourDigit(number)) continue;

        const last2 = number.slice(-2);
        const last3 = number.slice(-3);

        if (!seen2D.has(last2)) {
          seen2D.add(last2);
          numbers2D.push(last2);
        }

        if (!seen3D.has(last3)) {
          seen3D.add(last3);
          numbers3D.push(last3);
        }
      }

      derived2D.push({
        category: category.name,
        numbers: numbers2D
      });

      derived3D.push({
        category: category.name,
        numbers: numbers3D
      });
    }

    return {
      derived_from: "4D",
      label: "GLO 365 Derived Results",
      total_source_numbers: categories.reduce(
        (total, category) => total + category.numbers.length,
        0
      ),
      "2D": derived2D,
      "3D": derived3D
    };
  }

  function validate4DInput(body) {
    const drawDate = body.draw_date;
    const drawNumber = String(body.draw_number || "").trim();

    if (!validDate(drawDate)) {
      return "Invalid draw date.";
    }

    if (!validDrawNumber(drawNumber)) {
      return "Valid draw number is required.";
    }

    if (!validFourDigit(body.first_prize)) {
      return "1st Prize must contain exactly 4 digits.";
    }

    if (!validFourDigit(body.second_prize)) {
      return "2nd Prize must contain exactly 4 digits.";
    }

    if (!validFourDigit(body.third_prize)) {
      return "3rd Prize must contain exactly 4 digits.";
    }

    if (
      !Array.isArray(body.starter_numbers) ||
      body.starter_numbers.length !== 10 ||
      !body.starter_numbers.every(validFourDigit)
    ) {
      return "Starter must contain exactly 10 four-digit numbers.";
    }

    if (
      !Array.isArray(body.consolation_numbers) ||
      body.consolation_numbers.length !== 10 ||
      !body.consolation_numbers.every(validFourDigit)
    ) {
      return "Consolation must contain exactly 10 four-digit numbers.";
    }

    return null;
  }

  function validate649Input(body) {
    if (!validDate(body.draw_date)) {
      return "Invalid draw date.";
    }

    if (!validDrawNumber(String(body.draw_number || "").trim())) {
      return "Valid draw number is required.";
    }

    if (!validNumberArray(body.winning_numbers, 6, 1, 49)) {
      return "6/49 must contain exactly 6 numbers from 1 to 49.";
    }

    const numbers = body.winning_numbers.map(Number);

    if (new Set(numbers).size !== 6) {
      return "6/49 winning numbers must be unique.";
    }

    const additional = Number(body.additional_number);

    if (
      !Number.isInteger(additional) ||
      additional < 1 ||
      additional > 49 ||
      numbers.includes(additional)
    ) {
      return "Invalid additional number.";
    }

    if (!validPrizeGroups(body.prize_groups)) {
      return "Invalid prize groups. All 7 official groups are required.";
    }

    return null;
  }

  // ---------------------------------------------------------
  // DATABASE INITIALIZATION
  // Called by the main server after initializeDatabase().
  // ---------------------------------------------------------

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

      CREATE TABLE IF NOT EXISTS singapore_4d_results (
        id BIGSERIAL PRIMARY KEY,
        draw_date DATE NOT NULL,
        draw_number VARCHAR(50) NOT NULL,
        first_prize VARCHAR(4) NOT NULL,
        second_prize VARCHAR(4) NOT NULL,
        third_prize VARCHAR(4) NOT NULL,
        starter_numbers JSONB NOT NULL,
        consolation_numbers JSONB NOT NULL,
        published BOOLEAN NOT NULL DEFAULT FALSE,
        published_at TIMESTAMPTZ,
        created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(draw_date, draw_number)
      );

      CREATE INDEX IF NOT EXISTS idx_singapore_4d_results_date
        ON singapore_4d_results(draw_date DESC);

      CREATE TABLE IF NOT EXISTS singapore_649_results (
        id BIGSERIAL PRIMARY KEY,
        draw_date DATE NOT NULL,
        draw_number VARCHAR(50) NOT NULL,
        winning_numbers JSONB NOT NULL,
        additional_number INTEGER NOT NULL
          CHECK (additional_number BETWEEN 1 AND 49),
        prize_groups JSONB NOT NULL,
        published BOOLEAN NOT NULL DEFAULT FALSE,
        published_at TIMESTAMPTZ,
        created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        updated_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(draw_date, draw_number)
      );

      CREATE INDEX IF NOT EXISTS idx_singapore_649_results_date
        ON singapore_649_results(draw_date DESC);
    `);

    // Prevent published rows from being edited or deleted,
    // even if an endpoint is accidentally added later.
    await pool.query(`
      CREATE OR REPLACE FUNCTION singapore_prevent_published_result_change()
      RETURNS TRIGGER AS $$
      BEGIN
        IF OLD.published = TRUE THEN
          RAISE EXCEPTION 'Published Singapore results are permanently locked.';
        END IF;

        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
      END;
      $$ LANGUAGE plpgsql;

      DROP TRIGGER IF EXISTS singapore_4d_immutable
        ON singapore_4d_results;

      CREATE TRIGGER singapore_4d_immutable
      BEFORE UPDATE OR DELETE ON singapore_4d_results
      FOR EACH ROW
      EXECUTE FUNCTION singapore_prevent_published_result_change();

      DROP TRIGGER IF EXISTS singapore_649_immutable
        ON singapore_649_results;

      CREATE TRIGGER singapore_649_immutable
      BEFORE UPDATE OR DELETE ON singapore_649_results
      FOR EACH ROW
      EXECUTE FUNCTION singapore_prevent_published_result_change();
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

  // ---------------------------------------------------------
  // PUBLIC GAME LIST
  // ---------------------------------------------------------

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

  // ---------------------------------------------------------
  // PUBLIC SETTINGS
  // ---------------------------------------------------------

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

  app.get("/api/singapore/settings/:game",
    asyncRoute(async (req, res) => {
      const game = normalizeGame(req.params.game);

      if (!isValidGame(game)) {
        return sendError(res, 400, "Invalid Singapore game.");
      }

      const row = await getSettings(pool, game);

      res.json({
        success: true,
        settings: publicSettings(row)
      });
    })
  );

  // ---------------------------------------------------------
  // PUBLIC RESULTS
  // Only published results are visible.
  // ---------------------------------------------------------

  app.get("/api/singapore/results",
    asyncRoute(async (req, res) => {
      const game = req.query.game
        ? normalizeGame(req.query.game)
        : null;

      if (game && !isValidGame(game)) {
        return sendError(res, 400, "Invalid Singapore game.");
      }

      const limit = Math.min(
        Math.max(Number(req.query.limit) || 30, 1),
        100
      );

      if (!game || game === "4D" || game === "2D" || game === "3D") {
        const result4D = await pool.query(
          `SELECT id, draw_date, draw_number,
                  first_prize, second_prize, third_prize,
                  starter_numbers, consolation_numbers,
                  published_at
           FROM singapore_4d_results
           WHERE published = TRUE
           ORDER BY draw_date DESC, id DESC
           LIMIT $1`,
          [limit]
        );

        const rows = result4D.rows.map(row => ({
          ...row,
          derived_results: getDerivedResults(row)
        }));

        if (game === "2D" || game === "3D") {
          return res.json({
            success: true,
            game,
            label: "GLO 365 Derived Results",
            results: rows.map(row => ({
              id: row.id,
              draw_date: row.draw_date,
              draw_number: row.draw_number,
              derived_from: "4D",
              categories: row.derived_results[game],
              published_at: row.published_at
            }))
          });
        }

        if (game === "4D") {
          return res.json({
            success: true,
            game: "4D",
            results: rows
          });
        }

        const result649 = await pool.query(
          `SELECT id, draw_date, draw_number,
                  winning_numbers, additional_number,
                  prize_groups, published_at
           FROM singapore_649_results
           WHERE published = TRUE
           ORDER BY draw_date DESC, id DESC
           LIMIT $1`,
          [limit]
        );

        return res.json({
          success: true,
          results: {
            "4D": rows,
            "6/49": result649.rows
          }
        });
      }

      const result = await pool.query(
        `SELECT id, draw_date, draw_number,
                winning_numbers, additional_number,
                prize_groups, published_at
         FROM singapore_649_results
         WHERE published = TRUE
         ORDER BY draw_date DESC, id DESC
         LIMIT $1`,
        [limit]
      );

      res.json({
        success: true,
        game: "649",
        results: result.rows
      });
    })
  );

  // ---------------------------------------------------------
  // USER ACCOUNT
  // ---------------------------------------------------------

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

      res.json({
        success: true,
        user: result.rows[0]
      });
    })
  );

  // ---------------------------------------------------------
  // PLACE BET
  // ---------------------------------------------------------

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
          `INSERT INTO singapore_bets
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
           VALUES ($1, 'singapore_bet', $2, 'DEMO', $3, $4)`,
          [
            req.user.id,
            -amount,
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

  // ---------------------------------------------------------
  // USER BET HISTORY
  // ---------------------------------------------------------

  app.get("/api/singapore/bets", authenticateToken,
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

  // ---------------------------------------------------------
  // ADMIN SETTINGS
  // ---------------------------------------------------------

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
        `INSERT INTO singapore_game_settings
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
         RETURNING game, draw_number, draw_at,
                   prize_rate, betting_enabled,
                   updated_by, updated_at`,
        [
          game,
          drawNumber,
          drawTime,
          prizeRate,
          bettingEnabled,
          req.user.id
        ]
      );

      await writeAudit(
        req.user.id,
        "singapore_settings_updated",
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
        message: "Singapore game settings saved.",
        settings: publicSettings(result.rows[0])
      });
    })
  );

  // ---------------------------------------------------------
  // ADMIN: 4D RESULTS
  // ---------------------------------------------------------

  app.get("/api/admin/singapore/results/4d",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT *
         FROM singapore_4d_results
         ORDER BY draw_date DESC, id DESC
         LIMIT 200`
      );

      res.json({
        success: true,
        results: result.rows.map(row => ({
          ...row,
          derived_results: getDerivedResults(row)
        }))
      });
    })
  );

  // Create a new 4D draft.
  // Past draw dates are allowed.
  app.post("/api/admin/singapore/results/4d",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const error = validate4DInput(req.body);

      if (error) {
        return sendError(res, 400, error);
      }

      const result = await pool.query(
        `INSERT INTO singapore_4d_results
         (draw_date, draw_number,
          first_prize, second_prize, third_prize,
          starter_numbers, consolation_numbers,
          created_by, updated_by)
         VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$8)
         RETURNING *`,
        [
          req.body.draw_date,
          req.body.draw_number.trim(),
          req.body.first_prize,
          req.body.second_prize,
          req.body.third_prize,
          JSON.stringify(req.body.starter_numbers),
          JSON.stringify(req.body.consolation_numbers),
          req.user.id
        ]
      );

      await writeAudit(
        req.user.id,
        "singapore_4d_result_created",
        result.rows[0].id,
        {
          draw_date: req.body.draw_date,
          draw_number: req.body.draw_number
        }
      );

      res.status(201).json({
        success: true,
        message: "4D result draft created.",
        result: {
          ...result.rows[0],
          derived_results: getDerivedResults(result.rows[0])
        }
      });
    })
  );

  // Edit a 4D draft only.
  app.put("/api/admin/singapore/results/4d/:id",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return sendError(res, 400, "Invalid result ID.");
      }

      const error = validate4DInput(req.body);

      if (error) {
        return sendError(res, 400, error);
      }

      const result = await pool.query(
        `UPDATE singapore_4d_results
         SET draw_date = $1,
             draw_number = $2,
             first_prize = $3,
             second_prize = $4,
             third_prize = $5,
             starter_numbers = $6::jsonb,
             consolation_numbers = $7::jsonb,
             updated_by = $8,
             updated_at = NOW()
         WHERE id = $9 AND published = FALSE
         RETURNING *`,
        [
          req.body.draw_date,
          req.body.draw_number.trim(),
          req.body.first_prize,
          req.body.second_prize,
          req.body.third_prize,
          JSON.stringify(req.body.starter_numbers),
          JSON.stringify(req.body.consolation_numbers),
          req.user.id,
          id
        ]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          403,
          "Result not found or already published. Published results cannot be edited."
        );
      }

      await writeAudit(
        req.user.id,
        "singapore_4d_result_updated",
        id,
        { draw_date: req.body.draw_date }
      );

      res.json({
        success: true,
        message: "4D draft updated.",
        result: {
          ...result.rows[0],
          derived_results: getDerivedResults(result.rows[0])
        }
      });
    })
  );

  // Delete a 4D draft only.
  app.delete("/api/admin/singapore/results/4d/:id",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return sendError(res, 400, "Invalid result ID.");
      }

      const result = await pool.query(
        `DELETE FROM singapore_4d_results
         WHERE id = $1 AND published = FALSE
         RETURNING id`,
        [id]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          403,
          "Result not found or already published. Published results cannot be deleted."
        );
      }

      await writeAudit(
        req.user.id,
        "singapore_4d_result_deleted",
        id,
        {}
      );

      res.json({
        success: true,
        message: "4D draft deleted."
      });
    })
  );

  // Publish a 4D result permanently.
  app.post("/api/admin/singapore/results/4d/:id/publish",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return sendError(res, 400, "Invalid result ID.");
      }

      const result = await pool.query(
        `UPDATE singapore_4d_results
         SET published = TRUE,
             published_at = NOW(),
             updated_by = $2,
             updated_at = NOW()
         WHERE id = $1 AND published = FALSE
         RETURNING *`,
        [id, req.user.id]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          403,
          "Result not found or already published."
        );
      }

      await writeAudit(
        req.user.id,
        "singapore_4d_result_published",
        id,
        {
          draw_date: result.rows[0].draw_date,
          draw_number: result.rows[0].draw_number
        }
      );

      res.json({
        success: true,
        message: "4D result published and permanently locked.",
        result: {
          ...result.rows[0],
          derived_results: getDerivedResults(result.rows[0])
        }
      });
    })
  );

  // ---------------------------------------------------------
  // ADMIN: 6/49 RESULTS
  // ---------------------------------------------------------

  app.get("/api/admin/singapore/results/649",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT *
         FROM singapore_649_results
         ORDER BY draw_date DESC, id DESC
         LIMIT 200`
      );

      res.json({
        success: true,
        results: result.rows
      });
    })
  );

  // Create a new 6/49 draft.
  app.post("/api/admin/singapore/results/649",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const error = validate649Input(req.body);

      if (error) {
        return sendError(res, 400, error);
      }

      const result = await pool.query(
        `INSERT INTO singapore_649_results
         (draw_date, draw_number, winning_numbers,
          additional_number, prize_groups,
          created_by, updated_by)
         VALUES ($1,$2,$3::jsonb,$4,$5::jsonb,$6,$6)
         RETURNING *`,
        [
          req.body.draw_date,
          String(req.body.draw_number).trim(),
          JSON.stringify(req.body.winning_numbers.map(Number)),
          Number(req.body.additional_number),
          JSON.stringify(req.body.prize_groups),
          req.user.id
        ]
      );

      await writeAudit(
        req.user.id,
        "singapore_649_result_created",
        result.rows[0].id,
        {
          draw_date: req.body.draw_date,
          draw_number: req.body.draw_number
        }
      );

      res.status(201).json({
        success: true,
        message: "6/49 result draft created.",
        result: result.rows[0]
      });
    })
  );

  // Edit a 6/49 draft only.
  app.put("/api/admin/singapore/results/649/:id",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return sendError(res, 400, "Invalid result ID.");
      }

      const error = validate649Input(req.body);

      if (error) {
        return sendError(res, 400, error);
      }

      const result = await pool.query(
        `UPDATE singapore_649_results
         SET draw_date = $1,
             draw_number = $2,
             winning_numbers = $3::jsonb,
             additional_number = $4,
             prize_groups = $5::jsonb,
             updated_by = $6,
             updated_at = NOW()
         WHERE id = $7 AND published = FALSE
         RETURNING *`,
        [
          req.body.draw_date,
          String(req.body.draw_number).trim(),
          JSON.stringify(req.body.winning_numbers.map(Number)),
          Number(req.body.additional_number),
          JSON.stringify(req.body.prize_groups),
          req.user.id,
          id
        ]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          403,
          "Result not found or already published. Published results cannot be edited."
        );
      }

      await writeAudit(
        req.user.id,
        "singapore_649_result_updated",
        id,
        { draw_date: req.body.draw_date }
      );

      res.json({
        success: true,
        message: "6/49 draft updated.",
        result: result.rows[0]
      });
    })
  );

  // Delete a 6/49 draft only.
  app.delete("/api/admin/singapore/results/649/:id",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return sendError(res, 400, "Invalid result ID.");
      }

      const result = await pool.query(
        `DELETE FROM singapore_649_results
         WHERE id = $1 AND published = FALSE
         RETURNING id`,
        [id]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          403,
          "Result not found or already published. Published results cannot be deleted."
        );
      }

      await writeAudit(
        req.user.id,
        "singapore_649_result_deleted",
        id,
        {}
      );

      res.json({
        success: true,
        message: "6/49 draft deleted."
      });
    })
  );

  // Publish a 6/49 result permanently.
  app.post("/api/admin/singapore/results/649/:id/publish",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id <= 0) {
        return sendError(res, 400, "Invalid result ID.");
      }

      const result = await pool.query(
        `UPDATE singapore_649_results
         SET published = TRUE,
             published_at = NOW(),
             updated_by = $2,
             updated_at = NOW()
         WHERE id = $1 AND published = FALSE
         RETURNING *`,
        [id, req.user.id]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          403,
          "Result not found or already published."
        );
      }

      await writeAudit(
        req.user.id,
        "singapore_649_result_published",
        id,
        {
          draw_date: result.rows[0].draw_date,
          draw_number: result.rows[0].draw_number
        }
      );

      res.json({
        success: true,
        message: "6/49 result published and permanently locked.",
        result: result.rows[0]
      });
    })
  );

  // ---------------------------------------------------------
  // ADMIN BETS
  // ---------------------------------------------------------

  app.get("/api/admin/singapore/bets",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const game = req.query.game
        ? normalizeGame(req.query.game)
        : null;

      if (game && !isValidGame(game)) {
        return sendError(res, 400, "Invalid Singapore game.");
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

  // ---------------------------------------------------------
  // ADMIN SUMMARY
  // ---------------------------------------------------------

  app.get("/api/admin/singapore/summary",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(`
        SELECT COUNT(*)::int AS total_bets,
               COALESCE(SUM(amount), 0) AS total_points,
               COUNT(DISTINCT user_id)::int AS total_users
        FROM singapore_bets
      `);

      const resultsSummary = await pool.query(`
        SELECT
          (SELECT COUNT(*)::int
           FROM singapore_4d_results
           WHERE published = TRUE) AS published_4d,

          (SELECT COUNT(*)::int
           FROM singapore_4d_results
           WHERE published = FALSE) AS draft_4d,

          (SELECT COUNT(*)::int
           FROM singapore_649_results
           WHERE published = TRUE) AS published_649,

          (SELECT COUNT(*)::int
           FROM singapore_649_results
           WHERE published = FALSE) AS draft_649
      `);

      res.json({
        success: true,
        summary: {
          ...result.rows[0],
          results: resultsSummary.rows[0]
        }
      });
    })
  );

  console.log("Singapore Games routes registered.");

  return initializeSingaporeDatabase;
};
