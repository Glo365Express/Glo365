"use strict";

/**
 * GLO 365 - Thailand 3UP routes
 * This module preserves the existing 3UP API paths and behavior.
 * It does not initialize or alter database tables.
 */
module.exports = function registerThailand3UpRoutes({
  app,
  pool,
  asyncRoute,
  authenticateToken,
  requireAdmin,
  audit,
  sendError,
  getCurrentDraw,
  isDrawBettingLocked,
  DRAW_LOCK_MINUTES
}) {
  if (!app || !pool || !asyncRoute || !authenticateToken || !requireAdmin ||
      !audit || !sendError || !getCurrentDraw || !isDrawBettingLocked) {
    throw new Error("Thailand 3UP route dependencies are missing.");
  }

  function amountToCents(value) {
    if (value === "" || value === null || value === undefined) return 0;
    const number = Number(value);
    if (!Number.isFinite(number) || number < 0 || number > 100000 ||
        Math.round(number * 100) !== number * 100) return null;
    return Math.round(number * 100);
  }

  function centsToAmount(cents) {
    return (cents / 100).toFixed(2);
  }

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


};
