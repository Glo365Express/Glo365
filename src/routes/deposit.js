
"use strict";

/**
 * GLO 365 - Payment Methods & Deposit Routes
 *
 * Secure tenant separation:
 * - Primary Admin manages only Primary Admin payment methods.
 * - Primary Admin deposit operations exclude Sub-Admin customers.
 * - Sub-Admin routes remain isolated in src/routes/subadmin.js.
 * - All data remains in the shared PostgreSQL database.
 */

module.exports = function registerDepositRoutes({
  app,
  pool,
  authenticateToken,
  requireAdmin,
  asyncRoute,
  cleanText,
  sendError,
  audit
}) {
  if (
    !app ||
    !pool ||
    !authenticateToken ||
    !requireAdmin ||
    !asyncRoute ||
    !cleanText ||
    !sendError ||
    !audit
  ) {
    throw new Error("Deposit routes are missing required dependencies.");
  }

  // Primary Admin username is reserved by the main server.
  const PRIMARY_ADMIN_USERNAME = "adminglo365";

  // ==========================================
  // PRIMARY ADMIN PAYMENT METHODS
  // ==========================================

  // Only methods created by the logged-in Primary Admin.
  app.get(
    "/api/admin/payment-methods",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const q = cleanText(req.query.q, 150).toLowerCase();

      if (!q) {
        return res.json({ success: true, methods: [] });
      }

      const result = await pool.query(
        `SELECT id, preset, name, label, account, currency,
                instructions, active, created_at, updated_at
         FROM payment_methods
         WHERE created_by = $2
           AND LOWER(
             CONCAT_WS(
               ' ',
               name,
               label,
               account,
               currency,
               instructions,
               id::text
             )
           ) LIKE $1
         ORDER BY updated_at DESC
         LIMIT 100`,
        [`%${q}%`, req.user.id]
      );

      res.json({
        success: true,
        methods: result.rows
      });
    })
  );

  // Create Primary Admin payment method.
  app.post(
    "/api/admin/payment-methods",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const preset = cleanText(req.body.preset || "Custom", 40);
      const name = cleanText(req.body.name, 60);
      const label = cleanText(req.body.label, 60);
      const account = cleanText(req.body.account, 150);
      const currency = cleanText(
        req.body.currency || "BDT",
        10
      ).toUpperCase();

      const instructions = cleanText(
        req.body.instructions,
        1000
      );

      const active = req.body.active !== false;

      if (
        !name ||
        !/^[A-Z0-9]{2,10}$/.test(currency)
      ) {
        return sendError(
          res,
          400,
          "Invalid payment method details."
        );
      }

      const result = await pool.query(
        `INSERT INTO payment_methods
         (
           preset,
           name,
           label,
           account,
           currency,
           instructions,
           active,
           created_by,
           updated_by
         )
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)
         RETURNING *`,
        [
          preset,
          name,
          label,
          account,
          currency,
          instructions,
          active,
          req.user.id
        ]
      );

      await audit(
        req.user.id,
        "payment_method_created",
        null,
        {
          method_id: result.rows[0].id,
          name
        }
      );

      res.status(201).json({
        success: true,
        method: result.rows[0]
      });
    })
  );

  // Update only the logged-in Primary Admin's own method.
  app.put(
    "/api/admin/payment-methods/:id",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      const preset = cleanText(
        req.body.preset || "Custom",
        40
      );

      const name = cleanText(req.body.name, 60);
      const label = cleanText(req.body.label, 60);
      const account = cleanText(req.body.account, 150);

      const currency = cleanText(
        req.body.currency || "BDT",
        10
      ).toUpperCase();

      const instructions = cleanText(
        req.body.instructions,
        1000
      );

      const active = req.body.active !== false;

      if (
        !Number.isSafeInteger(id) ||
        id < 1 ||
        !name ||
        !/^[A-Z0-9]{2,10}$/.test(currency)
      ) {
        return sendError(
          res,
          400,
          "Invalid payment method details."
        );
      }

      const result = await pool.query(
        `UPDATE payment_methods
         SET
           preset=$1,
           name=$2,
           label=$3,
           account=$4,
           currency=$5,
           instructions=$6,
           active=$7,
           updated_by=$8,
           updated_at=NOW()
         WHERE id=$9
           AND created_by=$8
         RETURNING *`,
        [
          preset,
          name,
          label,
          account,
          currency,
          instructions,
          active,
          req.user.id,
          id
        ]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          404,
          "Payment method not found."
        );
      }

      await audit(
        req.user.id,
        "payment_method_updated",
        null,
        { method_id: id }
      );

      res.json({
        success: true,
        method: result.rows[0]
      });
    })
  );

  // Change status only for own payment method.
  app.patch(
    "/api/admin/payment-methods/:id/status",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      if (
        !Number.isSafeInteger(id) ||
        id < 1 ||
        typeof req.body.active !== "boolean"
      ) {
        return sendError(
          res,
          400,
          "Invalid method status."
        );
      }

      const result = await pool.query(
        `UPDATE payment_methods
         SET
           active=$1,
           updated_by=$2,
           updated_at=NOW()
         WHERE id=$3
           AND created_by=$2
         RETURNING *`,
        [
          req.body.active,
          req.user.id,
          id
        ]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          404,
          "Payment method not found."
        );
      }

      res.json({
        success: true,
        method: result.rows[0]
      });
    })
  );

  // Delete only own payment method.
  app.delete(
    "/api/admin/payment-methods/:id",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id < 1) {
        return sendError(
          res,
          400,
          "Invalid method ID."
        );
      }

      const result = await pool.query(
        `DELETE FROM payment_methods
         WHERE id=$1
           AND created_by=$2
         RETURNING id`,
        [id, req.user.id]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          404,
          "Payment method not found."
        );
      }

      res.json({
        success: true,
        message: "Payment method deleted."
      });
    })
  );

  // ==========================================
  // PUBLIC PRIMARY ADMIN PAYMENT METHODS
  // Sub-Admin methods are never exposed here.
  // ==========================================

  app.get(
    "/api/public/payment-methods",
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT
           id,
           preset,
           name,
           label,
           account,
           currency,
           instructions
         FROM payment_methods
         WHERE active=TRUE
           AND created_by=(
             SELECT id
             FROM users
             WHERE username=$1
               AND role='admin'
             LIMIT 1
           )
         ORDER BY name, id`,
        [PRIMARY_ADMIN_USERNAME]
      );

      res.json({
        success: true,
        methods: result.rows
      });
    })
  );

  // ==========================================
  // CUSTOMER DEPOSIT HISTORY
  // ==========================================

  app.get(
    "/api/deposits/me",
    authenticateToken,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT
           id,
           payment_method_id,
           method,
           payment_account,
           currency,
           amount,
           sender_account,
           transaction_id,
           status,
           credited_points,
           rejection_reason,
           created_at,
           reviewed_at
         FROM deposit_requests
         WHERE user_id=$1
         ORDER BY created_at DESC
         LIMIT 100`,
        [req.user.id]
      );

      res.json({
        success: true,
        requests: result.rows
      });
    })
  );

  // ==========================================
  // PRIMARY ADMIN CUSTOMER DEPOSIT REQUEST
  // Only ordinary customers without Sub-Admin.
  // ==========================================

  app.post(
    "/api/deposits",
    authenticateToken,
    asyncRoute(async (req, res) => {
      const methodId = Number(
        req.body.payment_method_id
      );

      const amount = Number(req.body.amount);

      const sender = cleanText(
        req.body.sender_account,
        150
      );

      const transactionId = cleanText(
        req.body.transaction_id,
        150
      );

      if (
        !Number.isSafeInteger(methodId) ||
        methodId < 1 ||
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > 10000000 ||
        !sender ||
        !transactionId
      ) {
        return sendError(
          res,
          400,
          "Invalid deposit request."
        );
      }

      // Verify this is a Main Admin customer.
      const customer = await pool.query(
        `SELECT id
         FROM users
         WHERE id=$1
           AND role='user'
           AND subadmin_owner_id IS NULL
         LIMIT 1`,
        [req.user.id]
      );

      if (!customer.rows.length) {
        return sendError(
          res,
          403,
          "This deposit endpoint is not available for this account."
        );
      }

      // Verify payment method belongs to Primary Admin.
      const methodResult = await pool.query(
        `SELECT
           id,
           name,
           account,
           currency
         FROM payment_methods
         WHERE id=$1
           AND active=TRUE
           AND created_by=(
             SELECT id
             FROM users
             WHERE username=$2
               AND role='admin'
             LIMIT 1
           )`,
        [
          methodId,
          PRIMARY_ADMIN_USERNAME
        ]
      );

      if (!methodResult.rows.length) {
        return sendError(
          res,
          400,
          "Payment method is unavailable."
        );
      }

      const method = methodResult.rows[0];

      try {
        const result = await pool.query(
          `INSERT INTO deposit_requests
           (
             user_id,
             payment_method_id,
             method,
             payment_account,
             currency,
             amount,
             sender_account,
             transaction_id
           )
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
           RETURNING id,status,created_at`,
          [
            req.user.id,
            method.id,
            method.name,
            method.account,
            method.currency,
            amount.toFixed(2),
            sender,
            transactionId
          ]
        );

        res.status(201).json({
          success: true,
          request: result.rows[0]
        });
      } catch (error) {
        if (error.code === "23505") {
          return sendError(
            res,
            409,
            "This transaction ID has already been submitted."
          );
        }

        throw error;
      }
    })
  );

  // ==========================================
  // PRIMARY ADMIN DEPOSIT LIST
  // Sub-Admin customers are excluded.
  // ==========================================

  app.get(
    "/api/admin/deposits",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const status = cleanText(
        req.query.status || "all",
        20
      ).toLowerCase();

      const search = cleanText(
        req.query.search,
        150
      ).toLowerCase();

      const params = [];

      let where = `
        u.role='user'
        AND u.subadmin_owner_id IS NULL
      `;

      if (
        ["pending", "approved", "rejected"].includes(status)
      ) {
        params.push(status);
        where += ` AND d.status=$${params.length}`;
      }

      if (search) {
        params.push(`%${search}%`);

        where += `
          AND LOWER(
            CONCAT_WS(
              ' ',
              u.username,
              d.id::text,
              d.transaction_id,
              d.method
            )
          ) LIKE $${params.length}
        `;
      }

      const [items, counts] = await Promise.all([
        pool.query(
          `SELECT
             d.id,
             d.user_id,
             u.username,
             d.method,
             d.payment_account,
             d.currency,
             d.amount,
             d.sender_account,
             d.transaction_id,
             d.status,
             d.credited_points,
             d.rejection_reason,
             d.reviewed_at,
             admin.username AS reviewed_by,
             d.created_at
           FROM deposit_requests d
           JOIN users u ON u.id=d.user_id
           LEFT JOIN users admin ON admin.id=d.reviewed_by
           WHERE ${where}
           ORDER BY d.created_at DESC
           LIMIT 500`,
          params
        ),

        pool.query(
          `SELECT
             COUNT(*)::int AS total,
             COUNT(*) FILTER (
               WHERE d.status='pending'
             )::int AS pending,
             COUNT(*) FILTER (
               WHERE d.status='approved'
             )::int AS approved,
             COUNT(*) FILTER (
               WHERE d.status='rejected'
             )::int AS rejected
           FROM deposit_requests d
           JOIN users u ON u.id=d.user_id
           WHERE u.role='user'
             AND u.subadmin_owner_id IS NULL`
        )
      ]);

      res.json({
        success: true,
        requests: items.rows,
        stats: counts.rows[0]
      });
    })
  );

  // ==========================================
  // PRIMARY ADMIN APPROVE DEPOSIT
  // ==========================================

  app.post(
    "/api/admin/deposits/:id/approve",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);
      const points = Number(req.body.points);

      if (
        !Number.isSafeInteger(id) ||
        id < 1 ||
        !Number.isFinite(points) ||
        points <= 0 ||
        points > 10000000 ||
        Math.round(points * 100) !== points * 100
      ) {
        return sendError(
          res,
          400,
          "Enter valid points to credit."
        );
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        // Lock only a Primary Admin customer's deposit.
        const found = await client.query(
          `SELECT d.*
           FROM deposit_requests d
           JOIN users u ON u.id=d.user_id
           WHERE d.id=$1
             AND u.role='user'
             AND u.subadmin_owner_id IS NULL
           FOR UPDATE OF d`,
          [id]
        );

        if (!found.rows.length) {
          await client.query("ROLLBACK");

          return sendError(
            res,
            404,
            "Deposit request not found."
          );
        }

        const request = found.rows[0];

        if (request.status !== "pending") {
          await client.query("ROLLBACK");

          return sendError(
            res,
            409,
            "This request has already been reviewed."
          );
        }

        // Lock only a normal customer account.
        const user = await client.query(
          `SELECT balance
           FROM users
           WHERE id=$1
             AND role='user'
             AND subadmin_owner_id IS NULL
           FOR UPDATE`,
          [request.user_id]
        );

        if (!user.rows.length) {
          await client.query("ROLLBACK");

          return sendError(
            res,
            404,
            "User not found."
          );
        }

        const balance = Number(user.rows[0].balance);

        const newBalance = Number(
          (balance + points).toFixed(2)
        );

        if (
          !Number.isFinite(newBalance) ||
          newBalance > 9999999999.99
        ) {
          await client.query("ROLLBACK");

          return sendError(
            res,
            400,
            "Wallet balance limit exceeded."
          );
        }

        await client.query(
          `UPDATE users
           SET balance=$1,updated_at=NOW()
           WHERE id=$2
             AND role='user'
             AND subadmin_owner_id IS NULL`,
          [
            newBalance,
            request.user_id
          ]
        );

        await client.query(
          `INSERT INTO wallet_transactions
           (
             user_id,
             type,
             amount,
             currency,
             description,
             reference
           )
           VALUES (
             $1,
             'deposit_credit',
             $2,
             'DEMO',
             $3,
             $4
           )`,
          [
            request.user_id,
            points,
            "Admin-approved deposit points",
            "DEP-" + id
          ]
        );

        const updated = await client.query(
          `UPDATE deposit_requests
           SET
             status='approved',
             credited_points=$1,
             reviewed_by=$2,
             reviewed_at=NOW()
           WHERE id=$3
             AND status='pending'
             AND EXISTS (
               SELECT 1
               FROM users u
               WHERE u.id=deposit_requests.user_id
                 AND u.role='user'
                 AND u.subadmin_owner_id IS NULL
             )
           RETURNING *`,
          [
            points,
            req.user.id,
            id
          ]
        );

        if (!updated.rows.length) {
          throw new Error(
            "Deposit approval state changed unexpectedly."
          );
        }

        await client.query("COMMIT");

        await audit(
          req.user.id,
          "deposit_approved",
          request.user_id,
          {
            deposit_id: id,
            credited_points: points
          }
        );

        res.json({
          success: true,
          request: updated.rows[0],
          new_balance: newBalance
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
  // PRIMARY ADMIN REJECT DEPOSIT
  // ==========================================

  app.post(
    "/api/admin/deposits/:id/reject",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = Number(req.params.id);

      const reason = cleanText(
        req.body.reason,
        200
      );

      if (
        !Number.isSafeInteger(id) ||
        id < 1 ||
        !reason
      ) {
        return sendError(
          res,
          400,
          "A rejection reason is required."
        );
      }

      const result = await pool.query(
        `UPDATE deposit_requests
         SET
           status='rejected',
           rejection_reason=$1,
           reviewed_by=$2,
           reviewed_at=NOW()
         WHERE id=$3
           AND status='pending'
           AND EXISTS (
             SELECT 1
             FROM users u
             WHERE u.id=deposit_requests.user_id
               AND u.role='user'
               AND u.subadmin_owner_id IS NULL
           )
         RETURNING *`,
        [
          reason,
          req.user.id,
          id
        ]
      );

      if (!result.rows.length) {
        return sendError(
          res,
          409,
          "Request not found or already reviewed."
        );
      }

      await audit(
        req.user.id,
        "deposit_rejected",
        result.rows[0].user_id,
        {
          deposit_id: id,
          reason
        }
      );

      res.json({
        success: true,
        request: result.rows[0]
      });
    })
  );
};
