// GLO 365 - Withdrawal Routes
// Source: existing live server.js withdrawal section.
// This module preserves the existing API paths and wallet-accounting behavior.
//
// Required dependencies:
// pool, authenticateToken, requireAdmin, asyncRoute, cleanText, sendError, audit
//
// Register from server.js only after importing the existing shared dependencies:
// registerWithdrawalRoutes(app, {
//   pool, authenticateToken, requireAdmin, asyncRoute, cleanText, sendError, audit
// });

module.exports = function registerWithdrawalRoutes(app, deps) {
  const {
    pool,
    authenticateToken,
    requireAdmin,
    asyncRoute,
    cleanText,
    sendError,
    audit
  } = deps || {};

  const required = {
    pool,
    authenticateToken,
    requireAdmin,
    asyncRoute,
    cleanText,
    sendError,
    audit
  };

  for (const [name, value] of Object.entries(required)) {
    if (!value) {
      throw new Error(`Withdrawal routes: missing dependency "${name}".`);
    }
  }

  // ==========================================
  // WITHDRAWAL REQUESTS (SERVER-SIDE DEMO REVIEW)
  // Approval/rejection changes request status only; no real payment is sent.
  // ==========================================

  app.post("/api/withdrawals", authenticateToken, asyncRoute(async (req, res) => {
    const amount = Number(req.body.amount);
    const method = cleanText(req.body.method, 80);
    const account = cleanText(req.body.account, 180);

    if (
      !Number.isFinite(amount) ||
      amount <= 0 ||
      amount > 10000000 ||
      Math.round(amount * 100) !== amount * 100 ||
      !method ||
      !account
    ) {
      return sendError(res, 400, "Enter a valid withdrawal amount, method and account.");
    }

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

      const balance = Number(walletResult.rows[0].balance || 0);

      if (!Number.isFinite(balance) || balance < amount) {
        await client.query("ROLLBACK");
        return sendError(res, 400, "Insufficient DEMO points.");
      }

      // Deduct points immediately when the request is created.
      // Admin approval must never deduct the same request a second time.
      await client.query(
        "UPDATE users SET balance=balance-$1,updated_at=NOW() WHERE id=$2",
        [amount.toFixed(2), req.user.id]
      );

      const result = await client.query(
        `INSERT INTO withdrawal_requests (user_id,amount,method,account,points_deducted)
         VALUES ($1,$2,$3,$4,TRUE)
         RETURNING id,amount,method,account,status,points_deducted,created_at`,
        [req.user.id, amount.toFixed(2), method, account]
      );

      const withdrawalId = result.rows[0].id;

      await client.query(
        `INSERT INTO wallet_transactions (user_id,type,amount,currency,description,reference)
         VALUES ($1,'withdrawal_debit',$2,'DEMO',$3,$4)`,
        [
          req.user.id,
          (-amount).toFixed(2),
          "Withdrawal points deducted when request was submitted",
          "WD-" + withdrawalId
        ]
      );

      const newBalance = Number((balance - amount).toFixed(2));

      await client.query("COMMIT");

      await audit(req.user.id, "withdrawal_requested", req.user.id, {
        withdrawal_id: withdrawalId,
        amount,
        new_balance: newBalance,
        points_deducted: true
      });

      res.status(201).json({
        success: true,
        request: result.rows[0],
        balance: newBalance,
        available_balance: newBalance,
        message: "Withdrawal request submitted. DEMO points have been deducted from your wallet."
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.get("/api/withdrawals/me", authenticateToken, asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT id,amount,method,account,status,rejection_reason,points_deducted,created_at,reviewed_at
       FROM withdrawal_requests WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
      [req.user.id]
    );

    res.json({ success: true, requests: result.rows });
  }));

  app.get("/api/admin/withdrawals", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const status = cleanText(req.query.status || "all", 20).toLowerCase();
    const search = cleanText(req.query.search, 150).toLowerCase();
    const params = [];
    let where = "TRUE";

    if (["pending", "approved", "rejected"].includes(status)) {
      params.push(status);
      where += ` AND w.status=$${params.length}`;
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
         WHERE ${where} ORDER BY w.created_at DESC LIMIT 500`,
        params
      ),
      pool.query(
        `SELECT COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE status='pending')::int AS pending,
                COUNT(*) FILTER (WHERE status='approved')::int AS approved,
                COUNT(*) FILTER (WHERE status='rejected')::int AS rejected
         FROM withdrawal_requests`
      )
    ]);

    res.json({ success: true, requests: items.rows, stats: counts.rows[0] });
  }));

  app.post("/api/admin/withdrawals/:id/approve", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return sendError(res, 400, "Invalid withdrawal request ID.");
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const found = await client.query(
        "SELECT * FROM withdrawal_requests WHERE id=$1 FOR UPDATE",
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

      // Old pending records may predate immediate deduction.
      // Deduct only those legacy requests once, during approval.
      if (request.points_deducted !== true) {
        const amount = Number(request.amount);

        const walletResult = await client.query(
          "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
          [request.user_id]
        );

        if (!walletResult.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 404, "Withdrawal user account was not found.");
        }

        const currentBalance = Number(walletResult.rows[0].balance || 0);

        if (!Number.isFinite(amount) || amount <= 0 || currentBalance < amount) {
          await client.query("ROLLBACK");
          return sendError(
            res,
            409,
            "This older pending request was not deducted at submission and the wallet has insufficient points."
          );
        }

        await client.query(
          "UPDATE users SET balance=balance-$1,updated_at=NOW() WHERE id=$2",
          [amount.toFixed(2), request.user_id]
        );

        await client.query(
          `INSERT INTO wallet_transactions(user_id,type,amount,currency,description,reference)
           VALUES($1,'withdrawal_debit',$2,'DEMO',$3,$4)`,
          [
            request.user_id,
            (-amount).toFixed(2),
            "Legacy withdrawal points deducted on approval",
            "WD-" + id
          ]
        );
      }

      const updated = await client.query(
        `UPDATE withdrawal_requests
         SET status='approved', points_deducted=TRUE, reviewed_by=$1, reviewed_at=NOW()
         WHERE id=$2 AND status='pending' RETURNING *`,
        [req.user.id, id]
      );

      if (!updated.rows.length) {
        throw new Error("Withdrawal approval state changed unexpectedly.");
      }

      const wallet = await client.query(
        "SELECT balance FROM users WHERE id=$1",
        [request.user_id]
      );

      const balance = wallet.rows.length ? Number(wallet.rows[0].balance) : null;

      await client.query("COMMIT");

      await audit(req.user.id, "withdrawal_approved", request.user_id, {
        withdrawal_id: id,
        amount: Number(request.amount),
        points_deducted_before_approval: true
      });

      res.json({
        success: true,
        request: updated.rows[0],
        new_balance: balance,
        message: "Withdrawal approved. Previously deducted DEMO points remain deducted; no wallet credit was made and no real payment was sent."
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
    const reason = cleanText(req.body.reason || "Rejected by admin", 200);

    if (!Number.isSafeInteger(id) || id < 1) {
      return sendError(res, 400, "Invalid withdrawal request ID.");
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const found = await client.query(
        "SELECT * FROM withdrawal_requests WHERE id=$1 FOR UPDATE",
        [id]
      );

      if (!found.rows.length) {
        await client.query("ROLLBACK");
        return sendError(res, 404, "Withdrawal request not found.");
      }

      const request = found.rows[0];

      if (request.status !== "pending") {
        await client.query("ROLLBACK");
        return sendError(res, 409, "Request not found or already reviewed.");
      }

      let refundedBalance = null;

      if (request.points_deducted === true) {
        const amount = Number(request.amount);

        if (!Number.isFinite(amount) || amount <= 0) {
          await client.query("ROLLBACK");
          return sendError(res, 400, "The withdrawal amount is invalid.");
        }

        const walletResult = await client.query(
          "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
          [request.user_id]
        );

        if (!walletResult.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 404, "Withdrawal user's account was not found.");
        }

        const currentBalance = Number(walletResult.rows[0].balance || 0);
        refundedBalance = Number((currentBalance + amount).toFixed(2));

        if (!Number.isFinite(refundedBalance) || refundedBalance > 9999999999.99) {
          await client.query("ROLLBACK");
          return sendError(res, 409, "Refund would exceed the wallet balance limit.");
        }

        await client.query(
          "UPDATE users SET balance=$1,updated_at=NOW() WHERE id=$2",
          [refundedBalance.toFixed(2), request.user_id]
        );

        await client.query(
          `INSERT INTO wallet_transactions (user_id,type,amount,currency,description,reference)
           VALUES ($1,'withdrawal_refund',$2,'DEMO',$3,$4)`,
          [
            request.user_id,
            amount.toFixed(2),
            "Refund for rejected withdrawal request",
            "WDR-" + id
          ]
        );
      }

      const updated = await client.query(
        `UPDATE withdrawal_requests
         SET status='rejected',rejection_reason=$1,reviewed_by=$2,reviewed_at=NOW()
         WHERE id=$3 AND status='pending' RETURNING *`,
        [reason, req.user.id, id]
      );

      if (!updated.rows.length) {
        throw new Error("Withdrawal rejection state changed unexpectedly.");
      }

      await client.query("COMMIT");

      await audit(req.user.id, "withdrawal_rejected", request.user_id, {
        withdrawal_id: id,
        reason,
        refunded: request.points_deducted === true,
        refunded_balance: refundedBalance
      });

      res.json({
        success: true,
        request: updated.rows[0],
        ...(refundedBalance !== null ? { new_balance: refundedBalance } : {}),
        message: request.points_deducted === true
          ? "Withdrawal rejected. DEMO points have been refunded to the wallet."
          : "Withdrawal rejected. No points were deducted for this legacy request."
      });
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));
};
