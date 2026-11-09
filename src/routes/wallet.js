"use strict";

/**
 * GLO 365 - Wallet read routes
 *
 * Extracted from the existing server.js without changing SQL, response
 * fields, route paths, authentication, or DEMO currency behavior.
 *
 * Important:
 * - This module only owns GET /api/wallet and GET /api/wallet/transactions.
 * - Wallet balance mutations remain in their existing deposit, withdrawal,
 *   betting, and admin routes until those transactions are migrated safely.
 * - Do not mount this module until server.js is updated to call
 *   registerWalletRoutes(app, dependencies).
 */

function registerWalletRoutes(app, dependencies) {
  const {
    pool,
    authenticateToken,
    asyncRoute,
    sendError
  } = dependencies || {};

  if (!app || typeof app.get !== "function") {
    throw new TypeError("A valid Express app is required.");
  }
  if (!pool || typeof pool.query !== "function") {
    throw new TypeError("A valid PostgreSQL pool is required.");
  }
  if (typeof authenticateToken !== "function") {
    throw new TypeError("authenticateToken middleware is required.");
  }
  if (typeof asyncRoute !== "function") {
    throw new TypeError("asyncRoute helper is required.");
  }
  if (typeof sendError !== "function") {
    throw new TypeError("sendError helper is required.");
  }

  // Existing route: GET /api/wallet
  app.get(
    "/api/wallet",
    authenticateToken,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        "SELECT balance FROM users WHERE id = $1",
        [req.user.id]
      );

      if (!result.rows.length) {
        return sendError(res, 404, "User not found.");
      }

      res.json({
        success: true,
        currency: "DEMO",
        is_demo: true,
        balance: result.rows[0].balance
      });
    })
  );

  // Existing route: GET /api/wallet/transactions
  app.get(
    "/api/wallet/transactions",
    authenticateToken,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id, type, amount, currency, description, reference, created_at
         FROM wallet_transactions
         WHERE user_id = $1
         ORDER BY created_at DESC
         LIMIT 100`,
        [req.user.id]
      );

      res.json({
        success: true,
        currency: "DEMO",
        transactions: result.rows
      });
    })
  );
}

module.exports = {
  registerWalletRoutes
};
