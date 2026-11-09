"use strict";

// GLO 365 authentication and role middleware.
// This module preserves the authentication rules from the existing server.
// It is exported as a factory so the existing server can pass its current
// database pool, JWT settings, and helper functions without duplicating them.

module.exports = function createAuthMiddleware({
  pool,
  jwt,
  JWT_SECRET,
  AUTH_COOKIE,
  PRIMARY_ADMIN_USERNAME,
  sendError,
  asyncRoute
}) {
  if (!pool || !jwt || !JWT_SECRET || !AUTH_COOKIE ||
      !PRIMARY_ADMIN_USERNAME || !sendError || !asyncRoute) {
    throw new Error("Missing required GLO 365 authentication dependencies.");
  }

  function getCookie(req, name) {
    const header = req.headers.cookie || "";

    for (const part of header.split(";")) {
      const index = part.indexOf("=");
      if (index < 0) continue;

      const key = part.slice(0, index).trim();
      if (key === name) {
        try {
          return decodeURIComponent(part.slice(index + 1).trim());
        } catch {
          return null;
        }
      }
    }

    return null;
  }

  async function authenticateToken(req, res, next) {
    const authHeader = req.headers.authorization || "";
    let token = null;

    if (authHeader.startsWith("Bearer ")) {
      token = authHeader.substring(7).trim();
    }

    if (!token) token = getCookie(req, AUTH_COOKIE);

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
         WHERE id = $1`,
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
      return next();
    } catch (error) {
      console.error("Authentication database error:", error.message);
      return sendError(
        res,
        500,
        "Authentication service temporarily unavailable."
      );
    }
  }

  function isPrimaryAdmin(user) {
    return Boolean(
      user &&
      user.role === "admin" &&
      user.username === PRIMARY_ADMIN_USERNAME
    );
  }

  function requireAdmin(req, res, next) {
    if (!isPrimaryAdmin(req.user)) {
      return sendError(res, 403, "Primary Admin access required.");
    }

    next();
  }

  function requirePermission(permission) {
    return asyncRoute(async (req, res, next) => {
      if (isPrimaryAdmin(req.user)) return next();

      if (req.user.role !== "moderator") {
        return sendError(res, 403, "Permission denied.");
      }

      const result = await pool.query(
        `SELECT permissions
         FROM moderator_permissions
         WHERE user_id = $1`,
        [req.user.id]
      );

      const permissions = result.rows[0]?.permissions || {};

      if (permissions[permission] !== true) {
        return sendError(res, 403, "You do not have this permission.");
      }

      next();
    });
  }

  return {
    getCookie,
    authenticateToken,
    isPrimaryAdmin,
    requireAdmin,
    requirePermission
  };
};
