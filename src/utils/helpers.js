"use strict";

// GLO 365 shared helper module.
// Functions are moved from the existing server.js without changing
// their validation rules or response formats.
// This module is not connected to server.js yet.

function createHelpers({ jwt, JWT_SECRET, AUTH_COOKIE, COOKIE_MAX_AGE, pool, DRAW_LOCK_MINUTES }) {
  if (!jwt || typeof jwt.sign !== "function") {
    throw new Error("createHelpers requires the jsonwebtoken module.");
  }

  if (!JWT_SECRET) {
    throw new Error("createHelpers requires JWT_SECRET.");
  }

  if (!pool || typeof pool.query !== "function") {
    throw new Error("createHelpers requires the PostgreSQL pool.");
  }

  const helpers = {
    sendError(res, status, message) {
      return res.status(status).json({
        success: false,
        message
      });
    },

    asyncRoute(handler) {
      return (req, res, next) => {
        Promise.resolve(handler(req, res, next)).catch(next);
      };
    },

    cleanText(value, maxLength = 255) {
      if (typeof value !== "string") return "";
      return value.trim().slice(0, maxLength);
    },

    publicUser(user) {
      return {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role || "user",
        status: user.status || "active",
        balance: user.balance,
        created_at: user.created_at
      };
    },

    createToken(user) {
      return jwt.sign(
        {
          id: user.id,
          username: user.username
        },
        JWT_SECRET,
        {
          expiresIn: "7d",
          issuer: "glo365"
        }
      );
    },

    setAuthCookie(res, token) {
      res.cookie(AUTH_COOKIE, token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        path: "/",
        maxAge: COOKIE_MAX_AGE
      });
    },

    clearAuthCookie(res) {
      res.clearCookie(AUTH_COOKIE, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        path: "/"
      });
    },

    getCookie(req, name) {
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
    },

    validUsername(username) {
      return /^[a-z0-9_]{3,30}$/.test(username);
    },

    validEmail(email) {
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    },

    validPassword(password) {
      return typeof password === "string" && password.length >= 6 && password.length <= 16;
    },

    validExternalEventUrl(value, platform) {
      try {
        const url = new URL(value);

        if (url.protocol !== "https:") return false;

        const host = url.hostname.toLowerCase();

        const youtubeHosts = [
          "youtube.com",
          "www.youtube.com",
          "m.youtube.com",
          "youtu.be",
          "www.youtube-nocookie.com"
        ];

        const facebookHosts = [
          "facebook.com",
          "www.facebook.com",
          "m.facebook.com",
          "fb.watch",
          "www.fb.watch"
        ];

        if (platform === "youtube") {
          return youtubeHosts.includes(host);
        }

        if (platform === "facebook") {
          return facebookHosts.includes(host);
        }

        return false;
      } catch {
        return false;
      }
    },

    validId(value) {
      const id = Number(value);

      return Number.isSafeInteger(id) && id > 0
        ? id
        : null;
    },

    validDrawDate(value) {
      if (typeof value !== "string" || !value.trim()) {
        return false;
      }

      return Number.isFinite(Date.parse(value));
    },

    async getCurrentDraw(client = pool) {
      const result = await client.query(
        `SELECT id, draw_number, draw_at, updated_by, updated_at
         FROM draw_settings
         WHERE id = 1
         LIMIT 1`
      );

      return result.rows[0] || null;
    },

    isDrawBettingLocked(draw) {
      if (!draw || !draw.draw_at) return true;

      const drawTime = new Date(draw.draw_at).getTime();

      if (!Number.isFinite(drawTime)) return true;

      return drawTime - Date.now() <= DRAW_LOCK_MINUTES * 60 * 1000;
    },

    amountToCents(value) {
      if (value === "" || value === null || value === undefined) return 0;

      const number = Number(value);

      if (
        !Number.isFinite(number) ||
        number < 0 ||
        number > 100000 ||
        Math.round(number * 100) !== number * 100
      ) {
        return null;
      }

      return Math.round(number * 100);
    },

    centsToAmount(cents) {
      return (cents / 100).toFixed(2);
    }
  };

  return helpers;
}

module.exports = createHelpers;
