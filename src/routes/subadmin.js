
"use strict";

/*
 * GLO 365 — Single Database Sub-Admin Routes
 *
 * Uses the existing Main Backend:
 * - Same PostgreSQL pool
 * - Same JWT authentication and cookies
 * - Same users table
 * - Same wallet_transactions table
 * - Same payment_methods, deposit_requests and withdrawal_requests
 *
 * No separate Express app, database pool or JWT secret.
 */

module.exports = function registerSubAdminRoutes(deps) {
  const {
    app,
    pool,
    authenticateToken,
    requireAdmin,
    asyncRoute,
    cleanText,
    sendError,
    audit,
    bcrypt,
    crypto,
    validUsername,
    validPassword,
    PRIMARY_ADMIN_USERNAME
  } = deps || {};

  const required = {
    app, pool, authenticateToken, requireAdmin, asyncRoute,
    cleanText, sendError, audit, bcrypt, crypto, validUsername
  };

  for (const [key, value] of Object.entries(required)) {
    if (!value) {
      throw new Error("Sub-Admin routes: missing dependency " + key);
    }
  }

  const validAmount = value => {
    const n = Number(value);
    return Number.isFinite(n) &&
      n > 0 &&
      n <= 10000000 &&
      Math.round(n * 100) === n * 100;
  };

  const validId = value => {
    const n = Number(value);
    return Number.isSafeInteger(n) && n > 0 ? n : null;
  };

  const makeReference = prefix =>
    prefix + "-" + crypto.randomUUID();

  const makeInviteCode = () =>
    "SA" + crypto.randomBytes(12).toString("hex").toUpperCase();

  function isSubAdmin(req) {
    return req.user && req.user.role === "subadmin";
  }

  function requireSubAdmin(req, res, next) {
    if (!isSubAdmin(req)) {
      return sendError(res, 403, "Sub-Admin access required.");
    }
    next();
  }

  function requireCustomer(req, res, next) {
    if (!req.user || req.user.role !== "user") {
      return sendError(res, 403, "Customer access required.");
    }
    next();
  }

  async function getOwnedCustomer(client, customerId, subadminId, lock = false) {
    const result = await client.query(
      `SELECT id,username,email,balance,status
       FROM users
       WHERE id=$1
         AND subadmin_owner_id=$2
         AND role='user'
       ${lock ? "FOR UPDATE" : ""}`,
      [customerId, subadminId]
    );
    return result.rows[0] || null;
  }

  async function getCustomerOwner(userId) {
    const result = await pool.query(
      `SELECT subadmin_owner_id
       FROM users
       WHERE id=$1 AND role='user'`,
      [userId]
    );
    return result.rows[0]?.subadmin_owner_id || null;
  }

  // =====================================================
  // MAIN ADMIN: SUB-ADMIN MANAGEMENT
  // =====================================================

  app.get(
    "/api/admin/subadmins",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(`
        SELECT
          s.id,
          s.username,
          s.email,
          s.status,
          s.subadmin_invite_code AS invite_code,
          s.balance,
          s.created_at,
          (
            SELECT COUNT(*)::int
            FROM users c
            WHERE c.subadmin_owner_id=s.id
              AND c.role='user'
          ) AS customer_count,
          COALESCE((
            SELECT SUM(t.amount)
            FROM subadmin_point_transfers t
            WHERE t.subadmin_id=s.id
          ),0) AS total_allocated
        FROM users s
        WHERE s.role='subadmin'
        ORDER BY s.id DESC
      `);

      res.json({
        success: true,
        subadmins: result.rows,
        bridge_ready: true
      });
    })
  );

  app.post(
    "/api/admin/subadmins",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const username = cleanText(req.body.username, 30).toLowerCase();
      const email = cleanText(req.body.email, 150).toLowerCase();
      const password = req.body.password;

      if (
        !validUsername(username) ||
        username === PRIMARY_ADMIN_USERNAME ||
        (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) ||
        typeof password !== "string" ||
        password.length < 10 ||
        password.length > 128
      ) {
        return sendError(res, 400, "Invalid Sub-Admin details. Password must be 10-128 characters.");
      }

      const passwordHash = await bcrypt.hash(password, 12);
      const inviteCode = makeInviteCode();

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const existing = await client.query(
          `SELECT id FROM users
           WHERE LOWER(username)=LOWER($1)
              OR ($2 <> '' AND LOWER(email)=LOWER($2))
           LIMIT 1`,
          [username, email]
        );

        if (existing.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 409, "Username or email already exists.");
        }

        const created = await client.query(
          `INSERT INTO users
            (username,email,password_hash,role,status,balance,subadmin_invite_code)
           VALUES ($1,$2,$3,'subadmin','active',0,$4)
           RETURNING id,username,email,role,status,balance,
                     subadmin_invite_code AS invite_code,created_at`,
          [username, email, passwordHash, inviteCode]
        );

        await client.query(
          `INSERT INTO profiles(user_id)
           VALUES($1)
           ON CONFLICT(user_id) DO NOTHING`,
          [created.rows[0].id]
        );

        await client.query("COMMIT");

        await audit(req.user.id, "subadmin_created", created.rows[0].id, {
          username
        });

        res.status(201).json({
          success: true,
          subadmin: created.rows[0]
        });
      } catch (error) {
        await client.query("ROLLBACK");
        if (error.code === "23505") {
          return sendError(res, 409, "Username or email already exists.");
        }
        throw error;
      } finally {
        client.release();
      }
    })
  );

  app.patch(
    "/api/admin/subadmins/:id/status",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = validId(req.params.id);
      const status = req.body.status;

      if (!id || !["active", "suspended"].includes(status)) {
        return sendError(res, 400, "Invalid Sub-Admin or status.");
      }

      const result = await pool.query(
        `UPDATE users
         SET status=$1,updated_at=NOW()
         WHERE id=$2 AND role='subadmin'
         RETURNING id,username,status`,
        [status, id]
      );

      if (!result.rows.length) {
        return sendError(res, 404, "Sub-Admin not found.");
      }

      await audit(req.user.id, "subadmin_status_changed", id, {
        status
      });

      res.json({
        success: true,
        subadmin: result.rows[0]
      });
    })
  );

  app.post(
    "/api/admin/subadmins/:id/allocate",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const id = validId(req.params.id);
      const amount = Number(req.body.amount);

      if (!id || !validAmount(amount)) {
        return sendError(res, 400, "Invalid allocation amount.");
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const admin = await client.query(
          `SELECT id,balance
           FROM users
           WHERE id=$1
             AND role='admin'
             AND username=$2
             AND status='active'
           FOR UPDATE`,
          [req.user.id, PRIMARY_ADMIN_USERNAME]
        );

        if (!admin.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 403, "Primary Admin access required.");
        }

        const sub = await client.query(
          `SELECT id,balance,status
           FROM users
           WHERE id=$1 AND role='subadmin'
           FOR UPDATE`,
          [id]
        );

        if (!sub.rows.length || sub.rows[0].status !== "active") {
          await client.query("ROLLBACK");
          return sendError(res, 404, "Active Sub-Admin not found.");
        }

        const debited = await client.query(
          `UPDATE users
           SET balance=balance-$1,updated_at=NOW()
           WHERE id=$2 AND balance >= $1
           RETURNING balance`,
          [amount.toFixed(2), req.user.id]
        );

        if (!debited.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 400, "Insufficient Main Admin balance.");
        }

        await client.query(
          `UPDATE users
           SET balance=balance+$1,updated_at=NOW()
           WHERE id=$2`,
          [amount.toFixed(2), id]
        );

        const reference = makeReference("SAALLOC");

        await client.query(
          `INSERT INTO wallet_transactions
            (user_id,type,amount,currency,description,reference)
           VALUES ($1,'subadmin_allocation',$2,'DEMO',$3,$4)`,
          [
            req.user.id,
            (-amount).toFixed(2),
            "Points allocated to Sub-Admin #" + id,
            reference
          ]
        );

        await client.query(
          `INSERT INTO wallet_transactions
            (user_id,type,amount,currency,description,reference)
           VALUES ($1,'subadmin_allocation_credit',$2,'DEMO',$3,$4)`,
          [
            id,
            amount.toFixed(2),
            "Points received from Main Admin",
            reference
          ]
        );

        await client.query(
          `INSERT INTO subadmin_point_transfers
            (main_admin_id,subadmin_id,amount,reference)
           VALUES ($1,$2,$3,$4)`,
          [req.user.id, id, amount.toFixed(2), reference]
        );

        const balance = await client.query(
          "SELECT balance FROM users WHERE id=$1",
          [id]
        );

        await client.query("COMMIT");

        await audit(req.user.id, "subadmin_points_allocated", id, {
          amount,
          reference
        });

        res.json({
          success: true,
          reference,
          amount,
          balance: balance.rows[0].balance,
          delivery_status: "completed"
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    })
  );

  app.get(
    "/api/admin/subadmin-transfers",
    authenticateToken,
    requireAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(`
        SELECT t.id,t.main_admin_id,t.subadmin_id,
               s.username AS subadmin_username,
               t.amount,t.reference,t.created_at
        FROM subadmin_point_transfers t
        JOIN users s ON s.id=t.subadmin_id
        ORDER BY t.id DESC
        LIMIT 300
      `);

      res.json({
        success: true,
        transfers: result.rows
      });
    })
  );

  // =====================================================
  // SUB-ADMIN DASHBOARD
  // =====================================================

  app.get(
    "/subadmin/dashboard",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(`
        SELECT
          s.id,
          s.username,
          s.email,
          s.balance,
          s.status,
          s.subadmin_invite_code,
          s.created_at,
          (
            SELECT COUNT(*)::int
            FROM users c
            WHERE c.subadmin_owner_id=s.id
              AND c.role='user'
          ) AS customer_count,
          COALESCE((
            SELECT SUM(t.amount)
            FROM subadmin_point_transfers t
            WHERE t.subadmin_id=s.id
          ),0) AS total_allocated
        FROM users s
        WHERE s.id=$1 AND s.role='subadmin'
      `, [req.user.id]);

      if (!result.rows.length) {
        return sendError(res, 404, "Sub-Admin account not found.");
      }

      const account = result.rows[0];

      res.json({
        success: true,
        account,
        customer_count: account.customer_count,
        total_allocated: account.total_allocated,
        dashboard: account
      });
    })
  );

  app.get(
    "/subadmin/users",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id,username,email,balance,status,created_at
         FROM users
         WHERE subadmin_owner_id=$1 AND role='user'
         ORDER BY id DESC
         LIMIT 500`,
        [req.user.id]
      );

      res.json({
        success: true,
        users: result.rows
      });
    })
  );

  app.patch(
    "/subadmin/users/:customerId/status",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const customerId = validId(req.params.customerId);
      const status = req.body.status;

      if (!customerId || !["active", "suspended"].includes(status)) {
        return sendError(res, 400, "Invalid customer or status.");
      }

      const result = await pool.query(
        `UPDATE users
         SET status=$1,updated_at=NOW()
         WHERE id=$2
           AND subadmin_owner_id=$3
           AND role='user'
         RETURNING id,username,status`,
        [status, customerId, req.user.id]
      );

      if (!result.rows.length) {
        return sendError(res, 404, "Customer not found.");
      }

      res.json({
        success: true,
        user: result.rows[0]
      });
    })
  );

  // =====================================================
  // CUSTOMER REGISTRATION THROUGH INVITE LINK
  // =====================================================

  app.post(
    "/api/subadmin/register",
    asyncRoute(async (req, res) => {
      const invite = cleanText(req.body.invite_code, 40).toUpperCase();
      const username = cleanText(req.body.username, 30).toLowerCase();
      const email = cleanText(req.body.email, 150).toLowerCase();
      const password = req.body.password;

      if (
        !invite ||
        !validUsername(username) ||
        !email ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
        typeof password !== "string" ||
        password.length < 6 ||
        password.length > 128
      ) {
        return sendError(res, 400, "Invalid registration details.");
      }

      if (username === PRIMARY_ADMIN_USERNAME) {
        return sendError(res, 409, "This username is reserved.");
      }

      const owner = await pool.query(
        `SELECT id
         FROM users
         WHERE subadmin_invite_code=$1
           AND role='subadmin'
           AND status='active'`,
        [invite]
      );

      if (!owner.rows.length) {
        return sendError(res, 404, "Invite link is invalid or inactive.");
      }

      const passwordHash = await bcrypt.hash(password, 12);
      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const created = await client.query(
          `INSERT INTO users
            (username,email,password_hash,role,status,balance,subadmin_owner_id)
           VALUES ($1,$2,$3,'user','active',0,$4)
           RETURNING id,username,email,role,status,balance,created_at`,
          [username, email, passwordHash, owner.rows[0].id]
        );

        await client.query(
          `INSERT INTO profiles(user_id)
           VALUES($1)
           ON CONFLICT(user_id) DO NOTHING`,
          [created.rows[0].id]
        );

        await client.query("COMMIT");

        res.status(201).json({
          success: true,
          user: created.rows[0],
          message: "Customer registered successfully."
        });
      } catch (error) {
        await client.query("ROLLBACK");

        if (error.code === "23505") {
          return sendError(res, 409, "Username or email already exists.");
        }

        throw error;
      } finally {
        client.release();
      }
    })
  );

  // =====================================================
  // SUB-ADMIN POINT DISTRIBUTION
  // =====================================================

  app.post(
    "/subadmin/users/:customerId/points",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const customerId = validId(req.params.customerId);
      const amount = Number(req.body.amount);

      if (!customerId || !validAmount(amount)) {
        return sendError(res, 400, "Invalid point distribution.");
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const owner = await client.query(
          `SELECT id,balance,status
           FROM users
           WHERE id=$1 AND role='subadmin'
           FOR UPDATE`,
          [req.user.id]
        );

        if (!owner.rows.length || owner.rows[0].status !== "active") {
          await client.query("ROLLBACK");
          return sendError(res, 403, "Sub-Admin account is inactive.");
        }

        const customer = await getOwnedCustomer(
          client,
          customerId,
          req.user.id,
          true
        );

        if (!customer || customer.status !== "active") {
          await client.query("ROLLBACK");
          return sendError(res, 404, "Active customer not found under this Sub-Admin.");
        }

        if (Number(owner.rows[0].balance) < amount) {
          await client.query("ROLLBACK");
          return sendError(res, 400, "Insufficient allocated points.");
        }

        const reference = makeReference("DIST");

        await client.query(
          `UPDATE users
           SET balance=balance-$1,updated_at=NOW()
           WHERE id=$2`,
          [amount.toFixed(2), req.user.id]
        );

        await client.query(
          `UPDATE users
           SET balance=balance+$1,updated_at=NOW()
           WHERE id=$2`,
          [amount.toFixed(2), customerId]
        );

        await client.query(
          `INSERT INTO subadmin_customer_point_transfers
            (subadmin_id,customer_id,amount,reference)
           VALUES ($1,$2,$3,$4)`,
          [req.user.id, customerId, amount.toFixed(2), reference]
        );

        await client.query(
          `INSERT INTO wallet_transactions
            (user_id,type,amount,currency,description,reference)
           VALUES ($1,'subadmin_distribution',$2,'DEMO',$3,$4)`,
          [
            req.user.id,
            (-amount).toFixed(2),
            "Points distributed to customer #" + customerId,
            reference
          ]
        );

        await client.query(
          `INSERT INTO wallet_transactions
            (user_id,type,amount,currency,description,reference)
           VALUES ($1,'subadmin_point_credit',$2,'DEMO',$3,$4)`,
          [
            customerId,
            amount.toFixed(2),
            "Points received from Sub-Admin",
            reference
          ]
        );

        const balance = await client.query(
          "SELECT balance FROM users WHERE id=$1",
          [req.user.id]
        );

        await client.query("COMMIT");

        res.json({
          success: true,
          reference,
          distributed: amount,
          subadmin_balance: balance.rows[0].balance
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    })
  );

  app.get(
    "/subadmin/point-history",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT
           t.id,
           t.customer_id,
           u.username AS customer_username,
           t.amount,
           t.reference,
           t.created_at
         FROM subadmin_customer_point_transfers t
         JOIN users u ON u.id=t.customer_id
         WHERE t.subadmin_id=$1
         ORDER BY t.id DESC
         LIMIT 300`,
        [req.user.id]
      );

      res.json({
        success: true,
        transfers: result.rows
      });
    })
  );

  // =====================================================
  // SUB-ADMIN PAYMENT METHODS
  // Only methods created by this Sub-Admin are manageable.
  // =====================================================

  app.get(
    "/subadmin/payment-methods",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id,preset,name,label,account,currency,instructions,
                active,created_at,updated_at
         FROM payment_methods
         WHERE created_by=$1
         ORDER BY id DESC`,
        [req.user.id]
      );

      res.json({
        success: true,
        methods: result.rows
      });
    })
  );

  app.post(
    "/subadmin/payment-methods",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const preset = cleanText(req.body.preset || "Custom", 40);
      const name = cleanText(req.body.name, 60);
      const label = cleanText(req.body.label, 60);
      const account = cleanText(req.body.account, 150);
      const currency = cleanText(req.body.currency || "BDT", 10).toUpperCase();
      const instructions = cleanText(req.body.instructions, 1000);

      if (!name || !account || !/^[A-Z0-9]{2,10}$/.test(currency)) {
        return sendError(res, 400, "Invalid payment method.");
      }

      const result = await pool.query(
        `INSERT INTO payment_methods
          (preset,name,label,account,currency,instructions,active,created_by,updated_by)
         VALUES ($1,$2,$3,$4,$5,$6,TRUE,$7,$7)
         RETURNING *`,
        [preset,name,label,account,currency,instructions,req.user.id]
      );

      res.status(201).json({
        success: true,
        method: result.rows[0]
      });
    })
  );

  app.patch(
    "/subadmin/payment-methods/:id",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const id = validId(req.params.id);

      if (!id) return sendError(res, 400, "Invalid payment method ID.");

      const name = req.body.name !== undefined
        ? cleanText(req.body.name, 60) : null;
      const label = req.body.label !== undefined
        ? cleanText(req.body.label, 60) : null;
      const account = req.body.account !== undefined
        ? cleanText(req.body.account, 150) : null;
      const instructions = req.body.instructions !== undefined
        ? cleanText(req.body.instructions, 1000) : null;
      const active = typeof req.body.active === "boolean"
        ? req.body.active : null;
      const currency = req.body.currency !== undefined
        ? cleanText(req.body.currency, 10).toUpperCase() : null;

      if (currency !== null && !/^[A-Z0-9]{2,10}$/.test(currency)) {
        return sendError(res, 400, "Invalid currency.");
      }

      const result = await pool.query(
        `UPDATE payment_methods SET
          name=COALESCE($1,name),
          label=COALESCE($2,label),
          account=COALESCE($3,account),
          instructions=COALESCE($4,instructions),
          active=COALESCE($5,active),
          currency=COALESCE($6,currency),
          updated_by=$7,
          updated_at=NOW()
         WHERE id=$8 AND created_by=$7
         RETURNING id,name,label,account,currency,instructions,active`,
        [name,label,account,instructions,active,currency,req.user.id,id]
      );

      if (!result.rows.length) {
        return sendError(res, 404, "Payment method not found.");
      }

      res.json({
        success: true,
        method: result.rows[0]
      });
    })
  );

  // =====================================================
  // CUSTOMER DEPOSITS
  // Uses the existing deposit_requests table.
  // =====================================================

  app.post(
    "/api/subadmin/customer/deposits",
    authenticateToken,
    requireCustomer,
    asyncRoute(async (req, res) => {
      const ownerId = await getCustomerOwner(req.user.id);

      if (!ownerId) {
        return sendError(res, 403, "This account is not linked to a Sub-Admin.");
      }

      const methodId = validId(req.body.payment_method_id);
      const amount = Number(req.body.amount);
      const sender = cleanText(req.body.sender_account, 150);
      const transactionId = cleanText(req.body.transaction_id, 150);

      if (!methodId || !validAmount(amount) || !sender || !transactionId) {
        return sendError(res, 400, "Invalid deposit request.");
      }

      const method = await pool.query(
        `SELECT id,name,account,currency
         FROM payment_methods
         WHERE id=$1 AND created_by=$2 AND active=TRUE`,
        [methodId, ownerId]
      );

      if (!method.rows.length) {
        return sendError(res, 400, "Payment method is unavailable.");
      }

      const m = method.rows[0];

      try {
        const result = await pool.query(
          `INSERT INTO deposit_requests
            (user_id,payment_method_id,method,payment_account,currency,
             amount,sender_account,transaction_id)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
           RETURNING id,status,created_at`,
          [
            req.user.id,
            m.id,
            m.name,
            m.account,
            m.currency,
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
          return sendError(res, 409, "This transaction ID has already been submitted.");
        }
        throw error;
      }
    })
  );

  app.get(
    "/api/subadmin/customer/deposits",
    authenticateToken,
    requireCustomer,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id,payment_method_id,method,payment_account,currency,
                amount,sender_account,transaction_id,status,
                credited_points,rejection_reason,created_at,reviewed_at
         FROM deposit_requests
         WHERE user_id=$1
         ORDER BY created_at DESC LIMIT 100`,
        [req.user.id]
      );

      res.json({
        success: true,
        requests: result.rows
      });
    })
  );

  app.get(
    "/api/subadmin/customer/payment-methods",
    authenticateToken,
    requireCustomer,
    asyncRoute(async (req, res) => {
      const ownerId = await getCustomerOwner(req.user.id);

      if (!ownerId) {
        return sendError(res, 403, "This account is not linked to a Sub-Admin.");
      }

      const result = await pool.query(
        `SELECT id,preset,name,label,account,currency,instructions
         FROM payment_methods
         WHERE created_by=$1 AND active=TRUE
         ORDER BY name,id`,
        [ownerId]
      );

      res.json({
        success: true,
        methods: result.rows
      });
    })
  );

  app.get(
    "/subadmin/deposits",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT d.*,u.username
         FROM deposit_requests d
         JOIN users u ON u.id=d.user_id
         WHERE u.subadmin_owner_id=$1
           AND u.role='user'
         ORDER BY d.id DESC
         LIMIT 300`,
        [req.user.id]
      );

      res.json({
        success: true,
        deposits: result.rows
      });
    })
  );

  app.post(
    "/subadmin/deposits/:id/review",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const id = validId(req.params.id);
      const decision = req.body.status;
      const note = cleanText(req.body.admin_note, 200);

      if (!id || !["approved", "rejected"].includes(decision)) {
        return sendError(res, 400, "Invalid deposit review.");
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const found = await client.query(
          `SELECT d.*
           FROM deposit_requests d
           JOIN users u ON u.id=d.user_id
           WHERE d.id=$1
             AND u.subadmin_owner_id=$2
             AND u.role='user'
           FOR UPDATE OF d`,
          [id, req.user.id]
        );

        if (!found.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 404, "Deposit not found.");
        }

        const deposit = found.rows[0];

        if (deposit.status !== "pending") {
          await client.query("ROLLBACK");
          return sendError(res, 409, "Deposit already reviewed.");
        }

        if (decision === "approved") {
          const credited = Number(deposit.amount);

          await client.query(
            `UPDATE users
             SET balance=balance+$1,updated_at=NOW()
             WHERE id=$2 AND subadmin_owner_id=$3`,
            [credited.toFixed(2), deposit.user_id, req.user.id]
          );

          await client.query(
            `INSERT INTO wallet_transactions
              (user_id,type,amount,currency,description,reference)
             VALUES ($1,'deposit_credit',$2,'DEMO',$3,$4)`,
            [
              deposit.user_id,
              credited.toFixed(2),
              "Deposit approved by Sub-Admin",
              "SA-DEP-" + id
            ]
          );
        }

        const updated = await client.query(
          `UPDATE deposit_requests
           SET status=$1,rejection_reason=$2,reviewed_by=$3,reviewed_at=NOW()
           WHERE id=$4 AND status='pending'
           RETURNING id,status,rejection_reason,reviewed_at`,
          [decision, note, req.user.id, id]
        );

        await client.query("COMMIT");

        res.json({
          success: true,
          deposit: updated.rows[0]
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    })
  );

  // =====================================================
  // CUSTOMER WITHDRAWALS
  // =====================================================

  app.post(
    "/api/subadmin/customer/withdrawals",
    authenticateToken,
    requireCustomer,
    asyncRoute(async (req, res) => {
      const ownerId = await getCustomerOwner(req.user.id);
      const amount = Number(req.body.amount);
      const method = cleanText(req.body.method || req.body.payout_method, 80);
      const account = cleanText(req.body.account || req.body.payout_account, 180);

      if (!ownerId) {
        return sendError(res, 403, "This account is not linked to a Sub-Admin.");
      }

      if (!validAmount(amount) || !method || !account) {
        return sendError(res, 400, "Invalid withdrawal request.");
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const user = await client.query(
          `SELECT id,balance
           FROM users
           WHERE id=$1 AND subadmin_owner_id=$2 AND role='user'
           FOR UPDATE`,
          [req.user.id, ownerId]
        );

        if (!user.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 404, "Customer account not found.");
        }

        if (Number(user.rows[0].balance) < amount) {
          await client.query("ROLLBACK");
          return sendError(res, 400, "Insufficient points.");
        }

        await client.query(
          `UPDATE users
           SET balance=balance-$1,updated_at=NOW()
           WHERE id=$2`,
          [amount.toFixed(2), req.user.id]
        );

        const created = await client.query(
          `INSERT INTO withdrawal_requests
            (user_id,amount,method,account,status,points_deducted)
           VALUES ($1,$2,$3,$4,'pending',TRUE)
           RETURNING id,amount,method,account,status,created_at`,
          [req.user.id, amount.toFixed(2), method, account]
        );

        await client.query(
          `INSERT INTO wallet_transactions
            (user_id,type,amount,currency,description,reference)
           VALUES ($1,'withdrawal_debit',$2,'DEMO',$3,$4)`,
          [
            req.user.id,
            (-amount).toFixed(2),
            "Points reserved for withdrawal request",
            "SA-WD-" + created.rows[0].id
          ]
        );

        await client.query("COMMIT");

        res.status(201).json({
          success: true,
          request: created.rows[0]
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    })
  );

  app.get(
    "/api/subadmin/customer/withdrawals",
    authenticateToken,
    requireCustomer,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT id,amount,method,account,status,rejection_reason,
                created_at,reviewed_at
         FROM withdrawal_requests
         WHERE user_id=$1
         ORDER BY created_at DESC LIMIT 100`,
        [req.user.id]
      );

      res.json({
        success: true,
        requests: result.rows
      });
    })
  );

  app.get(
    "/subadmin/withdrawals",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const result = await pool.query(
        `SELECT w.*,u.username
         FROM withdrawal_requests w
         JOIN users u ON u.id=w.user_id
         WHERE u.subadmin_owner_id=$1
           AND u.role='user'
         ORDER BY w.id DESC
         LIMIT 300`,
        [req.user.id]
      );

      res.json({
        success: true,
        withdrawals: result.rows
      });
    })
  );

  app.post(
    "/subadmin/withdrawals/:id/review",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const id = validId(req.params.id);
      const decision = req.body.status;
      const reason = cleanText(req.body.admin_note || req.body.reason, 200);

      if (!id || !["approved", "rejected"].includes(decision)) {
        return sendError(res, 400, "Invalid withdrawal review.");
      }

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        const found = await client.query(
          `SELECT w.*
           FROM withdrawal_requests w
           JOIN users u ON u.id=w.user_id
           WHERE w.id=$1
             AND u.subadmin_owner_id=$2
             AND u.role='user'
           FOR UPDATE OF w`,
          [id, req.user.id]
        );

        if (!found.rows.length) {
          await client.query("ROLLBACK");
          return sendError(res, 404, "Withdrawal not found.");
        }

        const withdrawal = found.rows[0];

        if (withdrawal.status !== "pending") {
          await client.query("ROLLBACK");
          return sendError(res, 409, "Withdrawal already reviewed.");
        }

        if (decision === "rejected" && withdrawal.points_deducted === true) {
          const amount = Number(withdrawal.amount);

          await client.query(
            `UPDATE users
             SET balance=balance+$1,updated_at=NOW()
             WHERE id=$2 AND subadmin_owner_id=$3`,
            [amount.toFixed(2), withdrawal.user_id, req.user.id]
          );

          await client.query(
            `INSERT INTO wallet_transactions
              (user_id,type,amount,currency,description,reference)
             VALUES ($1,'withdrawal_refund',$2,'DEMO',$3,$4)`,
            [
              withdrawal.user_id,
              amount.toFixed(2),
              "Refund for rejected withdrawal",
              "SA-WDR-" + id
            ]
          );
        }

        const updated = await client.query(
          `UPDATE withdrawal_requests
           SET status=$1,rejection_reason=$2,
               reviewed_by=$3,reviewed_at=NOW()
           WHERE id=$4 AND status='pending'
           RETURNING id,status,rejection_reason,reviewed_at`,
          [decision, reason, req.user.id, id]
        );

        await client.query("COMMIT");

        res.json({
          success: true,
          request: updated.rows[0],
          message: decision === "approved"
            ? "Withdrawal approved. Sub-Admin must complete payout separately."
            : "Withdrawal rejected. Reserved points have been returned."
        });
      } catch (error) {
        await client.query("ROLLBACK");
        throw error;
      } finally {
        client.release();
      }
    })
  );

  // =====================================================
  // SUB-ADMIN CUSTOMER TRANSACTION HISTORY
  // =====================================================

  app.get(
    "/subadmin/customer-history/:customerId",
    authenticateToken,
    requireSubAdmin,
    asyncRoute(async (req, res) => {
      const customerId = validId(req.params.customerId);

      if (!customerId) {
        return sendError(res, 400, "Invalid customer ID.");
      }

      const customer = await pool.query(
        `SELECT id,username,balance
         FROM users
         WHERE id=$1
           AND subadmin_owner_id=$2
           AND role='user'`,
        [customerId, req.user.id]
      );

      if (!customer.rows.length) {
        return sendError(res, 404, "Customer not found.");
      }

      const history = await pool.query(
        `SELECT id,type,amount,currency,description,reference,created_at
         FROM wallet_transactions
         WHERE user_id=$1
         ORDER BY id DESC
         LIMIT 200`,
        [customerId]
      );

      res.json({
        success: true,
        customer: customer.rows[0],
        transactions: history.rows
      });
    })
  );

  console.log("GLO 365 Single-Database Sub-Admin routes registered.");
};
