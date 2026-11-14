"use strict";

/**
 * GLO 365 — Same-database Sub-Admin routes.
 * Mount from the existing Main Server. No second server or database.
 * Main Admin creates Sub-Admins by username/password; Sub-Admins distribute
 * only points already allocated to their own account.
 */

const crypto = require("crypto");

function registerSubAdminRoutes(deps) {
  const {
    app, pool, authenticateToken, requireAdmin, asyncRoute, cleanText,
    sendError, audit, bcrypt, validUsername, validPassword, PRIMARY_ADMIN_USERNAME, createToken, setAuthCookie
  } = deps;
  if (!app || !pool || !authenticateToken || !requireAdmin || !bcrypt) {
    throw new TypeError("Sub-Admin route dependencies are incomplete.");
  }

  const validAmount = value => {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 && n <= 10000000 && Math.round(n * 100) === n * 100;
  };
  const inviteCode = () => crypto.randomBytes(18).toString("hex");
  const makeReference = prefix => `${prefix}-${crypto.randomUUID()}`;
  const requireSubAdmin = (req, res, next) => {
    if (req.user?.role !== "subadmin") return sendError(res, 403, "Sub-Admin access required.");
    next();
  };

  // MAIN ADMIN: create Sub-Admin using username and password only.
  app.post("/api/admin/subadmins", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const username = cleanText(req.body.username, 30).toLowerCase();
    const password = req.body.password;
    if (!validUsername(username) || username === PRIMARY_ADMIN_USERNAME) {
      return sendError(res, 400, "Username must be 3-30 characters using letters, numbers or underscore.");
    }
    if (!validPassword(password)) return sendError(res, 400, "Password must be 6-16 characters.");
    const passwordHash = await bcrypt.hash(password, 12);
    const code = inviteCode();
    const email = `subadmin_${username}@accounts.glo365.local`;
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const exists = await client.query("SELECT id FROM users WHERE username=$1 OR email=$2 FOR UPDATE", [username, email]);
      if (exists.rows.length) {
        await client.query("ROLLBACK");
        return sendError(res, 409, "This username is already in use.");
      }
      const created = await client.query(
        `INSERT INTO users (username,email,password_hash,balance,role,status,subadmin_invite_code)
         VALUES ($1,$2,$3,0,'subadmin','active',$4)
         RETURNING id,username,role,status,balance,subadmin_invite_code,created_at`,
        [username,email,passwordHash,code]
      );
      await client.query("INSERT INTO profiles (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING", [created.rows[0].id]);
      await client.query("COMMIT");
      await audit(req.user.id, "subadmin_created", created.rows[0].id, { username });
      return res.status(201).json({
        success: true,
        message: "Sub-Admin account created.",
        subadmin: created.rows[0],
        invite_link: `/register.html?subadmin=${code}`
      });
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") return sendError(res, 409, "Username already exists.");
      throw error;
    } finally { client.release(); }
  }));

  // MAIN ADMIN: list only Sub-Admin accounts, never password hashes.
  app.get("/api/admin/subadmins", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT id,username,role,status,balance,subadmin_invite_code,created_at
       FROM users WHERE role='subadmin' ORDER BY created_at DESC LIMIT 500`
    );
    res.json({ success: true, subadmins: result.rows });
  }));

  // MAIN ADMIN: allocate points atomically from own wallet to one Sub-Admin.
  app.post("/api/admin/subadmins/:id/allocate", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const id = Number(req.params.id), amount = Number(req.body.amount);
    if (!Number.isSafeInteger(id) || id < 1 || !validAmount(amount)) return sendError(res, 400, "Enter a valid Sub-Admin ID and amount.");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const admin = await client.query("SELECT id,balance FROM users WHERE id=$1 AND role='admin' AND username=$2 FOR UPDATE", [req.user.id, PRIMARY_ADMIN_USERNAME]);
      if (!admin.rows.length) { await client.query("ROLLBACK"); return sendError(res, 403, "Primary Admin account required."); }
      const sub = await client.query("SELECT id,username,balance,status FROM users WHERE id=$1 AND role='subadmin' FOR UPDATE", [id]);
      if (!sub.rows.length) { await client.query("ROLLBACK"); return sendError(res, 404, "Sub-Admin not found."); }
      if (sub.rows[0].status !== "active") { await client.query("ROLLBACK"); return sendError(res, 409, "Sub-Admin account is suspended."); }
      const adminBalance = Number(admin.rows[0].balance);
      if (adminBalance < amount) { await client.query("ROLLBACK"); return sendError(res, 400, "Insufficient Main Admin balance."); }
      const reference = makeReference("SA-ALLOC");
      await client.query("UPDATE users SET balance=balance-$1,updated_at=NOW() WHERE id=$2", [amount, req.user.id]);
      await client.query("UPDATE users SET balance=balance+$1,updated_at=NOW() WHERE id=$2", [amount, id]);
      await client.query(
        `INSERT INTO wallet_transactions (user_id,type,amount,currency,description,reference)
         VALUES ($1,'subadmin_allocation_out',$2,'DEMO',$3,$4),($5,'subadmin_allocation_in',$2,'DEMO',$6,$4)`,
        [req.user.id, amount, `Points allocated to Sub-Admin ${sub.rows[0].username}`, reference, id, "Points received from Main Admin"]
      );
      await client.query(
        `INSERT INTO subadmin_point_transfers (main_admin_id,subadmin_id,amount,reference) VALUES ($1,$2,$3,$4)`,
        [req.user.id,id,amount,reference]
      );
      const balances = await client.query("SELECT id,balance FROM users WHERE id=ANY($1::bigint[])", [[req.user.id,id]]);
      await client.query("COMMIT");
      await audit(req.user.id, "subadmin_points_allocated", id, { amount, reference });
      res.json({ success: true, message: "Points allocated successfully.", reference, balances: balances.rows });
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  }));

  app.patch("/api/admin/subadmins/:id/status", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const id = Number(req.params.id), status = cleanText(req.body.status, 20).toLowerCase();
    if (!Number.isSafeInteger(id) || id < 1 || !["active","suspended"].includes(status)) return sendError(res, 400, "Invalid Sub-Admin ID or status.");
    const result = await pool.query(
      "UPDATE users SET status=$1,updated_at=NOW() WHERE id=$2 AND role='subadmin' RETURNING id,username,role,status,balance",
      [status,id]
    );
    if (!result.rows.length) return sendError(res, 404, "Sub-Admin not found.");
    await audit(req.user.id, "subadmin_status_changed", id, { status });
    res.json({ success: true, subadmin: result.rows[0] });
  }));

  app.get("/api/admin/subadmin-transfers", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT t.id,t.amount,t.reference,t.created_at,s.username AS subadmin_username,a.username AS admin_username
       FROM subadmin_point_transfers t JOIN users s ON s.id=t.subadmin_id JOIN users a ON a.id=t.main_admin_id
       ORDER BY t.created_at DESC LIMIT 500`
    );
    res.json({ success: true, transfers: result.rows });
  }));

  // PUBLIC: registration through a Sub-Admin's unique invitation.
  // New account is created with zero points and is permanently linked to that Sub-Admin.
  app.post("/api/subadmin/register", asyncRoute(async (req, res) => {
    const code = cleanText(req.body.invite_code, 40);
    const username = cleanText(req.body.username, 30).toLowerCase();
    const email = cleanText(req.body.email, 150).toLowerCase();
    const password = req.body.password;
    if (!code || !validUsername(username) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !validPassword(password)) {
      return sendError(res, 400, "Enter a valid invite code, username, email and password.");
    }
    if (username === PRIMARY_ADMIN_USERNAME) return sendError(res, 409, "This username is reserved.");
    const passwordHash = await bcrypt.hash(password, 12);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const owner = await client.query("SELECT id FROM users WHERE subadmin_invite_code=$1 AND role='subadmin' AND status='active' FOR SHARE", [code]);
      if (!owner.rows.length) { await client.query("ROLLBACK"); return sendError(res, 404, "Invitation is invalid or inactive."); }
      const created = await client.query(
        `INSERT INTO users (username,email,password_hash,balance,role,status,subadmin_owner_id)
         VALUES ($1,$2,$3,0,'user','active',$4)
         RETURNING id,username,email,role,status,balance,created_at`,
        [username,email,passwordHash,owner.rows[0].id]
      );
      await client.query("INSERT INTO profiles (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING", [created.rows[0].id]);
      const referral = `GLO${created.rows[0].id}`;
      await client.query("UPDATE users SET referral_code=$1 WHERE id=$2", [referral,created.rows[0].id]);
      await client.query("COMMIT");
      const user = { ...created.rows[0], referral_code: referral };
      const token = createToken(user);
      setAuthCookie(res, token);
      return res.status(201).json({ success: true, message: "Account created under the Sub-Admin.", token, user });
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") return sendError(res, 409, "Username or email already exists.");
      throw error;
    } finally { client.release(); }
  }));

  // SUB-ADMIN: own summary and only own customers.
  app.get("/api/subadmin/dashboard", authenticateToken, requireSubAdmin, asyncRoute(async (req, res) => {
    const [account, customers, transfers] = await Promise.all([
      pool.query("SELECT id,username,balance,status,subadmin_invite_code,created_at FROM users WHERE id=$1 AND role='subadmin'", [req.user.id]),
      pool.query("SELECT COUNT(*)::int AS total FROM users WHERE role='user' AND subadmin_owner_id=$1", [req.user.id]),
      pool.query("SELECT COALESCE(SUM(amount),0)::numeric(12,2) AS allocated FROM subadmin_point_transfers WHERE subadmin_id=$1", [req.user.id])
    ]);
    if (!account.rows.length) return sendError(res, 404, "Sub-Admin account not found.");
    res.json({ success: true, account: account.rows[0], customer_count: customers.rows[0].total, total_allocated: transfers.rows[0].allocated });
  }));

  app.get("/api/subadmin/users", authenticateToken, requireSubAdmin, asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT id,username,email,balance,status,created_at FROM users
       WHERE role='user' AND subadmin_owner_id=$1 ORDER BY created_at DESC LIMIT 500`, [req.user.id]
    );
    res.json({ success: true, users: result.rows });
  }));

  // SUB-ADMIN: transfer only their own allocated balance to their own customer.
  app.post("/api/subadmin/users/:id/points", authenticateToken, requireSubAdmin, asyncRoute(async (req, res) => {
    const customerId = Number(req.params.id), amount = Number(req.body.amount);
    if (!Number.isSafeInteger(customerId) || customerId < 1 || !validAmount(amount)) return sendError(res, 400, "Enter a valid customer ID and amount.");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const sub = await client.query("SELECT id,balance,status FROM users WHERE id=$1 AND role='subadmin' FOR UPDATE", [req.user.id]);
      if (!sub.rows.length || sub.rows[0].status !== "active") { await client.query("ROLLBACK"); return sendError(res, 403, "Sub-Admin account is unavailable."); }
      const customer = await client.query("SELECT id,username,balance FROM users WHERE id=$1 AND role='user' AND subadmin_owner_id=$2 FOR UPDATE", [customerId,req.user.id]);
      if (!customer.rows.length) { await client.query("ROLLBACK"); return sendError(res, 404, "Customer not found in your account."); }
      if (Number(sub.rows[0].balance) < amount) { await client.query("ROLLBACK"); return sendError(res, 400, "Insufficient allocated points."); }
      const reference = makeReference("SA-CREDIT");
      await client.query("UPDATE users SET balance=balance-$1,updated_at=NOW() WHERE id=$2", [amount,req.user.id]);
      await client.query("UPDATE users SET balance=balance+$1,updated_at=NOW() WHERE id=$2", [amount,customerId]);
      await client.query(
        `INSERT INTO wallet_transactions (user_id,type,amount,currency,description,reference)
         VALUES ($1,'subadmin_points_out',$2,'DEMO',$3,$4),($5,'subadmin_points_in',$2,'DEMO',$6,$4)`,
        [req.user.id,amount,`Points distributed to ${customer.rows[0].username}`,reference,customerId,"Points received from Sub-Admin"]
      );
      await client.query("INSERT INTO subadmin_customer_point_transfers (subadmin_id,customer_id,amount,reference) VALUES ($1,$2,$3,$4)", [req.user.id,customerId,amount,reference]);
      const updated = await client.query("SELECT balance FROM users WHERE id=$1", [req.user.id]);
      await client.query("COMMIT");
      await audit(req.user.id,"subadmin_customer_points_sent",customerId,{amount,reference});
      res.json({ success:true,message:"Points transferred successfully.",reference,subadmin_balance:updated.rows[0].balance });
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  }));

  app.get("/api/subadmin/point-history", authenticateToken, requireSubAdmin, asyncRoute(async (req, res) => {
    const result = await pool.query(
      `SELECT id,customer_id,amount,reference,created_at FROM subadmin_customer_point_transfers
       WHERE subadmin_id=$1 ORDER BY created_at DESC LIMIT 500`, [req.user.id]
    );
    res.json({ success:true, transfers:result.rows });
  }));
}

module.exports = registerSubAdminRoutes;
