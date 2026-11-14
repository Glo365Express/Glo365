"use strict";

/*
 * GLO 365 — Single PostgreSQL Database Sub-Admin Routes
 * Uses the main server's shared pool, JWT authentication and users/wallet tables.
 * All Sub-Admin dashboard URLs use /api/subadmin/... to match the frontend API_BASE_URL.
 */

module.exports = function registerSubAdminRoutes(deps) {
  const {
    app, pool, authenticateToken, requireAdmin, asyncRoute, cleanText,
    sendError, audit, bcrypt, crypto, validUsername, PRIMARY_ADMIN_USERNAME
  } = deps || {};

  const required = { app, pool, authenticateToken, requireAdmin, asyncRoute, cleanText, sendError, audit, bcrypt, crypto, validUsername };
  for (const [key, value] of Object.entries(required)) {
    if (!value) throw new Error("Sub-Admin routes: missing dependency " + key);
  }

  const validId = value => {
    const n = Number(value);
    return Number.isSafeInteger(n) && n > 0 ? n : null;
  };
  const validAmount = value => {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 && n <= 10000000 && Math.round(n * 100) === n * 100;
  };
  const reference = prefix => prefix + "-" + crypto.randomUUID();
  const newInviteCode = () => "SA" + crypto.randomBytes(12).toString("hex").toUpperCase();
  const isSubAdmin = req => req.user && req.user.role === "subadmin";

  function requireSubAdmin(req, res, next) {
    if (!isSubAdmin(req)) return sendError(res, 403, "Sub-Admin access required.");
    next();
  }
  function requireCustomer(req, res, next) {
    if (!req.user || req.user.role !== "user") return sendError(res, 403, "Customer access required.");
    next();
  }

  async function ensureInviteCode(userId) {
    // Existing Sub-Admin accounts may predate invite-code support. Create a code lazily.
    for (let attempt = 0; attempt < 4; attempt++) {
      const code = newInviteCode();
      try {
        const result = await pool.query(
          `UPDATE users SET subadmin_invite_code=$1,updated_at=NOW()
           WHERE id=$2 AND role='subadmin' AND subadmin_invite_code IS NULL
           RETURNING subadmin_invite_code`, [code, userId]
        );
        if (result.rows[0]) return result.rows[0].subadmin_invite_code;
        const current = await pool.query(
          "SELECT subadmin_invite_code FROM users WHERE id=$1 AND role='subadmin'", [userId]
        );
        if (!current.rows.length) return null;
        if (current.rows[0].subadmin_invite_code) return current.rows[0].subadmin_invite_code;
      } catch (error) {
        if (error.code !== "23505") throw error;
      }
    }
    throw new Error("Could not create a unique Sub-Admin invite code.");
  }

  async function getCustomerOwner(userId) {
    const result = await pool.query("SELECT subadmin_owner_id FROM users WHERE id=$1 AND role='user'", [userId]);
    return result.rows[0]?.subadmin_owner_id || null;
  }

  // ---------------- MAIN ADMIN: SUB-ADMIN MANAGEMENT ----------------
  app.get("/api/admin/subadmins", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const result = await pool.query(`
      SELECT s.id,s.username,s.status,s.subadmin_invite_code AS invite_code,
             s.balance,s.created_at,
             (SELECT COUNT(*)::int FROM users c WHERE c.subadmin_owner_id=s.id AND c.role='user') AS customer_count,
             COALESCE((SELECT SUM(t.amount) FROM subadmin_point_transfers t WHERE t.subadmin_id=s.id),0) AS total_allocated
      FROM users s WHERE s.role='subadmin' ORDER BY s.id DESC
    `);
    res.json({ success:true, subadmins:result.rows, bridge_ready:true });
  }));

  app.post("/api/admin/subadmins", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const username = cleanText(req.body.username, 30).toLowerCase();
    // Sub-Admin creation intentionally requires ONLY username and password.
    // The users table has email NOT NULL, so create a unique reserved .invalid
    // placeholder internally. It is not a real mailbox and is never requested
    // from or shown to the Main Admin.
    const email = "subadmin-" + crypto.randomUUID() + "@no-email.glo365.invalid";
    const password = req.body.password;
    if (!validUsername(username) || username === PRIMARY_ADMIN_USERNAME ||
        typeof password !== "string" || password.length < 10 || password.length > 128) {
      return sendError(res, 400, "Enter a valid username and a password of 10-128 characters.");
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const inviteCode = newInviteCode();
      const created = await client.query(
        `INSERT INTO users(username,email,password_hash,role,status,balance,subadmin_invite_code)
         VALUES($1,$2,$3,'subadmin','active',0,$4)
         RETURNING id,username,role,status,balance,subadmin_invite_code AS invite_code,created_at`,
        [username,email,passwordHash,inviteCode]
      );
      await client.query("INSERT INTO profiles(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING", [created.rows[0].id]);
      await client.query("COMMIT");
      await audit(req.user.id, "subadmin_created", created.rows[0].id, { username });
      res.status(201).json({ success:true, subadmin:created.rows[0] });
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") return sendError(res, 409, "Username already exists. Please choose another username.");
      throw error;
    } finally { client.release(); }
  }));

  app.patch("/api/admin/subadmins/:id/status", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const id = validId(req.params.id), status = req.body.status;
    if (!id || !["active","suspended"].includes(status)) return sendError(res, 400, "Invalid Sub-Admin or status.");
    const result = await pool.query(
      "UPDATE users SET status=$1,updated_at=NOW() WHERE id=$2 AND role='subadmin' RETURNING id,username,status",
      [status,id]
    );
    if (!result.rows.length) return sendError(res, 404, "Sub-Admin not found.");
    await audit(req.user.id, "subadmin_status_changed", id, { status });
    res.json({ success:true, subadmin:result.rows[0] });
  }));

  app.post("/api/admin/subadmins/:id/allocate", authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
    const id = validId(req.params.id), amount = Number(req.body.amount);
    if (!id || !validAmount(amount)) return sendError(res, 400, "Invalid allocation amount.");
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const admin = await client.query(
        "SELECT id,balance FROM users WHERE id=$1 AND role='admin' AND username=$2 AND status='active' FOR UPDATE",
        [req.user.id,PRIMARY_ADMIN_USERNAME]
      );
      if (!admin.rows.length) { await client.query("ROLLBACK"); return sendError(res,403,"Primary Admin access required."); }
      const sub = await client.query("SELECT id,status FROM users WHERE id=$1 AND role='subadmin' FOR UPDATE", [id]);
      if (!sub.rows.length || sub.rows[0].status !== "active") { await client.query("ROLLBACK"); return sendError(res,404,"Active Sub-Admin not found."); }
      const debit = await client.query(
        "UPDATE users SET balance=balance-$1,updated_at=NOW() WHERE id=$2 AND balance >= $1 RETURNING balance",
        [amount.toFixed(2),req.user.id]
      );
      if (!debit.rows.length) { await client.query("ROLLBACK"); return sendError(res,400,"Insufficient Main Admin balance."); }
      await client.query("UPDATE users SET balance=balance+$1,updated_at=NOW() WHERE id=$2", [amount.toFixed(2),id]);
      const ref = reference("SAALLOC");
      await client.query(
        "INSERT INTO wallet_transactions(user_id,type,amount,currency,description,reference) VALUES($1,'subadmin_allocation',$2,'DEMO',$3,$4)",
        [req.user.id,(-amount).toFixed(2),"Points allocated to Sub-Admin #"+id,ref]
      );
      await client.query(
        "INSERT INTO wallet_transactions(user_id,type,amount,currency,description,reference) VALUES($1,'subadmin_allocation_credit',$2,'DEMO',$3,$4)",
        [id,amount.toFixed(2),"Points received from Main Admin",ref]
      );
      await client.query("INSERT INTO subadmin_point_transfers(main_admin_id,subadmin_id,amount,reference) VALUES($1,$2,$3,$4)", [req.user.id,id,amount.toFixed(2),ref]);
      const balance = await client.query("SELECT balance FROM users WHERE id=$1", [id]);
      await client.query("COMMIT");
      await audit(req.user.id,"subadmin_points_allocated",id,{amount,reference:ref});
      res.json({success:true,reference:ref,amount,balance:balance.rows[0].balance,delivery_status:"completed"});
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  }));

  app.get("/api/admin/subadmin-transfers", authenticateToken, requireAdmin, asyncRoute(async (req,res) => {
    const result = await pool.query(`SELECT t.id,t.main_admin_id,t.subadmin_id,s.username AS subadmin_username,t.amount,t.reference,t.created_at
      FROM subadmin_point_transfers t JOIN users s ON s.id=t.subadmin_id ORDER BY t.id DESC LIMIT 300`);
    res.json({success:true,transfers:result.rows});
  }));

  // ---------------- SUB-ADMIN DASHBOARD ----------------
  // IMPORTANT: These paths intentionally include /api to match API_BASE_URL in the HTML.
  app.get("/api/subadmin/dashboard", authenticateToken, requireSubAdmin, asyncRoute(async (req,res) => {
    const inviteCode = await ensureInviteCode(req.user.id);
    const result = await pool.query(`
      SELECT s.id,s.username,s.balance,s.status,s.subadmin_invite_code,s.created_at,
        (SELECT COUNT(*)::int FROM users c WHERE c.subadmin_owner_id=s.id AND c.role='user') AS customer_count,
        COALESCE((SELECT SUM(t.amount) FROM subadmin_point_transfers t WHERE t.subadmin_id=s.id),0) AS total_allocated
      FROM users s WHERE s.id=$1 AND s.role='subadmin'
    `,[req.user.id]);
    if (!result.rows.length) return sendError(res,404,"Sub-Admin account not found.");
    const account = {...result.rows[0],subadmin_invite_code:inviteCode};
    res.json({success:true,account,customer_count:account.customer_count,total_allocated:account.total_allocated,dashboard:account});
  }));

  app.get("/api/subadmin/users", authenticateToken, requireSubAdmin, asyncRoute(async (req,res) => {
    const result = await pool.query(`SELECT id,username,email,balance,status,created_at FROM users
      WHERE subadmin_owner_id=$1 AND role='user' ORDER BY id DESC LIMIT 500`,[req.user.id]);
    res.json({success:true,users:result.rows});
  }));

  app.patch("/api/subadmin/users/:customerId/status", authenticateToken, requireSubAdmin, asyncRoute(async (req,res) => {
    const customerId=validId(req.params.customerId), status=req.body.status;
    if(!customerId||!["active","suspended"].includes(status)) return sendError(res,400,"Invalid customer or status.");
    const result=await pool.query(`UPDATE users SET status=$1,updated_at=NOW()
      WHERE id=$2 AND subadmin_owner_id=$3 AND role='user' RETURNING id,username,status`,[status,customerId,req.user.id]);
    if(!result.rows.length) return sendError(res,404,"Customer not found.");
    res.json({success:true,user:result.rows[0]});
  }));

  // Invite registration endpoint (the standard /api/auth/register also accepts subadmin invite codes).
  app.post("/api/subadmin/register", asyncRoute(async (req,res) => {
    const invite=cleanText(req.body.invite_code || req.body.subadmin_invite_code,40).toUpperCase();
    const username=cleanText(req.body.username,30).toLowerCase();
    const email=cleanText(req.body.email,150).toLowerCase();
    const password=req.body.password;
    if(!invite||!validUsername(username)||!email||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||typeof password!=="string"||password.length<6||password.length>128)
      return sendError(res,400,"Invalid registration details.");
    if(username===PRIMARY_ADMIN_USERNAME) return sendError(res,409,"This username is reserved.");
    const owner=await pool.query("SELECT id FROM users WHERE subadmin_invite_code=$1 AND role='subadmin' AND status='active'",[invite]);
    if(!owner.rows.length) return sendError(res,404,"Invite link is invalid or inactive.");
    const hash=await bcrypt.hash(password,12), client=await pool.connect();
    try{
      await client.query("BEGIN");
      const created=await client.query(`INSERT INTO users(username,email,password_hash,role,status,balance,subadmin_owner_id)
        VALUES($1,$2,$3,'user','active',0,$4) RETURNING id,username,email,role,status,balance,created_at`,[username,email,hash,owner.rows[0].id]);
      await client.query("INSERT INTO profiles(user_id) VALUES($1) ON CONFLICT(user_id) DO NOTHING",[created.rows[0].id]);
      await client.query("COMMIT");
      res.status(201).json({success:true,user:created.rows[0],message:"Customer registered successfully."});
    }catch(error){await client.query("ROLLBACK");if(error.code==="23505")return sendError(res,409,"Username or email already exists.");throw error;}
    finally{client.release();}
  }));

  // ---------------- SUB-ADMIN POINT DISTRIBUTION ----------------
  app.post("/api/subadmin/users/:customerId/points", authenticateToken, requireSubAdmin, asyncRoute(async (req,res) => {
    const customerId=validId(req.params.customerId),amount=Number(req.body.amount);
    if(!customerId||!validAmount(amount))return sendError(res,400,"Invalid point distribution.");
    const client=await pool.connect();
    try{
      await client.query("BEGIN");
      const owner=await client.query("SELECT id,balance,status FROM users WHERE id=$1 AND role='subadmin' FOR UPDATE",[req.user.id]);
      if(!owner.rows.length||owner.rows[0].status!=="active"){await client.query("ROLLBACK");return sendError(res,403,"Sub-Admin account is inactive.");}
      const customer=await client.query("SELECT id,status FROM users WHERE id=$1 AND subadmin_owner_id=$2 AND role='user' FOR UPDATE",[customerId,req.user.id]);
      if(!customer.rows.length||customer.rows[0].status!=="active"){await client.query("ROLLBACK");return sendError(res,404,"Active customer not found under this Sub-Admin.");}
      if(Number(owner.rows[0].balance)<amount){await client.query("ROLLBACK");return sendError(res,400,"Insufficient allocated points.");}
      const ref=reference("DIST");
      await client.query("UPDATE users SET balance=balance-$1,updated_at=NOW() WHERE id=$2",[amount.toFixed(2),req.user.id]);
      await client.query("UPDATE users SET balance=balance+$1,updated_at=NOW() WHERE id=$2",[amount.toFixed(2),customerId]);
      await client.query("INSERT INTO subadmin_customer_point_transfers(subadmin_id,customer_id,amount,reference) VALUES($1,$2,$3,$4)",[req.user.id,customerId,amount.toFixed(2),ref]);
      await client.query("INSERT INTO wallet_transactions(user_id,type,amount,currency,description,reference) VALUES($1,'subadmin_distribution',$2,'DEMO',$3,$4)",[req.user.id,(-amount).toFixed(2),"Points distributed to customer #"+customerId,ref]);
      await client.query("INSERT INTO wallet_transactions(user_id,type,amount,currency,description,reference) VALUES($1,'subadmin_point_credit',$2,'DEMO',$3,$4)",[customerId,amount.toFixed(2),"Points received from Sub-Admin",ref]);
      const balance=await client.query("SELECT balance FROM users WHERE id=$1",[req.user.id]);
      await client.query("COMMIT");
      res.json({success:true,reference:ref,distributed:amount,subadmin_balance:balance.rows[0].balance,message:"Points transferred successfully."});
    }catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}
  }));

  app.get("/api/subadmin/point-history", authenticateToken, requireSubAdmin, asyncRoute(async (req,res) => {
    const result=await pool.query(`SELECT t.id,t.customer_id,u.username AS customer_username,t.amount,t.reference,t.created_at
      FROM subadmin_customer_point_transfers t JOIN users u ON u.id=t.customer_id
      WHERE t.subadmin_id=$1 ORDER BY t.id DESC LIMIT 300`,[req.user.id]);
    res.json({success:true,transfers:result.rows});
  }));

  // ---------------- SUB-ADMIN PAYMENT METHODS ----------------
  app.get("/api/subadmin/payment-methods", authenticateToken, requireSubAdmin, asyncRoute(async(req,res)=>{
    const result=await pool.query(`SELECT id,preset,name,label,account,currency,instructions,active,created_at,updated_at
      FROM payment_methods WHERE created_by=$1 ORDER BY id DESC`,[req.user.id]);
    res.json({success:true,methods:result.rows});
  }));
  app.post("/api/subadmin/payment-methods", authenticateToken, requireSubAdmin, asyncRoute(async(req,res)=>{
    const preset=cleanText(req.body.preset||"Custom",40),name=cleanText(req.body.name,60),label=cleanText(req.body.label,60),account=cleanText(req.body.account,150),currency=cleanText(req.body.currency||"BDT",10).toUpperCase(),instructions=cleanText(req.body.instructions,1000);
    if(!name||!account||!/^[A-Z0-9]{2,10}$/.test(currency))return sendError(res,400,"Invalid payment method.");
    const result=await pool.query(`INSERT INTO payment_methods(preset,name,label,account,currency,instructions,active,created_by,updated_by)
      VALUES($1,$2,$3,$4,$5,$6,TRUE,$7,$7) RETURNING id,preset,name,label,account,currency,instructions,active,created_at,updated_at`,[preset,name,label,account,currency,instructions,req.user.id]);
    res.status(201).json({success:true,method:result.rows[0]});
  }));
  app.patch("/api/subadmin/payment-methods/:id", authenticateToken, requireSubAdmin, asyncRoute(async(req,res)=>{
    const id=validId(req.params.id);if(!id)return sendError(res,400,"Invalid payment method ID.");
    const name=req.body.name!==undefined?cleanText(req.body.name,60):null,label=req.body.label!==undefined?cleanText(req.body.label,60):null,account=req.body.account!==undefined?cleanText(req.body.account,150):null,instructions=req.body.instructions!==undefined?cleanText(req.body.instructions,1000):null,active=typeof req.body.active==="boolean"?req.body.active:null,currency=req.body.currency!==undefined?cleanText(req.body.currency,10).toUpperCase():null;
    if(currency!==null&&!/^[A-Z0-9]{2,10}$/.test(currency))return sendError(res,400,"Invalid currency.");
    const result=await pool.query(`UPDATE payment_methods SET name=COALESCE($1,name),label=COALESCE($2,label),account=COALESCE($3,account),instructions=COALESCE($4,instructions),active=COALESCE($5,active),currency=COALESCE($6,currency),updated_by=$7,updated_at=NOW()
      WHERE id=$8 AND created_by=$7 RETURNING id,name,label,account,currency,instructions,active`,[name,label,account,instructions,active,currency,req.user.id,id]);
    if(!result.rows.length)return sendError(res,404,"Payment method not found.");res.json({success:true,method:result.rows[0]});
  }));

  // ---------------- CUSTOMER DEPOSIT / WITHDRAWAL REQUESTS ----------------
  app.get("/api/subadmin/customer/payment-methods", authenticateToken, requireCustomer, asyncRoute(async(req,res)=>{
    const ownerId=await getCustomerOwner(req.user.id);if(!ownerId)return sendError(res,403,"This account is not linked to a Sub-Admin.");
    const result=await pool.query(`SELECT id,preset,name,label,account,currency,instructions FROM payment_methods WHERE created_by=$1 AND active=TRUE ORDER BY name,id`,[ownerId]);
    res.json({success:true,methods:result.rows});
  }));
  app.post("/api/subadmin/customer/deposits", authenticateToken, requireCustomer, asyncRoute(async(req,res)=>{
    const ownerId=await getCustomerOwner(req.user.id),methodId=validId(req.body.payment_method_id),amount=Number(req.body.amount),sender=cleanText(req.body.sender_account,150),tx=cleanText(req.body.transaction_id,150);
    if(!ownerId)return sendError(res,403,"This account is not linked to a Sub-Admin.");
    if(!methodId||!validAmount(amount)||!sender||!tx)return sendError(res,400,"Invalid deposit request.");
    const method=await pool.query("SELECT id,name,account,currency FROM payment_methods WHERE id=$1 AND created_by=$2 AND active=TRUE",[methodId,ownerId]);
    if(!method.rows.length)return sendError(res,400,"Payment method is unavailable.");const m=method.rows[0];
    try{const result=await pool.query(`INSERT INTO deposit_requests(user_id,payment_method_id,method,payment_account,currency,amount,sender_account,transaction_id)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,status,created_at`,[req.user.id,m.id,m.name,m.account,m.currency,amount.toFixed(2),sender,tx]);res.status(201).json({success:true,request:result.rows[0]});}
    catch(error){if(error.code==="23505")return sendError(res,409,"This transaction ID has already been submitted.");throw error;}
  }));
  app.get("/api/subadmin/customer/deposits", authenticateToken, requireCustomer, asyncRoute(async(req,res)=>{
    const result=await pool.query(`SELECT id,payment_method_id,method,payment_account,currency,amount,sender_account,transaction_id,status,credited_points,rejection_reason,created_at,reviewed_at FROM deposit_requests WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,[req.user.id]);res.json({success:true,requests:result.rows});
  }));
  app.get("/api/subadmin/deposits", authenticateToken, requireSubAdmin, asyncRoute(async(req,res)=>{
    const result=await pool.query(`SELECT d.*,u.username FROM deposit_requests d JOIN users u ON u.id=d.user_id WHERE u.subadmin_owner_id=$1 AND u.role='user' ORDER BY d.id DESC LIMIT 300`,[req.user.id]);res.json({success:true,deposits:result.rows});
  }));
  app.post("/api/subadmin/deposits/:id/review", authenticateToken, requireSubAdmin, asyncRoute(async(req,res)=>{
    const id=validId(req.params.id),decision=req.body.status,note=cleanText(req.body.admin_note,200);if(!id||!["approved","rejected"].includes(decision))return sendError(res,400,"Invalid deposit review.");
    const client=await pool.connect();try{await client.query("BEGIN");
      const found=await client.query(`SELECT d.* FROM deposit_requests d JOIN users u ON u.id=d.user_id WHERE d.id=$1 AND u.subadmin_owner_id=$2 AND u.role='user' FOR UPDATE OF d`,[id,req.user.id]);
      if(!found.rows.length){await client.query("ROLLBACK");return sendError(res,404,"Deposit not found.");}const d=found.rows[0];
      if(d.status!=="pending"){await client.query("ROLLBACK");return sendError(res,409,"Deposit already reviewed.");}
      if(decision==="approved"){
        const credited=Number(d.amount);
        await client.query("UPDATE users SET balance=balance+$1,updated_at=NOW() WHERE id=$2 AND subadmin_owner_id=$3",[credited.toFixed(2),d.user_id,req.user.id]);
        await client.query("INSERT INTO wallet_transactions(user_id,type,amount,currency,description,reference) VALUES($1,'deposit_credit',$2,'DEMO',$3,$4)",[d.user_id,credited.toFixed(2),"Deposit approved by Sub-Admin","SA-DEP-"+id]);
      }
      const updated=await client.query(`UPDATE deposit_requests SET status=$1,rejection_reason=$2,credited_points=$3,reviewed_by=$4,reviewed_at=NOW() WHERE id=$5 AND status='pending' RETURNING id,status,rejection_reason,credited_points,reviewed_at`,[decision,note,decision==="approved"?d.amount:null,req.user.id,id]);
      await client.query("COMMIT");res.json({success:true,deposit:updated.rows[0]});
    }catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}
  }));

  app.post("/api/subadmin/customer/withdrawals", authenticateToken, requireCustomer, asyncRoute(async(req,res)=>{
    const ownerId=await getCustomerOwner(req.user.id),amount=Number(req.body.amount),method=cleanText(req.body.method||req.body.payout_method,80),account=cleanText(req.body.account||req.body.payout_account,180);
    if(!ownerId)return sendError(res,403,"This account is not linked to a Sub-Admin.");if(!validAmount(amount)||!method||!account)return sendError(res,400,"Invalid withdrawal request.");
    const client=await pool.connect();try{await client.query("BEGIN");const user=await client.query("SELECT id,balance FROM users WHERE id=$1 AND subadmin_owner_id=$2 AND role='user' FOR UPDATE",[req.user.id,ownerId]);
      if(!user.rows.length){await client.query("ROLLBACK");return sendError(res,404,"Customer account not found.");}if(Number(user.rows[0].balance)<amount){await client.query("ROLLBACK");return sendError(res,400,"Insufficient points.");}
      await client.query("UPDATE users SET balance=balance-$1,updated_at=NOW() WHERE id=$2",[amount.toFixed(2),req.user.id]);
      const created=await client.query(`INSERT INTO withdrawal_requests(user_id,amount,method,account,status,points_deducted) VALUES($1,$2,$3,$4,'pending',TRUE) RETURNING id,amount,method,account,status,created_at`,[req.user.id,amount.toFixed(2),method,account]);
      await client.query("INSERT INTO wallet_transactions(user_id,type,amount,currency,description,reference) VALUES($1,'withdrawal_debit',$2,'DEMO',$3,$4)",[req.user.id,(-amount).toFixed(2),"Points reserved for withdrawal request","SA-WD-"+created.rows[0].id]);
      await client.query("COMMIT");res.status(201).json({success:true,request:created.rows[0]});
    }catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}
  }));
  app.get("/api/subadmin/customer/withdrawals", authenticateToken, requireCustomer, asyncRoute(async(req,res)=>{
    const result=await pool.query("SELECT id,amount,method,account,status,rejection_reason,created_at,reviewed_at FROM withdrawal_requests WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100",[req.user.id]);res.json({success:true,requests:result.rows});
  }));
  app.get("/api/subadmin/withdrawals", authenticateToken, requireSubAdmin, asyncRoute(async(req,res)=>{
    const result=await pool.query(`SELECT w.*,u.username FROM withdrawal_requests w JOIN users u ON u.id=w.user_id WHERE u.subadmin_owner_id=$1 AND u.role='user' ORDER BY w.id DESC LIMIT 300`,[req.user.id]);res.json({success:true,withdrawals:result.rows});
  }));
  app.post("/api/subadmin/withdrawals/:id/review", authenticateToken, requireSubAdmin, asyncRoute(async(req,res)=>{
    const id=validId(req.params.id),decision=req.body.status,reason=cleanText(req.body.admin_note||req.body.reason,200);if(!id||!["approved","rejected"].includes(decision))return sendError(res,400,"Invalid withdrawal review.");
    const client=await pool.connect();try{await client.query("BEGIN");const found=await client.query(`SELECT w.* FROM withdrawal_requests w JOIN users u ON u.id=w.user_id WHERE w.id=$1 AND u.subadmin_owner_id=$2 AND u.role='user' FOR UPDATE OF w`,[id,req.user.id]);
      if(!found.rows.length){await client.query("ROLLBACK");return sendError(res,404,"Withdrawal not found.");}const w=found.rows[0];if(w.status!=="pending"){await client.query("ROLLBACK");return sendError(res,409,"Withdrawal already reviewed.");}
      if(decision==="rejected"&&w.points_deducted===true){await client.query("UPDATE users SET balance=balance+$1,updated_at=NOW() WHERE id=$2 AND subadmin_owner_id=$3",[Number(w.amount).toFixed(2),w.user_id,req.user.id]);await client.query("INSERT INTO wallet_transactions(user_id,type,amount,currency,description,reference) VALUES($1,'withdrawal_refund',$2,'DEMO',$3,$4)",[w.user_id,Number(w.amount).toFixed(2),"Refund for rejected withdrawal","SA-WDR-"+id]);}
      const updated=await client.query("UPDATE withdrawal_requests SET status=$1,rejection_reason=$2,reviewed_by=$3,reviewed_at=NOW() WHERE id=$4 AND status='pending' RETURNING id,status,rejection_reason,reviewed_at",[decision,reason,req.user.id,id]);await client.query("COMMIT");res.json({success:true,request:updated.rows[0],message:decision==="approved"?"Withdrawal approved. Sub-Admin must complete payout separately.":"Withdrawal rejected. Reserved points have been returned."});
    }catch(error){await client.query("ROLLBACK");throw error;}finally{client.release();}
  }));

  app.get("/api/subadmin/customer-history/:customerId", authenticateToken, requireSubAdmin, asyncRoute(async(req,res)=>{
    const customerId=validId(req.params.customerId);if(!customerId)return sendError(res,400,"Invalid customer ID.");
    const customer=await pool.query("SELECT id,username,balance FROM users WHERE id=$1 AND subadmin_owner_id=$2 AND role='user'",[customerId,req.user.id]);if(!customer.rows.length)return sendError(res,404,"Customer not found.");
    const history=await pool.query("SELECT id,type,amount,currency,description,reference,created_at FROM wallet_transactions WHERE user_id=$1 ORDER BY id DESC LIMIT 200",[customerId]);res.json({success:true,customer:customer.rows[0],transactions:history.rows});
  }));

  console.log("GLO 365 Single-Database Sub-Admin routes registered.");
};
