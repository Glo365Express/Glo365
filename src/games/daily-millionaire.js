// GLO 365 - Daily Millionaire Routes
// Extracted from the uploaded live server.js without changing API paths or SQL behavior.
// This module does not create/alter tables. Existing database initialization remains in server.js.
//
// Register only after the shared dependencies are available:
// registerDailyMillionaireRoutes(app, {
//   pool, authenticateToken, requireAdmin, asyncRoute, cleanText, sendError, audit
// });

module.exports = function registerDailyMillionaireRoutes(app, deps) {
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
      throw new Error(`Daily Millionaire routes: missing dependency "${name}".`);
    }
  }

// ==========================================
// MILLIONAIRE DRAW API (Asia/Dhaka, daily at 00:15 / 12:15 AM)
// Betting closes at 00:00 and reopens at 03:15 Bangladesh time.
// Result settlement updates history only; it never credits/debits wallet.
// ==========================================

async function getMillionaireSchedule() {
  const result = await pool.query(`
    WITH clock AS (
      SELECT NOW() AS now_at,
             ((NOW() AT TIME ZONE 'Asia/Dhaka')::date + TIME '00:15:00')
               AT TIME ZONE 'Asia/Dhaka' AS today_draw_at
    )
    SELECT now_at,
           CASE WHEN now_at < today_draw_at + INTERVAL '3 hours'
                THEN today_draw_at ELSE today_draw_at + INTERVAL '1 day' END AS draw_at
    FROM clock
  `);
  const drawAt = result.rows[0].draw_at;
  const draw = await pool.query(`
    INSERT INTO millionaire_draws (draw_date,draw_number,draw_at)
    VALUES ((($1::timestamptz AT TIME ZONE 'Asia/Dhaka')::date),
            (3679 + ((($1::timestamptz AT TIME ZONE 'Asia/Dhaka')::date - DATE '2026-11-03'))::int)::text || ':' || TO_CHAR($1::timestamptz AT TIME ZONE 'Asia/Dhaka','MM:DD'), $1)
    ON CONFLICT (draw_date) DO UPDATE SET draw_at=EXCLUDED.draw_at, updated_at=NOW()
    RETURNING id,draw_date,draw_number,draw_at,result,published_at
  `,[drawAt]);
  const row = draw.rows[0];
  const status = await pool.query(`
    SELECT NOW() >= ($1::timestamptz - INTERVAL '15 minutes')
       AND NOW() < ($1::timestamptz + INTERVAL '3 hours') AS betting_locked,
           NOW() AS server_now
  `,[row.draw_at]);
  return { draw:row, betting_locked:status.rows[0].betting_locked,
    server_now:status.rows[0].server_now, timezone:'Asia/Dhaka',
    draw_time:'00:15', lock_minutes:15, reopen_after_hours:3 };
}

app.get('/api/public/daily-millionaire-settings', asyncRoute(async (req,res) => {
  const schedule = await getMillionaireSchedule();
  res.json({ success:true, ...schedule,
    drawSettings:{ drawNumber:schedule.draw.draw_number, drawAt:schedule.draw.draw_at,
      drawDate:schedule.draw.draw_date, bettingLocked:schedule.betting_locked,
      lockMinutes:15, timezone:'Asia/Dhaka' }
  });
}));

app.get('/api/public/daily-millionaire/result', asyncRoute(async (req,res) => {
  const result = await pool.query(`
    SELECT id,draw_number,TO_CHAR(draw_date,'YYYY-MM-DD') AS draw_date,
           draw_at,result,published_at,updated_at
    FROM millionaire_draws WHERE result IS NOT NULL
    ORDER BY draw_date DESC LIMIT 1
  `);
  res.json({ success:true, result:result.rows[0] || null,
    latestResult:result.rows[0] || null });
}));

app.get('/api/public/daily-millionaire/results', asyncRoute(async (req,res) => {
  const result = await pool.query(`
    SELECT id,draw_number,TO_CHAR(draw_date,'YYYY-MM-DD') AS draw_date,
           draw_at,result,published_at,updated_at
    FROM millionaire_draws WHERE result IS NOT NULL
    ORDER BY draw_date DESC LIMIT 100
  `);
  res.json({ success:true, results:result.rows });
}));

app.post('/api/demo/daily-millionaire/bets', authenticateToken, asyncRoute(async (req,res) => {
  const input = Array.isArray(req.body) ? req.body :
    (Array.isArray(req.body.rows) ? req.body.rows :
    (Array.isArray(req.body.bets) ? req.body.bets :
    (Array.isArray(req.body.selections) ? req.body.selections : [req.body])));
  const entries = input.map(item => ({
    number:String(item.number ?? item.selection ?? item.selectedNumber ?? '').trim(),
    amount:Number(item.amount ?? item.betAmount ?? item.stake)
  })).filter(item => item.number || Number.isFinite(item.amount));
  if (!entries.length || entries.length > 50 || entries.some(x => !/^\d{3}$/.test(x.number) || !Number.isFinite(x.amount) || x.amount <= 0 || x.amount > 100000 || Math.round(x.amount*100)!==x.amount*100)) {
    return sendError(res,400,'Enter 3-digit numbers (000-999) and valid amounts.');
  }
  const total = entries.reduce((sum,x)=>sum+x.amount,0);
  if (!Number.isFinite(total) || total > 1000000) return sendError(res,400,'Invalid total bet amount.');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const schedule = await getMillionaireSchedule();
    // Re-check server time inside the transaction to prevent client-side bypass.
    const lockCheck = await client.query(`
      SELECT NOW() >= ($1::timestamptz - INTERVAL '15 minutes')
         AND NOW() < ($1::timestamptz + INTERVAL '3 hours') AS locked
    `,[schedule.draw.draw_at]);
    if (lockCheck.rows[0].locked) {
      await client.query('ROLLBACK');
      return sendError(res,403,'Millionaire betting is closed. It reopens at 03:15 AM Bangladesh time.');
    }
    const drawResult = await client.query(
      'SELECT id,result FROM millionaire_draws WHERE id=$1 FOR SHARE',[schedule.draw.id]);
    if (!drawResult.rows.length || drawResult.rows[0].result) {
      await client.query('ROLLBACK');
      return sendError(res,403,'This Millionaire draw is no longer accepting entries.');
    }
    const userResult = await client.query(
      'SELECT balance,status FROM users WHERE id=$1 FOR UPDATE',[req.user.id]);
    if (!userResult.rows.length) { await client.query('ROLLBACK'); return sendError(res,404,'User not found.'); }
    if (String(userResult.rows[0].status||'active').toLowerCase()!=='active') {
      await client.query('ROLLBACK'); return sendError(res,403,'Your account is not active.');
    }
    const balance = Number(userResult.rows[0].balance||0);
    if (balance < total) { await client.query('ROLLBACK'); return sendError(res,400,'Insufficient DEMO points.'); }
    await client.query('UPDATE users SET balance=balance-$1,updated_at=NOW() WHERE id=$2',[total.toFixed(2),req.user.id]);
    const saved=[];
    for (const item of entries) {
      const bet = await client.query(`
        INSERT INTO millionaire_bets(user_id,draw_id,selection,amount,status)
        VALUES($1,$2,$3,$4,'pending') RETURNING id,selection,amount,status,created_at
      `,[req.user.id,schedule.draw.id,item.number,item.amount.toFixed(2)]);
      saved.push(bet.rows[0]);
      await client.query(`
        INSERT INTO wallet_transactions(user_id,type,amount,currency,description,reference)
        VALUES($1,'demo_bet',$2,'DEMO',$3,$4)
      `,[req.user.id,(-item.amount).toFixed(2),'Millionaire demo entry','MLBET-'+bet.rows[0].id]);
    }
    const updatedWallet = await client.query('SELECT balance FROM users WHERE id=$1',[req.user.id]);
    await client.query('COMMIT');
    res.status(201).json({ success:true,message:'Millionaire entries submitted.',
      draw:schedule.draw,bets:saved,total_amount:total,
      balance:Number(updatedWallet.rows[0].balance) });
  } catch(error) {
    await client.query('ROLLBACK');
    console.error('Millionaire bet error:',error.message);
    return sendError(res,500,'Could not submit Millionaire entries.');
  } finally { client.release(); }
}));

app.get('/api/demo/daily-millionaire/bets/me', authenticateToken, asyncRoute(async (req,res) => {
  const result = await pool.query(`
    SELECT b.id,b.selection,b.amount,b.status,b.created_at,
           d.draw_number,TO_CHAR(d.draw_date,'YYYY-MM-DD') AS draw_date,
           d.draw_at,d.result
    FROM millionaire_bets b JOIN millionaire_draws d ON d.id=b.draw_id
    WHERE b.user_id=$1 ORDER BY b.created_at DESC LIMIT 200
  `,[req.user.id]);
  res.json({ success:true,bets:result.rows });
}));

app.get('/api/admin/daily-millionaire/draws', authenticateToken, requireAdmin, asyncRoute(async (req,res) => {
  const result = await pool.query(`
    SELECT id,draw_number,TO_CHAR(draw_date,'YYYY-MM-DD') AS draw_date,
           draw_at,result,published_at,updated_at
    FROM millionaire_draws ORDER BY draw_date DESC LIMIT 200
  `);
  res.json({ success:true,draws:result.rows });
}));

app.post('/api/admin/daily-millionaire/results', authenticateToken, requireAdmin, asyncRoute(async (req,res) => {
  const resultNumber = String(req.body.result ?? req.body.number ?? '').trim();
  if (!/^\d{3}$/.test(resultNumber)) return sendError(res,400,'Result must be exactly 3 digits (000-999).');
  const dateRaw = String(req.body.draw_date ?? req.body.date ?? '').trim();
  const drawNumber = cleanText(req.body.draw_number || '',40);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let draw;
    if (dateRaw) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dateRaw)) { await client.query('ROLLBACK'); return sendError(res,400,'Invalid draw date.'); }
      const found = await client.query(`
        INSERT INTO millionaire_draws(draw_date,draw_number,draw_at)
        VALUES($1,COALESCE(NULLIF($2,''),(3679 + ($1::date - DATE '2026-11-03'))::text || ':' || TO_CHAR($1::date,'MM:DD')),
          (($1::date + TIME '00:15:00') AT TIME ZONE 'Asia/Dhaka'))
        ON CONFLICT(draw_date) DO UPDATE SET updated_at=NOW()
        RETURNING *
      `,[dateRaw,drawNumber]);
      draw=found.rows[0];
    } else {
      const schedule=await getMillionaireSchedule();
      const found=await client.query('SELECT * FROM millionaire_draws WHERE id=$1 FOR UPDATE',[schedule.draw.id]);
      draw=found.rows[0];
    }
    const saved=await client.query(`
      UPDATE millionaire_draws SET result=$1,published_at=COALESCE(published_at,NOW()),
        updated_at=NOW(),updated_by=$2 WHERE id=$3 RETURNING *
    `,[resultNumber,req.user.id,draw.id]);
    const settlement=await client.query(`
      UPDATE millionaire_bets SET status=CASE WHEN selection=$1 THEN 'win' ELSE 'loss' END
      WHERE draw_id=$2 AND status='pending' RETURNING id
    `,[resultNumber,draw.id]);
    await client.query('COMMIT');
    await audit(req.user.id,'millionaire_result_published',null,{
      draw_id:draw.id,draw_date:draw.draw_date,result:resultNumber,
      settled_bets:settlement.rowCount,wallet_credited:false
    });
    res.json({ success:true,message:'Millionaire result published. Bet history updated; wallet balances were not changed.',
      result:saved.rows[0],settled_bets:settlement.rowCount });
  } catch(error) {
    await client.query('ROLLBACK');
    console.error('Millionaire result publish error:',error.message);
    return sendError(res,500,'Could not publish Millionaire result.');
  } finally { client.release(); }
}));

app.put('/api/admin/daily-millionaire/results/:id', authenticateToken, requireAdmin, asyncRoute(async (req,res) => {
  const id=Number(req.params.id);
  const resultNumber=String(req.body.result ?? req.body.number ?? '').trim();
  if (!Number.isSafeInteger(id)||id<1||!/^\d{3}$/.test(resultNumber)) return sendError(res,400,'Valid draw ID and 3-digit result are required.');
  const client=await pool.connect();
  try {
    await client.query('BEGIN');
    const found=await client.query('SELECT * FROM millionaire_draws WHERE id=$1 FOR UPDATE',[id]);
    if (!found.rows.length) { await client.query('ROLLBACK'); return sendError(res,404,'Millionaire draw not found.'); }
    const saved=await client.query(`UPDATE millionaire_draws SET result=$1,published_at=COALESCE(published_at,NOW()),updated_at=NOW(),updated_by=$2 WHERE id=$3 RETURNING *`,[resultNumber,req.user.id,id]);
    const settlement=await client.query(`UPDATE millionaire_bets SET status=CASE WHEN selection=$1 THEN 'win' ELSE 'loss' END WHERE draw_id=$2 RETURNING id`,[resultNumber,id]);
    await client.query('COMMIT');
    await audit(req.user.id,'millionaire_result_updated',null,{draw_id:id,result:resultNumber,settled_bets:settlement.rowCount,wallet_credited:false});
    res.json({success:true,message:'Millionaire result updated. Bet history recalculated without wallet changes.',result:saved.rows[0],settled_bets:settlement.rowCount});
  } catch(error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}));
};
