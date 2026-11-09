// GLO 365 - Structured Draw Results + Server Settlement
// Extracted from the uploaded server.js lines 4108-4250.
// API paths, SQL statements, settlement rules and audit behavior are retained.
//
// Register from server.js after the shared dependencies are initialized:
// registerResultsRoutes(app, {
//   pool, authenticateToken, requireAdmin, asyncRoute, sendError, audit
// });
//
// Keep the existing draw_results / demo_bets / demo_3up_bets / demo_6up_bets
// and affiliate_loss_commissions table initialization in server.js.

module.exports = function registerResultsRoutes(app, deps) {
  const {
    pool,
    authenticateToken,
    requireAdmin,
    asyncRoute,
    sendError,
    audit
  } = deps || {};

  const required = {
    pool,
    authenticateToken,
    requireAdmin,
    asyncRoute,
    sendError,
    audit
  };

  for (const [name, value] of Object.entries(required)) {
    if (!value) {
      throw new Error(`Results routes: missing dependency "${name}".`);
    }
  }

function resultMatches(game, selection, result) {
  const g = String(game || "").toLowerCase().replace(/[\s_-]/g, "");
  const n = String(selection || "").trim();
  const first = String(result.first_prize || "").padStart(6, "0");
  const last = String(result.last_two || "").padStart(2, "0");
  const fronts = Array.isArray(result.front_three) ? result.front_three : [];
  if (g.includes("single")) return /^\d$/.test(n) && n === first.slice(-1);
  if (g === "2d" || g.includes("2d")) return /^\d{1,2}$/.test(n) && n.padStart(2, "0") === last;
  if (g.includes("3up")) return /^\d{1,3}$/.test(n) && fronts.includes(n.padStart(3, "0"));
  if (g.includes("6up")) return /^\d{1,6}$/.test(n) && n.padStart(6, "0") === first;
  return false;
}

async function recordAffiliateLossCommission(client, userId, sourceTable, betId, lossPoints) {
  const points = Number(lossPoints);
  if (!Number.isFinite(points) || points <= 0) return false;

  const referral = await client.query(
    `SELECT a.id AS affiliate_id, a.commission_rate
     FROM users u
     JOIN users a ON a.id = u.referred_by
     WHERE u.id = $1 AND u.role = 'user'
       AND a.role = 'affiliate' AND a.status = 'active'
     FOR UPDATE OF a`,
    [userId]
  );
  if (!referral.rows.length) return false;

  const affiliateId = referral.rows[0].affiliate_id;
  const rate = Number(referral.rows[0].commission_rate || 0);
  if (!Number.isFinite(rate) || rate <= 0) return false;
  const commission = Math.round((points * rate / 100) * 100) / 100;
  if (commission <= 0) return false;

  await client.query(
    `INSERT INTO affiliate_loss_commissions
     (affiliate_id, referred_user_id, source_table, source_bet_id,
      loss_points, commission_rate, commission_amount)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (source_table, source_bet_id) DO NOTHING`,
    [affiliateId, userId, sourceTable, betId, points, rate, commission]
  );
  return true;
}

async function settleDrawBets(client, result) {
  let checked = 0, won = 0, lost = 0;
  const singleRows = await client.query(
    `SELECT id, user_id, game_name, selection, amount FROM demo_bets
     WHERE draw_date = $1 AND LOWER(status) NOT IN ('win','won','loss','lose','lost','cancelled','canceled')
     FOR UPDATE`, [result.draw_date]
  );
  for (const bet of singleRows.rows) {
    const isWin = resultMatches(bet.game_name, bet.selection, result);
    await client.query(`UPDATE demo_bets SET status=$1, result_id=$2 WHERE id=$3`, [isWin ? 'win' : 'loss', result.id, bet.id]);
    if (!isWin) await recordAffiliateLossCommission(client, bet.user_id, 'demo_bets', bet.id, bet.amount);
    checked++; if (isWin) won++; else lost++;
  }

  for (const [table, game] of [['demo_3up_bets','3up'], ['demo_6up_bets','6up']]) {
    const rows = await client.query(
      `SELECT id, user_id, rows, payable_amount FROM ${table}
       WHERE draw_date=$1 AND LOWER(status) NOT IN ('win','won','loss','lose','lost','cancelled','canceled')
       FOR UPDATE`, [result.draw_date]
    );
    for (const bet of rows.rows) {
      const selections = Array.isArray(bet.rows) ? bet.rows : [];
      const isWin = selections.some(row => {
        const n = String(row.number || '').trim();
        return game === '3up'
          ? /^\d{3}$/.test(n) && result.front_three.includes(n)
          : /^\d{6}$/.test(n) && n === result.first_prize;
      });
      await client.query(`UPDATE ${table} SET status=$1, result_id=$2 WHERE id=$3`, [isWin ? 'win' : 'loss', result.id, bet.id]);
      if (!isWin) await recordAffiliateLossCommission(client, bet.user_id, table, bet.id, bet.payable_amount);
      checked++; if (isWin) won++; else lost++;
    }
  }
  return { checked, won, lost };
}

app.get('/api/results', asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, TO_CHAR(draw_date, 'YYYY-MM-DD') AS date,
            first_prize AS "firstPrize", last_two AS "lastTwo",
            front_three AS "frontThree", published_at AS "publishedAt",
            updated_at AS "updatedAt"
     FROM draw_results ORDER BY draw_date DESC LIMIT 100`
  );
  res.json({ success: true, results: result.rows });
}));

app.get('/api/admin/results', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id, TO_CHAR(draw_date, 'YYYY-MM-DD') AS date,
            first_prize AS "firstPrize", last_two AS "lastTwo",
            front_three AS "frontThree", published_at AS "publishedAt",
            updated_at AS "updatedAt"
     FROM draw_results ORDER BY draw_date DESC LIMIT 100`
  );
  res.json({ success: true, results: result.rows });
}));

app.post('/api/admin/results', authenticateToken, requireAdmin, asyncRoute(async (req, res) => {
  const date = String(req.body.drawDate || req.body.date || '').trim();
  const firstRaw = String(req.body.firstPrize ?? '').trim();
  const lastRaw = String(req.body.lastTwo ?? '').trim();
  const frontRaw = req.body.frontThree;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^\d{1,6}$/.test(firstRaw) || !/^\d{1,2}$/.test(lastRaw)) {
    return sendError(res, 400, 'Enter a valid Draw Date, First Prize and Last Two.');
  }
  const fronts = Array.isArray(frontRaw)
    ? frontRaw.map(x => String(x).trim())
    : String(frontRaw || '').split(',').map(x => x.trim()).filter(Boolean);
  if (fronts.some(x => !/^\d{3}$/.test(x))) return sendError(res, 400, 'Every Front Three number must contain exactly 3 digits.');
  const uniqueFronts = [...new Set(fronts)];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const saved = await client.query(
      `INSERT INTO draw_results
       (draw_date, first_prize, last_two, front_three, published_at, updated_at, updated_by)
       VALUES ($1::date, $2, $3, $4::jsonb, NOW(), NOW(), $5)
       ON CONFLICT (draw_date) DO UPDATE SET
         first_prize=EXCLUDED.first_prize, last_two=EXCLUDED.last_two,
         front_three=EXCLUDED.front_three, updated_at=NOW(), updated_by=EXCLUDED.updated_by
       RETURNING id, TO_CHAR(draw_date, 'YYYY-MM-DD') AS date,
         first_prize AS "firstPrize", last_two AS "lastTwo", front_three AS "frontThree",
         published_at AS "publishedAt", updated_at AS "updatedAt"`,
      [date, firstRaw.padStart(6,'0'), lastRaw.padStart(2,'0'), JSON.stringify(uniqueFronts), req.user.id]
    );
    const result = saved.rows[0];
    // On re-publish, retain the original published_at timestamp.
    const settled = await settleDrawBets(client, { ...result, draw_date: date, first_prize: result.firstPrize, last_two: result.lastTwo, front_three: result.frontThree });
    await client.query('COMMIT');
    await audit(req.user.id, 'draw_result_published', null, { result_id: result.id, draw_date: date, ...settled });
    res.status(201).json({ success: true, message: 'Result published and bets settled.', result, settlement: settled });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Draw result publish error:', error.message);
    return sendError(res, 500, 'Could not publish or settle this result.');
  } finally { client.release(); }
}));
};
