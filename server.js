
'use strict';
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '32kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false'
    ? false
    : { rejectUnauthorized: false }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MANAGER_USERNAME = process.env.MANAGER_USERNAME;
const MANAGER_PASSWORD_HASH = process.env.MANAGER_PASSWORD_HASH;

function safeUser(r) {
  return {
    id: Number(r.id),
    userId: Number(r.id),
    username: r.username,
    status: r.status,
    creditScore: Number(r.credit_score),
    demoBalance: Number(r.demo_balance),
    inviteCode: r.invite_code,
    invitedBy: r.invited_by || '',
    registeredAt: r.registered_at
  };
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
}

function auth(requiredRole) {
  return (req, res, next) => {
    const raw = String(req.headers.authorization || '')
      .replace(/^Bearer\s+/i, '');

    try {
      if (!raw) throw new Error('missing token');
      const decoded = jwt.verify(raw, JWT_SECRET);

      if (requiredRole && decoded.role !== requiredRole) {
        return res.status(403).json({
          error: 'Manager access required.'
        });
      }

      req.auth = decoded;
      next();
    } catch {
      return res.status(401).json({
        error: 'Please sign in again.'
      });
    }
  };
}

async function init() {
  if (
    !process.env.DATABASE_URL ||
    !JWT_SECRET ||
    !MANAGER_USERNAME ||
    (!MANAGER_PASSWORD_HASH && !process.env.MANAGER_PASSWORD)
  ) {
    throw new Error(
      'Set DATABASE_URL, JWT_SECRET, MANAGER_USERNAME and either MANAGER_PASSWORD or MANAGER_PASSWORD_HASH in the hosting environment.'
    );
  }

  await pool.query(`
    CREATE SEQUENCE IF NOT EXISTS cryptotrade_user_id_seq
    START WITH 6000 INCREMENT BY 1 MINVALUE 6000
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ct_users (
      id BIGINT PRIMARY KEY DEFAULT nextval('cryptotrade_user_id_seq'),
      username TEXT NOT NULL,
      username_key TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Active'
        CHECK (status IN ('Active','Frozen','Inactive')),
      credit_score INTEGER NOT NULL DEFAULT 100
        CHECK (credit_score BETWEEN 0 AND 1000),
      demo_balance NUMERIC(18,2) NOT NULL DEFAULT 0,
      invite_code TEXT NOT NULL UNIQUE,
      invited_by TEXT,
      registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ct_manager_events (
      id BIGSERIAL PRIMARY KEY,
      event_type TEXT NOT NULL,
      username TEXT NOT NULL,
      user_id BIGINT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // FIX: Never set this sequence below its minimum value of 6000.
  // Existing users keep their IDs; the next new ID stays above the maximum.
  await pool.query(`
    SELECT setval(
      'cryptotrade_user_id_seq',
      GREATEST(
        6000,
        COALESCE((SELECT MAX(id) FROM ct_users), 6000)
      ),
      EXISTS (SELECT 1 FROM ct_users WHERE id >= 6000)
    )
  `);
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      ok: true,
      service: 'CryptoTrade shared backend'
    });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const inviteCode = String(req.body.inviteCode || '')
      .trim().toUpperCase();

    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
      return res.status(400).json({
        error: 'Use 3–32 letters, numbers, dots, dashes or underscores for the username.'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'Use a password with at least 8 characters.'
      });
    }

    let invitedBy = null;

    if (inviteCode) {
      const inv = await pool.query(
        'SELECT username FROM ct_users WHERE invite_code=$1',
        [inviteCode]
      );

      if (!inv.rowCount) {
        return res.status(400).json({
          error: 'Invite code was not found.'
        });
      }

      invitedBy = inv.rows[0].username;

      if (invitedBy.toLowerCase() === username.toLowerCase()) {
        return res.status(400).json({
          error: 'You cannot use your own invite code.'
        });
      }
    }

    const hash = await bcrypt.hash(password, 12);
    const usernameKey = username.toLowerCase();
    const invite = 'CT' + crypto.randomBytes(5).toString('hex').toUpperCase();

    const result = await pool.query(
      `INSERT INTO ct_users
        (username, username_key, password_hash, invite_code, invited_by)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING *`,
      [username, usernameKey, hash, invite, invitedBy]
    );

    const user = safeUser(result.rows[0]);

    await pool.query(
      `INSERT INTO ct_manager_events
        (event_type, username, user_id, details)
       VALUES ('registration',$1,$2,$3)`,
      [user.username, user.id, JSON.stringify({ invitedBy: user.invitedBy })]
    );

    res.status(201).json({
      message: 'Registration successful.',
      user
    });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({
        error: 'This username is already registered.'
      });
    }

    console.error('Register failed:', e.message);
    res.status(500).json({
      error: 'Could not complete registration. Please try again.'
    });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    const q = await pool.query(
      'SELECT * FROM ct_users WHERE username_key=$1',
      [username.toLowerCase()]
    );

    if (!q.rowCount ||
        !(await bcrypt.compare(password, q.rows[0].password_hash))) {
      return res.status(401).json({
        error: 'Account not found or password is incorrect.'
      });
    }

    const r = q.rows[0];

    if (r.status !== 'Active') {
      return res.status(403).json({
        error: r.status === 'Frozen'
          ? 'This demo account is frozen. Please contact the manager.'
          : 'This account is inactive. Please contact the manager.'
      });
    }

    const user = safeUser(r);

    res.json({
      token: signToken({
        role: 'user',
        userId: user.id,
        username: user.username
      }),
      user
    });
  } catch (e) {
    console.error('Login failed:', e.message);
    res.status(500).json({
      error: 'Login is temporarily unavailable.'
    });
  }
});

app.post('/api/manager/login', async (req, res) => {
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');

  const validPassword = MANAGER_PASSWORD_HASH
    ? await bcrypt.compare(password, MANAGER_PASSWORD_HASH)
    : (
        password.length === String(process.env.MANAGER_PASSWORD || '').length &&
        crypto.timingSafeEqual(
          Buffer.from(password),
          Buffer.from(String(process.env.MANAGER_PASSWORD || ''))
        )
      );

  if (
    username.toLowerCase() !== MANAGER_USERNAME.toLowerCase() ||
    !validPassword
  ) {
    return res.status(401).json({
      error: 'Manager username or password is incorrect.'
    });
  }

  res.json({
    token: signToken({
      role: 'manager',
      username: MANAGER_USERNAME
    }),
    manager: MANAGER_USERNAME
  });
});

app.get('/api/manager/overview', auth('manager'), async (_req, res) => {
  try {
    const [users, events] = await Promise.all([
      pool.query(
        'SELECT * FROM ct_users ORDER BY registered_at DESC, id DESC'
      ),
      pool.query(`
        SELECT e.id, e.event_type, e.username, e.user_id,
               e.details, e.created_at
        FROM ct_manager_events e
        ORDER BY e.created_at DESC
        LIMIT 100
      `)
    ]);

    res.json({
      users: users.rows.map(safeUser),
      events: events.rows.map(r => ({
        id: Number(r.id),
        type: r.event_type,
        username: r.username,
        demoId: r.user_id == null ? null : Number(r.user_id),
        time: r.created_at,
        invitedBy: r.details?.invitedBy || ''
      }))
    });
  } catch (e) {
    console.error('Manager overview failed:', e.message);
    res.status(500).json({
      error: 'Could not load manager data.'
    });
  }
});

app.patch('/api/manager/users/:id', auth('manager'), async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 6000) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  try {
    const allowed = ['status', 'creditScore', 'demoBalance', 'inviteCode'];
    const updates = [];
    const vals = [];

    if (req.body.status !== undefined) {
      if (!['Active', 'Frozen', 'Inactive'].includes(req.body.status)) {
        return res.status(400).json({ error: 'Invalid status.' });
      }
      vals.push(req.body.status);
      updates.push(`status=$${vals.length}`);
    }

    if (req.body.creditScore !== undefined) {
      const n = Number(req.body.creditScore);
      if (!Number.isInteger(n) || n < 0 || n > 1000) {
        return res.status(400).json({
          error: 'Score must be between 0 and 1000.'
        });
      }
      vals.push(n);
      updates.push(`credit_score=$${vals.length}`);
    }

    if (req.body.demoBalance !== undefined) {
      const n = Number(req.body.demoBalance);
      if (!Number.isFinite(n) || n < 0 || n > 1e12) {
        return res.status(400).json({ error: 'Invalid demo balance.' });
      }
      vals.push(n);
      updates.push(`demo_balance=$${vals.length}`);
    }

    if (req.body.inviteCode !== undefined) {
      const n = String(req.body.inviteCode).trim().toUpperCase();
      if (!/^[A-Z0-9_-]{3,32}$/.test(n)) {
        return res.status(400).json({ error: 'Invalid invite code.' });
      }
      vals.push(n);
      updates.push(`invite_code=$${vals.length}`);
    }

    if (!updates.length) {
      return res.status(400).json({
        error: 'No supported changes supplied.'
      });
    }

    vals.push(id);

    const q = await pool.query(
      `UPDATE ct_users SET ${updates.join(', ')}
       WHERE id=$${vals.length} RETURNING *`,
      vals
    );

    if (!q.rowCount) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = safeUser(q.rows[0]);

    await pool.query(
      `INSERT INTO ct_manager_events
        (event_type, username, user_id, details)
       VALUES ('manager_update',$1,$2,$3)`,
      [user.username, id, JSON.stringify(req.body)]
    );

    res.json({ user });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({
        error: 'That invite code is already in use.'
      });
    }

    console.error('Manager update failed:', e.message);
    res.status(500).json({ error: 'Could not update user.' });
  }
});

app.post('/api/manager/users/:id/notify', auth('manager'), async (req, res) => {
  const id = Number(req.params.id);
  const message = String(req.body.message || '').trim();

  if (!Number.isSafeInteger(id) || id < 6000 || !message || message.length > 1000) {
    return res.status(400).json({
      error: 'Enter a valid user ID and message.'
    });
  }

  try {
    const q = await pool.query(
      'SELECT username FROM ct_users WHERE id=$1',
      [id]
    );

    if (!q.rowCount) {
      return res.status(404).json({ error: 'User not found.' });
    }

    await pool.query(
      `INSERT INTO ct_manager_events
        (event_type, username, user_id, details)
       VALUES ('notification',$1,$2,$3)`,
      [q.rows[0].username, id, JSON.stringify({ message })]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({
      error: 'Could not save notification.'
    });
  }
});

app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`CryptoTrade backend listening on ${PORT}`);
    });
  })
  .catch(e => {
    console.error(e.message);
    process.exit(1);
  });
  
