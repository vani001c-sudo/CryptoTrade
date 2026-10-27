
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

// CORS: allow only configured website origins.
const allowedOrigins = String(process.env.ADMIN_ORIGIN || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader(
      'Access-Control-Allow-Headers',
      'Content-Type, Authorization'
    );
    res.setHeader(
      'Access-Control-Allow-Methods',
      'GET, POST, PATCH, OPTIONS'
    );
  }

  if (req.method === 'OPTIONS') {
    return res.sendStatus(
      !origin || allowedOrigins.includes(origin) ? 204 : 403
    );
  }

  next();
});

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

function safeUser(row) {
  return {
    id: Number(row.id),
    userId: Number(row.id),
    username: row.username,
    status: row.status,
    creditScore: Number(row.credit_score),
    demoBalance: Number(row.demo_balance),
    inviteCode: row.invite_code,
    invitedBy: row.invited_by || '',
    registeredAt: row.registered_at
  };
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
}

function auth(requiredRole) {
  return (req, res, next) => {
    const token = String(req.headers.authorization || '')
      .replace(/^Bearer\s+/i, '');

    try {
      if (!token) throw new Error('Missing token');

      const decoded = jwt.verify(token, JWT_SECRET);

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
      'Set DATABASE_URL, JWT_SECRET, MANAGER_USERNAME and either ' +
      'MANAGER_PASSWORD or MANAGER_PASSWORD_HASH in Render Environment.'
    );
  }

  // Keep the existing user-ID sequence starting at 6000.
  await pool.query(`
    CREATE SEQUENCE IF NOT EXISTS cryptotrade_user_id_seq
    START WITH 6000 INCREMENT BY 1 MINVALUE 6000
  `);

  // Create the table only if it does not already exist.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ct_users (
      id BIGINT PRIMARY KEY
        DEFAULT nextval('cryptotrade_user_id_seq'),
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

  // Prevent new IDs from colliding with existing users.
  const maxId = await pool.query(
    'SELECT MAX(id) AS max_id FROM ct_users'
  );

  const highestId = Math.max(
    5999,
    Number(maxId.rows[0].max_id || 5999)
  );

  await pool.query(
    "SELECT setval('cryptotrade_user_id_seq', $1, true)",
    [highestId]
  );
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'CryptoTrade shared backend' });
  } catch (error) {
    console.error('Health check failed:', error.message);
    res.status(503).json({ ok: false });
  }
});

// USER REGISTRATION
app.post('/api/register', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const inviteCode = String(req.body.inviteCode || '')
      .trim()
      .toUpperCase();

    if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
      return res.status(400).json({
        error: 'Username must contain 3–32 letters, numbers, dots, dashes or underscores.'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'Password must contain at least 8 characters.'
      });
    }

    let invitedBy = null;

    if (inviteCode) {
      const inviteResult = await pool.query(
        'SELECT username FROM ct_users WHERE invite_code = $1',
        [inviteCode]
      );

      if (!inviteResult.rowCount) {
        return res.status(400).json({
          error: 'Invite code was not found.'
        });
      }

      invitedBy = inviteResult.rows[0].username;

      if (invitedBy.toLowerCase() === username.toLowerCase()) {
        return res.status(400).json({
          error: 'You cannot use your own invite code.'
        });
      }
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const usernameKey = username.toLowerCase();
    const newInviteCode =
      'CT' + crypto.randomBytes(5).toString('hex').toUpperCase();

    const result = await pool.query(
      `INSERT INTO ct_users
        (username, username_key, password_hash, invite_code, invited_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [
        username,
        usernameKey,
        passwordHash,
        newInviteCode,
        invitedBy
      ]
    );

    const user = safeUser(result.rows[0]);

    await pool.query(
      `INSERT INTO ct_manager_events
        (event_type, username, user_id, details)
       VALUES ('registration', $1, $2, $3)`,
      [
        user.username,
        user.id,
        JSON.stringify({ invitedBy: user.invitedBy })
      ]
    );

    res.status(201).json({
      message: 'Registration successful.',
      user
    });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'This username is already registered.'
      });
    }

    console.error('Registration failed:', error.message);
    res.status(500).json({
      error: 'Could not complete registration. Please try again.'
    });
  }
});

// USER LOGIN
app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    const result = await pool.query(
      'SELECT * FROM ct_users WHERE username_key = $1',
      [username.toLowerCase()]
    );

    if (
      !result.rowCount ||
      !(await bcrypt.compare(password, result.rows[0].password_hash))
    ) {
      return res.status(401).json({
        error: 'Account not found or password is incorrect.'
      });
    }

    const row = result.rows[0];

    if (row.status !== 'Active') {
      return res.status(403).json({
        error: row.status === 'Frozen'
          ? 'This account is frozen. Please contact support.'
          : 'This account is inactive. Please contact support.'
      });
    }

    const user = safeUser(row);

    res.json({
      token: signToken({
        role: 'user',
        userId: user.id,
        username: user.username
      }),
      user
    });
  } catch (error) {
    console.error('User login failed:', error.message);
    res.status(500).json({
      error: 'Login is temporarily unavailable.'
    });
  }
});

// USER PROFILE / BALANCE
app.get('/api/me', auth('user'), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM ct_users WHERE id = $1',
      [req.auth.userId]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'User not found.' });
    }

    if (result.rows[0].status !== 'Active') {
      return res.status(403).json({
        error: 'This account is not active.'
      });
    }

    res.json({ user: safeUser(result.rows[0]) });
  } catch (error) {
    console.error('Profile load failed:', error.message);
    res.status(500).json({ error: 'Could not load user profile.' });
  }
});

// MANAGER LOGIN
app.post('/api/manager/login', async (req, res) => {
  try {
    const username = String(req.body.username || '');
    const password = String(req.body.password || '');

    let validPassword = false;

    if (MANAGER_PASSWORD_HASH) {
      validPassword = await bcrypt.compare(
        password,
        MANAGER_PASSWORD_HASH
      );
    } else {
      const expected = String(process.env.MANAGER_PASSWORD || '');

      if (password.length === expected.length) {
        validPassword = crypto.timingSafeEqual(
          Buffer.from(password),
          Buffer.from(expected)
        );
      }
    }

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
  } catch (error) {
    console.error('Manager login failed:', error.message);
    res.status(500).json({
      error: 'Manager login is temporarily unavailable.'
    });
  }
});

// MANAGER OVERVIEW
app.get('/api/manager/overview', auth('manager'), async (_req, res) => {
  try {
    const [users, events] = await Promise.all([
      pool.query(
        'SELECT * FROM ct_users ORDER BY registered_at DESC, id DESC'
      ),
      pool.query(`
        SELECT id, event_type, username, user_id, details, created_at
        FROM ct_manager_events
        ORDER BY created_at DESC
        LIMIT 100
      `)
    ]);

    res.json({
      users: users.rows.map(safeUser),
      events: events.rows.map(row => ({
        id: Number(row.id),
        type: row.event_type,
        username: row.username,
        userId: row.user_id == null ? null : Number(row.user_id),
        details: row.details,
        time: row.created_at
      }))
    });
  } catch (error) {
    console.error('Manager overview failed:', error.message);
    res.status(500).json({
      error: 'Could not load manager data.'
    });
  }
});

// MANAGER: UPDATE USER STATUS, DEMO BALANCE OR CREDIT SCORE
app.patch('/api/manager/users/:id', auth('manager'), async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isSafeInteger(id) || id < 6000) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  try {
    const allowedUpdates = [];
    const values = [];

    if (req.body.status !== undefined) {
      if (!['Active', 'Frozen', 'Inactive'].includes(req.body.status)) {
        return res.status(400).json({ error: 'Invalid status.' });
      }

      values.push(req.body.status);
      allowedUpdates.push(`status = $${values.length}`);
    }

    if (req.body.creditScore !== undefined) {
      const score = Number(req.body.creditScore);

      if (!Number.isInteger(score) || score < 0 || score > 1000) {
        return res.status(400).json({
          error: 'Credit score must be between 0 and 1000.'
        });
      }

      values.push(score);
      allowedUpdates.push(`credit_score = $${values.length}`);
    }

    if (req.body.demoBalance !== undefined) {
      const balance = Number(req.body.demoBalance);

      if (!Number.isFinite(balance) || balance < 0 || balance > 1e12) {
        return res.status(400).json({
          error: 'Invalid demo balance.'
        });
      }

      values.push(balance);
      allowedUpdates.push(`demo_balance = $${values.length}`);
    }

    if (req.body.inviteCode !== undefined) {
      const code = String(req.body.inviteCode)
        .trim()
        .toUpperCase();

      if (!/^[A-Z0-9_-]{3,32}$/.test(code)) {
        return res.status(400).json({
          error: 'Invalid invite code.'
        });
      }

      values.push(code);
      allowedUpdates.push(`invite_code = $${values.length}`);
    }

    if (!allowedUpdates.length) {
      return res.status(400).json({
        error: 'No supported changes supplied.'
      });
    }

    values.push(id);

    const result = await pool.query(
      `UPDATE ct_users
       SET ${allowedUpdates.join(', ')}
       WHERE id = $${values.length}
       RETURNING *`,
      values
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = safeUser(result.rows[0]);

    await pool.query(
      `INSERT INTO ct_manager_events
        (event_type, username, user_id, details)
       VALUES ('manager_update', $1, $2, $3)`,
      [user.username, id, JSON.stringify(req.body)]
    );

    res.json({ user });
  } catch (error) {
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'That invite code is already in use.'
      });
    }

    console.error('Manager user update failed:', error.message);
    res.status(500).json({ error: 'Could not update user.' });
  }
});

// MANAGER: SEND A MESSAGE TO A USER
app.post('/api/manager/users/:id/notify', auth('manager'), async (req, res) => {
  const id = Number(req.params.id);
  const message = String(req.body.message || '').trim();

  if (
    !Number.isSafeInteger(id) ||
    id < 6000 ||
    !message ||
    message.length > 1000
  ) {
    return res.status(400).json({
      error: 'Enter a valid user ID and message.'
    });
  }

  try {
    const result = await pool.query(
      'SELECT username FROM ct_users WHERE id = $1',
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: 'User not found.' });
    }

    await pool.query(
      `INSERT INTO ct_manager_events
        (event_type, username, user_id, details)
       VALUES ('notification', $1, $2, $3)`,
      [
        result.rows[0].username,
        id,
        JSON.stringify({ message })
      ]
    );

    res.json({ ok: true });
  } catch (error) {
    console.error('Notification failed:', error.message);
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
  .catch(error => {
    console.error('Backend startup failed:', error.message);
    process.exit(1);
  });
          
