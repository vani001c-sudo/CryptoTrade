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

// CORS: allow the GitHub Pages website
const ALLOWED_ORIGIN = 'https://vani001c-sudo.github.io';

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin === ALLOWED_ORIGIN) {
    res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  }

  res.setHeader('Vary', 'Origin');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET, POST, PATCH, OPTIONS'
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization'
  );

  if (req.method === 'OPTIONS') {
    return res.sendStatus(204);
  }

  next();
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false'
    ? false
    : { rejectUnauthorized: false }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MANAGER_USERNAME = process.env.MANAGER_USERNAME;
const MANAGER_PASSWORD = process.env.MANAGER_PASSWORD;
const MANAGER_PASSWORD_HASH = process.env.MANAGER_PASSWORD_HASH;

function safeUser(row) {
  return {
    id: Number(row.id),
    userId: Number(row.id),
    username: row.username,
    status: row.status,
    creditScore: Number(row.credit_score || 0),
    demoBalance: Number(row.demo_balance || 0),
    inviteCode: row.invite_code,
    invitedBy: row.invited_by,
    registeredAt: row.registered_at
  };
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' });
}

function requireManager(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Bearer\s+/i, '');

  if (!token) {
    return res.status(401).json({ error: 'Please sign in.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.role !== 'manager') {
      return res.status(403).json({ error: 'Manager access required.' });
    }

    req.manager = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired. Please sign in again.' });
  }
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

app.post('/api/manager/login', async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    if (!MANAGER_USERNAME || (!MANAGER_PASSWORD && !MANAGER_PASSWORD_HASH)) {
      return res.status(503).json({ error: 'Manager login is not configured.' });
    }

    const usernameOK =
      username.toLowerCase() === MANAGER_USERNAME.toLowerCase();

    let passwordOK = false;

    if (MANAGER_PASSWORD_HASH) {
      passwordOK = await bcrypt.compare(password, MANAGER_PASSWORD_HASH);
    } else if (MANAGER_PASSWORD) {
      const a = Buffer.from(password);
      const b = Buffer.from(MANAGER_PASSWORD);

      passwordOK =
        a.length === b.length &&
        crypto.timingSafeEqual(a, b);
    }

    if (!usernameOK || !passwordOK) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const token = signToken({
      role: 'manager',
      username: MANAGER_USERNAME
    });

    res.json({
      ok: true,
      token,
      manager: { username: MANAGER_USERNAME }
    });
  } catch (error) {
    console.error('Manager login error:', error.message);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.get('/api/manager/overview', requireManager, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, status, credit_score, demo_balance,
              invite_code, invited_by, registered_at
       FROM cryptotrade_users
       ORDER BY id DESC
       LIMIT 500`
    );

    res.json({
      ok: true,
      totalUsers: result.rowCount,
      users: result.rows.map(safeUser)
    });
  } catch (error) {
    console.error('Overview error:', error.message);
    res.status(500).json({ error: 'Could not load users. Check database table names.' });
  }
});

app.patch('/api/manager/users/:id', requireManager, async (req, res) => {
  const id = Number(req.params.id);

  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: 'Invalid user ID.' });
  }

  const allowed = ['status', 'demoBalance', 'creditScore'];
  const supplied = allowed.filter(key =>
    Object.prototype.hasOwnProperty.call(req.body, key)
  );

  if (supplied.length !== 1) {
    return res.status(400).json({
      error: 'Send exactly one supported field: status, demoBalance, or creditScore.'
    });
  }

  try {
    let result;

    if (supplied[0] === 'status') {
      const status = String(req.body.status);

      if (!['active', 'blocked', 'pending'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status.' });
      }

      result = await pool.query(
        `UPDATE cryptotrade_users
         SET status = $1 WHERE id = $2
         RETURNING id, username, status, credit_score, demo_balance,
                   invite_code, invited_by, registered_at`,
        [status, id]
      );
    } else {
      const key = supplied[0];
      const value = Number(req.body[key]);

      if (!Number.isFinite(value) || value < 0 || value > 1000000000) {
        return res.status(400).json({ error: 'Invalid amount or score.' });
      }

      const column = key === 'demoBalance' ? 'demo_balance' : 'credit_score';

      result = await pool.query(
        `UPDATE cryptotrade_users
         SET ${column} = $1 WHERE id = $2
         RETURNING id, username, status, credit_score, demo_balance,
                   invite_code, invited_by, registered_at`,
        [value, id]
      );
    }

    if (!result.rowCount) {
      return res.status(404).json({ error: 'User not found.' });
    }

    res.json({ ok: true, user: safeUser(result.rows[0]) });
  } catch (error) {
    console.error('Update user error:', error.message);
    res.status(500).json({ error: 'Could not update user.' });
  }
});

// Serve frontend files if they exist in the public folder.
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found.' });
});

async function start() {
  if (!process.env.DATABASE_URL || !JWT_SECRET || !MANAGER_USERNAME ||
      (!MANAGER_PASSWORD && !MANAGER_PASSWORD_HASH)) {
    console.error('Required Render environment variables are missing.');
    process.exit(1);
  }

  try {
    await pool.query('SELECT 1');
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`CryptoTrade backend listening on ${PORT}`);
    });
  } catch (error) {
    console.error('Database connection failed:', error.message);
    process.exit(1);
  }
}

start();
