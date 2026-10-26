
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(express.json({ limit: "20kb" }));

app.use(cors({
  origin: (process.env.CORS_ORIGIN || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean),
  methods: ["GET", "POST", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MANAGER_USERNAME = process.env.MANAGER_USERNAME;
const MANAGER_PASSWORD_HASH = process.env.MANAGER_PASSWORD_HASH;

function requireConfig() {
  if (!process.env.DATABASE_URL || !JWT_SECRET ||
      !MANAGER_USERNAME || !MANAGER_PASSWORD_HASH) {
    throw new Error("Required environment variables are missing.");
  }
}

function adminOnly(req, res, next) {
  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");

  if (!token) {
    return res.status(401).json({ error: "Admin login required" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "admin") throw new Error("Invalid role");
    req.admin = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS cryptotrade_users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(80) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'blocked')),
      demo_balance NUMERIC(14,2) NOT NULL DEFAULT 0
        CHECK (demo_balance >= 0),
      credit_score INTEGER NOT NULL DEFAULT 0
        CHECK (credit_score BETWEEN 0 AND 1000),
      registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS cryptotrade_activity_logs (
      id BIGSERIAL PRIMARY KEY,
      admin_username VARCHAR(80) NOT NULL,
      action VARCHAR(80) NOT NULL,
      target_user_id BIGINT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

async function logActivity(admin, action, userId, details = {}) {
  await pool.query(
    `INSERT INTO cryptotrade_activity_logs
     (admin_username, action, target_user_id, details)
     VALUES ($1, $2, $3, $4)`,
    [admin, action, userId || null, JSON.stringify(details)]
  );
}

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch {
    res.status(503).json({ ok: false, error: "Database unavailable" });
  }
});

app.post("/api/manager/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (typeof username !== "string" ||
        typeof password !== "string" ||
        username !== MANAGER_USERNAME) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, MANAGER_PASSWORD_HASH);
    if (!valid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { role: "admin", username },
      JWT_SECRET,
      { expiresIn: "2h" }
    );

    res.json({ ok: true, token, username });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/manager/overview", adminOnly, async (req, res) => {
  try {
    const users = await pool.query(`
      SELECT
        COUNT(*)::int AS total_users,
        COUNT(*) FILTER (WHERE status = 'active')::int AS active_users,
        COUNT(*) FILTER (WHERE status = 'blocked')::int AS blocked_users,
        COALESCE(SUM(demo_balance), 0)::numeric(14,2) AS total_demo_balance
      FROM cryptotrade_users
    `);

    const activity = await pool.query(`
      SELECT id, admin_username, action, target_user_id,
             details, created_at
      FROM cryptotrade_activity_logs
      ORDER BY id DESC LIMIT 20
    `);

    res.json({
      ok: true,
      overview: users.rows[0],
      recentActivity: activity.rows
    });
  } catch (err) {
    console.error("Overview error:", err.message);
    res.status(500).json({ error: "Could not load overview" });
  }
});

app.get("/api/manager/users", adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, status, demo_balance, credit_score,
             registered_at
      FROM cryptotrade_users
      ORDER BY id DESC LIMIT 500
    `);

    res.json({ ok: true, users: result.rows });
  } catch (err) {
    console.error("Users error:", err.message);
    res.status(500).json({ error: "Could not load users" });
  }
});

app.patch("/api/manager/users/:id", adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const { status, demoBalance, creditScore } = req.body || {};

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid user ID" });
  }

  const changes = [];
  const values = [];
  const details = {};

  if (status !== undefined) {
    if (!["active", "blocked"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }
    values.push(status);
    changes.push(`status = $${values.length}`);
    details.status = status;
  }

  if (demoBalance !== undefined) {
    const amount = Number(demoBalance);
    if (!Number.isFinite(amount) || amount < 0 || amount > 100000000) {
      return res.status(400).json({ error: "Invalid demo balance" });
    }
    values.push(amount.toFixed(2));
    changes.push(`demo_balance = $${values.length}`);
    details.demoBalance = amount;
  }

  if (creditScore !== undefined) {
    const score = Number(creditScore);
    if (!Number.isInteger(score) || score < 0 || score > 1000) {
      return res.status(400).json({ error: "Credit score must be 0–1000" });
    }
    values.push(score);
    changes.push(`credit_score = $${values.length}`);
    details.creditScore = score;
  }

  if (!changes.length) {
    return res.status(400).json({ error: "No valid changes supplied" });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    values.push(id);
    const updated = await client.query(
      `UPDATE cryptotrade_users
       SET ${changes.join(", ")}
       WHERE id = $${values.length}
       RETURNING id, username, status, demo_balance, credit_score`,
      values
    );

    if (!updated.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }

    await client.query(
      `INSERT INTO cryptotrade_activity_logs
       (admin_username, action, target_user_id, details)
       VALUES ($1, $2, $3, $4)`,
      [
        req.admin.username,
        "update_user",
        id,
        JSON.stringify(details)
      ]
    );

    await client.query("COMMIT");
    res.json({ ok: true, user: updated.rows[0] });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Update user error:", err.message);
    res.status(500).json({ error: "Could not update user" });
  } finally {
    client.release();
  }
});

app.get("/api/manager/activity", adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, admin_username, action, target_user_id,
             details, created_at
      FROM cryptotrade_activity_logs
      ORDER BY id DESC LIMIT 100
    `);

    res.json({ ok: true, activity: result.rows });
  } catch (err) {
    console.error("Activity error:", err.message);
    res.status(500).json({ error: "Could not load activity" });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: "API endpoint not found" });
});

async function start() {
  requireConfig();
  await initDatabase();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`CryptoTrade API running on port ${PORT}`);
  });
}

start().catch(err => {
  console.error("Server startup failed:", err.message);
  process.exit(1);
});
  
