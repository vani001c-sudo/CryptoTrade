
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(express.json({ limit: "20kb" }));

const allowedOrigins = (process.env.CORS_ORIGIN || "")
  .split(",").map(x => x.trim()).filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.length === 0 ||
        allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error("Origin not allowed"));
  }
}));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : undefined
});

const SECRET = process.env.JWT_SECRET;
const ADMIN_USER = process.env.MANAGER_USERNAME;
const ADMIN_HASH = process.env.MANAGER_PASSWORD_HASH;

async function setup() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ct_app_users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(80) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      demo_balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      credit_score INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ct_admin_logs (
      id BIGSERIAL PRIMARY KEY,
      admin_username VARCHAR(80) NOT NULL,
      action TEXT NOT NULL,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

function adminOnly(req, res, next) {
  try {
    const token = (req.headers.authorization || "")
      .replace(/^Bearer\s+/i, "");
    const data = jwt.verify(token, SECRET);
    if (data.role !== "admin") throw new Error("Not admin");
    req.admin = data;
    next();
  } catch {
    res.status(401).json({ error: "Admin login required" });
  }
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
    if (!ADMIN_USER || !ADMIN_HASH || !SECRET) {
      return res.status(503).json({ error: "Admin environment not configured" });
    }

    const { username, password } = req.body || {};
    if (username !== ADMIN_USER || typeof password !== "string" ||
        !(await bcrypt.compare(password, ADMIN_HASH))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign(
      { role: "admin", username },
      SECRET,
      { expiresIn: "2h" }
    );

    res.json({ ok: true, token, username });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (typeof username !== "string" ||
        !/^[a-zA-Z0-9_]{3,30}$/.test(username) ||
        typeof password !== "string" || password.length < 8) {
      return res.status(400).json({
        error: "Username must be 3-30 letters/numbers/underscores; password needs 8 characters"
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO ct_app_users (username, password_hash)
       VALUES ($1, $2)
       RETURNING id, username, status, demo_balance, created_at`,
      [username, hash]
    );

    res.status(201).json({ ok: true, user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      return res.status(409).json({ error: "Username already exists" });
    }
    console.error("Registration error:", err.message);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/user/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const result = await pool.query(
      `SELECT * FROM ct_app_users WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];

    if (!user || user.status !== "active" ||
        typeof password !== "string" ||
        !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid login or account blocked" });
    }

    const token = jwt.sign(
      { role: "user", id: user.id, username: user.username },
      SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      ok: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        demo_balance: user.demo_balance
      }
    });
  } catch (err) {
    console.error("User login error:", err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/manager/users", adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, status, demo_balance, credit_score, created_at
      FROM ct_app_users ORDER BY id DESC LIMIT 500
    `);
    res.json({ ok: true, users: result.rows });
  } catch (err) {
    console.error("List users error:", err.message);
    res.status(500).json({ error: "Could not load users" });
  }
});

app.get("/api/manager/overview", adminOnly, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT COUNT(*)::int AS total_users,
             COUNT(*) FILTER (WHERE status = 'active')::int AS active_users,
             COUNT(*) FILTER (WHERE status = 'blocked')::int AS blocked_users,
             COALESCE(SUM(demo_balance), 0)::numeric(14,2) AS total_demo_balance
      FROM ct_app_users
    `);
    res.json({ ok: true, overview: result.rows[0] });
  } catch (err) {
    console.error("Overview error:", err.message);
    res.status(500).json({ error: "Could not load overview" });
  }
});

app.patch("/api/manager/users/:id", adminOnly, async (req, res) => {
  const id = Number(req.params.id);
  const { status, demoBalance, creditScore } = req.body || {};

  if (!Number.isSafeInteger(id) || id < 1) {
    return res.status(400).json({ error: "Invalid user ID" });
  }

  const fields = [];
  const values = [];
  const details = {};

  if (status !== undefined) {
    if (!["active", "blocked"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }
    values.push(status);
    fields.push(`status = $${values.length}`);
    details.status = status;
  }

  if (demoBalance !== undefined) {
    const amount = Number(demoBalance);
    if (!Number.isFinite(amount) || amount < 0 || amount > 100000000) {
      return res.status(400).json({ error: "Invalid demo balance" });
    }
    values.push(amount.toFixed(2));
    fields.push(`demo_balance = $${values.length}`);
    details.demoBalance = amount;
  }

  if (creditScore !== undefined) {
    const score = Number(creditScore);
    if (!Number.isInteger(score) || score < 0 || score > 1000) {
      return res.status(400).json({ error: "Credit score must be 0-1000" });
    }
    values.push(score);
    fields.push(`credit_score = $${values.length}`);
    details.creditScore = score;
  }

  if (!fields.length) {
    return res.status(400).json({ error: "No changes supplied" });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    values.push(id);

    const updated = await client.query(
      `UPDATE ct_app_users SET ${fields.join(", ")}
       WHERE id = $${values.length}
       RETURNING id, username, status, demo_balance, credit_score`,
      values
    );

    if (!updated.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }

    await client.query(
      `INSERT INTO ct_admin_logs (admin_username, action, details)
       VALUES ($1, $2, $3)`,
      [req.admin.username, "update_user", JSON.stringify({ id, ...details })]
    );

    await client.query("COMMIT");
    res.json({ ok: true, user: updated.rows[0] });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Update error:", err.message);
    res.status(500).json({ error: "Could not update user" });
  } finally {
    client.release();
  }
});

app.get("/api/manager/activity", adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM ct_admin_logs ORDER BY id DESC LIMIT 100`
    );
    res.json({ ok: true, activity: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Could not load activity" });
  }
});

app.use((req, res) => res.status(404).json({ error: "Endpoint not found" }));

async function start() {
  if (!process.env.DATABASE_URL || !SECRET) {
    throw new Error("DATABASE_URL and JWT_SECRET must be set in Render");
  }
  await setup();
  app.listen(process.env.PORT || 3000, "0.0.0.0", () => {
    console.log("CryptoTrade API started");
  });
}

start().catch(err => {
  console.error("Startup failed:", err.message);
  process.exit(1);
});
    
