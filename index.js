require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();

/* =========================
   Basic Config
========================= */
const PORT = process.env.PORT || 3000;
const SECRET = process.env.SECRET || "regret-toast";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

app.use(express.json());
app.use(
  cors({
    origin: CORS_ORIGIN,
    credentials: false,
  })
);

// Supabase client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);

/* =========================
   Helpers / Auth
========================= */
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    const user = jwt.verify(token, SECRET);
    req.user = user; // { username }
    next();
  } catch (err) {
    return res.status(403).json({ error: "Invalid token" });
  }
}

/* =========================
   Health
========================= */
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "regret-backend", time: new Date().toISOString() });
});

/* =========================
   Auth
========================= */
// Register
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "username and password are required" });
    }

    const password_hash = await bcrypt.hash(password, 10);

    const { data, error } = await supabase
      .from("users")
      .insert([{ username, password_hash }])
      .select();

    if (error) return res.status(400).json({ error: error.message });
    res.status(201).json({ message: "User registered", user: data[0] });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "username and password are required" });
    }

    const { data, error } = await supabase
      .from("users")
      .select("*")
      .eq("username", username)
      .single();

    if (error || !data) return res.status(401).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, data.password_hash);
    if (!valid) return res.status(401).json({ error: "Wrong password" });

    const token = jwt.sign({ username }, SECRET, { expiresIn: "1h" });
    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

/* =========================
   Tones
========================= */
// List tones
app.get("/api/tones", async (_req, res) => {
  try {
    const { data, error } = await supabase
      .from("tones")
      .select("name, category")
      .order("name", { ascending: true });

    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Create tone (currently any authenticated user – we can gate to admins later)
app.post("/api/tones", authenticateToken, async (req, res) => {
  try {
    const { name, category } = req.body || {};
    const n = (name || "").trim();
    const c = (category || "").trim();

    if (!n || n.length < 2 || n.length > 50) {
      return res.status(400).json({ error: "Tone name 2–50 chars required" });
    }
    if (!["personal", "professional", "party"].includes(c)) {
      return res.status(400).json({ error: "Invalid category" });
    }

    const { data, error } = await supabase
      .from("tones")
      .insert({ name: n, category: c })
      .select("name, category")
      .single();

    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: "Tone created", tone: data });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

/* =========================
   Messages
========================= */
// Save message (REQUIRES valid tone)
app.post("/api/messages", authenticateToken, async (req, res) => {
  try {
    const { text, tone, is_anonymous } = req.body || {};
    const { username } = req.user || {};

    if (!text || !text.trim()) {
      return res.status(400).json({ error: "Message text is required" });
    }

    // Require tone
    const t = (tone || "").trim();
    if (!t) {
      return res.status(400).json({ error: "Tone is required" });
    }
    if (t.length < 2 || t.length > 50) {
      return res.status(400).json({ error: "Tone must be 2–50 chars" });
    }

    // Validate tone exists
    const { data: toneRow, error: toneErr } = await supabase
      .from("tones")
      .select("name")
      .eq("name", t)
      .single();

    if (toneErr || !toneRow) {
      return res.status(400).json({ error: "Invalid tone" });
    }

    const payload = {
      username: username || "anon",
      text: text.trim(),
      tone: t,
      is_anonymous: Boolean(is_anonymous),
    };

    const { data, error } = await supabase
      .from("messages")
      .insert([payload])
      .select()
      .single();

    if (error) return res.status(500).json({ error: error.message });

    res.status(201).json({ message: "Message saved", data });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Get all messages (newest first)
app.get("/api/messages", authenticateToken, async (_req, res) => {
  try {
    const { data, error } = await supabase
      .from("messages")
      .select("*")
      .order("inserted_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message });
    res.json(data || []);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

/* =========================
   Server
========================= */
app.listen(PORT, () => {
  console.log(`🚀 Server listening on http://localhost:${PORT}`);
});
