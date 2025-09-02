require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(express.json());
app.use(cors());

// Connect to Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const SECRET = process.env.SECRET || "regret-toast";

// Middleware to protect routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// Register
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  const password_hash = await bcrypt.hash(password, 10);

  const { data, error } = await supabase
    .from("users")
    .insert([{ username, password_hash }])
    .select();

  if (error) return res.status(400).json({ error: error.message });

  res.status(201).json({ message: "User registered", user: data[0] });
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const { data, error } = await supabase
    .from("users")
    .select("*")
    .eq("username", username)
    .single();

  if (error || !data)
    return res.status(401).json({ error: "Invalid credentials" });

  const valid = await bcrypt.compare(password, data.password_hash);
  if (!valid) return res.status(401).json({ error: "Wrong password" });

  const token = jwt.sign({ username }, SECRET, { expiresIn: "1h" });
  res.json({ message: "Login successful", token });
});

// Save message
app.post("/api/messages", authenticateToken, async (req, res) => {
  const { text } = req.body;
  const { username } = req.user;

  const { data, error } = await supabase
    .from("messages")
    .insert([{ username, text }])
    .select();

  if (error) return res.status(500).json({ error: error.message });

  res.status(201).json({ message: "Message saved", data: data[0] });
});

// Get all messages
app.get("/api/messages", authenticateToken, async (req, res) => {
  const { data, error } = await supabase
    .from("messages")
    .select("*")
    .order("inserted_at", { ascending: false });

  if (error) return res.status(500).json({ error: error.message });

  res.json(data);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
