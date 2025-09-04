// index.js — ReMemory (Groups v1)
// CommonJS style to match your current project

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

// lookup the current user's DB row by username
async function getUserByUsername(username) {
  const { data, error } = await supabase
    .from("users")
    .select("id, username")
    .eq("username", username)
    .single();
  if (error || !data) return null;
  return data; // { id, username }
}

// ensure tone exists
async function assertToneExists(toneName) {
  const { data, error } = await supabase
    .from("tones")
    .select("name")
    .eq("name", toneName)
    .single();
  if (error || !data) return false;
  return true;
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

    const token = jwt.sign({ username }, SECRET, { expiresIn: "12h" });
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

// Create tone (for now: any authenticated user; we’ll gate to admins later)
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
   Groups v1
========================= */
// Create a group
app.post("/api/groups", authenticateToken, async (req, res) => {
  try {
    const { name, visibility } = req.body || {};
    const n = (name || "").trim();
    const v = (visibility || "private").trim();
    if (!n || n.length < 2 || n.length > 100) {
      return res.status(400).json({ error: "Name must be 2–100 chars" });
    }
    if (!["public", "private", "workspace"].includes(v)) {
      return res.status(400).json({ error: "Invalid visibility" });
    }

    const me = await getUserByUsername(req.user.username);
    if (!me) return res.status(401).json({ error: "User not found" });

    const { data: group, error: gErr } = await supabase
      .from("groups")
      .insert({ name: n, visibility: v, created_by: me.id })
      .select("*")
      .single();
    if (gErr) return res.status(400).json({ error: gErr.message });

    // add creator as owner
    const { error: mErr } = await supabase
      .from("group_members")
      .insert({ group_id: group.id, user_id: me.id, role: "owner" });
    if (mErr) return res.status(400).json({ error: mErr.message });

    res.json({ message: "Group created", group });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// List my groups
app.get("/api/groups", authenticateToken, async (req, res) => {
  try {
    const me = await getUserByUsername(req.user.username);
    if (!me) return res.status(401).json({ error: "User not found" });

    const { data, error } = await supabase
      .from("group_members")
      .select("role, groups!inner(id, name, visibility, created_at)")
      .eq("user_id", me.id);
    if (error) return res.status(400).json({ error: error.message });

    const groups = (data || []).map((row) => ({
      id: row.groups.id,
      name: row.groups.name,
      visibility: row.groups.visibility,
      created_at: row.groups.created_at,
      role: row.role,
    }));
    res.json(groups);
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Invite a user to a group (owner/admin only)
app.post("/api/groups/:groupId/invite", authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { username } = req.body || {};
    const inviteeName = (username || "").trim();

    if (!inviteeName) return res.status(400).json({ error: "username required" });

    const me = await getUserByUsername(req.user.username);
    if (!me) return res.status(401).json({ error: "User not found" });

    const { data: myMembership, error: memErr } = await supabase
      .from("group_members")
      .select("role")
      .eq("group_id", groupId)
      .eq("user_id", me.id)
      .single();
    if (memErr || !myMembership) {
      return res.status(403).json({ error: "Not a member of this group" });
    }
    if (!["owner", "admin"].includes(myMembership.role)) {
      return res.status(403).json({ error: "Only owner/admin can invite" });
    }

    const invitee = await getUserByUsername(inviteeName);
    if (!invitee) return res.status(404).json({ error: "Invitee not found" });

    // add as member (ignore if already member)
    const { error: addErr } = await supabase
      .from("group_members")
      .insert({ group_id: groupId, user_id: invitee.id, role: "member" });
    if (addErr && !/duplicate key/i.test(addErr.message)) {
      return res.status(400).json({ error: addErr.message });
    }

    res.json({ message: "User invited (or already a member)" });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

/* =========================
   Messages (Public / Group / DM)
========================= */
// Create message
app.post("/api/messages", authenticateToken, async (req, res) => {
  try {
    const { text, original_text, tone, is_anonymous, visibility, group_id, recipient_user_id } = req.body || {};
    const t = (tone || "").trim();
    const vis = (visibility || "public").trim();

    if (!text || !text.trim()) {
      return res.status(400).json({ error: "Message text is required" });
    }
    if (!t) return res.status(400).json({ error: "Tone is required" });
    if (!(await assertToneExists(t))) return res.status(400).json({ error: "Invalid tone" });
    if (!["public", "group", "dm"].includes(vis)) {
      return res.status(400).json({ error: "Invalid visibility" });
    }

    const me = await getUserByUsername(req.user.username);
    if (!me) return res.status(401).json({ error: "User not found" });

    const payload = {
      username: me.username, // you’re storing sender username today
      text: text.trim(),
      original_text: original_text ? String(original_text) : null,
      tone: t,
      is_anonymous: Boolean(is_anonymous),
      visibility: vis,
      group_id: null,
      recipient_user_id: null,
    };

    if (vis === "group") {
      if (!group_id) return res.status(400).json({ error: "group_id required for group visibility" });
      // must be a member
      const { data: mem, error: memErr } = await supabase
        .from("group_members")
        .select("role")
        .eq("group_id", group_id)
        .eq("user_id", me.id)
        .single();
      if (memErr || !mem) return res.status(403).json({ error: "Not a member of this group" });
      payload.group_id = group_id;
    }

    if (vis === "dm") {
      if (!recipient_user_id) {
        return res.status(400).json({ error: "recipient_user_id required for dm visibility" });
      }
      if (Number(recipient_user_id) === Number(me.id)) {
        return res.status(400).json({ error: "Cannot DM yourself" });
      }
      payload.recipient_user_id = recipient_user_id;
    }

    const { data, error } = await supabase.from("messages").insert([payload]).select().single();
    if (error) return res.status(500).json({ error: error.message });

    res.status(201).json({ message: "Message saved", data });
  } catch (err) {
    res.status(500).json({ error: "Server error: " + err.message });
  }
});

// Get messages (by scope)
app.get("/api/messages", authenticateToken, async (req, res) => {
  try {
    const vis = (req.query.visibility || "public").trim();
    const limit = Math.min(Number(req.query.limit) || 50, 100);
    const me = await getUserByUsername(req.user.username);
    if (!me) return res.status(401).json({ error: "User not found" });

    let query = supabase.from("messages").select("*");

    if (vis === "public") {
      query = query.eq("visibility", "public").order("inserted_at", { ascending: false }).limit(limit);
    } else if (vis === "group") {
      const group_id = req.query.group_id || "";
      if (!group_id) return res.status(400).json({ error: "group_id is required for group messages" });

      // must be member
      const { data: mem, error: memErr } = await supabase
        .from("group_members")
        .select("role")
        .eq("group_id", group_id)
        .eq("user_id", me.id)
        .maybeSingle();
      if (memErr || !mem) return res.status(403).json({ error: "Not a member of this group" });

      query = query.eq("visibility", "group").eq("group_id", group_id)
        .order("inserted_at", { ascending: false }).limit(limit);
    } else if (vis === "dm") {
      const otherId = Number(req.query.recipient_user_id || 0);
      if (!otherId) return res.status(400).json({ error: "recipient_user_id is required for dm messages" });

      // DM between me.id and otherId
      query = query.eq("visibility", "dm")
        .in("recipient_user_id", [me.id, otherId])
        .order("inserted_at", { ascending: false })
        .limit(limit);
    } else {
      return res.status(400).json({ error: "Invalid visibility" });
    }

    const { data, error } = await query;
    if (error) return res.status(500).json({ error: error.message });

    // Mask public anon usernames
    const mapped = (data || []).map((m) => {
      if (m.visibility === "public" && m.is_anonymous) {
        return { ...m, username: "Anonymous" };
      }
      return m;
    });

    res.json(mapped);
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
