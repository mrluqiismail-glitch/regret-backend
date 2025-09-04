// require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(express.json());
app.use(cors());

// --- Supabase & JWT ---
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const SECRET = process.env.SECRET || "regret-toast";

// ---------- Helpers ----------
function signToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: "12h" });
}
function getAuthToken(req) {
  const authHeader = req.headers["authorization"];
  return authHeader && authHeader.split(" ")[1];
}
async function getUserByUsername(username, withHash = false) {
  const columns = withHash ? "id, username, password_hash" : "id, username";
  const { data, error } = await supabase
    .from("users")
    .select(columns)
    .eq("username", username)
    .single();
  if (error) return null;
  return data;
}
async function getUserById(id) {
  const { data, error } = await supabase
    .from("users")
    .select("id, username")
    .eq("id", id)
    .single();
  if (error) return null;
  return data;
}
async function isGroupMember(groupId, userId) {
  const { data, error } = await supabase
    .from("group_members")
    .select("user_id, role")
    .eq("group_id", groupId)
    .eq("user_id", userId)
    .single();
  if (error) return null;
  return data; // { user_id, role }
}
async function hasGroupRole(groupId, userId, roles = ["owner", "admin"]) {
  const m = await isGroupMember(groupId, userId);
  if (!m) return false;
  return roles.includes(m.role);
}

// ---------- Auth middleware ----------
async function authenticateToken(req, res, next) {
  const token = getAuthToken(req);
  if (!token) return res.status(401).json({ error: "No token" });

  jwt.verify(token, SECRET, async (err, payload) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = { id: payload.id, username: payload.username };
    if (!req.user.id || !req.user.username) {
      const dbUser = await getUserByUsername(payload.username);
      if (!dbUser) return res.status(401).json({ error: "User not found" });
      req.user = { id: dbUser.id, username: dbUser.username };
    }
    next();
  });
}

// ===================================================
//               BASIC & AUTH ROUTES
// ===================================================

app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "regret-backend", time: new Date().toISOString() });
});

// Register (unique usernames)
app.post("/api/register", async (req, res) => {
  try {
    let { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "username and password required" });

    const exists = await getUserByUsername(username);
    if (exists) return res.status(409).json({ error: "username already exists" });

    const password_hash = await bcrypt.hash(password, 10);
    const { data, error } = await supabase
      .from("users")
      .insert([{ username, password_hash }])
      .select()
      .single();
    if (error) return res.status(400).json({ error: error.message });

    // create blank profile row (so joins always have something)
    await supabase.from("profiles").upsert({ user_id: data.id });

    res.status(201).json({ message: "User registered", user: { id: data.id, username: data.username } });
  } catch (e) {
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "username and password required" });

    const user = await getUserByUsername(username, true);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Wrong password" });

    const token = signToken({ id: user.id, username: user.username });
    res.json({ message: "Login successful", token });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

// ===================================================
//                      USERS
// ===================================================

// Get id by username
app.get("/api/users", async (req, res) => {
  const { username } = req.query;
  if (!username) return res.status(400).json({ error: "username is required" });
  const user = await getUserByUsername(username);
  if (!user) return res.status(404).json({ error: "user not found" });
  res.json({ id: user.id, username: user.username });
});

// Search users by username (with profile preview)
app.get("/api/users/search", async (req, res) => {
  try {
    const { q = "", limit = 10 } = req.query;
    if (!q) return res.json([]);

    const { data: users, error: uErr } = await supabase
      .from("users")
      .select("id, username")
      .ilike("username", `%${q}%`)
      .limit(Number(limit));

    if (uErr) return res.status(500).json({ error: uErr.message });
    if (!users?.length) return res.json([]);

    const ids = users.map((u) => u.id);
    const { data: profs, error: pErr } = await supabase
      .from("profiles")
      .select("user_id, display_name, avatar_url")
      .in("user_id", ids);

    if (pErr) return res.status(500).json({ error: pErr.message });

    const map = Object.fromEntries((profs || []).map((p) => [p.user_id, p]));
    const out = users.map((u) => ({
      id: u.id,
      username: u.username,
      display_name: map[u.id]?.display_name || null,
      avatar_url: map[u.id]?.avatar_url || null,
    }));
    res.json(out);
  } catch {
    res.status(500).json({ error: "search failed" });
  }
});

// ===================================================
//                    PROFILES
// ===================================================

// Get a public profile by username
app.get("/api/profile/:username", async (req, res) => {
  const { username } = req.params;
  const user = await getUserByUsername(username);
  if (!user) return res.status(404).json({ error: "user not found" });

  const { data: profile, error } = await supabase
    .from("profiles")
    .select("display_name, bio, avatar_url, created_at, updated_at")
    .eq("user_id", user.id)
    .single();
  // If no row: code PGRST116; just return nulls
  if (error && error.code !== "PGRST116") return res.status(500).json({ error: error.message });

  res.json({
    username: user.username,
    profile: profile || { display_name: null, bio: null, avatar_url: null },
  });
});

// Get my profile (auth)
app.get("/api/profile", authenticateToken, async (req, res) => {
  const { data: profile, error } = await supabase
    .from("profiles")
    .select("display_name, bio, avatar_url, created_at, updated_at")
    .eq("user_id", req.user.id)
    .maybeSingle();

  if (error && error.code !== "PGRST116") return res.status(500).json({ error: error.message });

  res.json({
    username: req.user.username,
    profile: profile || { display_name: null, bio: null, avatar_url: null },
  });
});

// Shared profile upsert handler
async function upsertMyProfileHandler(req, res) {
  const { display_name = null, bio = null, avatar_url = null } = req.body || {};
  const { error } = await supabase
    .from("profiles")
    .upsert({
      user_id: req.user.id,
      display_name,
      bio,
      avatar_url,
      updated_at: new Date().toISOString(),
    });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: "Profile saved" });
}

// Upsert my profile (supports BOTH PUT and POST)
app.put("/api/profile", authenticateToken, upsertMyProfileHandler);
app.post("/api/profile", authenticateToken, upsertMyProfileHandler);

// ===================================================
//                      TONES
// ===================================================

app.get("/api/tones", async (_req, res) => {
  const { data, error } = await supabase
    .from("tones")
    .select("name, category")
    .order("name", { ascending: true });

  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ===================================================
//                      GROUPS
// ===================================================

// Create group
app.post("/api/groups", authenticateToken, async (req, res) => {
  try {
    const { name, visibility = "private" } = req.body || {};
    if (!name) return res.status(400).json({ error: "name is required" });

    const { data, error } = await supabase
      .from("groups")
      .insert([{ name, visibility, created_by: req.user.id }])
      .select()
      .single();
    if (error) return res.status(400).json({ error: error.message });

    await supabase.from("group_members").insert([{ group_id: data.id, user_id: req.user.id, role: "owner" }]);
    res.json({ message: "Group created", group: data });
  } catch {
    res.status(500).json({ error: "Failed to create group" });
  }
});

// List my groups
app.get("/api/groups", authenticateToken, async (req, res) => {
  try {
    const { data: memberships, error: mErr } = await supabase
      .from("group_members")
      .select("group_id, role")
      .eq("user_id", req.user.id);
    if (mErr) return res.status(500).json({ error: mErr.message });

    const ids = memberships.map((m) => m.group_id);
    if (ids.length === 0) return res.json([]);

    const { data: groups, error: gErr } = await supabase
      .from("groups")
      .select("id, name, visibility, created_at")
      .in("id", ids)
      .order("created_at", { ascending: false });
    if (gErr) return res.status(500).json({ error: gErr.message });

    const withRole = groups.map((g) => ({
      ...g,
      role: memberships.find((m) => m.group_id === g.id)?.role || "member",
    }));
    res.json(withRole);
  } catch {
    res.status(500).json({ error: "Failed to fetch groups" });
  }
});

// --- Invites ---

// Create invite (owner/admin only) by username
app.post("/api/groups/:groupId/invites", authenticateToken, async (req, res) => {
  try {
    const { groupId } = req.params;
    const { username } = req.body || {};
    if (!username) return res.status(400).json({ error: "username is required" });

    const admin = await hasGroupRole(groupId, req.user.id, ["owner", "admin"]);
    if (!admin) return res.status(403).json({ error: "Only owners/admins can invite" });

    const target = await getUserByUsername(username);
    if (!target) return res.status(400).json({ error: "user not found" });

    const already = await isGroupMember(groupId, target.id);
    if (already) return res.status(409).json({ error: "User is already a member" });

    const { data: pend, error: pErr } = await supabase
      .from("group_invites")
      .select("id")
      .eq("group_id", groupId)
      .eq("invited_user_id", target.id)
      .eq("status", "pending")
      .maybeSingle();
    if (pErr) return res.status(500).json({ error: pErr.message });
    if (pend) return res.status(409).json({ error: "Invite already pending" });

    const { data, error } = await supabase
      .from("group_invites")
      .insert([{ group_id: groupId, inviter_user_id: req.user.id, invited_user_id: target.id }])
      .select()
      .single();
    if (error) return res.status(400).json({ error: error.message });

    res.json({ message: "Invite created", invite: data });
  } catch {
    res.status(500).json({ error: "Failed to create invite" });
  }
});

// List pending invites for me
app.get("/api/invites", authenticateToken, async (req, res) => {
  const { data, error } = await supabase
    .from("group_invites")
    .select("id, group_id, status, created_at")
    .eq("invited_user_id", req.user.id)
    .eq("status", "pending")
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Accept invite
app.post("/api/invites/:inviteId/accept", authenticateToken, async (req, res) => {
  const { inviteId } = req.params;

  const { data: invite, error: iErr } = await supabase
    .from("group_invites")
    .select("id, group_id, invited_user_id, status")
    .eq("id", inviteId)
    .single();
  if (iErr) return res.status(400).json({ error: "Invite not found" });
  if (invite.invited_user_id !== req.user.id) return res.status(403).json({ error: "Not your invite" });
  if (invite.status !== "pending") return res.status(409).json({ error: "Invite is not pending" });

  const already = await isGroupMember(invite.group_id, req.user.id);
  if (!already) {
    const { error: mErr } = await supabase
      .from("group_members")
      .insert([{ group_id: invite.group_id, user_id: req.user.id, role: "member" }]);
    if (mErr) return res.status(400).json({ error: mErr.message });
  }

  await supabase.from("group_invites").update({ status: "accepted" }).eq("id", inviteId);
  res.json({ message: "Invite accepted" });
});

// Decline invite
app.post("/api/invites/:inviteId/decline", authenticateToken, async (req, res) => {
  const { inviteId } = req.params;
  const { data: invite, error: iErr } = await supabase
    .from("group_invites")
    .select("id, invited_user_id, status")
    .eq("id", inviteId)
    .single();
  if (iErr) return res.status(400).json({ error: "Invite not found" });
  if (invite.invited_user_id !== req.user.id) return res.status(403).json({ error: "Not your invite" });
  if (invite.status !== "pending") return res.status(409).json({ error: "Invite is not pending" });

  await supabase.from("group_invites").update({ status: "declined" }).eq("id", inviteId);
  res.json({ message: "Invite declined" });
});

// Admin: list group invites
app.get("/api/groups/:groupId/invites", authenticateToken, async (req, res) => {
  const { groupId } = req.params;
  const admin = await hasGroupRole(groupId, req.user.id, ["owner", "admin"]);
  if (!admin) return res.status(403).json({ error: "Only owners/admins can view invites" });

  const { data, error } = await supabase
    .from("group_invites")
    .select("id, invited_user_id, status, created_at")
    .eq("group_id", groupId)
    .order("created_at", { ascending: false });
  if (error) return res.status(500).json({ error: error.message });

  const ids = data.map((i) => i.invited_user_id);
  let usersMap = {};
  if (ids.length) {
    const { data: users } = await supabase.from("users").select("id, username").in("id", ids);
    usersMap = Object.fromEntries((users || []).map((u) => [u.id, u.username]));
  }
  res.json(data.map((i) => ({ ...i, username: usersMap[i.invited_user_id] || "unknown" })));
});

// ===================================================
//                      MESSAGES
// ===================================================

// Create message (public|group|dm) with optional media
app.post("/api/messages", authenticateToken, async (req, res) => {
  try {
    const {
      text,
      tone,
      is_anonymous = false,
      visibility = "public",
      group_id = null,
      recipient_user_id = null,
      original_text = null,
      media_url = null,
      media_type = null,
    } = req.body || {};

    if (!text || !tone) return res.status(400).json({ error: "text and tone are required" });
    if (!["public", "group", "dm"].includes(visibility))
      return res.status(400).json({ error: "invalid visibility" });
    if (media_type && !["image", "video"].includes(media_type))
      return res.status(400).json({ error: "invalid media_type" });

    if (visibility === "group") {
      if (!group_id) return res.status(400).json({ error: "group_id is required for group messages" });
      const member = await isGroupMember(group_id, req.user.id);
      if (!member) return res.status(403).json({ error: "Not a member of this group" });
    }
    if (visibility === "dm") {
      if (!recipient_user_id)
        return res.status(400).json({ error: "recipient_user_id is required for dm messages" });
      const exists = await getUserById(Number(recipient_user_id));
      if (!exists) return res.status(400).json({ error: "recipient user not found" });
    }

    const payload = {
      username: req.user.username,
      text,
      tone,
      is_anonymous: !!is_anonymous,
      visibility,
      group_id,
      recipient_user_id,
      original_text,
      media_url,
      media_type,
    };

    const { data, error } = await supabase.from("messages").insert([payload]).select().single();
    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json({ message: "Message saved", data });
  } catch {
    res.status(500).json({ error: "Failed to save message" });
  }
});

// Feeds
app.get("/api/messages", async (req, res) => {
  try {
    const { visibility = "public", group_id, recipient_user_id } = req.query;

    if (visibility === "public") {
      const { data, error } = await supabase
        .from("messages")
        .select(
          "id, username, text, tone, is_anonymous, visibility, group_id, recipient_user_id, original_text, media_url, media_type, inserted_at"
        )
        .eq("visibility", "public")
        .order("inserted_at", { ascending: false });
      if (error) return res.status(500).json({ error: error.message });
      const masked = data.map((m) => (m.is_anonymous ? { ...m, username: "Anonymous" } : m));
      return res.json(masked);
    }

    // Private feeds require auth
    const token = getAuthToken(req);
    if (!token) return res.status(401).json({ error: "No token" });

    let me;
    try {
      me = jwt.verify(token, SECRET);
    } catch {
      return res.status(403).json({ error: "Invalid token" });
    }

    if (visibility === "group") {
      if (!group_id) return res.status(400).json({ error: "group_id is required for group messages" });
      const member = await isGroupMember(group_id, me.id);
      if (!member) return res.status(403).json({ error: "Not a member of this group" });

      const { data, error } = await supabase
        .from("messages")
        .select(
          "id, username, text, tone, is_anonymous, visibility, group_id, recipient_user_id, original_text, media_url, media_type, inserted_at"
        )
        .eq("visibility", "group")
        .eq("group_id", group_id)
        .order("inserted_at", { ascending: false });
      if (error) return res.status(500).json({ error: error.message });
      return res.json(data);
    }

    if (visibility === "dm") {
      if (!recipient_user_id)
        return res.status(400).json({ error: "recipient_user_id is required for dm messages" });

      const meUser = await getUserById(me.id);
      const otherUser = await getUserById(Number(recipient_user_id));
      if (!meUser || !otherUser) return res.status(400).json({ error: "invalid user(s)" });

      // show both directions of the DM
      const orClause = `and(recipient_user_id.eq.${recipient_user_id},username.eq.${meUser.username}),and(recipient_user_id.eq.${me.id},username.eq.${otherUser.username})`;

      const { data, error } = await supabase
        .from("messages")
        .select(
          "id, username, text, tone, is_anonymous, visibility, group_id, recipient_user_id, original_text, media_url, media_type, inserted_at"
        )
        .eq("visibility", "dm")
        .or(orClause)
        .order("inserted_at", { ascending: false });
      if (error) return res.status(500).json({ error: error.message });
      return res.json(data);
    }

    return res.status(400).json({ error: "invalid visibility" });
  } catch {
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// ===================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
