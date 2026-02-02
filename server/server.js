import express from "express";
import { nanoid } from "nanoid";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

// If you already added JSON persistence, keep your persist.js and uncomment below:
// import { loadDbOrDefault, scheduleSaveDb, dataFilePath } from "./persist.js";

const app = express();
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 5173;
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret_change_me";

// -----------------------
// DB (in-memory by default)
// If you already have persist.js, swap to loadDbOrDefault + scheduleSaveDb.
// -----------------------
const db = {
  orgs: new Map(),     // orgId -> {orgId, name}
  users: new Map(),    // userId -> {userId, orgId, username, passwordHash, role, status, publicKeySpkiB64?}
  messages: new Map(), // msgId -> {msgId, orgId, createdBy, iv, ciphertext, aad, wrappedKeys, createdAt}
  audit: []            // array
};

function saveDb() {
  // If you have scheduleSaveDb(db), call it here
  // scheduleSaveDb(db);
}

function ensureOrg(orgId, name = "Demo Company") {
  if (!db.orgs.has(orgId)) db.orgs.set(orgId, { orgId, name });
}
ensureOrg("org_demo", "Demo Company");

// -----------------------
// Utils
// -----------------------
function getPublicBase(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

function audit(orgId, userId, action, details = {}, req = null) {
  db.audit.push({
    id: nanoid(10),
    orgId,
    userId,
    action,
    ...details,
    ip: req?.headers["x-forwarded-for"] || req?.socket?.remoteAddress || null,
    ua: req?.headers["user-agent"] || null,
    at: new Date().toISOString()
  });
  saveDb();
}

// -----------------------
// Auth middleware
// -----------------------
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
  if (!token) return res.status(401).json({ error: "Missing Bearer token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "Admin") return res.status(403).json({ error: "Admin only" });
  return next();
}

// -----------------------
// DEV: Seed Admin
// -----------------------
app.post("/dev/seed-admin", async (req, res) => {
  const { orgId = "org_demo", username = "admin", password = "admin123" } = req.body || {};
  ensureOrg(orgId, "New Org");

  const exists = Array.from(db.users.values()).some(
    (u) => u.orgId === orgId && u.username === username
  );
  if (exists) return res.json({ ok: true, note: "admin already exists" });

  const userId = nanoid(10);
  const passwordHash = await bcrypt.hash(String(password), 12);

  db.users.set(userId, {
    userId,
    orgId,
    username,
    passwordHash,
    role: "Admin",
    status: "Active",
    publicKeySpkiB64: null
  });

  saveDb();
  audit(orgId, userId, "seed_admin", { username }, req);

  return res.json({ ok: true, orgId, username, password });
});

// -----------------------
// Login
// -----------------------
app.post("/auth/login", async (req, res) => {
  const { orgId, username, password } = req.body || {};
  if (!orgId || !username || !password) {
    return res.status(400).json({ error: "orgId, username, password required" });
  }

  const user = Array.from(db.users.values()).find(
    (u) => u.orgId === orgId && u.username === username && u.status === "Active"
  );
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(String(password), user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });

  const token = jwt.sign(
    { userId: user.userId, orgId: user.orgId, role: user.role, username: user.username },
    JWT_SECRET,
    { expiresIn: "8h" }
  );

  audit(user.orgId, user.userId, "login", {}, req);

  return res.json({
    token,
    user: { userId: user.userId, orgId: user.orgId, role: user.role, username: user.username }
  });
});

// -----------------------
// Admin: create user
// -----------------------
app.post("/admin/users", requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role = "Member" } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "username/password required" });
  if (!["Admin", "Member"].includes(role)) return res.status(400).json({ error: "role must be Admin|Member" });

  const orgId = req.user.orgId;

  const exists = Array.from(db.users.values()).some(
    (u) => u.orgId === orgId && u.username === username
  );
  if (exists) return res.status(409).json({ error: "username already exists" });

  const userId = nanoid(10);
  const passwordHash = await bcrypt.hash(String(password), 12);

  db.users.set(userId, {
    userId,
    orgId,
    username,
    passwordHash,
    role,
    status: "Active",
    publicKeySpkiB64: null
  });

  saveDb();
  audit(orgId, req.user.userId, "create_user", { targetUserId: userId, username, role }, req);

  return res.json({ ok: true, userId, username, role });
});

// -----------------------
// Admin: Audit log
// -----------------------
app.get("/admin/audit", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.user.orgId;
  const limit = Math.min(Number(req.query.limit || 200), 1000);

  const items = (db.audit || [])
    .filter(a => a.orgId === orgId)
    .slice(-limit)
    .reverse();

  res.json({ items });
});

// -----------------------
// USER: register my public key
// -----------------------
app.post("/users/me/pubkey", requireAuth, (req, res) => {
  const { publicKeySpkiB64 } = req.body || {};
  if (!publicKeySpkiB64 || typeof publicKeySpkiB64 !== "string") {
    return res.status(400).json({ error: "publicKeySpkiB64 required" });
  }

  const me = db.users.get(req.user.userId);
  if (!me) return res.status(401).json({ error: "User not found" });

  me.publicKeySpkiB64 = publicKeySpkiB64;
  saveDb();

  audit(req.user.orgId, req.user.userId, "pubkey_register", {}, req);
  return res.json({ ok: true });
});

// -----------------------
// ORG: list users with public keys (for wrapping)
// Auth required, same org only.
// -----------------------
app.get("/org/users", requireAuth, (req, res) => {
  const orgId = req.user.orgId;

  const users = Array.from(db.users.values())
    .filter(u => u.orgId === orgId && u.status === "Active")
    .map(u => ({
      userId: u.userId,
      username: u.username,
      role: u.role,
      hasPublicKey: !!u.publicKeySpkiB64,
      publicKeySpkiB64: u.publicKeySpkiB64 // sender needs it to wrap DEK
    }));

  return res.json({ users });
});

// -----------------------
// Messages (Envelope encryption)
// POST /api/messages stores ciphertext + wrappedKeys map
// wrappedKeys: { [userId]: wrappedDekB64url }
// -----------------------
app.post("/api/messages", requireAuth, (req, res) => {
  const { iv, ciphertext, aad, wrappedKeys } = req.body || {};

  if (!iv || !ciphertext || !wrappedKeys || typeof wrappedKeys !== "object") {
    return res.status(400).json({ error: "iv, ciphertext, wrappedKeys required" });
  }

  const msgId = nanoid(12);
  const createdAt = new Date().toISOString();

  db.messages.set(msgId, {
    msgId,
    orgId: req.user.orgId,
    createdBy: req.user.userId,
    iv,
    ciphertext,
    aad: aad || null,
    wrappedKeys, // {userId: wrappedDekB64url}
    createdAt
  });

  saveDb();
  audit(req.user.orgId, req.user.userId, "encrypt_store", { messageId: msgId }, req);

  const base = getPublicBase(req);
  const url = `${base}/m/${msgId}`;
  return res.json({ id: msgId, url });
});

// GET /api/messages/:id returns ciphertext + wrappedKey ONLY for requesting user
app.get("/api/messages/:id", requireAuth, (req, res) => {
  const msg = db.messages.get(req.params.id);
  if (!msg) return res.status(404).json({ error: "Not found" });
  if (msg.orgId !== req.user.orgId) return res.status(403).json({ error: "Wrong org" });

  const wrappedDek = msg.wrappedKeys?.[req.user.userId];
  if (!wrappedDek) {
    audit(req.user.orgId, req.user.userId, "decrypt_denied", { messageId: msg.msgId }, req);
    return res.status(403).json({ error: "You are not an allowed recipient for this message" });
  }

  audit(req.user.orgId, req.user.userId, "decrypt_payload", { messageId: msg.msgId }, req);

  return res.json({
    id: msg.msgId,
    iv: msg.iv,
    ciphertext: msg.ciphertext,
    aad: msg.aad,
    wrappedDek,           // ONLY for current user
    createdAt: msg.createdAt
  });
});

// -----------------------
// Portal static + /m/:id
// -----------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const portalDir = path.join(__dirname, "..", "portal");

app.use("/portal", express.static(portalDir, { extensions: ["html"] }));

app.get("/m/:id", (req, res) => {
  res.sendFile(path.join(portalDir, "decrypt.html"));
});

app.get("/", (req, res) => res.redirect("/portal/compose.html"));

app.listen(PORT, () => {
  console.log(`QuantumMail server listening on ${PORT}`);
});
