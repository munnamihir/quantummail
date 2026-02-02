import express from "express";
import { nanoid } from "nanoid";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import { loadDbOrDefault, scheduleSaveDb, dataFilePath } from "./persist.js";

const app = express();
app.use(express.json({ limit: "1mb" }));

// ========================
// CONFIG
// ========================
const PORT = process.env.PORT || 5173;

// For MVP you can keep defaults; in prod set env vars.
const JWT_SECRET = process.env.JWT_SECRET || "dev_jwt_secret_change_me";
const SERVER_WRAP_SECRET =
  process.env.SERVER_WRAP_SECRET || "dev_wrap_secret_change_me_32bytes_min";

function getWrapKey() {
  return crypto.createHash("sha256").update(String(SERVER_WRAP_SECRET)).digest();
}

function getPublicBase(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

// ========================
// Persistent DB (JSON file)
// ========================
const defaultDb = {
  orgs: new Map(),
  users: new Map(),
  keys: new Map(),
  messages: new Map(),
  audit: []
};

const db = loadDbOrDefault(defaultDb);
console.log("📦 Persistence file:", dataFilePath());

// Ensure default org exists (safe)
function ensureOrg(orgId, name = "Demo Company") {
  if (!db.orgs.has(orgId)) {
    db.orgs.set(orgId, { orgId, name });
  }
  if (!db.keys.has(orgId)) {
    db.keys.set(orgId, []);
  }
}
ensureOrg("org_demo", "Demo Company");
scheduleSaveDb(db);

// ========================
// Audit
// ========================
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
  scheduleSaveDb(db);
}

// ========================
// Auth middleware
// ========================
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
  if (!token) return res.status(401).json({ error: "Missing Bearer token" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { userId, orgId, role, username }
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== "Admin") return res.status(403).json({ error: "Admin only" });
  return next();
}

// ========================
// Key wrapping (AES-256-GCM)
// ========================
function wrapRawKey(rawKeyBytes) {
  const wrapKey = getWrapKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", wrapKey, iv);
  const ciphertext = Buffer.concat([cipher.update(rawKeyBytes), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("base64url"),
    ct: ciphertext.toString("base64url"),
    tag: tag.toString("base64url")
  };
}

function unwrapRawKey(wrapped) {
  const wrapKey = getWrapKey();
  const iv = Buffer.from(wrapped.iv, "base64url");
  const ct = Buffer.from(wrapped.ct, "base64url");
  const tag = Buffer.from(wrapped.tag, "base64url");

  const decipher = crypto.createDecipheriv("aes-256-gcm", wrapKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ========================
// Helpers
// ========================
function getOrgKeys(orgId) {
  if (!db.keys.has(orgId)) db.keys.set(orgId, []);
  return db.keys.get(orgId);
}

function getActiveKeyRecord(orgId) {
  const keys = getOrgKeys(orgId);
  return keys.find((k) => k.status === "Active") || null;
}

// ========================
// DEV: Seed Admin
// ========================
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
    status: "Active"
  });

  scheduleSaveDb(db);
  audit(orgId, userId, "seed_admin", { username }, req);

  return res.json({ ok: true, orgId, username, password });
});

// ========================
// Login
// ========================
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

// ========================
// Admin: create users
// ========================
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
    status: "Active"
  });

  scheduleSaveDb(db);
  audit(orgId, req.user.userId, "create_user", { targetUserId: userId, username, role }, req);

  return res.json({ ok: true, userId, username, role });
});

// Admin: list users
app.get("/admin/users", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.user.orgId;

  const users = Array.from(db.users.values())
    .filter(u => u.orgId === orgId)
    .map(u => ({
      userId: u.userId,
      username: u.username,
      role: u.role,
      status: u.status
    }));

  res.json({ users });
});

// ========================
// Admin: Keys Rotation
// ========================
app.post("/admin/keys/rotate", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.user.orgId;
  const keys = getOrgKeys(orgId);

  const active = getActiveKeyRecord(orgId);
  const nextVersion = active ? active.version + 1 : 1;

  const rawKey = crypto.randomBytes(32);
  const wrapped = wrapRawKey(rawKey);

  if (active) active.status = "Retiring";

  const now = new Date().toISOString();
  keys.push({
    version: nextVersion,
    status: "Active",
    wrappedKey: wrapped,
    createdAt: now,
    activatedAt: now,
    retiredAt: null
  });

  scheduleSaveDb(db);
  audit(orgId, req.user.userId, "rotate_key", { keyVersion: nextVersion }, req);

  return res.json({ ok: true, activeVersion: nextVersion });
});

app.post("/admin/keys/:version/retire", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.user.orgId;
  const version = Number(req.params.version);

  const keys = getOrgKeys(orgId);
  const key = keys.find((k) => k.version === version);
  if (!key) return res.status(404).json({ error: "Key not found" });

  const active = getActiveKeyRecord(orgId);
  if (active && active.version === version) {
    return res.status(400).json({ error: "Cannot retire active key. Rotate first." });
  }

  key.status = "Retired";
  key.retiredAt = new Date().toISOString();

  scheduleSaveDb(db);
  audit(orgId, req.user.userId, "retire_key", { keyVersion: version }, req);

  return res.json({ ok: true });
});

// Admin: list keys (metadata only)
app.get("/admin/keys", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.user.orgId;
  const keys = getOrgKeys(orgId).map(k => ({
    version: k.version,
    status: k.status,
    createdAt: k.createdAt,
    activatedAt: k.activatedAt,
    retiredAt: k.retiredAt
  }));

  res.json({ keys });
});

// ========================
// Member: Key info / material
// ========================
app.get("/keys/active", requireAuth, (req, res) => {
  const active = getActiveKeyRecord(req.user.orgId);
  if (!active) return res.status(404).json({ error: "No active key. Admin must rotate/create one." });
  return res.json({ version: active.version });
});

app.get("/keys/:version/material", requireAuth, (req, res) => {
  const orgId = req.user.orgId;
  const version = Number(req.params.version);

  const keys = getOrgKeys(orgId);
  const key = keys.find((k) => k.version === version);

  if (!key) return res.status(404).json({ error: "Key not found" });
  if (key.status === "Retired") return res.status(410).json({ error: "Key retired" });

  const raw = unwrapRawKey(key.wrappedKey);

  // 🔥 This is the event you want to track in dashboard ("who accessed keys")
  audit(orgId, req.user.userId, "get_key_material", { keyVersion: version }, req);

  return res.json({ version, alg: "AES-GCM-256", keyB64: raw.toString("base64url") });
});

// ========================
// Messages (link sharing)
// ========================
app.post("/api/messages", requireAuth, (req, res) => {
  const { keyVersion, iv, ciphertext, aad } = req.body || {};
  if (!keyVersion || !iv || !ciphertext) {
    return res.status(400).json({ error: "keyVersion, iv, ciphertext required" });
  }

  const id = nanoid(12);
  const createdAt = new Date().toISOString();

  db.messages.set(id, {
    msgId: id,
    orgId: req.user.orgId,
    createdBy: req.user.userId,
    keyVersion: Number(keyVersion),
    iv,
    ciphertext,
    aad: aad || null,
    createdAt
  });

  scheduleSaveDb(db);
  audit(req.user.orgId, req.user.userId, "encrypt", { messageId: id, keyVersion: Number(keyVersion) }, req);

  const base = getPublicBase(req);
  const url = `${base}/m/${id}`;
  return res.json({ id, url });
});

app.get("/api/messages/:id", requireAuth, (req, res) => {
  const msg = db.messages.get(req.params.id);
  if (!msg) return res.status(404).json({ error: "Not found" });
  if (msg.orgId !== req.user.orgId) return res.status(403).json({ error: "Wrong org" });

  audit(req.user.orgId, req.user.userId, "fetch_message", { messageId: msg.msgId, keyVersion: msg.keyVersion }, req);

  return res.json({
    id: msg.msgId,
    keyVersion: msg.keyVersion,
    iv: msg.iv,
    ciphertext: msg.ciphertext,
    aad: msg.aad,
    createdAt: msg.createdAt
  });
});

// ========================
// Admin: Audit log
// ========================
app.get("/admin/audit", requireAuth, requireAdmin, (req, res) => {
  const orgId = req.user.orgId;
  const limit = Math.min(Number(req.query.limit || 200), 1000);

  const items = (db.audit || [])
    .filter(a => a.orgId === orgId)
    .slice(-limit)
    .reverse();

  res.json({ items });
});

// ========================
// Portal static + routes
// ========================
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
