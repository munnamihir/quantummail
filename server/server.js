import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { nanoid } from "nanoid";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: "1mb" }));

// In-memory store (MVP). If server restarts, links die.
<<<<<<< HEAD
// Later swap this for JSON/DB/Redis.
const store = new Map();

// Helper: build public base URL in Codespaces using forwarded URL (if present)
=======
// Later you can swap this for JSON/DB/Redis.
const store = new Map();

// Build public base URL in Codespaces using forwarded URL (if present)
>>>>>>> 59c231d (Update server.js)
function getPublicBase(req) {
  const proto = req.headers["x-forwarded-proto"] || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  return `${proto}://${host}`;
}

// --- API: create message ---
app.post("/api/messages", (req, res) => {
  const payload = req.body || {};

<<<<<<< HEAD
  // Minimal validation: must have iv/ciphertext (+ wrappedKeys in your enterprise model)
=======
>>>>>>> 59c231d (Update server.js)
  if (!payload.iv || !payload.ciphertext) {
    return res.status(400).json({ error: "Invalid payload" });
  }

  const id = nanoid(10);
  const createdAt = new Date().toISOString();
<<<<<<< HEAD

=======
>>>>>>> 59c231d (Update server.js)
  store.set(id, { ...payload, createdAt });

  const base = getPublicBase(req);

<<<<<<< HEAD
  // ✅ Canonical decrypt link (NOT /portal/m/...)
=======
  // ✅ canonical link
>>>>>>> 59c231d (Update server.js)
  const url = `${base}/m/${id}`;

  res.json({ id, url });
});

// --- API: fetch message ---
app.get("/api/messages/:id", (req, res) => {
  const id = req.params.id;
  const msg = store.get(id);
  if (!msg) return res.status(404).json({ error: "Not found" });
  res.json({ id, ...msg });
});

// Serve static portal files at /portal
const portalDir = path.join(__dirname, "..", "portal");
app.use("/portal", express.static(portalDir, { extensions: ["html"] }));

<<<<<<< HEAD
// ✅ /m/:id should load decrypt.html
=======
// ✅ /m/:id always loads portal/decrypt.html
>>>>>>> 59c231d (Update server.js)
app.get("/m/:id", (_req, res) => {
  res.sendFile(path.join(portalDir, "decrypt.html"));
});

// Nice default: go to compose
app.get("/", (_req, res) => res.redirect("/portal/compose.html"));

const PORT = process.env.PORT || 5173;
app.listen(PORT, () => {
  console.log(`QuantumMail portal running on port ${PORT}`);
});
