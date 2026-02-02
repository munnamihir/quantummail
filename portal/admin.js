const API = window.location.origin;

function $(id) { return document.getElementById(id); }

function setStatus(msg, ok = false) {
  const el = $("status");
  el.textContent = msg;
  el.className = ok ? "ok" : "muted";
}

function setError(msg) {
  $("error").textContent = msg || "";
}

function saveSession(s) {
  localStorage.setItem("qm_admin_session", JSON.stringify(s));
}

function loadSession() {
  try {
    const raw = localStorage.getItem("qm_admin_session");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function clearSession() {
  localStorage.removeItem("qm_admin_session");
}

async function apiFetch(path, opts = {}) {
  const session = loadSession();
  const headers = { ...(opts.headers || {}) };

  if (session?.token) headers["Authorization"] = `Bearer ${session.token}`;
  if (opts.json) headers["Content-Type"] = "application/json";

  const res = await fetch(`${API}${path}`, {
    method: opts.method || "GET",
    headers,
    body: opts.json ? JSON.stringify(opts.json) : opts.body
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function renderKeys(keys) {
  const tb = $("keysTable").querySelector("tbody");
  tb.innerHTML = "";
  for (const k of keys) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${k.version}</td>
      <td>${k.status}</td>
      <td>${k.createdAt || "-"}</td>
      <td>${k.activatedAt || "-"}</td>
      <td>${k.retiredAt || "-"}</td>
    `;
    tb.appendChild(tr);
  }
}

function renderUsers(users) {
  const tb = $("usersTable").querySelector("tbody");
  tb.innerHTML = "";
  for (const u of users) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${u.userId}</td>
      <td>${u.username}</td>
      <td>${u.role}</td>
      <td>${u.status}</td>
    `;
    tb.appendChild(tr);
  }
}

function renderAudit(items) {
  const tb = $("auditTable").querySelector("tbody");
  tb.innerHTML = "";
  for (const a of items) {
    const details = { ...a };
    delete details.id; delete details.orgId; delete details.userId;
    delete details.action; delete details.at; delete details.ip; delete details.ua;

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${a.at}</td>
      <td><b>${a.action}</b></td>
      <td>${a.userId || "-"}</td>
      <td><code>${escapeHtml(JSON.stringify(details))}</code></td>
      <td>${a.ip || "-"}</td>
    `;
    tb.appendChild(tr);
  }
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function refreshAll() {
  setError("");
  setStatus("Loading…");

  const active = await apiFetch("/keys/active");
  $("activeKey").textContent = active.version;

  const keys = await apiFetch("/admin/keys");
  renderKeys(keys.keys || []);

  const users = await apiFetch("/admin/users");
  renderUsers(users.users || []);

  const audit = await apiFetch("/admin/audit?limit=200");
  renderAudit(audit.items || []);

  setStatus("Loaded ✅", true);
}

async function login() {
  const orgId = ($("orgId").value || "").trim();
  const username = ($("username").value || "").trim();
  const password = $("password").value || "";

  if (!orgId || !username || !password) throw new Error("orgId/username/password required");

  const data = await apiFetch("/auth/login", {
    method: "POST",
    json: { orgId, username, password }
  });

  saveSession({ token: data.token, orgId, username });

  $("loginBox").style.display = "none";
  $("actionsBox").style.display = "";
  setStatus(`Signed in as ${username} (Admin).`, true);

  await refreshAll();
}

async function seedAdmin() {
  const orgId = ($("orgId").value || "org_demo").trim() || "org_demo";

  await apiFetch("/dev/seed-admin", {
    method: "POST",
    json: { orgId, username: "admin", password: "admin123" }
  });

  setStatus("Seeded (or already exists). Now login with admin/admin123.", true);
}

async function rotateKey() {
  await apiFetch("/admin/keys/rotate", { method: "POST" });
  await refreshAll();
}

async function createMember() {
  const username = prompt("Member username (e.g., alice):", "alice");
  if (!username) return;
  const password = prompt("Member password:", "alice123");
  if (!password) return;

  await apiFetch("/admin/users", {
    method: "POST",
    json: { username, password, role: "Member" }
  });

  await refreshAll();
}

function logout() {
  clearSession();
  $("loginBox").style.display = "";
  $("actionsBox").style.display = "none";
  $("activeKey").textContent = "-";
  setStatus("Logged out.");
}

// Wire up buttons
$("btnLogin").addEventListener("click", async () => {
  try { await login(); } catch (e) { setError(e.message || String(e)); }
});

$("btnSeed").addEventListener("click", async () => {
  try { await seedAdmin(); } catch (e) { setError(e.message || String(e)); }
});

$("btnRefresh").addEventListener("click", async () => {
  try { await refreshAll(); } catch (e) { setError(e.message || String(e)); }
});

$("btnRotate").addEventListener("click", async () => {
  try { await rotateKey(); } catch (e) { setError(e.message || String(e)); }
});

$("btnCreateUser").addEventListener("click", async () => {
  try { await createMember(); } catch (e) { setError(e.message || String(e)); }
});

$("btnLogout").addEventListener("click", logout);

// Init
(() => {
  const s = loadSession();
  if (s?.token) {
    $("orgId").value = s.orgId || "org_demo";
    $("username").value = s.username || "admin";
    $("loginBox").style.display = "none";
    $("actionsBox").style.display = "";
    setStatus(`Session found for ${s.username}. Refreshing…`, true);
    refreshAll().catch((e) => setError(e.message || String(e)));
  } else {
    $("orgId").value = "org_demo";
  }
})();
