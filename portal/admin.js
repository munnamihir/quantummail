const API = window.location.origin;

function $(id) { return document.getElementById(id); }

function setStatus(msg) { const el = $("status"); if (el) el.textContent = msg || ""; }
function setError(msg) { const el = $("error"); if (el) el.textContent = msg || ""; }

function showLoggedInUi(isLoggedIn) {
  const loginBox = $("loginBox");
  const actionsBox = $("actionsBox");
  if (loginBox) loginBox.style.display = isLoggedIn ? "none" : "block";
  if (actionsBox) actionsBox.style.display = isLoggedIn ? "block" : "none";
}

function saveSession(session) { localStorage.setItem("qm_admin_session", JSON.stringify(session)); }
function loadSession() {
  try { return JSON.parse(localStorage.getItem("qm_admin_session") || "null"); }
  catch { return null; }
}
function clearSession() { localStorage.removeItem("qm_admin_session"); }

async function apiFetch(path, { method = "GET", token = null, json = null } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (json) headers["Content-Type"] = "application/json";

  const res = await fetch(`${API}${path}`, { method, headers, body: json ? JSON.stringify(json) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Keep last audit in memory for CSV download
let lastAuditItems = [];

// -----------------------
// Rendering
// -----------------------
function renderUsers(users) {
  const tb = $("usersTable")?.querySelector("tbody");
  if (!tb) return;
  tb.innerHTML = "";

  for (const u of users) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(u.userId)}</td>
      <td>${escapeHtml(u.username)}</td>
      <td>${escapeHtml(u.role)}</td>
      <td>${escapeHtml(u.status)}</td>
      <td>${u.hasPublicKey ? "✅" : "❌"}</td>
    `;
    tb.appendChild(tr);
  }
}

function renderAudit(items) {
  lastAuditItems = Array.isArray(items) ? items : [];

  const tb = $("auditTable")?.querySelector("tbody");
  if (!tb) return;
  tb.innerHTML = "";

  for (const a of lastAuditItems) {
    const details = { ...a };
    delete details.id;
    delete details.orgId;
    delete details.userId;
    delete details.action;
    delete details.ip;
    delete details.ua;
    delete details.at;

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(a.at)}</td>
      <td>${escapeHtml(a.action)}</td>
      <td>${escapeHtml(a.userId)}</td>
      <td><code>${escapeHtml(JSON.stringify(details))}</code></td>
      <td>${escapeHtml(a.ip || "")}</td>
    `;
    tb.appendChild(tr);
  }
}

// -----------------------
// CSV download
// -----------------------
function csvEscape(v) {
  const s = v == null ? "" : String(v);
  return `"${s.replace(/"/g, '""')}"`;
}

function downloadTextFile(filename, text, mime = "text/csv") {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function auditToCsv(items) {
  const headers = ["time", "action", "userId", "ip", "userAgent", "details"];
  const lines = [headers.map(csvEscape).join(",")];

  for (const a of items) {
    const detailsObj = { ...a };
    delete detailsObj.id;
    delete detailsObj.orgId;
    delete detailsObj.userId;
    delete detailsObj.action;
    delete detailsObj.ip;
    delete detailsObj.ua;
    delete detailsObj.at;

    const row = [
      a.at || "",
      a.action || "",
      a.userId || "",
      a.ip || "",
      a.ua || "",
      Object.keys(detailsObj).length ? JSON.stringify(detailsObj) : ""
    ];

    lines.push(row.map(csvEscape).join(","));
  }

  return lines.join("\n");
}

// -----------------------
// Actions
// -----------------------
async function seedAdmin() {
  setError("");
  setStatus("Seeding admin…");
  const data = await apiFetch("/dev/seed-admin", {
    method: "POST",
    json: { orgId: "org_demo", username: "admin", password: "admin123" }
  });
  setStatus(`Seeded ✅ (${data.note || "created"})`);
}

async function loginAdmin() {
  setError("");
  setStatus("Logging in...");

  const orgId = $("orgId")?.value.trim();
  const username = $("username")?.value.trim();
  const password = $("password")?.value;

  if (!orgId || !username || !password) throw new Error("orgId, username, password required");

  const data = await apiFetch("/auth/login", { method: "POST", json: { orgId, username, password } });

  if (data?.user?.role !== "Admin") throw new Error("Not an admin user");

  saveSession({ token: data.token, user: data.user });
  showLoggedInUi(true);

  setStatus("Logged in ✅");
  await refreshAll();
}

async function refreshAll() {
  setError("");
  const session = loadSession();
  if (!session?.token) throw new Error("Not logged in");

  setStatus("Loading users + audit...");

  const [usersRes, auditRes] = await Promise.all([
    apiFetch("/admin/users", { token: session.token }),
    apiFetch("/admin/audit?limit=200", { token: session.token })
  ]);

  renderUsers(usersRes.users || []);
  renderAudit(auditRes.items || []);

  setStatus("Updated ✅");
}

async function createMember() {
  setError("");
  const session = loadSession();
  if (!session?.token) throw new Error("Not logged in");

  const newUsername = $("newUsername")?.value.trim();
  const newPassword = $("newPassword")?.value;
  const role = $("newRole")?.value || "Member";

  if (!newUsername || !newPassword) throw new Error("New username/password required");

  setStatus("Creating user...");
  await apiFetch("/admin/users", {
    method: "POST",
    token: session.token,
    json: { username: newUsername, password: newPassword, role }
  });

  $("newUsername").value = "";
  $("newPassword").value = "";

  setStatus("User created ✅");
  await refreshAll();
}

function logout() {
  clearSession();
  showLoggedInUi(false);
  setStatus("Logged out.");
  setError("");
  renderUsers([]);
  renderAudit([]);
}

// -----------------------
// Wire up
// -----------------------
document.addEventListener("DOMContentLoaded", async () => {
  $("btnSeed")?.addEventListener("click", () => seedAdmin().catch(e => setError(e.message || String(e))));
  $("btnLogin")?.addEventListener("click", () => loginAdmin().catch(e => setError(e.message || String(e))));
  $("btnRefresh")?.addEventListener("click", () => refreshAll().catch(e => setError(e.message || String(e))));
  $("btnCreateUser")?.addEventListener("click", () => createMember().catch(e => setError(e.message || String(e))));
  $("btnLogout")?.addEventListener("click", logout);

  $("btnDownloadAudit")?.addEventListener("click", () => {
    try {
      if (!lastAuditItems.length) {
        alert("No audit log loaded yet. Click Refresh first.");
        return;
      }
      const session = loadSession();
      const org = session?.user?.orgId || "org";
      const ts = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = `quantummail-audit-${org}-${ts}.csv`;
      downloadTextFile(filename, auditToCsv(lastAuditItems));
    } catch (e) {
      setError(e.message || String(e));
    }
  });

  // Auto-load if already logged in
  const session = loadSession();
  if (session?.token) {
    showLoggedInUi(true);
    refreshAll().catch(() => {});
  } else {
    showLoggedInUi(false);
  }
});
