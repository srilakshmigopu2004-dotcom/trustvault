"use strict";
// All user-controlled text is inserted with textContent (via h()), never innerHTML.
let csrf = "", me = null;
const $ = (s) => document.querySelector(s);

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null) continue;
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else e.setAttribute(k, v);
  }
  // DESIGN: Text nodes keep untrusted labels inert instead of interpreting them as markup.
  for (const k of kids.flat()) if (k != null) e.append(k.nodeType ? k : document.createTextNode(String(k)));
  return e;
}
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.classList.add("show"); setTimeout(() => t.classList.remove("show"), 2600); }

async function api(method, url, body, form) {
  const opt = { method, credentials: "same-origin", headers: {} };
  if (csrf) opt.headers["X-CSRF-Token"] = csrf;
  if (form) opt.body = form;
  else if (body) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(url, opt);
  let data = null; try { data = await r.json(); } catch (_) {}
  if (!r.ok) throw Object.assign(new Error((data && data.error) || r.statusText), { status: r.status });
  return data;
}
const guard = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message); if (e.status === 401) boot(); } };
const qs = (o) => Object.entries(o).filter(([, v]) => v).map(([k, v]) => k + "=" + encodeURIComponent(v)).join("&");
const kb = (n) => (n / 1024).toFixed(1) + " KB";

async function boot() {
  try { const u = await api("GET", "/api/auth/me"); me = u; csrf = u.csrf; } catch (_) { me = null; csrf = ""; }
  me ? shell() : loginView();
}

// DESIGN: A split layout adds a vault visual while preserving the existing sign-in flow.
function loginView() {
  document.body.classList.add("login-state");
  $("#nav").replaceChildren(); $("#who").textContent = "";
  // DESIGN: Keep credential types, autocomplete hints, and required checks unchanged for the server contract.
  const email = h("input", { type: "email", placeholder: "email", required: "", autocomplete: "username" });
  const pw = h("input", { type: "password", placeholder: "password", required: "", autocomplete: "current-password" });
  // DESIGN: The artwork is decorative; the form remains a separate, keyboard-accessible panel.
  $("#main").replaceChildren(h("section", { class: "login-layout", "aria-label": "Sign in to TrustVault" },
    h("div", { class: "login-art", "aria-hidden": "true" }, h("div", { class: "vault-dial" }), h("div", { class: "vault-seal" })),
    h("div", { class: "card login-card" }, h("h2", {}, "Sign in"),
    // DESIGN: Reuse the same endpoint and email/password keys; the redesign changes no authentication behavior.
    h("form", { class: "row", onsubmit: guard(async (ev) => {
      ev.preventDefault();
      await api("POST", "/api/auth/login", { email: email.value, password: pw.value }); boot();
    }) }, email, pw, h("button", { class: "primary" }, "Sign in")))));
}

function shell() {
  document.body.classList.remove("login-state");
  $("#who").textContent = `${me.name} (${me.role})`;
  // DESIGN: Owners get document-scoped modules; admins retain global audit access and viewers see only permitted documents.
  const tabs = me.role === "admin" ? [["Activity", adminView], ["Users", usersView], ["Profile", profileView]] : me.role === "owner"
    ? [["Documents", docsView], ["History", historyView], ["Recommendations", recommendationsView], ["Profile", profileView]]
    : [["Documents", docsView], ["Profile", profileView]];
  const nav = $("#nav"); nav.replaceChildren();
  tabs.forEach(([label, fn], i) => nav.append(h("button", { class: i ? "" : "active", onclick: (e) => {
    nav.querySelectorAll("button").forEach((b) => b.classList.remove("active")); e.target.classList.add("active"); fn();
  } }, label)));
  nav.append(h("span", { class: "grow" }), h("button", { onclick: guard(async () => { await api("POST", "/api/auth/logout"); boot(); }) }, "Sign out"));
  tabs[0][1]();
}

// DESIGN: The profile view edits only the signed-in account and never exposes credential hashes.
function profileView() {
  const name = h("input", { value: me.name, maxlength: "100", required: "", autocomplete: "name" });
  const email = h("input", { type: "email", value: me.email, maxlength: "254", required: "", autocomplete: "email" });
  const phone = h("input", { type: "tel", value: me.phone || "", maxlength: "32", autocomplete: "tel", placeholder: "+1 555 010 1234" });
  const currentPassword = h("input", { type: "password", autocomplete: "current-password", placeholder: "Required only when changing email" });
  const profileForm = h("form", { class: "card profile-card", onsubmit: guard(async (event) => {
    event.preventDefault();
    const body = { name: name.value, email: email.value, phone: phone.value };
    if (email.value.trim().toLowerCase() !== me.email) body.current_password = currentPassword.value;
    const updated = await api("PATCH", "/api/auth/profile", body);
    me = Object.assign(me, updated);
    $("#who").textContent = `${me.name} (${me.role})`;
    currentPassword.value = "";
    toast("Profile saved");
  }) },
    h("h3", {}, "Account details"),
    h("label", { class: "profile-field" }, h("span", {}, "Full name"), name),
    h("label", { class: "profile-field" }, h("span", {}, "Login email"), email),
    h("label", { class: "profile-field" }, h("span", {}, "Phone"), phone),
    h("label", { class: "profile-field" }, h("span", {}, "Current password"), currentPassword),
    h("p", { class: "mut profile-hint" }, "Current password is checked when you change your login email."),
    h("button", { class: "primary" }, "Save profile"));

  const current = h("input", { type: "password", required: "", autocomplete: "current-password" });
  const next = h("input", { type: "password", required: "", minlength: "12", maxlength: "200", autocomplete: "new-password" });
  const confirmNext = h("input", { type: "password", required: "", minlength: "12", maxlength: "200", autocomplete: "new-password" });
  const passwordForm = h("form", { class: "card profile-card", onsubmit: guard(async (event) => {
    event.preventDefault();
    if (next.value !== confirmNext.value) {
      toast("New passwords do not match");
      return;
    }
    await api("POST", "/api/auth/password", { current_password: current.value, new_password: next.value });
    // DESIGN: Password updates revoke all sessions, so return to sign-in rather than use a dead session.
    me = null;
    csrf = "";
    loginView();
    toast("Password changed. Sign in with your new password.");
  }) },
    h("h3", {}, "Change password"),
    h("label", { class: "profile-field" }, h("span", {}, "Current password"), current),
    h("label", { class: "profile-field" }, h("span", {}, "New password"), next),
    h("label", { class: "profile-field" }, h("span", {}, "Confirm new password"), confirmNext),
    h("p", { class: "mut profile-hint" }, "Use 12-200 characters. You will need to sign in again on your devices."),
    h("button", { class: "primary" }, "Update password"));

  $("#main").replaceChildren(h("h2", {}, "Profile"),
    h("p", { class: "module-intro" }, "Manage the details used for your TrustVault account."),
    h("div", { class: "profile-grid" }, profileForm, passwordForm));
}

// DESIGN: This helper limits added modules to documents the current owner can manage.
async function managedDocuments() {
  const result = await api("GET", "/api/documents?limit=100");
  return result.items.filter((doc) => doc.my_access === "manage");
}

// DESIGN: History requests one managed document at a time through its existing audit endpoint.
async function historyView() {
  let documents = [];
  const documentSelect = h("select", { "aria-label": "Document" });
  const results = h("div", { class: "module-results" });
  // DESIGN: The selection is checked against the managed list before making a document audit request.
  const loadHistory = guard(async () => {
    const doc = documents.find((item) => String(item.id) === documentSelect.value);
    if (!doc) {
      results.replaceChildren(h("p", { class: "empty-state" }, "No managed documents are available."));
      return;
    }
    const audit = await api("GET", `/api/documents/${doc.id}/audit`);
    results.replaceChildren(
      h("div", { class: "module-meta" }, `${audit.items.length} event(s) for ${doc.name}`),
      audit.items.length ? h("table", {},
        h("thead", {}, h("tr", {}, ["When", "Actor", "Event", "Outcome", "Details"].map((label) => h("th", {}, label)))),
        h("tbody", {}, audit.items.map((event) => h("tr", {},
          h("td", {}, event.ts.replace("T", " ").slice(0, 19)),
          h("td", {}, event.actor_email || "System"),
          h("td", {}, event.action),
          h("td", { class: "status status-audit status-" + event.outcome }, event.outcome),
          h("td", {}, JSON.stringify(event.detail || {})))))
        ) : h("p", { class: "empty-state" }, "No history for this document yet."));
  });
  documents = await managedDocuments();
  documentSelect.replaceChildren(...documents.map((doc) => h("option", { value: String(doc.id) }, doc.name)));
  // DESIGN: The module keeps selection and reload controls together for quick document-to-document review.
  const controls = h("form", { class: "row module-controls", onsubmit: (event) => { event.preventDefault(); loadHistory(); } },
    documentSelect, h("button", { class: "primary" }, "Load history"));
  $("#main").replaceChildren(h("h2", {}, "History"),
    h("p", { class: "module-intro" }, "Review audit events for documents you manage."), controls, results);
  if (documents.length) loadHistory();
  else results.replaceChildren(h("p", { class: "empty-state" }, "No managed documents are available."));
}

// DESIGN: Recommendations reuse the existing metadata-only suggestion endpoint and require a human grant confirmation.
async function recommendationsView() {
  let documents = [];
  const documentSelect = h("select", { "aria-label": "Document" });
  const results = h("div", { class: "recommendation-results" });
  // DESIGN: Selecting another document clears stale candidates so a suggestion cannot be confirmed against the wrong record.
  documentSelect.addEventListener("change", () => results.replaceChildren());
  // DESIGN: The request remains advisory and is sent only for a document in the manager-filtered list.
  const requestSuggestions = guard(async (event) => {
    event.preventDefault();
    const doc = documents.find((item) => String(item.id) === documentSelect.value);
    if (!doc) {
      results.replaceChildren(h("p", { class: "empty-state" }, "Choose a managed document first."));
      return;
    }
    const suggestion = await api("POST", `/api/documents/${doc.id}/suggestions`);
    // DESIGN: Server notes, names, emails, and reasons are rendered as text nodes, never interpreted as HTML.
    const candidates = suggestion.candidates.map((candidate) => {
      const confirmButton = h("button", { class: "primary", type: "button", onclick: guard(async () => {
        if (!confirm(`Give ${candidate.email} read access to ${doc.name}?`)) return;
        await api("POST", `/api/documents/${doc.id}/grants`, {
          email: candidate.email, level: "read", suggestion_id: suggestion.suggestion_id,
        });
        confirmButton.textContent = "Granted";
        confirmButton.disabled = "";
        toast("Read access granted");
      }) }, "Confirm read access");
      return h("article", { class: "recommendation-row" },
        h("div", {}, h("strong", {}, candidate.name), h("div", { class: "mut" }, candidate.email),
          h("p", { class: "recommendation-reason" }, candidate.reason)), confirmButton);
    });
    results.replaceChildren(
      h("p", { class: "module-note" }, suggestion.note),
      candidates.length ? h("div", { class: "recommendation-list" }, candidates)
        : h("p", { class: "empty-state" }, "No suggested recipients for this document."));
  });
  documents = await managedDocuments();
  documentSelect.replaceChildren(...documents.map((doc) => h("option", { value: String(doc.id) }, doc.name)));
  // DESIGN: Recommendations stay transparent about their metadata basis and manual approval requirement.
  const controls = h("form", { class: "row module-controls", onsubmit: requestSuggestions },
    documentSelect, h("button", { class: "primary" }, "Find recipients"));
  $("#main").replaceChildren(h("h2", {}, "Recommendations"),
    h("p", { class: "module-intro" }, "Metadata-based suggestions. Access is granted only after your confirmation."),
    controls, results);
  if (!documents.length) results.replaceChildren(h("p", { class: "empty-state" }, "No managed documents are available."));
}

// DESIGN: The document ledger keeps existing document queries while adding access-level presentation.
function docsView() {
  const f = {};
  const field = (name, ph, type = "text") => (f[name] = h("input", { type, placeholder: ph, "aria-label": ph }));
  const list = h("div"), panel = h("div");
  // DESIGN: Search remains the same request path; only rendered status cells receive visual classes.
  const search = guard(async (ev) => {
    ev && ev.preventDefault();
    const d = await api("GET", "/api/documents?" + qs(Object.fromEntries(Object.entries(f).map(([k, e]) => [k, e.value]))));
    list.replaceChildren(h("div", { class: "mut" }, `${d.total} document(s)`), h("table", {},
      h("thead", {}, h("tr", {}, ["Name", "Category", "Owner", "My access", "Size", "Created", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, d.items.map((x) => h("tr", {}, h("td", {}, x.name), h("td", {}, x.category), h("td", {}, x.owner_name),
        // DESIGN: The pill decorates the existing access text without changing its value or permission check.
        h("td", { class: "status status-access status-" + x.my_access }, x.my_access), h("td", {}, kb(x.size)), h("td", {}, x.created_at.slice(0, 10)),
        h("td", {}, h("a", { href: `/api/documents/${x.id}/download` }, "Download"), " ",
          x.my_access === "manage" ? [h("button", { onclick: () => sharePanel(x) }, "Share"), " ",
            h("button", { class: "danger", onclick: guard(async () => { if (confirm(`Delete ${x.name}?`)) { await api("DELETE", `/api/documents/${x.id}`); toast("Deleted"); search(); panel.replaceChildren(); } }) }, "Delete")] : null))))));
  });
  // DESIGN: Sharing controls keep their existing grant contract while the activity trail gains outcome pills.
  const sharePanel = guard(async (doc) => {
    const [g, a] = await Promise.all([api("GET", `/api/documents/${doc.id}/grants`), api("GET", `/api/documents/${doc.id}/audit`)]);
    const email = h("input", { type: "email", placeholder: "person's email", required: "" });
    const level = h("select", {}, h("option", { value: "read" }, "read"), h("option", { value: "edit" }, "edit"));
    const sug = h("div");
    const grant = guard(async (em, lv, sid) => { await api("POST", `/api/documents/${doc.id}/grants`, { email: em, level: lv, suggestion_id: sid }); toast("Access granted"); sharePanel(doc); });
    panel.replaceChildren(h("div", { class: "card" }, h("h3", {}, "Sharing: " + doc.name),
      h("table", {}, h("tbody", {}, g.items.length ? g.items.map((x) => h("tr", {}, h("td", {}, x.email),
        // DESIGN: Grant levels use the same visual key as document access, while text remains a safe text node.
        h("td", { class: "status status-access status-" + x.level }, x.level),
        h("td", {}, h("button", { class: "danger", onclick: guard(async () => { await api("DELETE", `/api/documents/${doc.id}/grants/${x.user_id}`); toast("Access revoked"); sharePanel(doc); }) }, "Revoke")))) : h("tr", {}, h("td", { class: "mut" }, "Only you can access this document")))),
      h("form", { class: "row", onsubmit: (ev) => { ev.preventDefault(); grant(email.value, level.value); } }, email, level, h("button", { class: "primary" }, "Grant")),
      h("div", { class: "row" }, h("button", { onclick: guard(async () => {
        const s = await api("POST", `/api/documents/${doc.id}/suggestions`);
        sug.replaceChildren(h("div", { class: "mut" }, s.note), s.candidates.length ? s.candidates.map((c) => h("div", { class: "row" },
          h("span", {}, `${c.name} <${c.email}> – ${c.reason}`),
          h("button", { onclick: () => confirm(`Give ${c.email} read access?`) && grant(c.email, "read", s.suggestion_id) }, "Confirm read access"))) : h("div", { class: "mut" }, "No suggestions."));
      }) }, "Suggest people"), sug),
      h("h3", {}, "Activity on this document"),
      h("table", {}, h("tbody", {}, a.items.slice(0, 15).map((r) => h("tr", {}, h("td", {}, r.ts.replace("T", " ").slice(0, 19)), h("td", {}, r.actor_email || "—"),
        h("td", { class: "status status-audit status-" + r.outcome }, r.action + (r.outcome === "ok" ? "" : " (" + r.outcome + ")"))))))));
  });
  const parts = [h("h2", {}, "Documents"),
    h("form", { class: "row", onsubmit: search }, field("q", "name"), field("owner", "owner"), field("category", "category"),
      field("date_from", "from", "date"), field("date_to", "to", "date"), h("button", {}, "Search"))];
  if (me.role === "owner") {
    const file = h("input", { type: "file", required: "" }), cat = h("input", { placeholder: "category (e.g. hr)" });
    parts.push(h("form", { class: "row", onsubmit: guard(async (ev) => {
      ev.preventDefault(); const fd = new FormData(); fd.append("file", file.files[0]); fd.append("category", cat.value || "general");
      await api("POST", "/api/documents", null, fd); toast("Uploaded"); ev.target.reset(); search();
    }) }, h("strong", {}, "Upload"), file, cat, h("button", { class: "primary" }, "Upload")));
  }
  $("#main").replaceChildren(...parts, list, panel); search();
}

// DESIGN: The admin ledger keeps the same audit filters and verification actions while clarifying outcomes.
function adminView() {
  const out = h("div");
  const f = { actor: h("input", { placeholder: "actor email" }), action: h("input", { placeholder: "action" }),
    outcome: h("select", {}, ["", "ok", "denied", "rejected"].map((o) => h("option", { value: o }, o || "any outcome"))) };
  // DESIGN: Audit requests and filters are unchanged; status classes only affect the outcome's appearance.
  const load = guard(async (ev) => {
    ev && ev.preventDefault();
    const [act, log] = await Promise.all([api("GET", "/api/admin/activity"),
      api("GET", "/api/admin/audit?" + qs({ actor: f.actor.value, action: f.action.value, outcome: f.outcome.value, limit: 100 }))]);
    out.replaceChildren(
      h("div", { class: "card" }, h("h3", {}, "Worth noticing (last 24h)"), act.alerts.length ? act.alerts.map((a) => h("div", { class: "bad" }, `${a.kind}: ${a.actor || a.target} ×${a.count}`)) : h("div", { class: "mut" }, "Nothing flagged."),
        h("h3", {}, "Permission changes"), h("table", {}, h("tbody", {}, act.permission_changes.slice(0, 10).map((p) => h("tr", {}, h("td", {}, p.ts.slice(0, 19).replace("T", " ")), h("td", {}, p.actor_email), h("td", {}, p.action), h("td", {}, p.doc_name), h("td", {}, JSON.stringify({ to: p.detail.email, level: p.detail.level }))))))),
      h("table", {}, h("thead", {}, h("tr", {}, ["When", "Actor", "Action", "Outcome", "Document", "Detail"].map((t) => h("th", {}, t)))),
        h("tbody", {}, log.items.map((r) => h("tr", {}, h("td", {}, r.ts.slice(0, 19).replace("T", " ")), h("td", {}, r.actor_email || "—"), h("td", {}, r.action),
          h("td", { class: "status status-audit status-" + r.outcome }, r.outcome), h("td", {}, r.doc_name || ""), h("td", {}, JSON.stringify(r.detail)))))));
  });
  const verify = guard(async () => { const v = await api("GET", "/api/admin/audit/verify"); const hd = await api("GET", "/api/admin/audit/head");
    toast(v.ok ? `Audit chain intact (${v.checked} rows). Head ${hd.head.slice(0, 12)}…` : `CHAIN BROKEN at row ${v.first_bad_id}`); });
  $("#main").replaceChildren(h("h2", {}, "Activity & audit"), h("form", { class: "row", onsubmit: load }, f.actor, f.action, f.outcome, h("button", {}, "Filter"), h("button", { type: "button", onclick: verify }, "Verify audit chain")), out);
  load();
}

async function usersView() {
  const out = h("div");
  const load = guard(async () => {
    const d = await api("GET", "/api/admin/users");
    out.replaceChildren(h("table", {}, h("thead", {}, h("tr", {}, ["Email", "Name", "Role", "Active", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, d.items.map((u) => h("tr", {}, h("td", {}, u.email), h("td", {}, u.name),
        h("td", {}, h("select", { disabled: u.id === me.id ? "" : null, onchange: guard(async (e) => { await api("PATCH", `/api/admin/users/${u.id}`, { role: e.target.value }); toast("Role updated"); load(); }) },
          ["admin", "owner", "viewer"].map((r) => h("option", Object.assign({ value: r }, r === u.role ? { selected: "" } : {}), r)))),
        h("td", {}, u.active ? "yes" : "no"),
        h("td", {}, u.id === me.id ? "" : h("button", { onclick: guard(async () => { await api("PATCH", `/api/admin/users/${u.id}`, { active: !u.active }); toast(u.active ? "Deactivated; sessions ended" : "Activated"); load(); }) }, u.active ? "Deactivate" : "Activate")))))));
  });
  const e = h("input", { type: "email", placeholder: "email", required: "" }), n = h("input", { placeholder: "name", required: "" });
  const p = h("input", { type: "password", placeholder: "password (12+ chars)", required: "", minlength: "12", autocomplete: "new-password" });
  const r = h("select", {}, ["viewer", "owner", "admin"].map((x) => h("option", { value: x }, x)));
  $("#main").replaceChildren(h("h2", {}, "Users"), h("form", { class: "row", onsubmit: guard(async (ev) => {
    ev.preventDefault(); await api("POST", "/api/admin/users", { email: e.value, name: n.value, password: p.value, role: r.value }); toast("User created"); ev.target.reset(); load();
  }) }, e, n, p, r, h("button", { class: "primary" }, "Create user")), out);
  load();
}

boot();
