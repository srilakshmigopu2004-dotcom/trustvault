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

function loginView() {
  $("#nav").replaceChildren(); $("#who").textContent = "";
  const email = h("input", { type: "email", placeholder: "email", required: "", autocomplete: "username" });
  const pw = h("input", { type: "password", placeholder: "password", required: "", autocomplete: "current-password" });
  $("#main").replaceChildren(h("div", { class: "card" }, h("h2", {}, "Sign in"),
    h("form", { class: "row", onsubmit: guard(async (ev) => {
      ev.preventDefault();
      await api("POST", "/api/auth/login", { email: email.value, password: pw.value }); boot();
    }) }, email, pw, h("button", { class: "primary" }, "Sign in"))));
}

function shell() {
  $("#who").textContent = `${me.name} (${me.role})`;
  const tabs = me.role === "admin" ? [["Activity", adminView], ["Users", usersView]] : [["Documents", docsView]];
  const nav = $("#nav"); nav.replaceChildren();
  tabs.forEach(([label, fn], i) => nav.append(h("button", { class: i ? "" : "active", onclick: (e) => {
    nav.querySelectorAll("button").forEach((b) => b.classList.remove("active")); e.target.classList.add("active"); fn();
  } }, label)));
  nav.append(h("span", { class: "grow" }), h("button", { onclick: guard(async () => { await api("POST", "/api/auth/logout"); boot(); }) }, "Sign out"));
  tabs[0][1]();
}

// ------------------------------------------------------------------ documents
function docsView() {
  const f = {};
  const field = (name, ph, type = "text") => (f[name] = h("input", { type, placeholder: ph, "aria-label": ph }));
  const list = h("div"), panel = h("div");
  const search = guard(async (ev) => {
    ev && ev.preventDefault();
    const d = await api("GET", "/api/documents?" + qs(Object.fromEntries(Object.entries(f).map(([k, e]) => [k, e.value]))));
    list.replaceChildren(h("div", { class: "mut" }, `${d.total} document(s)`), h("table", {},
      h("thead", {}, h("tr", {}, ["Name", "Category", "Owner", "My access", "Size", "Created", ""].map((t) => h("th", {}, t)))),
      h("tbody", {}, d.items.map((x) => h("tr", {}, h("td", {}, x.name), h("td", {}, x.category), h("td", {}, x.owner_name),
        h("td", {}, x.my_access), h("td", {}, kb(x.size)), h("td", {}, x.created_at.slice(0, 10)),
        h("td", {}, h("a", { href: `/api/documents/${x.id}/download` }, "Download"), " ",
          x.my_access === "manage" ? [h("button", { onclick: () => sharePanel(x) }, "Share"), " ",
            h("button", { class: "danger", onclick: guard(async () => { if (confirm(`Delete ${x.name}?`)) { await api("DELETE", `/api/documents/${x.id}`); toast("Deleted"); search(); panel.replaceChildren(); } }) }, "Delete")] : null))))));
  });
  const sharePanel = guard(async (doc) => {
    const [g, a] = await Promise.all([api("GET", `/api/documents/${doc.id}/grants`), api("GET", `/api/documents/${doc.id}/audit`)]);
    const email = h("input", { type: "email", placeholder: "person's email", required: "" });
    const level = h("select", {}, h("option", { value: "read" }, "read"), h("option", { value: "edit" }, "edit"));
    const sug = h("div");
    const grant = guard(async (em, lv, sid) => { await api("POST", `/api/documents/${doc.id}/grants`, { email: em, level: lv, suggestion_id: sid }); toast("Access granted"); sharePanel(doc); });
    panel.replaceChildren(h("div", { class: "card" }, h("h3", {}, "Sharing: " + doc.name),
      h("table", {}, h("tbody", {}, g.items.length ? g.items.map((x) => h("tr", {}, h("td", {}, x.email), h("td", {}, x.level),
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
        h("td", { class: r.outcome === "ok" ? "" : "bad" }, r.action + (r.outcome === "ok" ? "" : " (" + r.outcome + ")"))))))));
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

// ------------------------------------------------------------------ admin
function adminView() {
  const out = h("div");
  const f = { actor: h("input", { placeholder: "actor email" }), action: h("input", { placeholder: "action" }),
    outcome: h("select", {}, ["", "ok", "denied", "rejected"].map((o) => h("option", { value: o }, o || "any outcome"))) };
  const load = guard(async (ev) => {
    ev && ev.preventDefault();
    const [act, log] = await Promise.all([api("GET", "/api/admin/activity"),
      api("GET", "/api/admin/audit?" + qs({ actor: f.actor.value, action: f.action.value, outcome: f.outcome.value, limit: 100 }))]);
    out.replaceChildren(
      h("div", { class: "card" }, h("h3", {}, "Worth noticing (last 24h)"), act.alerts.length ? act.alerts.map((a) => h("div", { class: "bad" }, `${a.kind}: ${a.actor || a.target} ×${a.count}`)) : h("div", { class: "mut" }, "Nothing flagged."),
        h("h3", {}, "Permission changes"), h("table", {}, h("tbody", {}, act.permission_changes.slice(0, 10).map((p) => h("tr", {}, h("td", {}, p.ts.slice(0, 19).replace("T", " ")), h("td", {}, p.actor_email), h("td", {}, p.action), h("td", {}, p.doc_name), h("td", {}, JSON.stringify({ to: p.detail.email, level: p.detail.level }))))))),
      h("table", {}, h("thead", {}, h("tr", {}, ["When", "Actor", "Action", "Outcome", "Document", "Detail"].map((t) => h("th", {}, t)))),
        h("tbody", {}, log.items.map((r) => h("tr", {}, h("td", {}, r.ts.slice(0, 19).replace("T", " ")), h("td", {}, r.actor_email || "—"), h("td", {}, r.action),
          h("td", { class: r.outcome === "ok" ? "" : "bad" }, r.outcome), h("td", {}, r.doc_name || ""), h("td", {}, JSON.stringify(r.detail)))))));
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
