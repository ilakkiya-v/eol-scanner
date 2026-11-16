"use strict";
// EOL Scanner UI — dependency-free so it works fully offline inside the lab.

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const app = $("#app");
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV = ["critical", "high", "medium", "low", "info"];
let pollTimer = null;

// ---------------------------------------------------------------- utils
async function api(path, opts = {}) {
  const o = { headers: {}, ...opts };
  if (o.body && !(o.body instanceof FormData)) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(o.body); }
  const r = await fetch(path, o);
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.detail) ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : `HTTP ${r.status}`);
  return data;
}
function toast(msg, ms = 2600) {
  const t = $("#toast"); t.textContent = msg; t.classList.add("show");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("show"), ms);
}
const ago = (ts) => {
  if (!ts) return "-";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "just now"; if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`; return new Date(ts * 1000).toLocaleDateString();
};
const sevBadge = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const statusBadge = (s) => `<span class="badge ${esc(s)}">${esc((s || "unknown").replace("_", " "))}</span>`;
const store = {
  get(k, d) { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } },
};

// theme
(function initTheme() {
  const t = store.get("theme", null);
  if (t) document.documentElement.dataset.theme = t;
  $("#themeBtn").onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next; store.set("theme", next);
  };
})();

document.addEventListener("click", (e) => {
  const b = e.target.closest("button.copy");
  if (b) {
    e.preventDefault();
    const txt = b.parentElement.querySelector("code").textContent;
    navigator.clipboard?.writeText(txt).then(() => toast("Copied"), () => toast("Copy failed"));
  }
});

// ---------------------------------------------------------------- router
const routes = { "": dashboard, "new-web": newWeb, "new-code": newCode, scan: scanView, settings, lookup };
function route() {
  clearInterval(pollTimer);
  const [name, arg] = location.hash.replace(/^#\/?/, "").split("/");
  $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.r === (name || "dashboard")));
  (routes[name] || dashboard)(arg).catch((e) => { app.innerHTML = `<div class="notice err">${esc(e.message)}</div>`; });
  window.scrollTo(0, 0);
}
window.addEventListener("hashchange", route);
route();

// ---------------------------------------------------------------- dashboard
async function dashboard() {
  clearInterval(pollTimer);
  const [scans, settingsData, feeds] = await Promise.all([api("/api/scans"), api("/api/settings"), api("/api/feeds")]);
  const tot = { critical: 0, high: 0, eol: 0, comps: 0 };
  scans.forEach((s) => { const c = s.summary?.severity_counts || {}; tot.critical += c.critical || 0; tot.high += c.high || 0;
    tot.eol += s.summary?.eol_components || 0; tot.comps += s.summary?.components || 0; });
  const noScope = !(settingsData.scope.allow || []).length;
  app.innerHTML = `
  <div class="page-head"><div><h1>Dashboard</h1><div class="muted">Find end-of-life components in authorized lab apps and plan how to contain them.</div></div>
    <div class="row"><a class="btn" href="#/new-web">New web scan</a><a class="btn ghost" href="#/new-code">Upload code</a></div></div>
  ${noScope ? `<div class="notice">No targets are in scope yet. Add the authorized lab hosts in <a href="#/settings">Settings → Scope</a> before scanning.</div>` : ""}
  <div class="stats">
    <div class="stat"><div class="v">${scans.length}</div><div class="l">Scans</div></div>
    <div class="stat crit"><div class="v">${tot.critical}</div><div class="l">Critical findings</div></div>
    <div class="stat high"><div class="v">${tot.high}</div><div class="l">High findings</div></div>
    <div class="stat med"><div class="v">${tot.eol}</div><div class="l">EOL components</div></div>
    <div class="stat"><div class="v">${esc(feeds.active?.products ?? "-")}</div><div class="l">Products in EOL DB</div></div>
  </div>
  <div class="panel"><h2>Recent scans</h2>
  ${scans.length ? `<div class="table-wrap"><table><thead><tr><th>Target</th><th>Type</th><th>Status</th><th>Critical / High</th><th class="hide-sm">EOL</th><th class="hide-sm">Operator</th><th>When</th></tr></thead><tbody>
    ${scans.map((s) => { const c = s.summary?.severity_counts || {}; return `<tr class="click" data-id="${esc(s.id)}">
      <td><b>${esc(s.target)}</b><div class="muted small">${esc(s.id)}${s.ticket ? " · " + esc(s.ticket) : ""}</div></td>
      <td>${s.kind === "web" ? "Web · " + esc(s.mode) : "Code review"}</td><td>${statusBadge(s.status)}</td>
      <td>${["done", "cancelled"].includes(s.status) ? `<span style="color:var(--crit)">${c.critical || 0}</span> / <span style="color:var(--high)">${c.high || 0}</span>` : ["running", "queued"].includes(s.status) ? `<div class="progress" style="width:90px"><div style="width:${(s.progress || 0) * 100}%"></div></div>` : `<span class="muted">-</span>`}</td>
      <td class="hide-sm">${s.summary?.eol_components ?? "-"}</td><td class="hide-sm">${esc(s.operator)}</td><td class="muted">${ago(s.created)}</td></tr>`; }).join("")}
  </tbody></table></div>` : `<div class="empty">No scans yet.</div>`}</div>`;
  $$("tr.click").forEach((tr) => (tr.onclick = () => (location.hash = `#/scan/${tr.dataset.id}`)));
  if (scans.some((s) => ["running", "queued"].includes(s.status))) pollTimer = setInterval(() => location.hash.match(/^#?\/?$/) && dashboard(), 3000);
}

// ---------------------------------------------------------------- new web scan
async function newWeb() {
  const s = await api("/api/settings");
  const d = s.scan_defaults;
  const last = store.get("lastScan", {});
  app.innerHTML = `
  <div class="page-head"><div><h1>New web scan</h1><div class="muted">Fingerprints the app, maps every component to its lifecycle and known vulnerabilities.</div></div></div>
  <form class="panel" id="f">
    <label>Target URL</label>
    <input type="text" name="target" placeholder="https://app.qa.lab.corp" required value="${esc(last.target || "")}">
    <div class="hint" id="scopeHint">Must match the scope allowlist.</div>
    <label>Scan depth</label>
    <div class="modes">
      <label class="mode"><input type="radio" name="mode" value="passive"><b>Passive</b><p>Normal page loads only. Headers, HTML, JavaScript libraries.</p></label>
      <label class="mode"><input type="radio" name="mode" value="safe" checked><b>Safe checks</b><p>+ ~40 well-known files (lockfiles, .git, status pages) and error-page fingerprinting.</p></label>
      <label class="mode"><input type="radio" name="mode" value="active"><b>Active probing</b><p>+ product version endpoints, admin/debug consoles, HTTP methods, legacy TLS. Noisier; no exploit payloads.</p></label>
    </div>
    <div class="grid cols-2">
      <div><label>Operator <span class="muted">(audit trail)</span></label><input type="text" name="operator" required value="${esc(last.operator || "")}"></div>
      <div><label>Ticket / authorization ref <span class="muted">(optional)</span></label><input type="text" name="ticket" placeholder="e.g. SEC-1234" value="${esc(last.ticket || "")}"></div>
    </div>
    <details class="adv"><summary>Advanced: authentication, rate limits, TLS</summary>
      <div class="grid cols-3">
        <div><label>Requests / sec</label><input type="number" step="0.5" min="0.2" name="rate_per_sec" value="${esc(d.rate_per_sec)}"></div>
        <div><label>Concurrency</label><input type="number" min="1" max="16" name="concurrency" value="${esc(d.concurrency)}"></div>
        <div><label>Max pages to crawl</label><input type="number" min="1" max="500" name="max_pages" value="${esc(d.max_pages)}"></div>
        <div><label>Timeout (s)</label><input type="number" min="2" name="timeout" value="${esc(d.timeout)}"></div>
      </div>
      <label class="check"><input type="checkbox" name="verify_tls" ${d.verify_tls ? "checked" : ""}> Verify TLS certificates <span class="muted">(off by default: lab apps usually use internal CAs)</span></label>
      <label class="check"><input type="checkbox" name="use_proxy"> Route through HTTP(S)_PROXY from the environment</label>
      <label>Extra request headers <span class="muted">(one per line, e.g. Authorization: Bearer …; values are not stored)</span></label>
      <textarea name="headers" placeholder="Authorization: Bearer eyJ..."></textarea>
      <label>Cookie header <span class="muted">(for authenticated crawl; not stored)</span></label>
      <input type="text" name="cookies" placeholder="SESSION=...; other=...">
    </details>
    <label class="check"><input type="checkbox" name="attest" required> I am authorized to test this target and it is within the agreed scope and window.</label>
    <div class="row"><button type="submit">Start scan</button><span class="muted small" id="err"></span></div>
  </form>`;
  const f = $("#f");
  const hint = $("#scopeHint");
  let t;
  f.target.oninput = () => { clearTimeout(t); t = setTimeout(async () => {
    const v = f.target.value.trim(); if (!v) return;
    const r = await api(`/api/scope/check?url=${encodeURIComponent(v)}`);
    hint.innerHTML = r.in_scope ? `<span style="color:var(--ok)">✓ In scope</span>` : `<span style="color:var(--crit)">✗ ${esc(r.reason)}</span> — <a href="#/settings">edit scope</a>`;
  }, 300); };
  if (f.target.value) f.target.oninput();
  f.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(f);
    const headers = {};
    (fd.get("headers") || "").split("\n").forEach((l) => { const i = l.indexOf(":"); if (i > 0) headers[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
    const body = { target: fd.get("target").trim(), mode: fd.get("mode"), operator: fd.get("operator"), ticket: fd.get("ticket"),
      attest: !!fd.get("attest"), headers, cookies: fd.get("cookies") || "", rate_per_sec: +fd.get("rate_per_sec"),
      concurrency: +fd.get("concurrency"), max_pages: +fd.get("max_pages"), timeout: +fd.get("timeout"),
      verify_tls: !!fd.get("verify_tls"), use_proxy: !!fd.get("use_proxy") };
    store.set("lastScan", { target: body.target, operator: body.operator, ticket: body.ticket });
    f.querySelector("button").disabled = true;
    try { const r = await api("/api/scans/web", { method: "POST", body }); location.hash = `#/scan/${r.id}`; }
    catch (err) { $("#err").innerHTML = `<span style="color:var(--crit)">${esc(err.message)}</span>`; f.querySelector("button").disabled = false; }
  };
}

// ---------------------------------------------------------------- new code review
async function newCode() {
  const last = store.get("lastScan", {});
  app.innerHTML = `
  <div class="page-head"><div><h1>Code review</h1><div class="muted">Upload a .zip / .tar.gz of the application. It is extracted in a sandboxed folder, parsed, and never executed.</div></div></div>
  <form class="panel" id="f">
    <div class="drop" id="drop"><b>Drop an archive here</b><br><span class="small">or click to choose (.zip, .tar, .tar.gz · deployed WAR/EAR/JAR files are supported inside)</span>
      <input type="file" name="file" accept=".zip,.tar,.gz,.tgz,.war,.jar,.ear" hidden></div>
    <div class="hint" id="fname"></div>
    <div class="grid cols-2">
      <div><label>Operator</label><input type="text" name="operator" required value="${esc(last.operator || "")}"></div>
      <div><label>Ticket / authorization ref <span class="muted">(optional)</span></label><input type="text" name="ticket" value="${esc(last.ticket || "")}"></div>
    </div>
    <label class="check"><input type="checkbox" name="include_node_modules"> Include node_modules (slower; usually the lockfile is enough)</label>
    <label class="check"><input type="checkbox" name="attest" required> I am authorized to review this source code.</label>
    <div class="hint">What is checked: dependency manifests &amp; lockfiles (npm, PyPI, Maven/Gradle, Composer, RubyGems, Go, NuGet), runtime pins (.nvmrc, runtime.txt, TargetFramework, Dockerfile FROM), vendored JS libraries, bundled JARs, and risky legacy patterns.</div>
    <div class="row" style="margin-top:12px"><button type="submit">Upload &amp; review</button><span class="muted small" id="err"></span></div>
  </form>`;
  const f = $("#f"), drop = $("#drop"), input = f.file;
  drop.onclick = () => input.click();
  input.onchange = () => ($("#fname").textContent = input.files[0] ? `${input.files[0].name} · ${(input.files[0].size / 1048576).toFixed(1)} MB` : "");
  ["dragover", "dragenter"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => { if (e.dataTransfer.files[0]) { input.files = e.dataTransfer.files; input.onchange(); } });
  f.onsubmit = async (e) => {
    e.preventDefault();
    if (!input.files[0]) return ($("#err").textContent = "Choose an archive first.");
    const fd = new FormData();
    fd.append("file", input.files[0]); fd.append("operator", f.operator.value); fd.append("ticket", f.ticket.value);
    fd.append("attest", f.attest.checked); fd.append("include_node_modules", f.include_node_modules.checked);
    store.set("lastScan", { ...last, operator: f.operator.value, ticket: f.ticket.value });
    f.querySelector("button").disabled = true; $("#err").textContent = "Uploading…";
    try { const r = await api("/api/scans/code", { method: "POST", body: fd }); location.hash = `#/scan/${r.id}`; }
    catch (err) { $("#err").innerHTML = `<span style="color:var(--crit)">${esc(err.message)}</span>`; f.querySelector("button").disabled = false; }
  };
}

// ---------------------------------------------------------------- scan view
const ui = { tab: "findings", sev: new Set(), cat: "", q: "" };

async function scanView(id) {
  const scan = await api(`/api/scans/${id}`);
  const running = ["running", "queued"].includes(scan.status);
  const findings = running ? [] : await api(`/api/scans/${id}/findings`);
  renderScan(scan, findings);
  if (running) pollTimer = setInterval(async () => {
    const s = await api(`/api/scans/${id}`);
    if (["running", "queued"].includes(s.status)) { updateProgress(s); }
    else { clearInterval(pollTimer); renderScan(s, await api(`/api/scans/${id}/findings`)); toast(`Scan ${s.status}`); }
  }, 1500);
}

function updateProgress(s) {
  const p = $("#prog"); if (p) p.style.width = `${(s.progress || 0) * 100}%`;
  const m = $("#progMsg"); if (m) m.textContent = s.message || "";
  const lg = $("#log"); if (lg && ui.tab === "log") lg.innerHTML = logHtml(s.log);
}
const logHtml = (log) => (log || []).map(([t, l]) => `<div><span class="muted">${new Date(t * 1000).toLocaleTimeString()}</span> ${esc(l)}</div>`).join("");

function renderScan(scan, findings) {
  const s = scan.summary || {}, c = s.severity_counts || {};
  const running = ["running", "queued"].includes(scan.status);
  app.innerHTML = `
  <div class="page-head"><div>
      <div class="muted small"><a href="#/">Dashboard</a> / ${scan.kind === "web" ? "Web scan" : "Code review"} · ${esc(scan.id)}</div>
      <h1 style="word-break:break-all">${esc(scan.target)}</h1>
      <div class="muted small">${statusBadge(scan.status)} ${scan.kind === "web" ? "mode <b>" + esc(scan.mode) + "</b> · " : ""}operator ${esc(scan.operator)}${scan.ticket ? " · " + esc(scan.ticket) : ""} · started ${ago(scan.created)}${s.requests ? ` · ${s.requests} requests` : ""}${s.files_scanned ? ` · ${s.files_scanned} files` : ""}</div>
    </div>
    <div class="row">
      ${running ? `<button class="danger" id="cancel">Cancel</button>` : `
      <a class="btn ghost" href="/api/scans/${esc(scan.id)}/report.html">HTML</a>
      <a class="btn ghost" href="/api/scans/${esc(scan.id)}/report.md">Markdown</a>
      <a class="btn ghost" href="/api/scans/${esc(scan.id)}/report.csv">CSV</a>
      <a class="btn ghost" href="/api/scans/${esc(scan.id)}/report.json">JSON</a>
      ${scan.kind === "web" ? `<button class="ghost" id="rescan">Re-scan</button>` : ""}
      <button class="danger" id="del">Delete</button>`}
    </div></div>
  ${running ? `<div class="panel"><div class="row" style="justify-content:space-between"><b>Scanning…</b><span class="muted small" id="progMsg">${esc(scan.message)}</span></div>
    <div class="progress" style="margin-top:8px"><div id="prog" style="width:${(scan.progress || 0) * 100}%"></div></div></div>` : ""}
  ${scan.status === "error" ? `<div class="notice err"><b>Scan failed:</b> ${esc(scan.message)}</div>` : ""}
  ${!running ? `<div class="stats">
    <div class="stat crit"><div class="v">${c.critical || 0}</div><div class="l">Critical</div></div>
    <div class="stat high"><div class="v">${c.high || 0}</div><div class="l">High</div></div>
    <div class="stat med"><div class="v">${c.medium || 0}</div><div class="l">Medium</div></div>
    <div class="stat"><div class="v">${(c.low || 0) + (c.info || 0)}</div><div class="l">Low / info</div></div>
    <div class="stat crit"><div class="v">${s.eol_components || 0}</div><div class="l">EOL components</div></div>
    <div class="stat"><div class="v">${s.components || 0}</div><div class="l">Components found</div></div>
  </div>` : ""}
  <div class="tabs" id="tabs">
    ${["findings", "inventory", ...(scan.kind === "web" ? ["surface"] : ["ai-review"]), "log"].map((t) => `<button data-t="${t}" class="${ui.tab === t ? "on" : ""}">${{ findings: `Findings (${findings.length})`, inventory: `Inventory (${(s.inventory || []).length})`, surface: "Attack surface", "ai-review": "AI review", log: "Log" }[t]}</button>`).join("")}
  </div>
  <div id="tabBody"></div>`;
  $("#cancel")?.addEventListener("click", async () => { await api(`/api/scans/${scan.id}/cancel`, { method: "POST" }); toast("Cancelling…"); });
  $("#del")?.addEventListener("click", async () => { if (confirm("Delete this scan and its findings?")) { await api(`/api/scans/${scan.id}`, { method: "DELETE" }); location.hash = "#/"; } });
  $("#rescan")?.addEventListener("click", async () => {
    try { const r = await api("/api/scans/web", { method: "POST", body: { target: scan.target, mode: scan.mode, operator: scan.operator, ticket: scan.ticket, attest: confirm("Re-run this scan? Confirm you are still authorized to test this target.") } }); location.hash = `#/scan/${r.id}`; }
    catch (e) { toast(e.message, 5000); }
  });
  $$("#tabs button").forEach((b) => (b.onclick = () => { ui.tab = b.dataset.t; renderScan(scan, findings); }));
  const body = $("#tabBody");
  if (ui.tab === "findings") renderFindings(body, findings, running);
  else if (ui.tab === "inventory") renderInventory(body, s.inventory || []);
  else if (ui.tab === "surface") renderSurface(body, s);
  else if (ui.tab === "ai-review") renderAiReview(body, scan);
  else body.innerHTML = `<div class="log" id="log">${logHtml(scan.log)}</div>`;
}

function renderFindings(body, findings, running) {
  if (running) { body.innerHTML = `<div class="empty">Findings appear when the scan completes. Watch progress in the Log tab.</div>`; return; }
  const cats = [...new Set(findings.map((f) => f.category))].sort();
  body.innerHTML = `
  <div class="filters">
    ${SEV.map((s) => `<button class="chip ${ui.sev.has(s) ? "on" : ""}" data-sev="${s}">${s} (${findings.filter((f) => f.severity === s).length})</button>`).join("")}
    <select id="cat"><option value="">All categories</option>${cats.map((c) => `<option ${ui.cat === c ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>
    <input type="text" id="q" placeholder="Filter by text, CVE, product…" value="${esc(ui.q)}">
  </div><div id="list"></div>`;
  const draw = () => {
    const q = ui.q.toLowerCase();
    const list = findings
      .filter((f) => !ui.sev.size || ui.sev.has(f.severity))
      .filter((f) => !ui.cat || f.category === ui.cat)
      .filter((f) => !q || JSON.stringify([f.title, f.product, f.version, f.location, (f.vulns || []).map((v) => [v.id, v.aliases])]).toLowerCase().includes(q))
      .sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || (b.vuln_count || 0) - (a.vuln_count || 0));
    $("#list").innerHTML = list.length ? list.map(findingHtml).join("") : `<div class="empty">${findings.length ? "No findings match the filters." : "No findings. Check the Inventory tab for everything detected."}</div>`;
    $$("button.ai-btn").forEach((b) => (b.onclick = () => aiAdvise(b)));
  };
  $$(".chip[data-sev]").forEach((b) => (b.onclick = () => { ui.sev.has(b.dataset.sev) ? ui.sev.delete(b.dataset.sev) : ui.sev.add(b.dataset.sev); b.classList.toggle("on"); draw(); }));
  $("#cat").onchange = (e) => { ui.cat = e.target.value; draw(); };
  $("#q").oninput = (e) => { ui.q = e.target.value; draw(); };
  draw();
}

function findingHtml(f) {
  const lc = f.lifecycle || {};
  const ev = Array.isArray(f.evidence) ? f.evidence : f.evidence ? [{ location: f.location, text: f.evidence }] : [];
  return `<details class="finding" data-id="${esc(f.id)}">
  <summary>${sevBadge(f.severity)}<div><div class="t">${esc(f.title)}</div><div class="loc">${esc(f.location || "")}</div></div>
    <div class="meta row">${f.vuln_count ? `<span class="badge">${f.vuln_count} vulns</span>` : ""}<span class="badge">${esc(f.category)}</span>${f.confidence ? `<span class="badge">${esc(f.confidence)} conf.</span>` : ""}</div></summary>
  <div class="body">
    ${lc.status ? `<h3>Lifecycle</h3><dl class="kv">
      <dt>Status</dt><dd>${statusBadge(lc.status)}${lc.curated ? ' <span class="muted small">(curated data)</span>' : ""}</dd>
      <dt>Product / version</dt><dd>${esc(f.product)} ${esc(f.version || "?")}${f.package && f.package !== f.product ? ` <span class="muted">(${esc(f.ecosystem)}: ${esc(f.package)})</span>` : ""}</dd>
      ${lc.cycle ? `<dt>Release cycle</dt><dd>${esc(lc.cycle)}${lc.cycle_latest ? ` · last patch ${esc(lc.cycle_latest)}` : ""}</dd>` : ""}
      ${lc.eol_date ? `<dt>End of life</dt><dd>${esc(lc.eol_date)}${lc.days_past_eol ? ` <span class="muted">(${lc.days_past_eol} days ago)</span>` : ""}</dd>` : ""}
      ${lc.support_end ? `<dt>Active support ended</dt><dd>${esc(lc.support_end)}</dd>` : ""}
      ${lc.latest_cycle ? `<dt>Current release</dt><dd>${esc(lc.latest_cycle)} (${esc(lc.latest_version || "-")})</dd>` : ""}
      ${lc.note ? `<dt>Note</dt><dd>${esc(lc.note)}</dd>` : ""}
      ${f.direct === false ? `<dt>Dependency</dt><dd>transitive (pulled in by another package)</dd>` : ""}
    </dl>` : ""}
    ${(f.vulns || []).length ? `<h3>Known vulnerabilities <span class="muted small">(${esc(f.osv_source)})</span></h3><div class="table-wrap"><table>
      <thead><tr><th>ID</th><th>Sev</th><th>Summary</th><th class="hide-sm">Fixed in</th></tr></thead><tbody>
      ${f.vulns.slice(0, 25).map((v) => `<tr><td class="mono"><a href="https://osv.dev/vulnerability/${encodeURIComponent(v.id)}" target="_blank" rel="noopener">${esc((v.aliases || [])[0] || v.id)}</a></td>
        <td>${sevBadge(v.severity)}${v.cvss ? ` <span class="muted small">${v.cvss}</span>` : ""}</td><td>${esc(v.summary)}</td><td class="hide-sm mono">${esc((v.fixed || []).slice(0, 3).join(", "))}</td></tr>`).join("")}
      </tbody></table></div>${f.vulns.length > 25 ? `<div class="muted small">+${f.vulns.length - 25} more in the JSON export</div>` : ""}` : ""}
    ${ev.length ? `<h3>Evidence</h3>${ev.slice(0, 6).map((e) => `<div class="small"><span class="muted">${esc(e.source || "")}</span> <code>${esc(e.location || "")}</code><pre class="evidence"><code>${esc(e.text)}</code></pre></div>`).join("")}` : ""}
    ${(f.locations || []).length > 1 ? `<h3>All locations</h3><pre class="evidence"><code>${esc(f.locations.map((l) => `${l.path}:${l.line}  ${l.code}`).join("\n"))}</code></pre>` : ""}
    ${(f.containment || []).length ? `<h3>Containment (no code change needed)</h3>${f.containment.map((m) => `<div class="mit"><b>${esc(m.title)}</b><span class="k">${esc(m.kind)} · ${esc(m.effort)} effort</span><div class="small">${esc(m.detail)}</div>
      ${m.snippet ? `<pre><button class="copy ghost">Copy</button><code>${esc(m.snippet)}</code></pre>` : ""}</div>`).join("")}` : ""}
    ${f.extended_support ? `<h3>Extended support options</h3><div class="small">${esc(f.extended_support)}</div>` : ""}
    ${(f.manual_tests || []).length ? `<h3>Manual verification <span class="muted small">(authorized lab only)</span></h3><ul class="tests small">${f.manual_tests.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>` : ""}
    <div class="ai">${f.ai_advice ? `<b>AI-assisted plan</b><div class="md small">${esc(f.ai_advice)}</div>` : `<div class="row"><input type="text" class="ctx" placeholder="Optional environment notes (e.g. behind F5, Windows 2012, no egress)"><button class="ghost ai-btn" data-id="${esc(f.id)}">Ask AI for a tailored containment plan</button></div>`}</div>
  </div></details>`;
}

async function aiAdvise(btn) {
  const box = btn.closest(".ai"); const ctx = box.querySelector(".ctx").value;
  btn.disabled = true; btn.textContent = "Thinking…";
  try { const r = await api(`/api/findings/${btn.dataset.id}/advise`, { method: "POST", body: { context: ctx } });
    box.innerHTML = `<b>AI-assisted plan</b><div class="md small">${esc(r.advice)}</div>`; }
  catch (e) { btn.disabled = false; btn.textContent = "Ask AI for a tailored containment plan"; toast(e.message, 6000); }
}

function renderInventory(body, inv) {
  const order = { eol: 0, eol_soon: 1, unknown: 3, supported: 2 };
  const rows = [...inv].sort((a, b) => (order[a.status] ?? 4) - (order[b.status] ?? 4) || b.vulns - a.vulns);
  body.innerHTML = `<div class="filters"><input type="text" id="iq" placeholder="Filter components…"><label class="check" style="margin:0"><input type="checkbox" id="onlyKnown" checked> Hide unknown-lifecycle packages without vulns</label></div>
  <div class="panel" style="padding:0"><div class="table-wrap"><table><thead><tr><th>Component</th><th>Version</th><th>Lifecycle</th><th class="hide-sm">EOL date</th><th class="hide-sm">Latest</th><th>Vulns</th><th class="hide-sm">Source</th></tr></thead><tbody id="ib"></tbody></table></div></div>`;
  const draw = () => {
    const q = $("#iq").value.toLowerCase(), ok = $("#onlyKnown").checked;
    $("#ib").innerHTML = rows.filter((i) => (!ok || i.status !== "unknown" || i.vulns) && (!q || `${i.product} ${i.package} ${i.version}`.toLowerCase().includes(q)))
      .slice(0, 1500).map((i) => `<tr><td><b>${esc(i.product)}</b>${i.package && i.package !== i.product ? `<div class="muted small">${esc(i.ecosystem)}: ${esc(i.package)}${i.direct === false ? " · transitive" : ""}</div>` : ""}</td>
      <td class="mono">${esc(i.version || "?")}${i.confidence === "low" ? ' <span class="muted small">(range)</span>' : ""}</td><td>${statusBadge(i.status)}</td>
      <td class="hide-sm">${esc(i.eol_date || "")}</td><td class="hide-sm mono">${esc(i.latest || "")}</td><td>${i.vulns ? `<b style="color:var(--high)">${i.vulns}</b>` : "0"}</td>
      <td class="hide-sm muted small">${esc((i.sources || []).join(", "))}</td></tr>`).join("") || `<tr><td colspan="7" class="empty">Nothing to show.</td></tr>`;
  };
  $("#iq").oninput = draw; $("#onlyKnown").onchange = draw; draw();
}

function renderSurface(body, s) {
  const tls = s.tls || {};
  body.innerHTML = `<div class="grid cols-2">
    <div class="panel"><h2>TLS</h2>${tls.protocol || tls.error ? `<dl class="kv">
      ${tls.error ? `<dt>Error</dt><dd>${esc(tls.error)}</dd>` : ""}
      ${tls.protocol ? `<dt>Negotiated</dt><dd>${esc(tls.protocol)} · ${esc(tls.cipher)}</dd>` : ""}
      ${tls.not_after ? `<dt>Cert expires</dt><dd>${esc(tls.not_after)}${tls.days_to_expiry != null ? ` (${tls.days_to_expiry} days)` : ""}</dd>` : ""}
      ${tls.issuer ? `<dt>Issuer</dt><dd>${esc(tls.issuer.organizationName || tls.issuer.commonName || "")}</dd>` : ""}
      ${tls.verified != null ? `<dt>Chain valid</dt><dd>${tls.verified ? "yes" : "no — " + esc(tls.verify_error || "")}</dd>` : ""}
      ${tls.legacy ? `<dt>Legacy protocols</dt><dd>${Object.entries(tls.legacy).map(([k, v]) => `${esc(k)}: ${v === null ? "not testable from this host" : v ? "<b style='color:var(--crit)'>accepted</b>" : "rejected"}`).join("<br>")}</dd>` : ""}
    </dl>` : `<div class="muted">Not an HTTPS target.</div>`}</div>
    <div class="panel"><h2>Crawled pages (${(s.pages || []).length})</h2><pre class="evidence"><code>${esc((s.pages || []).join("\n"))}</code></pre></div>
  </div>
  <div class="panel"><h2>Scripts referenced (${(s.scripts || []).length})</h2><pre class="evidence"><code>${esc((s.scripts || []).join("\n"))}</code></pre></div>`;
}

async function renderAiReview(body, scan) {
  const st = (await api("/api/settings")).llm_status;
  const existing = scan.summary?.ai_review;
  body.innerHTML = `<div class="panel">
    ${!st.enabled ? `<div class="notice">AI assist is off. Enable Claude or a local Ollama model in <a href="#/settings">Settings → AI assist</a>. The rule-based results are complete without it.</div>` :
      `<div class="notice ${st.send_code || st.provider === "ollama" ? "" : "ok"}">${st.provider === "ollama" ? "Using the local Ollama model; code snippets stay on your network." : st.send_code ? "Code snippets around findings WILL be sent to the Anthropic API." : "Only metadata (components, findings) will be sent; source snippets are withheld."}</div>
       <button id="runAi">${existing ? "Re-run" : "Run"} AI code review</button>`}
    <div id="aiOut" class="ai" style="${existing ? "" : "display:none"}"><div class="md small">${esc(existing || "")}</div></div></div>`;
  $("#runAi")?.addEventListener("click", async (e) => {
    e.target.disabled = true; e.target.textContent = "Reviewing… (can take a minute)";
    try { const r = await api(`/api/scans/${scan.id}/ai-review`, { method: "POST" }); $("#aiOut").style.display = ""; $("#aiOut .md").textContent = r.review; }
    catch (err) { toast(err.message, 6000); }
    e.target.disabled = false; e.target.textContent = "Re-run AI code review";
  });
}

// ---------------------------------------------------------------- settings
async function settings() {
  const [s, feeds] = await Promise.all([api("/api/settings"), api("/api/feeds")]);
  const snap = feeds.snapshot || {};
  app.innerHTML = `
  <div class="page-head"><div><h1>Settings</h1><div class="muted">Scope, data feeds, AI assist and scan defaults. Stored in the local data volume.</div></div></div>
  <div class="panel"><h2>Scope allowlist</h2>
    <div class="muted small">Every request (including redirects) is checked against these rules. Deny wins. Formats: <code>app.lab.corp</code>, <code>*.qa.corp</code>, <code>10.20.0.0/16</code>, <code>host:8443</code>.</div>
    <div class="grid cols-2"><div><label>Allow</label><textarea id="allow">${esc((s.scope.allow || []).join("\n"))}</textarea></div>
    <div><label>Deny</label><textarea id="deny" placeholder="prod.corp&#10;*.prod.corp">${esc((s.scope.deny || []).join("\n"))}</textarea></div></div>
    <div class="row" style="margin-top:10px"><button id="saveScope">Save scope</button></div></div>

  <div class="panel"><h2>Data feeds</h2>
    <dl class="kv">
      <dt>Active EOL data</dt><dd>${esc(feeds.active?.products)} products · generated ${esc(feeds.active?.generated || "?")}<div class="muted small">${esc(feeds.active?.source || "")}</div></dd>
      <dt>Bundled snapshot</dt><dd>${snap.bundled ? `${esc(snap.bundled.products)} products · ${esc(snap.bundled.generated)}` : "missing"}</dd>
      <dt>Synced snapshot</dt><dd>${snap.live ? `${esc(snap.live.products)} products · ${esc(snap.live.generated)}` : "never synced (using bundled)"}</dd>
      <dt>Connectivity</dt><dd id="conn"><button class="ghost" id="checkConn">Check</button></dd>
    </dl>
    <label class="check"><input type="checkbox" id="online" ${s.feeds.online ? "checked" : ""}> Use live feeds when reachable (falls back to snapshot/cache when offline)</label>
    <label class="check"><input type="checkbox" id="osv" ${s.feeds.osv ? "checked" : ""}> Look up known vulnerabilities in OSV.dev (package name + version are sent; results cached for offline use)</label>
    <div class="row"><button id="saveFeeds">Save</button><button class="ghost" id="sync">Sync EOL data from endoflife.date now</button></div>
    <div class="hint">Going into an air-gapped lab? Sync here first (or run <code>python scripts/build_snapshot.py</code>) and run your scans of the same apps once online to warm the OSV cache.</div></div>

  <div class="panel"><h2>AI assist <span class="muted small">(optional)</span></h2>
    <label>Provider</label><select id="prov">
      <option value="none">Off — rule-based only</option><option value="anthropic">Claude (Anthropic API · needs ANTHROPIC_API_KEY)</option><option value="ollama">Local model via Ollama</option></select>
    <div class="grid cols-3">
      <div><label>Claude model</label><input type="text" id="model" value="${esc(s.llm.model)}"></div>
      <div><label>Ollama URL</label><input type="text" id="ourl" value="${esc(s.llm.ollama_url)}"></div>
      <div><label>Ollama model</label><input type="text" id="omodel" value="${esc(s.llm.ollama_model)}"></div>
    </div>
    <label class="check"><input type="checkbox" id="sendCode" ${s.llm.send_code ? "checked" : ""}> Allow sending source-code snippets to the Anthropic API during AI code review <span class="muted">(off = metadata only; check your data-handling policy)</span></label>
    <div class="row"><button id="saveLlm">Save</button></div></div>

  <div class="panel"><h2>Scan defaults</h2><div class="grid cols-3">
    <div><label>Requests / sec</label><input type="number" step="0.5" id="d_rate" value="${esc(s.scan_defaults.rate_per_sec)}"></div>
    <div><label>Concurrency</label><input type="number" id="d_conc" value="${esc(s.scan_defaults.concurrency)}"></div>
    <div><label>Max pages</label><input type="number" id="d_pages" value="${esc(s.scan_defaults.max_pages)}"></div>
    <div><label>Timeout (s)</label><input type="number" id="d_to" value="${esc(s.scan_defaults.timeout)}"></div></div>
    <label class="check"><input type="checkbox" id="d_tls" ${s.scan_defaults.verify_tls ? "checked" : ""}> Verify TLS by default</label>
    <div class="row"><button id="saveDefaults">Save</button></div></div>`;
  $("#prov").value = s.llm.provider || "none";
  const lines = (id) => $(id).value.split("\n").map((x) => x.trim()).filter(Boolean);
  const saved = (p) => p.then(() => toast("Saved")).catch((e) => toast(e.message, 5000));
  $("#saveScope").onclick = () => saved(api("/api/scope", { method: "PUT", body: { allow: lines("#allow"), deny: lines("#deny") } }));
  $("#saveFeeds").onclick = () => saved(api("/api/settings", { method: "PUT", body: { feeds: { online: $("#online").checked, osv: $("#osv").checked } } }));
  $("#saveLlm").onclick = () => saved(api("/api/settings", { method: "PUT", body: { llm: { provider: $("#prov").value, model: $("#model").value, ollama_url: $("#ourl").value, ollama_model: $("#omodel").value, send_code: $("#sendCode").checked } } }));
  $("#saveDefaults").onclick = () => saved(api("/api/settings", { method: "PUT", body: { scan_defaults: { rate_per_sec: +$("#d_rate").value, concurrency: +$("#d_conc").value, max_pages: +$("#d_pages").value, timeout: +$("#d_to").value, verify_tls: $("#d_tls").checked } } }));
  $("#checkConn").onclick = async () => { $("#conn").textContent = "Checking…"; const r = await api("/api/feeds?check=true");
    $("#conn").innerHTML = Object.entries(r.connectivity).map(([k, v]) => `${esc(k)}: ${v ? '<span style="color:var(--ok)">reachable</span>' : '<span style="color:var(--crit)">unreachable</span>'}`).join(" · "); };
  $("#sync").onclick = async (e) => { e.target.disabled = true; e.target.textContent = "Syncing…";
    try { const r = await api("/api/feeds/sync", { method: "POST" }); toast(`Synced ${r.products} products`); settings(); }
    catch (err) { toast(err.message, 6000); e.target.disabled = false; e.target.textContent = "Sync EOL data from endoflife.date now"; } };
}

// ---------------------------------------------------------------- lookup
async function lookup() {
  const products = await api("/api/eol/products");
  app.innerHTML = `
  <div class="page-head"><div><h1>EOL lookup</h1><div class="muted">Check a single product/version against the lifecycle database, e.g. from a banner you saw manually.</div></div></div>
  <form class="panel" id="f"><div class="grid cols-3">
    <div><label>Product</label><input type="text" name="product" list="plist" placeholder="tomcat, php, jquery, iis…" required></div>
    <div><label>Version</label><input type="text" name="version" placeholder="8.5.31"></div>
    <div style="align-self:end"><button type="submit">Look up</button></div></div>
    <datalist id="plist">${products.map((p) => `<option value="${esc(p)}">`).join("")}</datalist></form>
  <div id="out"></div>`;
  $("#f").onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const r = await api(`/api/eol/lookup?product=${encodeURIComponent(fd.get("product"))}&version=${encodeURIComponent(fd.get("version"))}`);
    $("#out").innerHTML = `<div class="panel">${!r.known_product ? `<div class="notice">Unknown product “${esc(r.product)}”. Try the suggestions list.</div>` : `<dl class="kv">
      <dt>Status</dt><dd>${statusBadge(r.status)}${r.outdated_patch ? ' <span class="badge">behind latest patch</span>' : ""}</dd>
      <dt>Product</dt><dd>${esc(r.product)} ${esc(r.version || "")}</dd>
      ${r.cycle ? `<dt>Cycle</dt><dd>${esc(r.cycle)} (latest patch ${esc(r.cycle_latest || "-")})</dd>` : ""}
      ${r.eol_date ? `<dt>EOL</dt><dd>${esc(r.eol_date)}</dd>` : ""}
      ${r.support_end ? `<dt>Active support ended</dt><dd>${esc(r.support_end)}</dd>` : ""}
      <dt>Current release</dt><dd>${esc(r.latest_cycle || "-")} (${esc(r.latest_version || "-")})</dd>
      ${r.note ? `<dt>Note</dt><dd>${esc(r.note)}</dd>` : ""}</dl>`}</div>`;
  };
}
