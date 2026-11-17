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
  const current = () => document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const label = () => $("#themeBtn").setAttribute("aria-label", `Switch to ${current() === "dark" ? "light" : "dark"} theme`);
  label();
  $("#themeBtn").onclick = () => {
    const next = current() === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next; store.set("theme", next); label();
  };
})();

// ---------------------------------------------------------------- accessibility pass (runs after every render)
let _uid = 0;
function enhance(root = app) {
  // 1. Tie each <label> to the field that follows it (screen readers announce the label; clicking it focuses the field)
  $$("label:not([for])", root).forEach((l) => {
    if (l.querySelector("input,select,textarea")) return;
    let el = l.nextElementSibling;
    while (el && !el.matches("input,select,textarea") && !(el.querySelector && el.querySelector("input,select,textarea"))) el = el.nextElementSibling;
    const field = el && (el.matches("input,select,textarea") ? el : el.querySelector("input,select,textarea"));
    if (!field || field.type === "hidden") return;
    if (!field.id) field.id = `f${++_uid}`;
    l.htmlFor = field.id;
  });
  // 2. Click-only widgets become keyboard-operable
  $$(".drop", root).forEach((d) => {
    if (d.getAttribute("role")) return;
    d.setAttribute("role", "button"); d.tabIndex = 0;
    d.setAttribute("aria-label", (d.querySelector("b")?.textContent || "Choose a file") + ". Press Enter to choose a file.");
    d.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); d.click(); } });
  });
  // 3. State for assistive tech
  $$(".tabs", root).forEach((t) => {
    t.setAttribute("role", "tablist");
    $$("button", t).forEach((b) => { b.setAttribute("role", "tab"); b.setAttribute("aria-selected", b.classList.contains("on") ? "true" : "false"); });
  });
  $$(".chip[data-sev]", root).forEach((c) => c.setAttribute("aria-pressed", c.classList.contains("on") ? "true" : "false"));
  $$(".progress", root).forEach((p) => {
    const bar = p.firstElementChild; const v = Math.round(parseFloat(bar && bar.style.width) || 0);
    p.setAttribute("role", "progressbar"); p.setAttribute("aria-valuemin", "0"); p.setAttribute("aria-valuemax", "100");
    p.setAttribute("aria-valuenow", String(v)); if (!p.getAttribute("aria-label")) p.setAttribute("aria-label", "Progress");
  });
  $$("button.copy", root).forEach((b) => b.setAttribute("aria-label", "Copy this snippet"));
  // 4. Page title follows the page heading
  const h1 = $("h1", root);
  document.title = h1 ? `${h1.textContent.trim().slice(0, 60)} · EOL Scanner` : "EOL Scanner";
}
let _enhanceQueued = false;
new MutationObserver(() => {
  if (_enhanceQueued) return; _enhanceQueued = true;
  requestAnimationFrame(() => { _enhanceQueued = false; enhance(); });
}).observe(app, { childList: true, subtree: true });

document.addEventListener("click", (e) => {
  const b = e.target.closest("button.copy");
  if (b) {
    e.preventDefault();
    const txt = b.parentElement.querySelector("code").textContent;
    navigator.clipboard?.writeText(txt).then(() => toast("Copied"), () => toast("Copy failed"));
  }
});

// ---------------------------------------------------------------- router
const routes = { "": dashboard, "new-web": newWeb, "new-code": newCode, import: importPage, scan: scanView, settings, lookup };
function route() {
  clearInterval(pollTimer);
  const [name, arg] = location.hash.replace(/^#\/?/, "").split("/");
  $$("#nav a").forEach((a) => {
    const on = a.dataset.r === (name || "dashboard");
    a.classList.toggle("active", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  (routes[name] || dashboard)(arg).catch((e) => { app.innerHTML = `<div class="notice err" role="alert">${esc(e.message)}</div>`; });
  window.scrollTo(0, 0);
  if (route._ran) app.focus({ preventScroll: true });  // move screen-reader focus to the new page (not on first load)
  route._ran = true;
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
  ${(() => { const b = {}; scans.forEach((s) => { const id = s.options?.batch; if (id) (b[id] = b[id] || []).push(s); });
    const ids = Object.keys(b); return ids.length ? `<div class="panel"><h2>Multi-target scans</h2>${ids.slice(0, 8).map((id) => `<div class="row" style="justify-content:space-between;margin:6px 0">
      <span><b>${b[id].length} targets</b> <span class="muted small">${esc(b[id].map((s) => s.target).slice(0, 4).join(", "))}${b[id].length > 4 ? "…" : ""} · ${b[id].filter((s) => s.status === "done").length} done</span></span>
      <span class="row"><a class="btn ghost" href="/api/batches/${esc(id)}/report.html">Combined HTML</a><a class="btn ghost" href="/api/batches/${esc(id)}/report.csv">CSV</a><a class="btn ghost" href="/api/batches/${esc(id)}/report.md">Markdown</a></span></div>`).join("")}</div>` : ""; })()}
  <div class="panel"><h2>Recent scans</h2>
  ${scans.length ? `<div class="table-wrap"><table><thead><tr><th>Target</th><th>Type</th><th>Status</th><th>Critical / High</th><th class="hide-sm">EOL</th><th class="hide-sm">Operator</th><th>When</th></tr></thead><tbody>
    ${scans.map((s) => { const c = s.summary?.severity_counts || {}; return `<tr class="click" data-id="${esc(s.id)}">
      <td><a class="rowlink" href="#/scan/${esc(s.id)}">${esc(s.target)}</a><div class="muted small">${esc(s.id)}${s.ticket ? " · " + esc(s.ticket) : ""}</div></td>
      <td>${kindLabel(s)}</td><td>${statusBadge(s.status)}</td>
      <td>${["done", "cancelled"].includes(s.status) ? `<span style="color:var(--crit)">${c.critical || 0}</span> / <span style="color:var(--high)">${c.high || 0}</span>` : ["running", "queued"].includes(s.status) ? `<div class="progress" style="width:90px" aria-label="Scan progress"><div style="width:${(s.progress || 0) * 100}%"></div></div>` : `<span class="muted">-</span>`}</td>
      <td class="hide-sm">${s.summary?.eol_components ?? "-"}</td><td class="hide-sm">${esc(s.operator)}</td><td class="muted">${ago(s.created)}</td></tr>`; }).join("")}
  </tbody></table></div>` : `<div class="empty">No scans yet.</div>`}</div>`;
  $$("tr.click").forEach((tr) => (tr.onclick = () => (location.hash = `#/scan/${tr.dataset.id}`)));
  if (scans.some((s) => ["running", "queued"].includes(s.status))) pollTimer = setInterval(() => location.hash.match(/^#?\/?$/) && dashboard(), 3000);
}

const kindLabel = (s) => (s.kind === "web" ? "Web · " + esc(s.mode) + (s.options?.batch ? " · batch" : "") + (s.options?.burp?.scan ? " + Burp" : "") + (s.summary?.ai_review_status?.state === "done" ? " + AI" : "") : s.kind === "import" ? "Import · " + esc(s.mode) : s.kind === "passive" ? "Traffic · " + esc(s.mode) : "Code review" + (s.summary?.ai_review_status?.state === "done" ? " + AI" : ""));

// ---------------------------------------------------------------- new web scan
async function newWeb() {
  const [s, caps] = await Promise.all([api("/api/settings"), api("/api/capabilities").catch(() => ({}))]);
  const d = s.scan_defaults;
  const last = store.get("lastScan", {});
  const aiReady = s.llm.provider === "anthropic" && s.llm.send_code;
  app.innerHTML = `
  <div class="page-head"><div><h1>New web scan</h1><div class="muted">Crawls the app, finds every component and its end-of-life status, checks common weaknesses, and can hand the results to Burp Suite and Claude.</div></div></div>
  <form id="f" class="steps">
    <section class="panel step"><h2><span class="num" aria-hidden="true">1</span>Target</h2>
      <label>Target URL</label>
      <textarea name="target" rows="2" placeholder="https://app.qa.lab.corp&#10;(one target per line to scan several at once)" required>${esc(last.target || "")}</textarea>
      <div class="row between"><div class="hint" id="scopeHint">Must match the scope allowlist. Several lines = one scan per target plus a combined report.</div>
        <button type="button" class="ghost" id="useAllow">Use all allowlisted hosts</button></div>
    </section>
    <section class="panel step"><h2><span class="num" aria-hidden="true">2</span>How deep</h2>
      <div class="modes">
        <label class="mode"><input type="radio" name="mode" value="passive"><b>Passive</b><p>Normal page loads, robots.txt and sitemaps only. Headers, HTML, JavaScript libraries.</p></label>
        <label class="mode"><input type="radio" name="mode" value="safe" checked><b>Safe checks</b><p>+ API documents (OpenAPI/Swagger), ~40 well-known files (lockfiles, .git, status pages), CORS and error-page fingerprinting.</p></label>
        <label class="mode"><input type="radio" name="mode" value="active"><b>Active probing</b><p>+ product version endpoints, admin/debug consoles, HTTP methods, legacy TLS. Noisier; no exploit payloads.</p></label>
      </div>
      <div class="grid cols-3" style="margin-top:6px">
        <div><label>Max pages to crawl</label><input type="number" min="1" max="2000" name="max_pages" value="${esc(d.max_pages)}"></div>
        <div style="grid-column: span 2"><label class="check" style="margin-top:28px"><input type="checkbox" name="render_js" ${caps.browser ? "" : "disabled"}> Also render pages in a headless browser <span class="muted">(single-page apps; ${caps.browser ? "same scope and rate limits" : "not installed: pip install -r requirements-browser.txt, then playwright install chromium"})</span></label></div>
      </div>
    </section>
    <section class="panel step"><h2><span class="num" aria-hidden="true">3</span>Extra engines <span class="muted small">optional</span></h2>
      <div class="engines">
        <label class="engine"><input type="checkbox" name="burp_proxy"><span><b>Send the crawl through Burp</b><br><span class="muted small">Every page, script and API call lands in Burp's HTTP history and site map (proxy ${esc(s.burp.proxy_url)}), ready for Repeater.</span></span></label>
        <label class="engine"><input type="checkbox" name="burp_scan"><span><b>Run a Burp Suite Pro scan too</b> <span id="burpState" class="small"></span><br><span class="muted small">Burp crawls and audits the same target through its REST API (scope limited to this host); its issues appear in Web findings.</span></span></label>
        <label class="engine"><input type="checkbox" name="ai_review" ${aiReady ? "" : "disabled"}><span><b>AI web review when the scan finishes ✦</b><br><span class="muted small">${aiReady ? "Claude checks every finding, looks for what automated checks miss, and writes a manual check (PoC) for each issue." : `Connect Claude and allow sending crawled pages in <a href="#/settings">Settings → AI assist</a>.`}</span></span></label>
      </div>
    </section>
    <section class="panel step"><h2><span class="num" aria-hidden="true">4</span>Authorization</h2>
      <div class="grid cols-2">
        <div><label>Operator <span class="muted">(audit trail)</span></label><input type="text" name="operator" required value="${esc(last.operator || "")}"></div>
        <div><label>Ticket / authorization ref <span class="muted">(optional)</span></label><input type="text" name="ticket" placeholder="e.g. SEC-1234" value="${esc(last.ticket || "")}"></div>
      </div>
      <details class="adv"><summary>Advanced: authenticated crawl, rate limits, TLS, proxy</summary>
        <div class="grid cols-3">
          <div><label>Requests / sec</label><input type="number" step="0.5" min="0.2" name="rate_per_sec" value="${esc(d.rate_per_sec)}"></div>
          <div><label>Concurrency</label><input type="number" min="1" max="16" name="concurrency" value="${esc(d.concurrency)}"></div>
          <div><label>Timeout (s)</label><input type="number" min="2" name="timeout" value="${esc(d.timeout)}"></div>
        </div>
        <label class="check"><input type="checkbox" name="verify_tls" ${d.verify_tls ? "checked" : ""}> Verify TLS certificates <span class="muted">(off by default: lab apps usually use internal CAs)</span></label>
        <label class="check"><input type="checkbox" name="use_proxy"> Route through HTTP(S)_PROXY from the environment</label>
        <label>Extra request headers <span class="muted">(one per line, e.g. Authorization: Bearer …; values are not stored)</span></label>
        <textarea name="headers" placeholder="Authorization: Bearer eyJ..."></textarea>
        <label>Cookie header <span class="muted">(log in with a test account, copy the session cookie from Burp or the browser; not stored)</span></label>
        <input type="text" name="cookies" placeholder="SESSION=...; other=...">
      </details>
      <label class="check"><input type="checkbox" name="attest" required> I am authorized to test this target and it is within the agreed scope and window.</label>
      <div class="row"><button type="submit">Start scan</button><span class="muted small" id="err"></span></div>
    </section>
  </form>`;
  const burpBox = $("#f").burp_scan;
  burpBox.onchange = async () => { if (!burpBox.checked) return ($("#burpState").textContent = "");
    $("#burpState").textContent = "checking Burp…";
    const r = await api("/api/burp/test", { method: "POST" }).catch((e) => ({ ok: false, error: e.message }));
    $("#burpState").innerHTML = r.ok ? `<span style="color:var(--ok)">✓ Burp REST API reachable</span>` : `<span style="color:var(--crit)">✗ ${esc(r.error)}</span> <a href="#/settings">Settings</a>`; };
  const f = $("#f");
  const hint = $("#scopeHint");
  let t;
  const targetsOf = () => f.target.value.split("\n").map((x) => x.trim()).filter(Boolean);
  f.target.oninput = () => { clearTimeout(t); t = setTimeout(async () => {
    const list = targetsOf(); if (!list.length) return;
    const res = await Promise.all(list.slice(0, 50).map((v) => api(`/api/scope/check?url=${encodeURIComponent(v)}`).then((r) => [v, r])));
    const bad = res.filter(([, r]) => !r.in_scope);
    hint.innerHTML = !bad.length ? `<span style="color:var(--ok)">✓ ${list.length > 1 ? `All ${list.length} targets` : "Target"} in scope</span>`
      : `<span style="color:var(--crit)">✗ ${bad.length} not in scope: ${bad.slice(0, 3).map(([v, r]) => esc(v) + " (" + esc(r.reason) + ")").join("; ")}</span> — <a href="#/settings">edit scope</a>`;
  }, 300); };
  $("#useAllow").onclick = async () => { const hosts = await api("/api/scope/hosts");
    if (!hosts.length) return toast("The allowlist has no exact hosts (wildcards and IP ranges can't be crawled). Add hosts in Settings.", 6000);
    f.target.value = hosts.map((h) => (h.includes("://") ? h : "https://" + h)).join("\n"); f.target.oninput(); };
  if (f.target.value) f.target.oninput();
  f.onsubmit = async (e) => {
    e.preventDefault();
    const fd = new FormData(f);
    const headers = {};
    (fd.get("headers") || "").split("\n").forEach((l) => { const i = l.indexOf(":"); if (i > 0) headers[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
    const targets = targetsOf();
    const body = { target: targets[0] || "", mode: fd.get("mode"), operator: fd.get("operator"), ticket: fd.get("ticket"),
      attest: !!fd.get("attest"), headers, cookies: fd.get("cookies") || "", rate_per_sec: +fd.get("rate_per_sec"),
      concurrency: +fd.get("concurrency"), max_pages: +fd.get("max_pages"), timeout: +fd.get("timeout"),
      verify_tls: !!fd.get("verify_tls"), use_proxy: !!fd.get("use_proxy"), render_js: !!fd.get("render_js"),
      burp_proxy: !!fd.get("burp_proxy"), burp_scan: !!fd.get("burp_scan"), ai_review: !!fd.get("ai_review") };
    store.set("lastScan", { target: body.target, operator: body.operator, ticket: body.ticket });
    f.querySelector("button[type=submit]").disabled = true;
    try {
      if (targets.length > 1) {
        const r = await api("/api/batches/web", { method: "POST", body: { ...body, targets } });
        toast(`Started ${r.started.length} scans${r.skipped.length ? `, skipped ${r.skipped.length} out of scope` : ""}`, 6000);
        location.hash = "#/";
      } else { const r = await api("/api/scans/web", { method: "POST", body }); location.hash = `#/scan/${r.id}`; } }
    catch (err) { $("#err").innerHTML = `<span style="color:var(--crit)">${esc(err.message)}</span>`; f.querySelector("button[type=submit]").disabled = false; }
  };
}

// ---------------------------------------------------------------- new code review
async function newCode() {
  const last = store.get("lastScan", {});
  const caps = await api("/api/capabilities").catch(() => ({}));
  const cfg = await api("/api/settings");
  const aiReady = cfg.llm.provider === "anthropic" && cfg.llm.send_code;
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
    <label class="check"><input type="checkbox" name="ai_review" ${aiReady ? "checked" : "disabled"}> Run the <b>AI deep review</b> after the scan <span class="muted">(${aiReady ? "sends the source code to " + (cfg.llm.platform === "claude_code" ? "your Claude Code login" : "your Claude API connection") : "set up Claude and allow sending code in Settings → AI assist"})</span></label>
    <label class="check"><input type="checkbox" name="semgrep" ${caps.semgrep ? "checked" : "disabled"}> Also run <b>Semgrep</b> data-flow rules <span class="muted">(${caps.semgrep ? "installed" : "not installed: pip install semgrep"})</span></label>
    <label class="check"><input type="checkbox" name="attest" required> I am authorized to review this source code.</label>
    <div class="hint">What is checked: dependency manifests &amp; lockfiles (npm, PyPI, Maven/Gradle, Composer, RubyGems, Go, NuGet), runtime pins (.nvmrc, runtime.txt, TargetFramework, Dockerfile FROM), vendored JS libraries, bundled JARs, risky legacy patterns, and injection-prone code (SQL, command, XSS, file path, SSRF, XXE, redirects), each mapped to the URL and parameter that reaches it. Pattern matches show where to look; confirm each one. For full data-flow analysis, run Semgrep or CodeQL and <a href="#/import">import the results</a>.</div>
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
    fd.append("ai_review", f.ai_review.checked); fd.append("semgrep", f.semgrep.checked);
    store.set("lastScan", { ...last, operator: f.operator.value, ticket: f.ticket.value });
    f.querySelector("button").disabled = true; $("#err").textContent = "Uploading…";
    try { const r = await api("/api/scans/code", { method: "POST", body: fd }); location.hash = `#/scan/${r.id}`; }
    catch (err) { $("#err").innerHTML = `<span style="color:var(--crit)">${esc(err.message)}</span>`; f.querySelector("button").disabled = false; }
  };
}

// ---------------------------------------------------------------- import other tools' results
async function importPage() {
  const last = store.get("lastScan", {});
  const scans = (await api("/api/scans")).filter((x) => x.status === "done");
  app.innerHTML = `
  <div class="page-head"><div><h1>Import results</h1><div class="muted">Bring in findings from other scanners so they get containment advice and land in one report.</div></div></div>
  <form class="panel" id="f">
    <div class="drop" id="drop"><b>Drop a report file here</b><br><span class="small">or click to choose · format is detected automatically</span>
      <input type="file" name="file" accept=".json,.jsonl,.xml,.sarif" hidden></div>
    <div class="hint" id="fname"></div>
    <dl class="kv small" style="margin-top:10px">
      <dt>OWASP ZAP</dt><dd>Report → Traditional JSON or XML report</dd>
      <dt>Burp Suite</dt><dd>Select issues → Report selected issues → XML</dd>
      <dt>Semgrep</dt><dd><code>semgrep --config auto --json -o semgrep.json</code></dd>
      <dt>SARIF</dt><dd>CodeQL, Snyk Code, Checkmarx, SonarQube, Bandit, ESLint… (<code>--sarif</code> / <code>--format sarif-latest</code>)</dd>
      <dt>Nuclei</dt><dd><code>nuclei -u &lt;target&gt; -jsonl -o nuclei.jsonl</code></dd>
      <dt>Burp proxy history</dt><dd>Proxy → HTTP history → select items → right-click → <b>Save items</b> (XML, base64 on). Analysed passively for versions, end-of-life components and header/cookie issues; no traffic is sent.</dd>
      <dt>HAR file</dt><dd>Browser DevTools → Network → <b>Save all as HAR</b> (or ZAP/Fiddler export). Analysed passively the same way.</dd>
    </dl>
    <label>Add to</label>
    <select name="into_scan"><option value="">A new entry on the dashboard</option>${scans.map((x) => `<option value="${esc(x.id)}">Existing scan: ${esc(x.target)} (${kindLabel(x)} · ${esc(x.id)})</option>`).join("")}</select>
    <div class="grid cols-2">
      <div><label>Operator</label><input type="text" name="operator" required value="${esc(last.operator || "")}"></div>
      <div><label>Ticket / authorization ref <span class="muted">(optional)</span></label><input type="text" name="ticket" value="${esc(last.ticket || "")}"></div>
    </div>
    <label class="check"><input type="checkbox" name="attest" required> These results come from testing I was authorized to do.</label>
    <div class="row" style="margin-top:12px"><button type="submit">Import</button><span class="muted small" id="err"></span></div>
  </form>`;
  const f = $("#f"), drop = $("#drop"), input = f.file;
  drop.onclick = () => input.click();
  input.onchange = () => ($("#fname").textContent = input.files[0] ? `${input.files[0].name} · ${(input.files[0].size / 1048576).toFixed(1)} MB` : "");
  ["dragover", "dragenter"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => { if (e.dataTransfer.files[0]) { input.files = e.dataTransfer.files; input.onchange(); } });
  f.onsubmit = async (e) => {
    e.preventDefault();
    if (!input.files[0]) return ($("#err").textContent = "Choose a report file first.");
    const fd = new FormData();
    fd.append("file", input.files[0]); fd.append("operator", f.operator.value); fd.append("ticket", f.ticket.value);
    fd.append("attest", f.attest.checked); fd.append("into_scan", f.into_scan.value);
    store.set("lastScan", { ...last, operator: f.operator.value, ticket: f.ticket.value });
    f.querySelector("button").disabled = true; $("#err").textContent = "Importing…";
    try { const r = await api("/api/scans/import", { method: "POST", body: fd });
      toast(r.passive ? `Analysing ${r.tool} (no traffic is sent)…` : `Imported ${r.imported} findings from ${r.tool}`); location.hash = `#/scan/${r.id}`; }
    catch (err) { $("#err").innerHTML = `<span style="color:var(--crit)">${esc(err.message)}</span>`; f.querySelector("button").disabled = false; }
  };
}

// ---------------------------------------------------------------- scan view
const ui = { tab: "", sev: new Set(), cat: "", q: "", ai: false };
const COMPONENT_CATS = ["eol", "eol-soon", "vulnerable-component", "outdated", "version-unknown"];
// Findings are shown in three separate groups: end-of-life / vulnerable components, code vulnerabilities, web findings.
const groupOf = (f, kind) => (COMPONENT_CATS.includes(f.category) ? "components" : kind === "code" ? "code" : kind === "import" ? "all" : "web");

async function scanView(id) {
  const [scan, caps] = await Promise.all([api(`/api/scans/${id}`), api("/api/capabilities").catch(() => ({}))]);
  ui.ai = !!(caps.ai && caps.ai.enabled);
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
  const p = $("#prog"); if (p) { p.style.width = `${(s.progress || 0) * 100}%`; p.parentElement.setAttribute("aria-valuenow", String(Math.round((s.progress || 0) * 100))); }
  const m = $("#progMsg"); if (m) m.textContent = s.message || "";
  const lg = $("#log"); if (lg && ui.tab === "log") lg.innerHTML = logHtml(s.log);
}
const logHtml = (log) => (log || []).map(([t, l]) => `<div><span class="muted">${new Date(t * 1000).toLocaleTimeString()}</span> ${esc(l)}</div>`).join("");

function tabsFor(scan, findings) {
  const s = scan.summary || {};
  const n = (g) => findings.filter((f) => groupOf(f, scan.kind) === g).length;
  const t = [];
  if (scan.kind === "code") t.push(["code", "Code vulnerabilities", n("code")]);
  if (["web", "passive"].includes(scan.kind)) t.push(["web", "Web findings", n("web")]);
  if (scan.kind === "import") t.push(["all", "Findings", n("all")]);
  t.push(["components", "EOL & components", n("components")]);
  if (["web", "passive"].includes(scan.kind)) t.push(["surface", "Attack surface", (s.endpoints || []).length || (s.pages || []).length]);
  if (scan.kind !== "import") t.push(["inventory", "All components", (s.inventory || []).length]);
  if (["code", "web"].includes(scan.kind)) t.push(["ai-review", "AI review ✦", null]);
  t.push(["log", "Log", null]);
  return t;
}

const sevLine = (list) => SEV.filter((v) => list.some((f) => f.severity === v))
  .map((v) => `<span class="sevdot ${v}">${list.filter((f) => f.severity === v).length} ${v}</span>`).join("") || `<span class="muted">nothing found</span>`;

function renderScan(scan, findings) {
  const s = scan.summary || {};
  const running = ["running", "queued"].includes(scan.status);
  const tabs = tabsFor(scan, findings);
  if (!tabs.some(([k]) => k === ui.tab)) ui.tab = tabs[0][0];
  const grp = (g) => findings.filter((f) => groupOf(f, scan.kind) === g);
  const mainKey = scan.kind === "code" ? "code" : scan.kind === "import" ? "all" : "web";
  const main = grp(mainKey), comps = grp("components");
  const ai = s.ai_review_status || {};
  const hasAi = ["code", "web"].includes(scan.kind);
  const vulnComps = (s.inventory || []).filter((i) => i.vulns).length;
  app.innerHTML = `
  <div class="page-head"><div>
      <div class="muted small"><a href="#/">Dashboard</a> / ${scan.kind === "web" ? "Web scan" : scan.kind === "import" ? "Imported results" : scan.kind === "passive" ? "Recorded traffic (passive)" : "Code review"} · ${esc(scan.id)}</div>
      <h1 style="word-break:break-all">${esc(scan.target)}</h1>
      <div class="muted small">${statusBadge(scan.status)} ${scan.kind === "web" ? "mode <b>" + esc(scan.mode) + "</b> · " : ""}operator ${esc(scan.operator)}${scan.ticket ? " · " + esc(scan.ticket) : ""} · started ${ago(scan.created)}${s.requests ? ` · ${s.requests} requests` : ""}${s.files_scanned ? ` · ${s.files_scanned} files` : ""}${(s.imports || []).length ? ` · imported: ${s.imports.map((i) => `${esc(i.tool)} (${i.count})`).join(", ")}` : ""}${s.burp && !s.burp.error ? ` · Burp scan ${esc(s.burp.status || "")} (${s.burp.issues} issue types)` : ""}</div>
    </div>
    <div class="row">
      ${running ? `<button class="danger" id="cancel">Cancel</button>` : `
      ${hasAi ? `<button id="goAi">AI review ✦</button>` : ""}
      ${scan.kind === "web" ? `<button class="ghost" id="rescan">Re-scan</button>` : ""}
      <details class="menu"><summary class="btn ghost">Export</summary><div class="menu-list">
        <a href="/api/scans/${esc(scan.id)}/report.html">HTML report</a><a href="/api/scans/${esc(scan.id)}/report.md">Markdown</a>
        <a href="/api/scans/${esc(scan.id)}/report.csv">CSV</a><a href="/api/scans/${esc(scan.id)}/report.json">JSON</a></div></details>
      <button class="danger ghost" id="del">Delete</button>`}
    </div></div>
  ${running ? `<div class="panel"><div class="row" style="justify-content:space-between"><b>Scanning…</b><span class="muted small" id="progMsg">${esc(scan.message)}</span></div>
    <div class="progress" style="margin-top:8px" aria-label="Scan progress"><div id="prog" style="width:${(scan.progress || 0) * 100}%"></div></div></div>` : ""}
  ${scan.status === "error" ? `<div class="notice err"><b>Scan failed:</b> ${esc(scan.message)}</div>` : ""}
  ${s.burp && s.burp.error ? `<div class="notice err"><b>Burp scan skipped:</b> ${esc(s.burp.error)}</div>` : ""}
  ${!running ? `<div class="overview">
    <button type="button" class="ov ${main.some((f) => ["critical", "high"].includes(f.severity)) ? "hot" : ""}" data-go="${mainKey}">
      <span class="ov-h">${{ code: "Code vulnerabilities", web: "Web findings", all: "Findings" }[mainKey]}</span><span class="ov-v">${main.length}</span><span class="ov-s">${sevLine(main)}</span></button>
    <button type="button" class="ov ${s.eol_components ? "hot" : ""}" data-go="components">
      <span class="ov-h">End-of-life components</span><span class="ov-v">${s.eol_components || 0}</span>
      <span class="ov-s"><span class="sevdot medium">${s.eol_soon_components || 0} EOL soon</span><span class="sevdot high">${vulnComps} with known CVEs</span><span class="muted">${s.components || 0} found</span></span></button>
    ${["web", "passive"].includes(scan.kind) ? `<button type="button" class="ov" data-go="surface">
      <span class="ov-h">Attack surface</span><span class="ov-v">${(s.endpoints || []).length || (s.pages || []).length}</span>
      <span class="ov-s"><span class="muted">${(s.endpoints || []).length ? "endpoints" : "pages"} · ${(s.pages || []).length} pages · ${(s.endpoints || []).filter((e) => (e.params || []).length).length} with parameters</span></span></button>` : ""}
    ${hasAi ? `<button type="button" class="ov ai" data-go="ai-review">
      <span class="ov-h">AI review ✦</span><span class="ov-v small-v">${ai.state === "done" ? `${ai.found ?? 0} new` : esc(ai.state || "not run")}</span>
      <span class="ov-s"><span class="muted">${ai.state === "done" ? "findings from Claude, with manual checks" : ai.state === "running" || ai.state === "queued" ? "in progress…" : "Claude checks every finding and writes manual checks"}</span></span></button>` : ""}
  </div>` : ""}
  <div class="tabs" id="tabs">
    ${tabs.map(([k, label, n]) => `<button data-t="${k}" class="${ui.tab === k ? "on" : ""}">${label}${n != null ? ` <span class="count">${n}</span>` : ""}</button>`).join("")}
  </div>
  <div id="tabBody"></div>`;
  $("#cancel")?.addEventListener("click", async () => { await api(`/api/scans/${scan.id}/cancel`, { method: "POST" }); toast("Cancelling…"); });
  $("#del")?.addEventListener("click", async () => { if (confirm("Delete this scan, its findings and any kept source / crawl data?")) { await api(`/api/scans/${scan.id}`, { method: "DELETE" }); location.hash = "#/"; } });
  $("#rescan")?.addEventListener("click", async () => {
    try { const o = scan.options || {};
      const r = await api("/api/scans/web", { method: "POST", body: { target: scan.target, mode: scan.mode, operator: scan.operator, ticket: scan.ticket,
        burp_scan: !!o.burp?.scan, burp_proxy: !!o.burp?.proxy, render_js: !!o.render_js, attest: confirm("Re-run this scan? Confirm you are still authorized to test this target.") } });
      location.hash = `#/scan/${r.id}`; }
    catch (e) { toast(e.message, 5000); }
  });
  const go = (t) => { ui.tab = t; renderScan(scan, findings); };
  $$("#tabs button").forEach((b) => (b.onclick = () => go(b.dataset.t)));
  $$(".ov[data-go]").forEach((b) => (b.onclick = () => go(b.dataset.go)));
  $("#goAi")?.addEventListener("click", () => go("ai-review"));
  const body = $("#tabBody");
  if (["code", "web", "all"].includes(ui.tab)) renderFindings(body, grp(ui.tab), running, ui.tab);
  else if (ui.tab === "components") renderComponents(body, comps, s.inventory || [], running);
  else if (ui.tab === "inventory") renderInventory(body, s.inventory || []);
  else if (ui.tab === "surface") renderSurface(body, s);
  else if (ui.tab === "ai-review") renderAiReview(body, scan);
  else body.innerHTML = `<div class="log" id="log">${logHtml(scan.log)}</div>`;
}

const EMPTY = {
  code: "No code vulnerabilities found by the rules. Run the AI review for a deeper look (access control, logic, data flow).",
  web: "No web findings. Check the Attack surface tab for everything the crawl found, or run the AI review.",
  components: "No end-of-life or vulnerable components. The All components tab lists everything detected.",
  all: "No findings.",
};

function renderFindings(body, findings, running, group) {
  if (running) { body.innerHTML = `<div class="empty">Findings appear when the scan completes. Watch progress in the Log tab.</div>`; return; }
  const cats = [...new Set(findings.map((f) => f.category))].sort();
  body.innerHTML = `
  <div class="filters">
    ${SEV.filter((s) => findings.some((f) => f.severity === s)).map((s) => `<button type="button" class="chip ${ui.sev.has(s) ? "on" : ""}" data-sev="${s}">${s} <span class="muted">${findings.filter((f) => f.severity === s).length}</span></button>`).join("")}
    ${cats.length > 1 ? `<select id="cat"><option value="">All types</option>${cats.map((c) => `<option ${ui.cat === c ? "selected" : ""}>${esc(c)}</option>`).join("")}</select>` : ""}
    <input type="text" id="q" placeholder="Filter by text, CVE, file, URL…" value="${esc(ui.q)}">
  </div><div id="list"></div>`;
  const draw = () => {
    const q = ui.q.toLowerCase();
    const list = findings
      .filter((f) => !ui.sev.size || ui.sev.has(f.severity))
      .filter((f) => !ui.cat || !cats.includes(ui.cat) || f.category === ui.cat)
      .filter((f) => !q || JSON.stringify([f.title, f.product, f.version, f.location, f.source_tool, (f.vulns || []).map((v) => [v.id, v.aliases])]).toLowerCase().includes(q))
      .sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity) || (b.vuln_count || 0) - (a.vuln_count || 0));
    $("#list").innerHTML = list.length ? list.map(findingHtml).join("") : `<div class="empty">${findings.length ? "No findings match the filters." : EMPTY[group]}</div>`;
    bindFindingButtons();
  };
  $$(".chip[data-sev]").forEach((b) => (b.onclick = () => { ui.sev.has(b.dataset.sev) ? ui.sev.delete(b.dataset.sev) : ui.sev.add(b.dataset.sev); b.classList.toggle("on"); draw(); }));
  if ($("#cat")) $("#cat").onchange = (e) => { ui.cat = e.target.value; draw(); };
  $("#q").oninput = (e) => { ui.q = e.target.value; draw(); };
  draw();
}

function bindFindingButtons() {
  $$("button.ai-btn").forEach((b) => (b.onclick = () => aiAdvise(b)));
  $$("button.mc-btn").forEach((b) => (b.onclick = () => aiManualCheck(b)));
}

// End-of-life view: one compact table first (what is old, since when, how many CVEs, where it was seen), then details.
function renderComponents(body, comps, inv, running) {
  if (running) { body.innerHTML = `<div class="empty">Results appear when the scan completes.</div>`; return; }
  const order = { eol: 0, eol_soon: 1, supported: 2, unknown: 3 };
  const rows = inv.filter((i) => ["eol", "eol_soon"].includes(i.status) || i.vulns)
    .sort((a, b) => (order[a.status] ?? 4) - (order[b.status] ?? 4) || b.vulns - a.vulns);
  body.innerHTML = `${rows.length ? `<div class="panel" style="padding:0"><div class="table-wrap"><table>
    <thead><tr><th>Component</th><th>Version</th><th>Lifecycle</th><th class="hide-sm">End of life</th><th class="hide-sm">Latest</th><th>CVEs</th><th class="hide-sm">Seen at</th></tr></thead><tbody>
    ${rows.map((i) => `<tr><td><b>${esc(i.product)}</b>${i.package && i.package !== i.product ? `<div class="muted small">${esc(i.ecosystem)}: ${esc(i.package)}</div>` : ""}</td>
      <td class="mono">${esc(i.version || "?")}</td><td>${statusBadge(i.status)}</td><td class="hide-sm">${esc(i.eol_date || "")}</td>
      <td class="hide-sm mono">${esc(i.latest || "")}</td><td>${i.vulns ? `<b style="color:var(--high)">${i.vulns}</b>` : "0"}</td>
      <td class="hide-sm small muted" style="word-break:break-all">${seenAt(i)}</td></tr>`).join("")}
    </tbody></table></div></div>
    <h2 class="section-h">Details and containment</h2>` : ""}<div id="compList"></div>`;
  renderFindings($("#compList"), comps, false, "components");
}

// Where a component was seen; the scanner's own random 404 probe is shown as "error page".
const seenAt = (i) => esc(((i.locations || [])[0] || (i.sources || []).join(", ")).replace(/^(https?:\/\/[^/]+)\/eolscan-[0-9a-f]+\.html$/, "$1 (error page)"));

const mcHtml = (mc) => `<div class="poc"><div class="poc-h"><b>Manual check (PoC)</b><span class="muted small">benign probe · run only in the authorized lab</span></div>
  ${mc.request ? `<pre><button class="copy ghost" type="button">Copy</button><code>${esc(mc.request)}</code></pre>` : ""}
  ${mc.probe || mc.expected ? `<dl class="kv small">${mc.probe ? `<dt>Probe</dt><dd>${esc(mc.probe)}</dd>` : ""}${mc.expected ? `<dt>Confirms it</dt><dd>${esc(mc.expected)}</dd>` : ""}</dl>` : ""}
  ${(mc.steps || []).length ? `<ol class="tests small">${mc.steps.map((t) => `<li>${esc(t)}</li>`).join("")}</ol>` : ""}</div>`;

function manualCheckBlock(f, comp) {
  if (f.manual_check) return mcHtml(f.manual_check);
  const older = (f.verification_steps || []).length ? `<div class="poc"><div class="poc-h"><b>How to verify</b><span class="muted small">from the AI review</span></div><ol class="tests small">${f.verification_steps.map((t) => `<li>${esc(t)}</li>`).join("")}</ol></div>` : "";
  const label = comp ? "Write a check for this component with AI" : "Write a manual check (PoC) with AI";
  return older + `<div class="poc-ask">${ui.ai ? `<button type="button" class="ghost mc-btn" data-id="${esc(f.id)}">${label}</button><span class="muted small">${comp ? "how to confirm the version and whether the vulnerable feature is exposed" : "the request to send, a benign probe, and what confirms it"}</span>`
    : `<span class="muted small">Connect Claude in <a href="#/settings">Settings → AI assist</a> to get a manual check (PoC) for this finding.</span>`}</div>`;
}

function findingHtml(f) {
  const lc = f.lifecycle || {};
  const comp = COMPONENT_CATS.includes(f.category);
  const ev = Array.isArray(f.evidence) ? f.evidence : f.evidence ? [{ location: f.location, text: f.evidence }] : [];
  const v = f.ai_verdict && f.ai_verdict.verdict;
  const verdictBadge = v ? `<span class="badge verdict ${v === "confirmed" ? "bad" : v === "likely false positive" ? "good" : ""}">AI: ${esc(v)}</span>` : "";
  const containment = [...(f.containment || [])];
  const cves = f.vulns || [];
  return `<details class="finding" data-id="${esc(f.id)}">
  <summary>${sevBadge(f.severity)}<div><div class="t">${esc(f.title)}</div><div class="loc">${esc(f.location || "")}</div></div>
    <div class="meta row">${verdictBadge}${f.manual_check ? `<span class="badge poc-b">PoC</span>` : ""}${f.vuln_count ? `<span class="badge">${f.vuln_count} CVEs</span>` : ""}${f.source_tool ? `<span class="badge">${esc(f.source_tool)}</span>` : ""}${f.confidence ? `<span class="badge">${esc(f.confidence)} conf.</span>` : ""}</div></summary>
  <div class="body">
    ${v ? `<div class="notice ${v === "confirmed" ? "err" : v === "likely false positive" ? "ok" : ""}"><b>AI review: ${esc(v)}</b> — ${esc(f.ai_verdict.reason || "")}</div>` : ""}
    ${comp && lc.status ? `<h3>Lifecycle</h3><dl class="kv">
      <dt>Status</dt><dd>${statusBadge(lc.status)}${lc.curated ? ' <span class="muted small">(curated data)</span>' : ""}</dd>
      <dt>Product / version</dt><dd>${esc(f.product)} ${esc(f.version || "?")}${f.package && f.package !== f.product ? ` <span class="muted">(${esc(f.ecosystem)}: ${esc(f.package)})</span>` : ""}</dd>
      ${lc.cycle ? `<dt>Release cycle</dt><dd>${esc(lc.cycle)}${lc.cycle_latest ? ` · last patch ${esc(lc.cycle_latest)}` : ""}</dd>` : ""}
      ${lc.eol_date ? `<dt>End of life</dt><dd>${esc(lc.eol_date)}${lc.days_past_eol ? ` <span class="muted">(${lc.days_past_eol} days ago)</span>` : ""}</dd>` : ""}
      ${lc.support_end ? `<dt>Active support ended</dt><dd>${esc(lc.support_end)}</dd>` : ""}
      ${lc.latest_cycle ? `<dt>Current release</dt><dd>${esc(lc.latest_cycle)} (${esc(lc.latest_version || "-")})</dd>` : ""}
      ${lc.note ? `<dt>Note</dt><dd>${esc(lc.note)}</dd>` : ""}
      ${f.direct === false ? `<dt>Dependency</dt><dd>transitive (pulled in by another package)</dd>` : ""}
    </dl>` : ""}
    ${cves.length ? `<h3>Known vulnerabilities <span class="muted small">(${esc(f.osv_source)})</span></h3>${cveTable(cves.slice(0, 8))}
      ${cves.length > 8 ? `<details class="more"><summary>Show ${cves.length - 8} more</summary>${cveTable(cves.slice(8, 50))}</details>` : ""}` : ""}
    ${!comp && (f.detail || (f.cwe || []).length) ? `<h3>What it is</h3><div class="small">${esc(f.detail || "")}${(f.cwe || []).length ? ` <span class="muted">${f.cwe.map((c) => `<a href="https://cwe.mitre.org/data/definitions/${esc(c.replace("CWE-", ""))}.html" target="_blank" rel="noopener">${esc(c)}</a>`).join(" ")}</span>` : ""}</div>` : ""}
    ${f.entry_point ? `<h3>Reached via</h3><div class="small"><code>${esc(f.entry_point.method || "GET")} ${esc(f.entry_point.path || "(route not found: search the code for callers)")}</code>${(f.entry_point.params || []).length ? ` · parameter${f.entry_point.params.length > 1 ? "s" : ""}: <code>${f.entry_point.params.map(esc).join("</code>, <code>")}</code>` : ""} <span class="muted">(${esc(f.entry_point.how || "AI review")})</span></div>` : ""}
    ${manualCheckBlock(f, comp)}
    ${ev.length ? `<h3>Evidence</h3>${ev.slice(0, 4).map((e) => `<div class="small"><span class="muted">${esc(e.source || "")}</span> <code>${esc(e.location || "")}</code><pre class="evidence"><code>${esc(e.text)}</code></pre></div>`).join("")}` : ""}
    ${(f.review_steps || []).length ? `<h3>Confirm in the code <span class="muted small">(pattern matches need a human check)</span></h3><ol class="tests small">${f.review_steps.map((t) => `<li>${esc(t)}</li>`).join("")}</ol>` : ""}
    ${(f.ai_containment || []).length || containment.length ? `<h3>Containment <span class="muted small">(no code change needed)</span></h3>
      ${(f.ai_containment || []).length ? `<ul class="tests small">${f.ai_containment.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>` : ""}
      ${containment.map((m) => `<div class="mit"><b>${esc(m.title)}</b><span class="k">${esc(m.kind)} · ${esc(m.effort)} effort</span><div class="small">${esc(m.detail)}</div>
      ${m.snippet ? `<pre><button class="copy ghost" type="button">Copy</button><code>${esc(m.snippet)}</code></pre>` : ""}</div>`).join("")}` : ""}
    ${f.tool_solution ? `<h3>Fix suggested by ${esc(f.source_tool || "the tool")} <span class="muted small">(needs a code change)</span></h3><div class="small">${esc(f.tool_solution)}</div>` : ""}
    ${f.extended_support ? `<h3>Extended support options</h3><div class="small">${esc(f.extended_support)}</div>` : ""}
    ${(f.manual_tests || []).length ? `<details class="more"><summary>More checks for the lab (${f.manual_tests.length})</summary><ul class="tests small">${f.manual_tests.map((t) => `<li>${esc(t)}</li>`).join("")}</ul></details>` : ""}
    ${(f.locations || []).length > 1 ? `<details class="more"><summary>All locations (${f.locations.length})</summary><pre class="evidence"><code>${esc(f.locations.map((l) => `${l.path}${l.line ? ":" + l.line : ""}  ${l.code || ""}`).join("\n"))}</code></pre></details>` : ""}
    ${(f.references || []).length ? `<details class="more"><summary>References (${f.references.length})</summary><ul class="small">${f.references.map((r) => /^https?:/.test(r) ? `<li><a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a></li>` : `<li>${esc(r)}</li>`).join("")}</ul></details>` : ""}
    <div class="ai">${f.ai_advice ? `<b>AI containment plan</b><div class="md small">${esc(f.ai_advice)}</div>` : ui.ai ? `<div class="row"><input type="text" class="ctx" placeholder="Optional environment notes (e.g. behind F5, Windows 2012, no egress)"><button type="button" class="ghost ai-btn" data-id="${esc(f.id)}">Ask AI for a tailored containment plan</button></div>` : ""}</div>
  </div></details>`;
}

const cveTable = (list) => `<div class="table-wrap"><table>
  <thead><tr><th>ID</th><th>Sev</th><th>Summary</th><th class="hide-sm">Fixed in</th></tr></thead><tbody>
  ${list.map((v) => `<tr><td class="mono"><a href="https://osv.dev/vulnerability/${encodeURIComponent(v.id)}" target="_blank" rel="noopener">${esc((v.aliases || [])[0] || v.id)}</a></td>
    <td>${sevBadge(v.severity)}${v.cvss ? ` <span class="muted small">${v.cvss}</span>` : ""}</td><td>${esc(v.summary)}</td><td class="hide-sm mono">${esc((v.fixed || []).slice(0, 3).join(", "))}</td></tr>`).join("")}
  </tbody></table></div>`;

async function aiAdvise(btn) {
  const box = btn.closest(".ai"); const ctx = box.querySelector(".ctx").value;
  btn.disabled = true; btn.textContent = "Thinking…";
  try { const r = await api(`/api/findings/${btn.dataset.id}/advise`, { method: "POST", body: { context: ctx } });
    box.innerHTML = `<b>AI containment plan</b><div class="md small">${esc(r.advice)}</div>`; }
  catch (e) { btn.disabled = false; btn.textContent = "Ask AI for a tailored containment plan"; toast(e.message, 6000); }
}

async function aiManualCheck(btn) {
  const box = btn.closest(".poc-ask"); const label = btn.textContent;
  btn.disabled = true; btn.textContent = "Writing the manual check…";
  try { const r = await api(`/api/findings/${btn.dataset.id}/manual-check`, { method: "POST" });
    box.outerHTML = mcHtml(r.manual_check); }
  catch (e) { btn.disabled = false; btn.textContent = label; toast(e.message, 6000); }
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
  const eps = s.endpoints || [];
  const pages = s.page_info && s.page_info.length ? s.page_info : (s.pages || []).map((u) => ({ url: u }));
  const methods = [...new Set(eps.map((e) => e.method))].sort();
  const flags = (e) => [e.login ? `<span class="badge">login form</span>` : "", e.upload ? `<span class="badge">file upload</span>` : "",
    e.method === "POST" && e.csrf_token === false ? `<span class="badge warn">no anti-CSRF token</span>` : "",
    e.not_followed ? `<span class="badge" title="${esc(e.not_followed)}">not crawled</span>` : "", e.auth ? `<span class="badge">auth</span>` : ""].join("");
  body.innerHTML = `
  ${s.burp && !s.burp.error ? `<div class="notice ok"><b>Burp Suite scan ${esc(s.burp.status || "")}</b> · task ${esc(s.burp.task_id)} · ${s.burp.issues} issue types imported into Web findings${s.burp.metrics ? ` · ${esc(s.burp.metrics.crawl_requests_made || 0)} crawl / ${esc(s.burp.metrics.audit_requests_made || 0)} audit requests` : ""}. Open Burp's Dashboard for the full task.</div>` : ""}
  <div class="panel"><div class="row between"><h2>Endpoints <span class="muted small">(${eps.length})</span></h2>
    ${eps.length ? `<div class="row tools"><select id="em" aria-label="Method"><option value="">All methods</option>${methods.map((m) => `<option>${esc(m)}</option>`).join("")}</select>
      <label class="check" style="margin:0"><input type="checkbox" id="ep"> with parameters</label>
      <input type="text" id="eq" placeholder="Filter…" aria-label="Filter endpoints"><button type="button" class="ghost" id="copyUrls">Copy URLs</button></div>` : ""}</div>
    ${eps.length ? `<div class="hint">Everything the crawl found: links, forms, JavaScript calls, robots.txt, sitemaps and API documents. "Copy URLs" gives a list you can paste into Burp (Target → Site map, or a new scan's URL list).</div>
    <div class="table-wrap"><table class="eps"><thead><tr><th>Method</th><th>Path</th><th>Parameters</th><th class="hide-sm">Found via</th><th>Status</th></tr></thead><tbody id="epb"></tbody></table></div>`
    : `<div class="muted">No endpoint map for this scan (scans made before this version show the page list below).</div>`}</div>
  <div class="grid cols-2">
    <div class="panel"><h2>Pages <span class="muted small">(${pages.length})</span></h2><div class="table-wrap" style="max-height:420px"><table><tbody>
      ${pages.slice(0, 500).map((p) => `<tr><td style="word-break:break-all"><a href="${esc(p.url)}" target="_blank" rel="noopener">${esc(p.url)}</a>${p.title ? `<div class="muted small">${esc(p.title)}</div>` : ""}</td><td class="mono small">${esc(p.status || "")}</td></tr>`).join("")}
    </tbody></table></div></div>
    <div class="panel"><h2>TLS</h2>${tls.protocol || tls.error ? `<dl class="kv">
      ${tls.error ? `<dt>Error</dt><dd>${esc(tls.error)}</dd>` : ""}
      ${tls.protocol ? `<dt>Negotiated</dt><dd>${esc(tls.protocol)} · ${esc(tls.cipher)}</dd>` : ""}
      ${tls.not_after ? `<dt>Cert expires</dt><dd>${esc(tls.not_after)}${tls.days_to_expiry != null ? ` (${tls.days_to_expiry} days)` : ""}</dd>` : ""}
      ${tls.issuer ? `<dt>Issuer</dt><dd>${esc(tls.issuer.organizationName || tls.issuer.commonName || "")}</dd>` : ""}
      ${tls.verified != null ? `<dt>Chain valid</dt><dd>${tls.verified ? "yes" : "no — " + esc(tls.verify_error || "")}</dd>` : ""}
      ${tls.legacy ? `<dt>Legacy protocols</dt><dd>${Object.entries(tls.legacy).map(([k, v]) => `${esc(k)}: ${v === null ? "not testable from this host" : v ? "<b style='color:var(--crit)'>accepted</b>" : "rejected"}`).join("<br>")}</dd>` : ""}
    </dl>` : `<div class="muted">Not an HTTPS target.</div>`}
    <h2 style="margin-top:18px">Scripts <span class="muted small">(${(s.scripts || []).length})</span></h2><pre class="evidence" style="max-height:220px"><code>${esc((s.scripts || []).join("\n"))}</code></pre></div>
  </div>`;
  if (!eps.length) return;
  const view = () => {
    const m = $("#em").value, wp = $("#ep").checked, q = $("#eq").value.toLowerCase();
    return eps.filter((e) => (!m || e.method === m) && (!wp || (e.params || []).length) && (!q || JSON.stringify(e).toLowerCase().includes(q)));
  };
  const draw = () => {
    $("#epb").innerHTML = view().slice(0, 2000).map((e) => `<tr><td><span class="method ${esc(e.method)}">${esc(e.method)}</span></td>
      <td style="word-break:break-all"><span class="mono small">${esc(e.url.replace(/^https?:\/\/[^/]+/, "") || "/")}</span>${e.title ? `<div class="muted small">${esc(e.title)}</div>` : ""}<div>${flags(e)}</div></td>
      <td>${(e.params || []).map((p) => `<code class="param">${esc(p)}</code>`).join(" ")}</td>
      <td class="hide-sm small muted">${esc((e.sources || []).join(", "))}</td><td class="mono small">${esc(e.status || "")}</td></tr>`).join("") || `<tr><td colspan="5" class="empty">Nothing matches.</td></tr>`;
  };
  $("#em").onchange = $("#ep").onchange = draw; $("#eq").oninput = draw; draw();
  $("#copyUrls").onclick = async () => {
    const urls = [...new Set(view().filter((e) => !e.url.includes("{")).map((e) => e.example || e.url))].join("\n");
    try { await navigator.clipboard.writeText(urls); toast(`Copied ${urls.split("\n").length} URLs`); } catch { toast("Copy failed: your browser blocked clipboard access", 5000); }
  };
}

async function renderAiReview(body, scan) {
  const cfg = await api("/api/settings");
  const st = scan.summary?.ai_review_status || {};
  const llm = cfg.llm, enabled = llm.provider === "anthropic";
  const running = ["queued", "running"].includes(st.state);
  const web = scan.kind === "web";
  const kept = web ? scan.summary?.snapshot_dir : scan.summary?.source_dir;
  const where = (cfg.llm_status.platform === "claude_code") ? "your Claude Code login" : "the configured Claude API connection";
  const what = web ? "the crawled pages, scripts and endpoints of this scan" : "this scan's source code";
  body.innerHTML = `<div class="panel"><h2>AI ${web ? "web" : "code"} review</h2>
    ${web ? `<p class="small">Claude goes through everything the crawl saw, like a pentester reading proxy history: it maps login, roles and sensitive functions, checks every finding (confirmed / likely false positive / needs a manual check), looks for what automated checks miss (reflected input, verbose errors, IDOR candidates, open redirects, SSRF-style URL parameters, forms without anti-CSRF tokens, secrets in scripts, exposed admin functions), and says where each end-of-life component is exposed. Every finding comes with a <b>manual check (PoC)</b> — the request to send in Burp Repeater with a harmless probe value and what confirms it — and containment that needs no code change.${cfg.llm_status.platform === "claude_code" ? "" : ` With an API connection it may also send up to ${esc(cfg.code_review.web_live_requests ?? 40)} live GET requests to the target (in scope, Safe/Active scans only) to confirm reflections.`}</p>`
    : `<p class="small">Claude reads the source like a reviewer: finds the entry points, traces user input to dangerous code, checks each pattern match from the automated scan (confirmed / likely false positive / needs runtime check), and looks for what patterns miss (access control, auth, logic, deserialization, file handling…). Each vulnerability comes with the URL and parameter, the data flow, a <b>manual check (PoC)</b> with a harmless probe, and containment.</p>`}
    ${!enabled ? `<div class="notice">Connect Claude first in <a href="#/settings">Settings → AI assist</a> (Claude Code with your work login, or an API connection).</div>`
      : !llm.send_code ? `<div class="notice">Tick <b>"I'm allowed to send source code and crawled pages to this Claude connection"</b> in <a href="#/settings">Settings → AI assist</a> to enable this.</div>`
      : !kept ? `<div class="notice">${web ? "This scan has no saved crawl data (it was made before this version, or the data was deleted). Re-scan the target to use the AI review." : "The source for this scan isn't kept any more. Upload the archive again to run the AI review."}</div>`
      : `<div class="notice">${esc(what[0].toUpperCase() + what.slice(1))} will be sent to ${where}. Large ${web ? "apps" : "codebases"} can take 10–40 minutes.</div>
         <div class="row"><button id="runAi" ${running ? "disabled" : ""}>${running ? "Reviewing…" : st.state === "done" ? "Run the AI review again" : "Run the AI review"}</button>
         ${running ? `<button class="danger ghost" id="stopAi">Stop</button>` : ""}
         ${!running ? `<button class="ghost" id="dropSrc">${web ? "Delete saved crawl data" : "Delete kept source"}</button>` : ""}</div>`}
    ${st.state ? `<dl class="kv small" style="margin-top:12px"><dt>Status</dt><dd>${esc(st.state)}${st.error ? ` — <span style="color:var(--crit)">${esc(st.error)}</span>` : ""}</dd>
      ${st.engine ? `<dt>Engine</dt><dd>${esc(st.engine)}${st.model ? " · " + esc(st.model) : ""}</dd>` : ""}
      ${st.found != null ? `<dt>New findings</dt><dd>${st.found} (with the Claude badge in ${web ? "Web findings" : "Code vulnerabilities"})</dd>` : ""}
      ${st.turns ? `<dt>Steps</dt><dd>${st.turns}${st.cost_usd != null ? ` · reported cost $${Number(st.cost_usd).toFixed(2)}` : ""}</dd>` : ""}</dl>` : ""}
    ${running ? `<div class="muted small">Progress is in the Log tab (lines starting with [AI]). This page refreshes by itself.</div>` : ""}
  </div>
  ${scan.summary?.ai_review ? `<div class="panel"><h2>Reviewer summary</h2><div class="md small">${esc(scan.summary.ai_review)}</div></div>` : ""}`;
  $("#runAi")?.addEventListener("click", async (e) => {
    if (!confirm(`Send ${what} to ${where} for review?`)) return;
    e.target.disabled = true;
    try { await api(`/api/scans/${scan.id}/ai-review`, { method: "POST" }); toast("AI review started"); scanView(scan.id); }
    catch (err) { toast(err.message, 6000); e.target.disabled = false; } });
  $("#stopAi")?.addEventListener("click", async () => { await api(`/api/scans/${scan.id}/cancel`, { method: "POST" }); toast("Stopping…"); });
  $("#dropSrc")?.addEventListener("click", async () => { if (!confirm(`Delete the ${web ? "saved crawl data" : "kept source"} for this scan? The AI review can't run afterwards.`)) return;
    await api(`/api/scans/${scan.id}/source`, { method: "DELETE" }); toast("Deleted"); scanView(scan.id); });
  if (running) { clearInterval(pollTimer); pollTimer = setInterval(async () => {
    const s2 = await api(`/api/scans/${scan.id}`); if (!["queued", "running"].includes(s2.summary?.ai_review_status?.state)) { clearInterval(pollTimer); toast("AI review " + (s2.summary?.ai_review_status?.state || "finished")); renderScan(s2, await api(`/api/scans/${scan.id}/findings`)); } }, 4000); }
}

// ---------------------------------------------------------------- settings
async function settings() {
  const [s, feeds, lo, caps] = await Promise.all([api("/api/settings"), api("/api/feeds"), api("/api/llm/options"), api("/api/capabilities").catch(() => ({}))]);
  const bc = s.burp.scan_configs || {};
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
    <div class="grid cols-3">
      <div><label>Provider</label><select id="prov">
        <option value="none">Off — rule-based only</option><option value="anthropic">Claude</option><option value="ollama">Local model via Ollama</option></select></div>
      <div class="llm-claude"><label>Connection</label><select id="plat">${Object.entries(lo.platforms).map(([k, v]) => `<option value="${esc(k)}">${esc(v.label)}</option>`).join("")}</select></div>
      <div class="llm-claude"><label>Model <span class="muted small">(pick or type any ID / ARN)</span></label><input type="text" id="model" list="modelPresets" value="${esc(s.llm.model)}">
        <datalist id="modelPresets">${lo.models.map((m) => `<option value="${esc(m.id)}">${esc(m.label)}</option>`).join("")}</datalist></div>
    </div>
    <div class="grid cols-3 llm-claude">
      <div data-plat="gateway"><label>Gateway URL</label><input type="text" id="l_base_url" placeholder="https://llm-gateway.corp/anthropic" value="${esc(s.llm.base_url)}"></div>
      <div data-plat="bedrock bedrock_invoke aws"><label>AWS region</label><input type="text" id="l_aws_region" placeholder="us-east-1" value="${esc(s.llm.aws_region)}"></div>
      <div data-plat="bedrock bedrock_invoke aws"><label>AWS profile <span class="muted small">(optional)</span></label><input type="text" id="l_aws_profile" placeholder="default / sso-profile" value="${esc(s.llm.aws_profile)}"></div>
      <div data-plat="aws google_cloud"><label>Workspace ID</label><input type="text" id="l_workspace_id" placeholder="wrkspc_…" value="${esc(s.llm.workspace_id)}"></div>
      <div data-plat="vertex google_cloud"><label>GCP project</label><input type="text" id="l_gcp_project" value="${esc(s.llm.gcp_project)}"></div>
      <div data-plat="vertex"><label>Vertex region</label><input type="text" id="l_gcp_region" placeholder="global" value="${esc(s.llm.gcp_region)}"></div>
      <div data-plat="foundry"><label>Foundry resource</label><input type="text" id="l_foundry_resource" placeholder="my-foundry-resource" value="${esc(s.llm.foundry_resource)}"></div>
    </div>
    <div class="grid cols-3 llm-claude">
      <div data-plat="claude_code" style="grid-column: span 2"><label>Claude Code path <span class="muted small">(leave empty to find it automatically)</span></label><input type="text" id="l_claude_cli" placeholder="e.g. C:\\Users\\you\\.local\\bin\\claude.exe" value="${esc(s.llm.claude_cli || "")}"></div>
      <div><label>Review depth (effort)</label><select id="l_effort"><option value="medium">medium</option><option value="high">high (recommended)</option><option value="xhigh">xhigh</option><option value="max">max (slowest)</option></select></div>
    </div>
    <div class="small llm-claude" id="credState" style="margin-top:6px"></div>
    <div class="hint llm-claude" id="platAuth"></div>
    <div class="grid cols-3 llm-ollama">
      <div><label>Ollama URL</label><input type="text" id="ourl" value="${esc(s.llm.ollama_url)}"></div>
      <div><label>Ollama model</label><input type="text" id="omodel" value="${esc(s.llm.ollama_model)}"></div>
    </div>
    <label class="check llm-claude"><input type="checkbox" id="sendCode" ${s.llm.send_code ? "checked" : ""}> I'm allowed to send source code and crawled pages to this Claude connection <span class="muted">(required for the AI code and web reviews and for code excerpts in manual checks; check your data-handling policy)</span></label>
    <div class="hint llm-claude">This app never asks for or stores keys. API connections read them from environment variables on the machine running the scanner; the Claude Code connection uses your own Claude login. See the setup guide for exact steps.</div>
    <div class="row"><button id="saveLlm">Save</button><button class="ghost" id="testLlm">Test connection</button><span id="llmTest" class="small"></span></div></div>

  <div class="panel"><h2>Code review</h2><div class="grid cols-3">
    <div><label>Semgrep ruleset <span class="muted small">(registry name or local folder)</span></label><input type="text" id="cr_sg" value="${esc(s.code_review.semgrep_config)}"></div>
    <div><label>AI review: max steps</label><input type="number" min="5" max="300" id="cr_turns" value="${esc(s.code_review.max_turns)}"></div>
    <div><label>AI review: time limit (min)</label><input type="number" min="5" max="240" id="cr_to" value="${esc(s.code_review.timeout_min)}"></div>
    <div><label>AI web review: live GET requests</label><input type="number" min="0" max="200" id="cr_live" value="${esc(s.code_review.web_live_requests ?? 40)}"></div></div>
    <div class="hint">"p/default" downloads Semgrep's public rules (internet needed; your code is not uploaded). For offline labs, point to a folder of rules copied in beforehand. More AI steps = more thorough on large codebases, but slower and more expensive.</div>
    <div class="row"><button id="saveCr">Save</button></div></div>

  <div class="panel"><h2>Burp Suite Professional <span class="muted small">(optional)</span></h2>
    <div class="grid cols-3">
      <div><label>Proxy listener</label><input type="text" id="b_proxy" value="${esc(s.burp.proxy_url)}"></div>
      <div><label>REST API URL</label><input type="text" id="b_api" value="${esc(s.burp.api_url)}"></div>
      <div><label>Max wait for a Burp scan (min)</label><input type="number" min="5" max="1440" id="b_max" value="${esc(s.burp.max_minutes)}"></div>
    </div>
    <details class="adv"><summary>Burp scan configurations per scan depth</summary>
      <div class="hint">Names from Burp's configuration library, one per line. Leave empty for the defaults shown.</div>
      <div class="grid cols-3">
        <div><label>Passive</label><textarea id="b_passive" placeholder="Crawl strategy - faster&#10;Audit checks - passive">${esc((bc.passive || []).join("\n"))}</textarea></div>
        <div><label>Safe</label><textarea id="b_safe" placeholder="Crawl strategy - faster&#10;Audit checks - light active">${esc((bc.safe || []).join("\n"))}</textarea></div>
        <div><label>Active</label><textarea id="b_active" placeholder="Crawl strategy - more complete&#10;Audit checks - all except time-based detection methods">${esc((bc.active || []).join("\n"))}</textarea></div>
      </div></details>
    <div class="hint">In Burp: <b>Settings → Suite → REST API → Service running</b>. If you create an API key there, set <code>BURP_API_KEY</code> before starting the scanner (it is never stored here) — currently <b>${caps.burp_key_set ? "set" : "not set"}</b>. The proxy option only needs Burp's normal proxy listener. Only Burp Suite Professional has this REST API.</div>
    <div class="row"><button id="saveBurp">Save</button><button class="ghost" id="testBurp">Test connection</button><span id="burpTest" class="small"></span></div></div>

  <div class="panel"><h2>Scan defaults</h2><div class="grid cols-3">
    <div><label>Requests / sec</label><input type="number" step="0.5" id="d_rate" value="${esc(s.scan_defaults.rate_per_sec)}"></div>
    <div><label>Concurrency</label><input type="number" id="d_conc" value="${esc(s.scan_defaults.concurrency)}"></div>
    <div><label>Max pages</label><input type="number" id="d_pages" value="${esc(s.scan_defaults.max_pages)}"></div>
    <div><label>Timeout (s)</label><input type="number" id="d_to" value="${esc(s.scan_defaults.timeout)}"></div></div>
    <label class="check"><input type="checkbox" id="d_tls" ${s.scan_defaults.verify_tls ? "checked" : ""}> Verify TLS by default</label>
    <div class="row"><button id="saveDefaults">Save</button></div></div>`;
  $("#prov").value = s.llm.provider || "none";
  $("#plat").value = s.llm.platform || "anthropic";
  const llmFields = ["base_url", "aws_region", "aws_profile", "workspace_id", "gcp_project", "gcp_region", "foundry_resource", "claude_cli", "effort"];
  $("#l_effort").value = s.llm.effort || "high";
  const llmBody = () => { const b = { provider: $("#prov").value, platform: $("#plat").value, model: $("#model").value.trim(),
      ollama_url: $("#ourl").value.trim(), ollama_model: $("#omodel").value.trim(), send_code: $("#sendCode").checked };
    llmFields.forEach((f) => (b[f] = $("#l_" + f).value.trim())); return b; };
  const showCred = () => { const plat = $("#plat").value, e = (lo.env || {})[plat] || {};
    $("#credState").innerHTML = e.kind === "cli" ? (e.set ? `<span style="color:var(--ok)">✓ Claude Code found on this machine.</span> <span class="muted">Press Test to check it is signed in.</span>` : `<span style="color:var(--crit)">✗ Claude Code not found.</span> <span class="muted">Install it and sign in once (see the guide), or enter its path above.</span>`)
      : e.kind === "env" ? (e.set ? `<span style="color:var(--ok)">✓ ${esc(e.set)} is set in the scanner's environment.</span>` : `<span class="muted">Needs ${e.names.map(esc).join(" or ")} set in the scanner's environment before it starts.</span>`)
      : `<span class="muted">Uses your cloud login on this machine.</span>`; };
  const syncLlm = () => { const prov = $("#prov").value, plat = $("#plat").value;
    document.querySelectorAll(".llm-claude").forEach((el) => (el.hidden = prov !== "anthropic"));
    document.querySelectorAll(".llm-ollama").forEach((el) => (el.hidden = prov !== "ollama"));
    document.querySelectorAll("[data-plat]").forEach((el) => (el.hidden = !el.dataset.plat.split(" ").includes(plat)));
    $("#platAuth").textContent = "Credentials: " + (lo.platforms[plat] || {}).auth;
    $("#testLlm").disabled = prov === "none"; showCred(); };
  $("#prov").onchange = $("#plat").onchange = syncLlm; syncLlm();
  $("#testLlm").onclick = async () => { const out = $("#llmTest"); out.textContent = "Testing…"; out.style.color = "";
    try { const r = await api("/api/llm/test", { method: "POST", body: llmBody() });
      out.style.color = r.ok ? "var(--ok)" : "var(--crit)";
      out.textContent = r.ok ? `Connected · ${r.model} · ${r.seconds}s` : r.error; }
    catch (e) { out.style.color = "var(--crit)"; out.textContent = e.message; } };
  const lines = (id) => $(id).value.split("\n").map((x) => x.trim()).filter(Boolean);
  const saved = (p) => p.then(() => toast("Saved")).catch((e) => toast(e.message, 5000));
  $("#saveScope").onclick = () => saved(api("/api/scope", { method: "PUT", body: { allow: lines("#allow"), deny: lines("#deny") } }));
  $("#saveFeeds").onclick = () => saved(api("/api/settings", { method: "PUT", body: { feeds: { online: $("#online").checked, osv: $("#osv").checked } } }));
  $("#saveLlm").onclick = () => saved(api("/api/settings", { method: "PUT", body: { llm: llmBody() } }));
  $("#saveCr").onclick = () => saved(api("/api/settings", { method: "PUT", body: { code_review: { semgrep_config: $("#cr_sg").value.trim(), max_turns: +$("#cr_turns").value, timeout_min: +$("#cr_to").value, web_live_requests: +$("#cr_live").value } } }));
  const burpBody = () => ({ proxy_url: $("#b_proxy").value.trim(), api_url: $("#b_api").value.trim(), max_minutes: +$("#b_max").value,
    scan_configs: Object.fromEntries(["passive", "safe", "active"].map((m) => [m, lines("#b_" + m)]).filter(([, v]) => v.length)) });
  $("#saveBurp").onclick = () => saved(api("/api/settings", { method: "PUT", body: { burp: burpBody() } }));
  $("#testBurp").onclick = async () => { const out = $("#burpTest"); out.textContent = "Testing…"; out.style.color = "";
    const r = await api("/api/burp/test", { method: "POST", body: burpBody() }).catch((e) => ({ ok: false, error: e.message }));
    out.style.color = r.ok ? "var(--ok)" : "var(--crit)";
    out.textContent = r.ok ? `Connected · ${r.issue_definitions} issue definitions · ${r.seconds}s` : r.error; };
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
