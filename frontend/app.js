import { CONFIG } from "./config.js";
import { NET, startDiscovery, wallets, state as wState, subscribe, short, safeIcon, friendly, connectInjected, connectBurner, newBurnerKey, disconnect, restore, switchToStudionet, readClient, writeClient } from "./wallet.js";

const saved = (() => { try { return localStorage.getItem("gl_contract") || ""; } catch { return ""; } })();
const ADDR = (CONFIG.CONTRACT_ADDRESS || saved || "").trim();
const LIVE = /^0x[0-9a-fA-F]{40}$/.test(ADDR);
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const COL = { GREEN: "#00F59B", AMBER: "#F59E0B", RED: "#EF4444", UNREACHABLE: "#64748B" };
const when = t => new Date(Number(t) * 1000).toLocaleString();
const pre = code => "<pre><code>" + esc(code) + "</code></pre>";
const norm = v => v instanceof Map ? Object.fromEntries([...v].map(([k, x]) => [k, norm(x)])) : Array.isArray(v) ? v.map(norm) : typeof v === "bigint" ? Number(v) : v;

/* ---------- demo data (used only while CONTRACT_ADDRESS is empty) ---------- */
const now = Math.floor(Date.now() / 1000);
const mk = (url, verdict, risk, category, impersonates, reasons, flags, n = 1) => ({
  url, host: url.split("/")[2], verdict, risk, category, impersonates, reasons, flags, reachable: true,
  reporter: "0x00000000000000000000000000000000000d3m0d", last_scanner: "0x00000000000000000000000000000000000d3m0d", summary: reasons[0] || "", history: [{ at: now - 86400 * n, verdict, risk }],
  first_seen: now - 86400 * n, last_scanned: now - 3600 * n, scan_count: n });
const DEMO = [
  mk("https://orchard-notes.example/guides", "GREEN", 8, "none", "", ["Static reading guide with no forms or credential requests."], [], 2),
  mk("https://fresh-deals-hub.example/login", "AMBER", 52, "fake_store", "", ["Login form on a store with no visible company details.", "Discount banner pressures a fast decision."], ["password_field", "urgency_language"], 1),
  mk("https://claim-airdrop-now.example/wallet", "RED", 91, "wallet_drainer", "A well-known wallet", ["Asks visitors to type a recovery phrase.", "Form posts to a different domain."], ["seed_phrase_request", "cross_origin_form", "lure_word_in_host"], 3),
  mk("http://198.51.100.7/update", "RED", 78, "malware_lure", "", ["Prompts a software update download from a bare IP address."], ["ip_host", "no_https"], 1),
];
const demoStats = () => ({ urls: DEMO.length, contributors: 1, scan_operations: DEMO.reduce((a, d) => a + d.scan_count, 0),
  verdicts: ["GREEN", "AMBER", "RED", "UNREACHABLE"].reduce((o, v) => (o[v] = DEMO.filter(d => d.verdict === v).length, o), {}) });
function demoScan(url) {
  const m = /^https?:\/\/([a-z0-9.-]+)(\/\S*)?$/i.exec(url);
  if (!m) throw new Error("Enter a plain http(s) URL.");
  const host = m[1].toLowerCase(); let h = 0; for (const ch of url) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  let risk = h % 25; const flags = [];
  if (/^http:/i.test(url)) { risk += 10; flags.push("no_https"); }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) { risk += 25; flags.push("ip_host"); }
  if (/login|verify|wallet|airdrop|claim|secure/.test(host)) { risk += 30; flags.push("lure_word_in_host"); }
  risk = Math.min(100, risk);
  const verdict = risk < 35 ? "GREEN" : risk >= 70 ? "RED" : "AMBER";
  return mk(url, verdict, risk, "none", "", ["Simulated result for demo mode. Deploy the contract to get a real validator verdict."], flags);
}

/* ---------- chain access: reads need no wallet, writes use the connected wallet ---------- */
async function read(fn, args = []) { const c = await readClient(); return norm(await c.readContract({ address: ADDR, functionName: fn, args })); }
const COOLDOWN = 60;
async function liveScan(url, step) {
  const c = await writeClient();
  let prev = null; try { prev = await read("get_scan", [url]); } catch {}
  const before = prev ? prev.scan_count : 0;
  if (prev) {
    const wait = Number(prev.last_scanned) + COOLDOWN - Math.floor(Date.now() / 1000);
    if (wait > 0 && wait <= COOLDOWN) throw new Error("This URL was scanned moments ago. Try again in about " + wait + " seconds, or open its stored verdict from the Check button.");
  }
  step(1);
  const call = { address: ADDR, functionName: "scan", args: [url], value: 0n };
  let fees;
  if (typeof c.estimateTransactionFeesForWrite === "function") {
    try { const e = await c.estimateTransactionFeesForWrite(call); fees = { distribution: e.distribution, feeValue: e.feeValue }; } catch {}
  }
  const hash = await c.writeContract(fees ? { ...call, fees } : call);
  step(2);
  let receipt;
  try { receipt = await c.waitForTransactionReceipt({ hash, status: "ACCEPTED", retries: 90, interval: 3000 }); }
  catch (e) { throw new Error("Validators did not finish in time. The transaction may still complete, so look in the Registry in a minute. Transaction " + hash + ". " + friendly(e)); }
  const st = String((receipt && (receipt.statusName || receipt.status_name)) || "");
  if (/UNDETERMINED|CANCELED|TIMEOUT/i.test(st)) throw new Error("The network could not agree on a verdict (" + st + "). Try again, or pick a more static page. Transaction " + hash);
  const lr = receipt && receipt.consensus_data && receipt.consensus_data.leader_receipt && receipt.consensus_data.leader_receipt[0];
  if ((lr && lr.execution_result && lr.execution_result !== "SUCCESS") || /ERROR/i.test(String((receipt && receipt.txExecutionResultName) || ""))) throw new Error("The contract rejected this scan. The host must be public and the URL must not have been scanned in the last minute. Transaction " + hash);
  step(3);
  const rec = await read("get_scan", [url]);
  if (!rec || rec.scan_count <= before) throw new Error("The transaction finished but the registry did not change. Open it in Studio to read the contract error. Transaction " + hash);
  return { rec, hash };
}
async function demoRun(url, step) { for (let i = 1; i <= 3; i++) { step(i); await sleep(800); } return { rec: demoScan(url), hash: "" }; }

/* ---------- shared views & UI components ---------- */
const timeline = h => !Array.isArray(h) || h.length < 2 ? "" : `<div class="tl" aria-label="Verdict history, oldest first">${h.map(x => `<span style="--c:${COL[x.verdict] || COL.UNREACHABLE}" title="${esc(x.verdict)}, risk ${Number(x.risk)}, ${esc(when(x.at))}"><i style="height:${Math.max(8, Number(x.risk))}%"></i></span>`).join("")}<em>Last ${h.length} checks</em></div>`;

const card = (r, hash) => `<article class="result" style="--c:${COL[r.verdict] || COL.UNREACHABLE}">
  <div class="top"><span class="badge">${esc(r.verdict)}</span><b>${esc(r.url)}</b></div>
  <div class="gauge"><i style="width:${Number(r.risk)}%"></i></div>
  ${r.summary ? `<p class="sum">${esc(r.summary)}</p>` : ""}
  <p class="note">Risk ${Number(r.risk)} / 100. ${r.category && r.category !== "none" ? "Threat Category: <strong>" + esc(r.category.replace(/_/g, " ")) + "</strong>." : "No threat category assigned."}${r.impersonates ? " Impersonation warning: <strong>" + esc(r.impersonates) + "</strong>." : ""}</p>
  ${r.reasons && r.reasons.length ? `<ul>${r.reasons.map(x => "<li>" + esc(x) + "</li>").join("")}</ul>` : ""}
  ${r.flags && r.flags.length ? `<div class="chips">${r.flags.map(f => "<span>" + esc(f.replace(/_/g, " ")) + "</span>").join("")}</div>` : ""}
  ${timeline(r.history)}
  <p class="meta">
    <a href="#/host/${encodeURIComponent(r.host)}">Host Intel (${esc(r.host)})</a> • 
    Scanned: ${esc(when(r.last_scanned))} • 
    ${Number(r.scan_count)} scan(s) recorded • 
    Reporter: <code>${esc(short(r.reporter))}</code>
    ${hash ? ` • <a href="${esc(NET.explorer)}/tx/${esc(hash)}" target="_blank" rel="noopener">Tx: ${esc(short(hash))}</a>` : ""}
  </p>
</article>`;

const row = r => `<details class="row" data-v="${esc(r.verdict)}" data-s="${esc((r.url + " " + (r.category || "")).toLowerCase())}" style="--c:${COL[r.verdict] || COL.UNREACHABLE}">
  <summary>
    <span class="dot"></span>
    <b>${esc(r.host)}</b>
    <span class="url">${esc(r.url.replace(/^https?:\/\/[^/]+/, ""))}</span>
    <span class="meter"><i style="width:${Number(r.risk)}%"></i></span>
    <span style="font-family:var(--font-mono);font-size:0.88rem;color:var(--text-muted);text-align:right;">${Number(r.risk)}</span>
  </summary>
  <div class="detail">${card(r).replace(/^<article class="result"/, '<article class="result" style="box-shadow:none;margin:0"')}</div>
</details>`;

async function getStats() { try { return LIVE ? await read("stats") : demoStats(); } catch { return null; } }
const statHtml = s => !s ? '<p class="note">Registry statistics are currently synchronizing...</p>' :
  [["URLs Indexed", s.urls], ["Consensus Scans", s.scan_operations], ["Contributors", s.contributors], ["Green (Safe)", s.verdicts.GREEN], ["Amber (Caution)", s.verdicts.AMBER], ["Red (Threat)", s.verdicts.RED]].map(([l, v]) => `<div><b>${Number(v) || 0}</b><span>${l}</span></div>`).join("");

// Accepts a full public http(s) URL. A fragment is dropped, userinfo is refused.
// Printable ASCII enforcement ensures punycode/percent-encoding is applied before validator submission.
const cleanUrl = v => {
  let u = String(v || "").trim().split("#")[0];
  if (/\s/.test(u)) return "";
  if (/[^\x21-\x7e]/.test(u)) { try { u = new URL(u).href.split("#")[0]; } catch { return ""; } }
  return /^https?:\/\/[^\s@\/?]+\.[^\s@\/?]+([\/?]\S*)?$/i.test(u) && u.length >= 10 && u.length <= 300 ? u : "";
};

/* ---------- pages ---------- */
let timer;
const Home = {
  html: () => `<section class="hero">
    <div>
      <div class="hero-badge"><i></i> GenLayer Intelligent Contract • Studionet</div>
      <h1>Know a link is safe before anyone clicks it</h1>
      <p class="lead">GreenLight is an on-chain, decentralized URL trust registry. AI validators independently fetch the page, evaluate deterministic code signals, reason through an LLM, and reach consensus on an immutable verdict.</p>
      
      <form class="scan" id="hf">
        <input id="hu" type="url" placeholder="Paste a link to check (e.g. https://example.com)" required maxlength="300" aria-label="URL to check">
        <button type="submit">Check Stored Verdict</button>
      </form>
      
      <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;margin-top:0.6rem;">
        <span class="note" style="font-size:0.8rem;">Quick test:</span>
        <a class="chip-preset" href="#/check/https%3A%2F%2Forchard-notes.example%2Fguides" style="font-size:0.78rem;padding:0.2rem 0.6rem;background:rgba(255,255,255,0.05);border:1px solid var(--line);border-radius:99px;">Safe Guide</a>
        <a class="chip-preset" href="#/check/https%3A%2F%2Ffresh-deals-hub.example%2Flogin" style="font-size:0.78rem;padding:0.2rem 0.6rem;background:rgba(255,255,255,0.05);border:1px solid var(--line);border-radius:99px;">Suspicious Store</a>
        <a class="chip-preset" href="#/check/https%3A%2F%2Fclaim-airdrop-now.example%2Fwallet" style="font-size:0.78rem;padding:0.2rem 0.6rem;background:rgba(255,255,255,0.05);border:1px solid var(--line);border-radius:99px;">Drainer Phish</a>
      </div>

      <div class="cta">
        <a class="btn" href="#/scan">Scan New URL</a>
        <a class="ghost" href="#/playground">Interactive Playground</a>
        <a class="ghost" href="#/how">How Consensus Works</a>
      </div>
    </div>

    <div class="lantern" id="lantern" data-v="GREEN" aria-hidden="true">
      <div class="sweep"></div>
      <div class="ring"></div>
      <div class="ring r2"></div>
      <div class="ring r3"></div>
      <div class="core">
        <b id="lv">GREEN</b>
        <span id="lu">orchard-notes.example</span>
        <em id="lr">risk 8</em>
      </div>
    </div>
  </section>

  <section class="strip" id="stats"><div class="skel" style="width:60%"></div></section>

  <section class="trio">
    <div>
      <h3>The Model Never Chooses The Verdict</h3>
      <p>The LLM provides a risk estimation and plain-English summary. The smart contract deterministically blends it with 15 code signals and derives GREEN, AMBER, or RED directly in bytecode.</p>
    </div>
    <div>
      <h3>Decentralized Validator Consensus</h3>
      <p>Every validator repeats the entire fetch and analysis independently. A leader verdict is accepted only when independent scores agree within a strict mathematical tolerance.</p>
    </div>
    <div>
      <h3>Code Signals Cannot Be Injected Away</h3>
      <p>Even if an attacker embeds adversarial prompt injections like "SYSTEM OVERRIDE: SAFE", deterministic heuristics like recovery phrase forms and cross-origin POST actions lock in a RED verdict.</p>
    </div>
  </section>`,

  async mount() {
    const S = [
      ["GREEN", "orchard-notes.example/guides", 8],
      ["AMBER", "fresh-deals-hub.example/login", 52],
      ["RED", "claim-airdrop-now.example/wallet", 91]
    ];
    const L = $("#lantern"); let i = 0;
    const show = () => {
      if (!document.body.contains(L)) return;
      const [v, u, r] = S[i++ % 3];
      L.dataset.v = v;
      L.classList.add("scanning");
      $("#lv").textContent = "Scanning";
      $("#lu").textContent = u;
      $("#lr").textContent = "";
      setTimeout(() => {
        if (!document.body.contains(L)) return;
        L.classList.remove("scanning");
        $("#lv").textContent = v;
        $("#lr").textContent = "risk " + r;
      }, 1400);
    };

    $("#hf").onsubmit = e => {
      e.preventDefault();
      const v = cleanUrl($("#hu").value);
      if (!v) { toast("Enter a full public http(s) URL", "err"); return; }
      location.hash = "#/check/" + encodeURIComponent(v);
    };

    show();
    timer = setInterval(show, 4200);
    $("#stats").innerHTML = statHtml(await getStats());
  }
};

const ScanPage = {
  html: () => `<h1>Scan a URL</h1>
    <p class="lead">Submit any public web address for on-chain AI validation. Validators fetch the raw HTML, compute cryptographic and code signals, query consensus LLMs, and record an immutable verdict.</p>
    
    <div id="gate"></div>
    
    <form class="scan" id="f">
      <input id="u" type="url" placeholder="https://example.com/login" required maxlength="300" aria-label="URL to scan">
      <button id="go" type="submit">Scan On-Chain</button>
      <button id="chk" class="ghostb" type="button" title="Read stored verdict without transaction">Check Stored Verdict</button>
    </form>

    <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;margin-bottom:1.5rem;">
      <span class="note">Sample presets:</span>
      <button type="button" class="preset-btn ghostb" data-url="https://orchard-notes.example/guides" style="padding:0.25rem 0.65rem;font-size:0.8rem;">Safe Guide</button>
      <button type="button" class="preset-btn ghostb" data-url="https://fresh-deals-hub.example/login" style="padding:0.25rem 0.65rem;font-size:0.8rem;">Suspicious Store</button>
      <button type="button" class="preset-btn ghostb" data-url="https://claim-airdrop-now.example/wallet" style="padding:0.25rem 0.65rem;font-size:0.8rem;">Drainer Phish</button>
      <button type="button" class="preset-btn ghostb" data-url="http://198.51.100.7/update" style="padding:0.25rem 0.65rem;font-size:0.8rem;">Malware IP</button>
    </div>

    <ol class="steps" id="steps" aria-live="polite">
      <li>Submit transaction to GenLayer Studionet</li>
      <li>Leader validator fetches HTML and computes code heuristics</li>
      <li>Network validators independently verify equivalence & reach consensus</li>
      <li>Verdict permanently recorded on-chain</li>
    </ol>
    <div id="out"></div>`,

  mount() {
    const steps = [...document.querySelectorAll("#steps li")];
    const mark = n => steps.forEach((li, i) => li.className = i < n - 1 ? "done" : i === n - 1 ? "now" : "");
    const gate = () => {
      const g = $("#gate"); if (!g) return; const s = wState();
      if (!LIVE) g.innerHTML = '<div class="callout" style="border-left-color:var(--amber);"><strong>Demo Mode Active:</strong> Results are simulated in your browser. Deploy the contract or paste a contract address in settings to activate real Studionet consensus.</div>';
      else if (!s.address) { g.innerHTML = '<div class="callout">Connect an EIP-6963 wallet or generate a Test Key to broadcast scan transactions. <button id="gc" type="button" style="margin-left:0.6rem;">Connect Wallet</button></div>'; $("#gc").onclick = openWallets; }
      else if (bad(s)) { g.innerHTML = `<div class="callout" style="border-left-color:var(--amber);">Your wallet is connected to Chain ID ${esc(s.chainId)}. <button id="gs" type="button" style="margin-left:0.6rem;">Switch to ${esc(NET.name)}</button></div>`; $("#gs").onclick = doSwitch; }
      else g.innerHTML = `<p class="note">Connected as <code>${esc(s.address)}</code> on <strong>${esc(NET.name)}</strong>.</p>`;
    };
    cleanups.push(subscribe(gate)); gate();

    try { const pre = decodeURIComponent(location.hash.split("/")[2] || ""); if (pre) $("#u").value = pre; } catch {}

    document.querySelectorAll(".preset-btn").forEach(btn => {
      btn.onclick = () => { $("#u").value = btn.dataset.url; };
    });

    $("#chk").onclick = () => {
      const v = cleanUrl($("#u").value);
      if (!v) { $("#u").reportValidity(); return; }
      location.hash = "#/check/" + encodeURIComponent(v);
    };

    $("#f").onsubmit = async e => {
      e.preventDefault();
      const url = cleanUrl($("#u").value);
      const out = $("#out"), go = $("#go");
      out.innerHTML = "";

      if (LIVE && !wState().address) { openWallets(); return; }
      go.disabled = true;

      try {
        if (!url) throw new Error("Enter a valid http(s) URL (between 10 and 300 characters).");
        const { rec, hash } = LIVE ? await liveScan(url, mark) : await demoRun(url, mark);
        mark(5);
        out.innerHTML = card(rec, hash) + `
          <div style="margin-top:1rem;display:flex;gap:0.6rem;flex-wrap:wrap;">
            <a class="ghost" href="#/check/${encodeURIComponent(url)}">Permanent Link</a>
            <button type="button" class="ghostb" id="cp-json">Copy JSON Result</button>
          </div>`;
        const cj = $("#cp-json");
        if (cj) cj.onclick = async () => {
          try { await navigator.clipboard.writeText(JSON.stringify(rec, null, 2)); toast("JSON copied to clipboard"); } catch {}
        };
      } catch (err) {
        mark(0);
        out.innerHTML = `<div class="err">${esc(friendly(err))}</div>`;
      } finally {
        go.disabled = false;
      }
    };
  }
};

const SKEL = '<div class="skel"></div><div class="skel"></div><div class="skel"></div>';
const demoBrowse = (verdict, query, offset) => {
  const q = String(query || "").toLowerCase();
  const all = DEMO.filter(d => (!verdict || d.verdict === verdict) && (!q || d.url.toLowerCase().includes(q)));
  return { items: all.slice(offset, offset + 10), more: offset + 10 < all.length, truncated: false };
};
const browse = (verdict, query, scanner, offset) => LIVE ? read("browse", [verdict, query, scanner, offset, 10]) : Promise.resolve(demoBrowse(verdict, query, offset));

function pager(list, more, fetchPage, empty) {
  let offset = 0, gen = 0;
  const trunc = $("#trunc");
  const load = async reset => {
    const my = ++gen;
    if (reset) { offset = 0; list.innerHTML = SKEL; more.hidden = true; }
    try {
      const d = await fetchPage(offset);
      if (my !== gen) return;
      if (offset === 0) list.innerHTML = d.items.length || d.more ? "" : empty;
      list.insertAdjacentHTML("beforeend", d.items.map(row).join(""));
      offset += d.raw ?? d.items.length;
      more.hidden = !d.more;
      if (trunc) trunc.hidden = !d.truncated;
      if (!d.items.length && d.more) return load(false);
    } catch (e) {
      if (my !== gen) return;
      list.innerHTML = `<div class="err">Could not load registry records: ${esc(friendly(e))} <button type="button" id="retry" style="margin-left:0.5rem;">Retry</button></div>`;
      $("#retry").onclick = () => load(true);
    }
  };
  more.onclick = () => load(false);
  return load;
}

const listShell = extra => `${extra || ""}<div id="list">${SKEL}</div><p id="trunc" class="note" hidden>Only the latest feed window was queried. Use specific filters to explore older records.</p><p style="margin-top:1.2rem;"><button id="more" type="button" hidden>Load More Entries</button></p>`;

const Check = {
  html: () => `<h1>URL Trust Inspector</h1><div id="chk">${SKEL}</div>`,
  async mount() {
    const e = epoch, box = $("#chk");
    let raw = "";
    try { raw = decodeURIComponent(location.hash.split("/")[2] || ""); } catch {}
    if (!raw) { box.innerHTML = '<p class="note">No URL specified. <a href="#/scan">Go to Scan page.</a></p>'; return; }
    const enc = encodeURIComponent(raw);
    try {
      const rec = LIVE ? await read("get_scan", [raw]) : (DEMO.find(d => d.url === raw) || null);
      if (e !== epoch) return;
      let flagged = "";
      if (rec && LIVE) {
        try {
          const h = await read("host_overview", [rec.host]);
          if (h.flagged) flagged = `<div class="callout" style="border-left-color:var(--red);"><strong>Host Reputation Warning:</strong> The domain <code>${esc(rec.host)}</code> has ${Number(h.red_urls)} RED URLs on record. Future scans receive a +15 risk neighborhood penalty. <a href="#/host/${encodeURIComponent(rec.host)}">View Domain Report</a></div>`;
        } catch {}
      }
      if (e !== epoch) return;
      box.innerHTML = rec
        ? flagged + card(rec) + `
          <div style="display:flex;gap:0.7rem;flex-wrap:wrap;margin-top:1.2rem;">
            <button id="cp" type="button">Copy Link to Result</button>
            <a class="btn" href="#/scan/${enc}">Scan Again</a>
            <a class="ghost" href="#/host/${encodeURIComponent(rec.host)}">Domain Intel</a>
          </div>`
        : `<div class="callout">
            <h3 style="margin-top:0;">Unregistered Address</h3>
            <p>No validator has inspected <code>${esc(raw)}</code> yet.</p>
            <a class="btn" href="#/scan/${enc}">Scan Now On-Chain</a>
           </div>`;
      const cp = $("#cp");
      if (cp) cp.onclick = async () => {
        try { await navigator.clipboard.writeText(location.href); toast("Direct link copied to clipboard"); }
        catch { toast("Failed to copy link", "err"); }
      };
    } catch (e) {
      box.innerHTML = `<div class="err">${esc(friendly(e))}</div>`;
    }
  }
};

const Registry = {
  html: () => `<h1>Registry Explorer</h1>
    <p class="lead">Browse all judged web addresses in real-time. Click any record to inspect reasons, detected threat categories, code signals, and historical verdicts.</p>` + listShell(
    `<div class="filters">
      <input id="q" type="search" placeholder="Search by URL, domain or keywords..." aria-label="Search by address" maxlength="100">
      <select id="fv" aria-label="Verdict">
        <option value="">All Verdicts</option>
        <option value="GREEN">GREEN (Safe)</option>
        <option value="AMBER">AMBER (Caution)</option>
        <option value="RED">RED (Threat)</option>
        <option value="UNREACHABLE">UNREACHABLE (Offline)</option>
      </select>
    </div>`),
  mount() {
    const load = pager($("#list"), $("#more"), off => browse($("#fv").value, $("#q").value, "", off), '<p class="note">No matching URLs found. <a href="#/scan">Submit a new scan.</a></p>');
    let t;
    $("#q").oninput = () => { clearTimeout(t); t = setTimeout(() => load(true), 300); };
    $("#fv").onchange = () => load(true);
    load(true);
  }
};

/* ---------- Interactive Playground Simulator ---------- */
const Playground = {
  html: () => `<h1>Heuristics & Scoring Simulator</h1>
    <p class="lead">Test the deterministic math behind GreenLight. Toggle code signals, set the LLM risk score, and see how the mathematical blending formula calculates the final verdict on-chain.</p>
    
    <div class="playground-box">
      <div class="playground-grid">
        <div>
          <h3>1. Simulated Code Signals</h3>
          <p class="note">Select detected signals to compute the heuristic score:</p>
          <div class="signal-toggle-group" id="pg-signals">
            <button type="button" class="signal-btn" data-flag="no_https" data-pts="10">No HTTPS (+10)</button>
            <button type="button" class="signal-btn" data-flag="ip_host" data-pts="25">Bare IP Host (+25)</button>
            <button type="button" class="signal-btn" data-flag="punycode" data-pts="20">Punycode / Homograph (+20)</button>
            <button type="button" class="signal-btn" data-flag="risky_tld" data-pts="8">Risky TLD (+8)</button>
            <button type="button" class="signal-btn" data-flag="lure_word_in_host" data-pts="10">Lure Word in Domain (+10)</button>
            <button type="button" class="signal-btn" data-flag="deep_subdomain" data-pts="8">Deep Subdomain (+8)</button>
            <button type="button" class="signal-btn" data-flag="hyphen_heavy" data-pts="8">Hyphen Heavy (+8)</button>
            <button type="button" class="signal-btn" data-flag="password_field" data-pts="15">Password Field (+15)</button>
            <button type="button" class="signal-btn" data-flag="seed_phrase_request" data-pts="30">Seed Phrase Request (+30)</button>
            <button type="button" class="signal-btn" data-flag="wallet_connect_lure" data-pts="15">Wallet Connect Lure (+15)</button>
            <button type="button" class="signal-btn" data-flag="urgency_language" data-pts="10">Urgency Language (+10)</button>
            <button type="button" class="signal-btn" data-flag="giveaway_lure" data-pts="15">Giveaway Lure (+15)</button>
            <button type="button" class="signal-btn" data-flag="cross_origin_form" data-pts="15">Cross-Origin Form (+15)</button>
            <button type="button" class="signal-btn" data-flag="obfuscated_script" data-pts="10">Obfuscated Script (+10)</button>
            <button type="button" class="signal-btn" data-flag="repeat_offender_host" data-pts="15">Repeat Offender Host (+15)</button>
          </div>
          
          <h3>2. LLM Estimated Risk</h3>
          <div style="margin:1rem 0;">
            <div style="display:flex;justify-content:space-between;margin-bottom:0.4rem;">
              <span>AI Risk Assessment:</span>
              <strong id="pg-llm-val" style="color:var(--leaf);font-family:var(--font-mono);font-size:1.1rem;">20</strong>
            </div>
            <input type="range" id="pg-llm" min="0" max="100" value="20" style="width:100%;accent-color:var(--leaf);">
          </div>
        </div>

        <div>
          <h3>3. Verdict Calculation</h3>
          <div style="background:rgba(0,0,0,0.4);border:1px solid var(--line);border-radius:16px;padding:1.4rem;">
            <div style="display:flex;justify-content:space-between;margin-bottom:0.8rem;">
              <span class="note">Code Heuristic Score:</span>
              <strong id="pg-heur" style="font-family:var(--font-mono);">0</strong>
            </div>
            <div style="display:flex;justify-content:space-between;margin-bottom:0.8rem;">
              <span class="note">LLM Weight (65%):</span>
              <span id="pg-llm-weighted" style="font-family:var(--font-mono);">13</span>
            </div>
            <div style="display:flex;justify-content:space-between;margin-bottom:0.8rem;">
              <span class="note">Heuristic Weight (35%):</span>
              <span id="pg-heur-weighted" style="font-family:var(--font-mono);">0</span>
            </div>
            <div style="display:flex;justify-content:space-between;margin-bottom:0.8rem;">
              <span class="note">Hard Floor Trigger (>= 70):</span>
              <span id="pg-hard-floor" style="font-family:var(--font-mono);color:var(--text-muted);">NO</span>
            </div>
            <div style="display:flex;justify-content:space-between;margin-bottom:0.8rem;">
              <span class="note">Host Neighborhood Bonus:</span>
              <span id="pg-bonus" style="font-family:var(--font-mono);color:var(--text-muted);">0</span>
            </div>
            <hr style="border:none;border-top:1px solid var(--line);margin:1rem 0;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
              <strong style="font-size:1.1rem;">Blended Risk Score:</strong>
              <strong id="pg-final-risk" style="font-size:1.6rem;font-family:var(--font-mono);color:var(--leaf);">13</strong>
            </div>
            
            <div style="text-align:center;padding:1.2rem;border-radius:14px;background:rgba(255,255,255,0.02);border:2px solid var(--leaf);" id="pg-verdict-box">
              <span class="badge" id="pg-verdict-badge" style="font-size:1.1rem;padding:0.4rem 1.4rem;">GREEN</span>
              <p id="pg-verdict-desc" class="note" style="margin:0.8rem 0 0;">No meaningful threat signals detected.</p>
            </div>
          </div>
        </div>
      </div>
    </div>`,

  mount() {
    const btns = document.querySelectorAll(".signal-btn");
    const slider = $("#pg-llm");
    const llmVal = $("#pg-llm-val");

    function recalc() {
      let heur = 0;
      let hasBonus = false;
      btns.forEach(b => {
        if (b.classList.contains("active")) {
          if (b.dataset.flag === "repeat_offender_host") hasBonus = true;
          else heur += parseInt(b.dataset.pts, 10);
        }
      });
      heur = Math.min(100, heur);
      const llm = parseInt(slider.value, 10);
      llmVal.textContent = llm;

      let blended = Math.floor((llm * 65 + heur * 35) / 100);
      const hardFloor = heur >= 70;
      if (hardFloor) blended = Math.max(blended, 70);
      if (hasBonus) blended += 15;
      blended = Math.max(0, Math.min(100, blended));

      let verdict = "AMBER";
      let desc = "Unclear or mildly suspicious characteristics.";
      let col = COL.AMBER;
      if (blended < 35) { verdict = "GREEN"; desc = "Verified safe. No significant threat vectors identified."; col = COL.GREEN; }
      else if (blended >= 70) { verdict = "RED"; desc = "High risk detected. Likely phishing, wallet drainer, or exploit lure."; col = COL.RED; }

      $("#pg-heur").textContent = heur;
      $("#pg-llm-weighted").textContent = Math.floor((llm * 65) / 100);
      $("#pg-heur-weighted").textContent = Math.floor((heur * 35) / 100);
      $("#pg-hard-floor").textContent = hardFloor ? "YES (Forces RED)" : "NO";
      $("#pg-hard-floor").style.color = hardFloor ? "var(--red)" : "var(--text-muted)";
      $("#pg-bonus").textContent = hasBonus ? "+15" : "0";
      $("#pg-bonus").style.color = hasBonus ? "var(--amber)" : "var(--text-muted)";

      $("#pg-final-risk").textContent = blended;
      $("#pg-final-risk").style.color = col;

      const vBox = $("#pg-verdict-box");
      const vBadge = $("#pg-verdict-badge");
      vBox.style.borderColor = col;
      vBadge.style.backgroundColor = col;
      vBadge.style.color = "#070B0E";
      vBadge.textContent = verdict;
      $("#pg-verdict-desc").textContent = desc;
    }

    btns.forEach(b => {
      b.onclick = () => {
        b.classList.toggle("active");
        recalc();
      };
    });

    slider.oninput = recalc;
    recalc();
  }
};

const Me = {
  html: () => `<h1>My Scans & Contributions</h1><div id="meh"></div>` + listShell(),
  mount() {
    const list = $("#list"), more = $("#more"); let load = null, who = "";
    const render = async () => {
      const e = epoch;
      const s = wState(); if (s.address === who && load) return; who = s.address;
      if (!s.address) {
        $("#meh").innerHTML = '<div class="callout">Connect your wallet to track submissions and scans you initiated. <button id="mc" type="button" style="margin-left:0.6rem;">Connect Wallet</button></div>';
        $("#mc").onclick = openWallets; list.innerHTML = ""; more.hidden = true; load = null; return;
      }
      let n = "";
      if (LIVE) { try { n = " " + Number((await read("contributor", [s.address])).scans) + " total scans recorded."; } catch {} }
      if (e !== epoch) return;
      $("#meh").innerHTML = `<p class="lead">Connected with <code>${esc(s.address)}</code>.${esc(n)}</p><p class="note">Displaying URLs where your address was the most recent contributor. If another user rescans a URL, it updates to their address.</p>`;
      load = pager(list, more, off => browse("", "", s.address.toLowerCase(), off), '<p class="note">You haven’t submitted any scans yet. <a href="#/scan">Scan your first URL.</a></p>');
      load(true);
    };
    cleanups.push(subscribe(render)); render();
  }
};

const Host = {
  html: () => {
    let h = ""; try { h = decodeURIComponent(location.hash.split("/")[2] || ""); } catch {}
    return `<h1>Domain Intelligence</h1><p class="lead">${esc(h) || "Domain"}</p><div id="hov"></div>` + listShell();
  },
  async mount() {
    const e = epoch;
    let h = ""; try { h = decodeURIComponent(location.hash.split("/")[2] || "").toLowerCase(); } catch {}
    if (!h) { $("#list").innerHTML = '<p class="note">No host specified. <a href="#/registry">Open Registry.</a></p>'; return; }
    if (LIVE) {
      try {
        const o = await read("host_overview", [h]);
        if (e !== epoch) return;
        $("#hov").innerHTML = `<div class="callout" style="${o.flagged ? 'border-left-color:var(--red);' : ''}">
          <p style="margin:0;"><strong>${Number(o.red_urls)} RED URL(s)</strong> flagged on this host.${o.flagged ? " ⚠ Host flagged: Any new scan on this domain receives an automatic +15 point neighborhood penalty." : " Host is within normal thresholds."}</p>
        </div>`;
      } catch {}
    }
    if (e !== epoch) return;
    pager($("#list"), $("#more"), async off => {
      const d = await browse("", h, "", off);
      return { ...d, raw: d.items.length, items: d.items.filter(r => r.host === h) };
    }, '<p class="note">No scans found for this host yet.</p>')(true);
  }
};

const How = {
  html: () => `<h1>How GreenLight Works</h1>
    <p class="lead">GreenLight achieves trusted on-chain verification through GenLayer's Equivalence Principle: multi-validator execution combining deterministic code analysis with independent LLM reasoning.</p>

    <h2>The 7-Step Consensus Pipeline</h2>
    <ol class="flow">
      <li><b>URL Normalization & Security Screening.</b> Scheme and host are lowercased, default ports and fragments are stripped. RFC 1918 private IPs, AWS/GCP metadata endpoints, loopback ranges, and wildcard DNS resolvers (nip.io, sslip.io, vcap.me) are rejected to eliminate Server-Side Request Forgery (SSRF).</li>
      <li><b>Decentralized Web Fetching.</b> The leader validator fetches the raw HTML body. Network errors, timeouts, or HTTP status >= 400 immediately yield UNREACHABLE without risking invalid model hallucinations.</li>
      <li><b>Deterministic Code Heuristics.</b> 15 objective signals are calculated in pure code: password inputs, seed-phrase requests, wallet-connect lures, urgency terms, cross-origin form destinations, punycode spoofing, and obfuscated scripts.</li>
      <li><b>LLM Reasoning & Category Extraction.</b> The AI validator analyzes the text against ground-truth heuristics to estimate risk (0–100), identify impersonation targets, determine the threat category, and summarize in one clear sentence.</li>
      <li><b>Deterministic Score Blending.</b> Score = 65% Model + 35% Heuristics. If heuristic score >= 70, the final risk is forced to at least RED. If the domain already has >= 2 RED URLs, a +15 repeat-offender bonus is added.</li>
      <li><b>Validator Consensus & Equivalence Rule.</b> Validators independently repeat steps 2–5. A leader's block is accepted only if: both saw reachability, URL flags match identically, leader fields are well-formed, and risk scores differ by no more than 20 points.</li>
      <li><b>Immutable On-Chain Finalization.</b> Counters, host penalty tables, feed indexes, and historical sparkline entries are committed to storage.</li>
    </ol>

    <h2>Scoring Thresholds & Meaning</h2>
    <table>
      <thead><tr><th>Verdict</th><th>Risk Score</th><th>Security Definition</th></tr></thead>
      <tbody>
        <tr><td><span class="badge" style="background:var(--leaf);color:#000;">GREEN</span></td><td>0 to 34</td><td>No significant threat or phishing vectors found.</td></tr>
        <tr><td><span class="badge" style="background:var(--amber);color:#000;">AMBER</span></td><td>35 to 69</td><td>Unclear, promotional, or mildly suspicious patterns.</td></tr>
        <tr><td><span class="badge" style="background:var(--red);color:#000;">RED</span></td><td>70 to 100</td><td>Definite phishing, wallet drainer, fake store, or malware lure.</td></tr>
        <tr><td><span class="badge" style="background:var(--grey);color:#fff;">UNREACHABLE</span></td><td>None</td><td>Page failed to fetch (HTTP 4xx/5xx, timeout, or DNS failure).</td></tr>
      </tbody>
    </table>

    <div class="callout">
      <strong>Why Tolerance-Based Consensus?</strong> Two separate LLM calls will rarely produce the exact same text token for token, but both will recognize a recovery phrase phishing lure as dangerous. By comparing the calculated risk score within a 20-point boundary rather than raw text equality, GenLayer achieves resilient, robust consensus without nondeterministic stalls.
    </div>`
};

const DOCS = {
  overview: ["Architecture Overview", `<p>GreenLight answers one question on-chain: <em>is this web address safe to open?</em> It stores one record per normalised URL: verdict, risk score, category, possible impersonated brand, a one-sentence plain-language summary written by the model, up to three reasons, the signals that fired, and the last eight verdict checks.</p>
    <p>Anyone can scan, rescan a URL after 60 seconds (one address can submit a scan every 15 seconds), or read for free. Other Intelligent Contracts can call <code>is_safe(url)</code> before they accept or forward a link.</p>
    <h3>On-Chain Record Structure</h3>
    <table>
      <thead><tr><th>Field</th><th>Type</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td><code>verdict</code>, <code>risk</code></td><td>str, u32</td><td>Categorical band (GREEN, AMBER, RED) and 0-100 blended score.</td></tr>
        <tr><td><code>category</code></td><td>str</td><td>Threat type: phishing, wallet_drainer, scam_giveaway, malware_lure, fake_store, impersonation, other, none.</td></tr>
        <tr><td><code>reasons</code>, <code>flags</code></td><td>str, str</td><td>Model explanation and deterministic heuristics that fired.</td></tr>
        <tr><td><code>reporter</code>, <code>last_scanner</code></td><td>Address</td><td>Original discoverer and most recent contributor.</td></tr>
        <tr><td><code>history</code></td><td>str</td><td>Sliding window of the last 8 scans, used for the history timeline.</td></tr>
      </tbody>
    </table>`],

  signals: ["Heuristic Signals Reference", `<p>Signals are computed deterministically in pure code with zero LLM dependency. They are repeatable, cheap, and impossible to bypass with prompt injections.</p>
    <table>
      <thead><tr><th>Signal</th><th>Points</th><th>Detection Rule</th></tr></thead>
      <tbody>
        <tr><td><code>no_https</code></td><td>10</td><td>Protocol is plain HTTP instead of HTTPS.</td></tr>
        <tr><td><code>ip_host</code></td><td>25</td><td>Host is an IPv4 address instead of a domain name.</td></tr>
        <tr><td><code>punycode</code></td><td>20</td><td>Domain contains xn-- homograph spoofing characters.</td></tr>
        <tr><td><code>deep_subdomain</code></td><td>8</td><td>Five or more subdomain labels.</td></tr>
        <tr><td><code>hyphen_heavy</code></td><td>8</td><td>Three or more hyphens in domain name.</td></tr>
        <tr><td><code>risky_tld</code></td><td>8</td><td>Top-level domain in high-abuse list (.zip, .top, .click, etc.).</td></tr>
        <tr><td><code>lure_word_in_host</code></td><td>10</td><td>Host contains keywords: login, verify, wallet, airdrop, claim.</td></tr>
        <tr><td><code>password_field</code></td><td>15</td><td>HTML contains password input field.</td></tr>
        <tr><td><code>seed_phrase_request</code></td><td>30</td><td>Input field combined with mnemonic/seed phrase keywords.</td></tr>
        <tr><td><code>wallet_connect_lure</code></td><td>15</td><td>Wallet connection pressure language.</td></tr>
        <tr><td><code>urgency_language</code></td><td>10</td><td>Two or more urgency terms ("act now", "suspended in 24 hours").</td></tr>
        <tr><td><code>giveaway_lure</code></td><td>15</td><td>"Double your crypto" or "guaranteed return" language.</td></tr>
        <tr><td><code>cross_origin_form</code></td><td>15</td><td>Form action posts credentials to a foreign external origin.</td></tr>
        <tr><td><code>obfuscated_script</code></td><td>10</td><td>eval() and atob() present in script blocks.</td></tr>
        <tr><td><code>repeat_offender_host</code></td><td>+15</td><td>Domain already has 2 or more RED URLs recorded.</td></tr>
      </tbody>
    </table>`],

  consensus: ["Validator Consensus & Equivalence", `<p>GreenLight utilizes GenLayer's Equivalence Principle with a custom leader and validator function pair via <code>gl.vm.run_nondet_unsafe</code>.</p>
    <p>The leader validator executes the full pipeline. Every subsequent validator executes it independently and votes to accept only if:</p>
    <ul>
      <li>Both validators observed the page reachable, or both observed it unreachable.</li>
      <li>The leader's verdict matches its own risk score.</li>
      <li>URL-derived flags match identically between leader and validator.</li>
      <li>Risk scores land within the 20-point <code>RISK_TOLERANCE</code> window.</li>
      <li>Leader returned a valid category and no more than 3 reasons.</li>
    </ul>
    <p>If any validator check fails, the network rejects the leader and rotates to another validator.</p>`],

  security: ["Security & Attack Defenses", `<h3>Prompt Injection Defenses</h3>
    <p>HTML text is strictly enclosed in fenced tags and declared untrusted in model prompts. Furthermore, strong code signals enforce a hard floor: any page triggering >= 70 code heuristic points is locked to RED regardless of what the LLM outputs.</p>
    <h3>SSRF & Private Network Shield</h3>
    <p>Internal domains (.local, .internal, .lan, .corp), reserved IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10), and wildcard DNS services (nip.io, sslip.io, vcap.me) are screened before any fetch is initiated.</p>
    <h3>Takedown Persistence</h3>
    <p>If an attacker launches a malicious site and takes it offline right before rescanning, GreenLight retains the RED verdict through 2 consecutive unreachable scans, transitioning to UNREACHABLE only on the 3rd consecutive miss.</p>`],

  wallets: ["Wallet Integration & EIP-6963", `<p>GreenLight supports the latest Ethereum wallet standards:</p>
    <ul>
      <li><strong>EIP-6963:</strong> Multi-injected wallet discovery. MetaMask, Rabby, Coinbase Wallet, OKX, Phantom, and Brave are detected concurrently without provider collisions.</li>
      <li><strong>Automatic Studionet Switching:</strong> Automatically prompts your wallet to switch to Chain ID 61999 (GenLayer Studionet) with custom RPC and explorer URLs.</li>
      <li><strong>Test Key (Burner Wallet):</strong> Instant throwaway cryptographic key stored in browser localStorage for testing without any wallet extension.</li>
      <li><strong>Zero-Cost Reads:</strong> Looking up verdicts, browsing the registry, checking host stats, and copying reports requires zero wallet connection and zero gas fees.</li>
    </ul>`],

  deploy: ["Deployment & Contracts", `<p>Deploy <code>contracts/green_light.py</code> directly to Studionet using the GenLayer CLI or npm deploy script:</p>
    ${pre(`npm install\nnpm run deploy\n# Or with custom deployer private key:\nPRIVATE_KEY=0x... npm run deploy`)}
    <p>The deploy script automatically compiles the contract, signs the deployment transaction on Studionet, retrieves the deployed contract address from validator receipts, and updates <code>frontend/config.js</code>.</p>`]
};

const Docs = {
  html: () => {
    const k = (location.hash.split("/")[2] || "overview");
    const known = Object.hasOwn(DOCS, k);
    const d = known ? DOCS[k] : DOCS.overview;
    const key = known ? k : "overview";
    return `<div class="docs">
      <nav class="side" aria-label="Documentation">
        ${Object.entries(DOCS).map(([id, [t]]) => `<a href="#/docs/${id}" class="${id === key ? "on" : ""}">${t}</a>`).join("")}
      </nav>
      <article>
        <h1>${d[0]}</h1>
        ${d[1]}
      </article>
    </div>`;
  }
};

const Integrate = {
  html: () => `<h1>Developer Integration</h1>
    <p class="lead">Integrate GreenLight into your own dApps or GenLayer Intelligent Contracts to protect your users from malicious external links.</p>

    <h2>1. Calling from Another Intelligent Contract</h2>
    <p>Perform on-chain safety verification in Python without gas cost for read-only view calls:</p>
    ${pre(`from genlayer import *
import typing

@gl.contract_interface
class GreenLightRegistry:
    class View:
        def is_safe(self, url: str) -> bool: ...
        def check(self, url: str) -> typing.Any: ...
    class Write:
        def scan(self, url: str) -> None: ...

# In your contract logic:
registry = GreenLightRegistry(Address("0xYourDeployedAddress"))
if not registry.view().is_safe(user_submitted_url):
    raise gl.vm.UserError("[SECURITY] Link is not verified safe by GreenLight")`)}

    <h2>2. Calling from JavaScript / TypeScript</h2>
    <p>Query the registry in web frontends or Node.js services using <code>genlayer-js</code>:</p>
    ${pre(`import { createClient } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

const client = createClient({ chain: studionet });
const result = await client.readContract({
  address: "0xYourDeployedAddress",
  functionName: "get_scan",
  args: ["https://example.com/login"]
});

console.log("Verdict:", result.verdict); // "GREEN" | "AMBER" | "RED"
console.log("Risk Score:", result.risk);    // 0 - 100`)}

    <h2>Contract Methods Reference</h2>
    <table>
      <thead><tr><th>Method</th><th>Kind</th><th>Returns</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td><code>scan(url)</code></td><td>write</td><td>void</td><td>Submits a URL to validator consensus and updates on-chain registry.</td></tr>
        <tr><td><code>is_safe(url)</code></td><td>view</td><td>bool</td><td>Returns true only if the URL is indexed with a GREEN verdict.</td></tr>
        <tr><td><code>get_scan(url)</code></td><td>view</td><td>object | null</td><td>Returns full scan record with history, signals, and summary.</td></tr>
        <tr><td><code>check(url)</code></td><td>view</td><td>object</td><td>Returns compact integrator object: {known, safe, verdict, risk, last_scanned}.</td></tr>
        <tr><td><code>browse(...)</code></td><td>view</td><td>object</td><td>Filtered pagination over newest feed window.</td></tr>
        <tr><td><code>recent(off, lim)</code></td><td>view</td><td>object</td><td>Newest records list (max limit 25).</td></tr>
        <tr><td><code>host_overview(h)</code></td><td>view</td><td>object</td><td>Returns RED URL count and flagged penalty state for domain.</td></tr>
        <tr><td><code>stats()</code></td><td>view</td><td>object</td><td>Aggregate registry statistics and verdict distribution.</td></tr>
        <tr><td><code>contributor(a)</code></td><td>view</td><td>object</td><td>Returns total scans contributed by given address.</td></tr>
        <tr><td><code>config()</code></td><td>view</td><td>object</td><td>Returns contract version and consensus constants.</td></tr>
      </tbody>
    </table>`
};

/* ---------- wallet ui ---------- */
const wbtn = $("#wbtn"), menu = $("#wmenu"), dlg = $("#wm");
const bad = s => s.kind === "injected" && s.chainId !== NET.chainId;
const imgOf = src => src ? `<img src="${esc(src)}" alt="" width="28" height="28">` : '<span class="wi"></span>';
function toast(msg, kind = "ok") {
  const t = document.createElement("div");
  t.className = "toast " + kind;
  t.textContent = msg;
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 4500);
}
function closeMenu() { menu.hidden = true; wbtn.setAttribute("aria-expanded", "false"); }
function renderMenu() {
  const s = wState(); if (!s.address) { closeMenu(); return; }
  menu.innerHTML = `<div class="mtop">${imgOf(s.icon)}<b>${esc(s.name)}</b></div><code>${esc(s.address)}</code>
    <p class="note" style="margin:0.4rem 0;">${s.kind === "burner" ? "Throwaway testing key stored in this browser." : bad(s) ? "Wrong Network: Chain " + esc(s.chainId) : "Connected to " + esc(NET.name)}</p>
    <div class="macts">
      <button class="ghostb" type="button" data-a="copy">Copy Address</button>
      ${bad(s) ? '<button type="button" data-a="switch">Switch to Studionet</button>' : ""}
      ${s.kind === "burner" ? '<button class="ghostb" type="button" data-a="newkey">New Test Key</button>' : ""}
      <button class="ghostb" type="button" data-a="out">Disconnect</button>
    </div>`;
}
function renderWallets() {
  const list = wallets(), s = wState();
  $("#wl").innerHTML = list.map(w => `<button class="wopt" type="button" data-u="${esc(w.info.uuid)}" ${s.busy ? "disabled" : ""}>${imgOf(safeIcon(w.info.icon))}<span>${esc(w.info.name)}</span></button>`).join("")
    + (list.length ? "" : '<p class="note">No browser wallet detected. Install MetaMask, Rabby, or Coinbase Wallet.</p>')
    + `<button class="wopt" type="button" data-u="burner" ${s.busy ? "disabled" : ""}><span class="wi">T</span><span>Test Key (Burner)<small>Instant throwaway key. No extension required.</small></span></button>`;
  $("#we").textContent = s.error || "";
}
function renderAcct() {
  const s = wState(); wbtn.disabled = s.busy;
  if (s.busy) { wbtn.className = ""; wbtn.textContent = "Connecting..."; }
  else if (!s.address) { wbtn.className = ""; wbtn.textContent = "Connect wallet"; closeMenu(); }
  else { wbtn.className = "ghostb acctbtn"; wbtn.innerHTML = `<span class="st ${bad(s) ? "warn" : "ok"}"></span>${esc(short(s.address))}`; }
  if (!menu.hidden) renderMenu();
  if (dlg.open) renderWallets();
}
function openWallets() { if (dlg.open) return; renderWallets(); $("#we").textContent = ""; dlg.showModal(); }
async function doSwitch() { try { await switchToStudionet(); toast("Switched to " + NET.name); } catch (e) { toast(friendly(e), "err"); } }
$("#wl").onclick = async e => {
  const b = e.target.closest(".wopt"); if (!b) return; const u = b.dataset.u;
  try {
    if (u === "burner") await connectBurner(); else await connectInjected(wallets().find(w => w.info.uuid === u));
    if (wState().address) { dlg.close(); toast("Wallet connected successfully"); if (bad(wState())) toast("Please switch network to Studionet", "err"); }
  } catch (err) { $("#we").textContent = friendly(err); }
};
menu.onclick = async e => {
  const a = e.target.closest("[data-a]")?.dataset.a; if (!a) return;
  try {
    if (a === "copy") { await navigator.clipboard.writeText(wState().address); toast("Address copied to clipboard"); }
    else if (a === "switch") await doSwitch();
    else if (a === "out") { closeMenu(); await disconnect(); toast("Disconnected"); }
    else if (a === "newkey") { await disconnect(); newBurnerKey(); await connectBurner(); toast("New test key created"); }
  } catch (err) { toast(friendly(err), "err"); }
};
wbtn.onclick = e => { e.stopPropagation(); if (!wState().address) return openWallets(); if (menu.hidden) { renderMenu(); menu.hidden = false; wbtn.setAttribute("aria-expanded", "true"); } else closeMenu(); };
$("#wx").onclick = () => dlg.close();
dlg.addEventListener("click", e => { if (e.target === dlg) dlg.close(); });
document.addEventListener("click", e => { if (!menu.hidden && !menu.contains(e.target) && e.target !== wbtn) closeMenu(); });
document.addEventListener("keydown", e => { if (e.key === "Escape") closeMenu(); });

/* ---------- router ---------- */
const cleanups = [];
let epoch = 0;
const routes = {
  home: Home,
  scan: ScanPage,
  check: Check,
  registry: Registry,
  playground: Playground,
  me: Me,
  host: Host,
  how: How,
  docs: Docs,
  integrate: Integrate
};
let last = "";
function route() {
  epoch++;
  clearInterval(timer);
  cleanups.splice(0).forEach(f => f());
  document.body.classList.remove("navopen");
  $("#nb").setAttribute("aria-expanded", "false");
  const k = (location.hash.replace(/^#\/?/, "") || "home").split("/")[0];
  const page = Object.hasOwn(routes, k) ? routes[k] : Home;
  const app = $("#app");
  app.classList.remove("in");
  app.innerHTML = page.html();
  void app.offsetWidth;
  app.classList.add("in");

  document.querySelectorAll("nav a[data-k]").forEach(a => {
    a.classList.toggle("on", a.dataset.k === (k === "check" ? "scan" : k === "host" ? "registry" : Object.hasOwn(routes, k) ? k : "home"));
  });

  if (page.mount) page.mount();
  if (k + location.hash !== last) scrollTo(0, 0);
  last = k + location.hash;
}

const mode = $("#mode"), cd = $("#cd");
mode.textContent = LIVE ? "Studionet " + ADDR.slice(0, 6) + "..." + ADDR.slice(-4) : "Demo mode";
mode.title = "Contract settings";
mode.onclick = () => { $("#ca").value = ADDR; $("#ce").textContent = ""; $("#cr").hidden = !saved; cd.showModal(); };
$("#cx").onclick = () => cd.close();
$("#cs").onclick = () => {
  const v = $("#ca").value.trim();
  if (!/^0x[0-9a-fA-F]{40}$/.test(v)) { $("#ce").textContent = "Enter a valid 42-character address starting with 0x."; return; }
  try { localStorage.setItem("gl_contract", v); } catch {}
  location.reload();
};
$("#cr").onclick = () => { try { localStorage.removeItem("gl_contract"); } catch {} location.reload(); };
$("#nb").onclick = () => { const o = document.body.classList.toggle("navopen"); $("#nb").setAttribute("aria-expanded", String(o)); };

subscribe(renderAcct);
startDiscovery();
renderAcct();
addEventListener("hashchange", route);
route();
restore();
