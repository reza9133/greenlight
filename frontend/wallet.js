// GreenLight wallet layer.
//
// - Discovers every injected wallet through EIP-6963 (MetaMask, Rabby, Coinbase,
//   OKX, Trust, Phantom EVM, Brave and any other compliant wallet) and falls back
//   to window.ethereum for legacy wallets.
// - Adds and selects the Studionet network automatically.
// - Handles connect, account and network changes, restore on reload and disconnect.
// - Offers a throwaway "test key" for people without a wallet.
// - Reads never need a wallet. Writes go through the connected wallet.

import { CONFIG } from "./config.js";

const defaults = {
  chainId: 61999,
  name: "GenLayer Studionet",
  rpc: "https://studio.genlayer.com/api",
  explorer: "https://explorer-studio.genlayer.com",
  currency: { name: "GEN", symbol: "GEN", decimals: 18 },
};
export const NET = Object.freeze({ ...defaults, ...(CONFIG.NETWORK || {}) });
const CHAIN_HEX = "0x" + Number(NET.chainId).toString(16);

const KEY_WALLET = "gl_wallet";
const KEY_PK = "gl_pk";
const store = {
  get: k => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch {} },
  del: k => { try { localStorage.removeItem(k); } catch {} },
};

/* ---------- state ---------- */
const blank = () => ({ kind: null, name: "", icon: "", rdns: "", provider: null, address: "", chainId: null, busy: false, error: "" });
let S = blank();
let seq = 0;            // bumped on every connect/disconnect so stale async work is ignored
let off = null;         // removes provider listeners
let writer = null, writerKey = "", reader = null, burner = null, sdk = null;
const subs = new Set();
export const state = () => S;
export function subscribe(fn) { subs.add(fn); return () => subs.delete(fn); }
function patch(p) { S = { ...S, ...p }; subs.forEach(f => { try { f(S); } catch (e) { console.error(e); } }); }

/* ---------- helpers ---------- */
const hexToNum = h => parseInt(String(h), 16);
export const short = a => a ? a.slice(0, 6) + "..." + a.slice(-4) : "";
export const safeIcon = s => typeof s === "string" && /^data:image\/(png|jpeg|webp|gif|svg\+xml)[;,]/.test(s) ? s : "";
export function friendly(e) {
  const code = e && (e.code ?? (e.cause && e.cause.code));
  const msg = String((e && (e.shortMessage || e.message)) || e || "Unknown error");
  if (code === 4001 || /user rejected|user denied|rejected the request/i.test(msg)) return "Request rejected in the wallet.";
  if (code === -32002) return "The wallet already has a pending request. Open it and respond.";
  return msg.length > 200 ? msg.slice(0, 200) + "..." : msg;
}
// A wallet popup that is closed without an answer can leave a request hanging forever. Give up after a while.
function withTimeout(promise, ms, message) {
  let t;
  const timer = new Promise((_, reject) => { t = setTimeout(() => reject(new Error(message)), ms); if (t && t.unref) t.unref(); });
  return Promise.race([promise, timer]).finally(() => clearTimeout(t));
}
const newKey = () => "0x" + [...crypto.getRandomValues(new Uint8Array(32))].map(b => b.toString(16).padStart(2, "0")).join("");

/* ---------- discovery (EIP-6963) ---------- */
const found = new Map();
export function startDiscovery() {
  addEventListener("eip6963:announceProvider", e => {
    const d = e.detail;
    if (d && d.info && d.info.uuid && d.provider && typeof d.provider.request === "function") { found.set(d.info.uuid, d); patch({}); }
  });
  dispatchEvent(new Event("eip6963:requestProvider"));
}
export function wallets() {
  const list = [...found.values()].sort((a, b) => String(a.info.name).localeCompare(String(b.info.name)));
  if (!list.length && typeof window !== "undefined" && window.ethereum && typeof window.ethereum.request === "function")
    list.push({ info: { uuid: "legacy", name: "Browser wallet", icon: "", rdns: "legacy" }, provider: window.ethereum });
  return list;
}

/* ---------- provider events ---------- */
function detach() { if (off) { off(); off = null; } }
function attach(p) {
  detach();
  const lost = () => { writer = null; store.del(KEY_WALLET); detach(); patch(blank()); };
  const onAccounts = a => { writer = null; if (!Array.isArray(a) || !a.length) lost(); else patch({ address: a[0] }); };
  const onChain = c => { writer = null; patch({ chainId: hexToNum(c) }); };
  if (typeof p.on === "function") { p.on("accountsChanged", onAccounts); p.on("chainChanged", onChain); p.on("disconnect", lost); }
  off = () => {
    if (typeof p.removeListener !== "function") return;
    p.removeListener("accountsChanged", onAccounts); p.removeListener("chainChanged", onChain); p.removeListener("disconnect", lost);
  };
}

/* ---------- connect / switch / disconnect ---------- */
async function adopt(entry, accounts, my) {
  const p = entry.provider;
  const chainId = hexToNum(await p.request({ method: "eth_chainId" }));
  if (my !== seq) return false;
  attach(p);
  writer = null;
  patch({ kind: "injected", name: String(entry.info.name || "Wallet"), icon: safeIcon(entry.info.icon), rdns: String(entry.info.rdns || ""),
    provider: p, address: accounts[0], chainId, busy: false, error: "" });
  store.set(KEY_WALLET, String(entry.info.rdns || "legacy"));
  return true;
}

export async function connectInjected(entry) {
  if (S.busy || !entry) return false;
  const my = ++seq;
  detach(); writer = null;
  patch({ ...blank(), busy: true });
  try {
    const accounts = await withTimeout(entry.provider.request({ method: "eth_requestAccounts" }), 120000, "The wallet did not respond. Open it, or close the popup and try again.");
    if (my !== seq) return false;
    if (!Array.isArray(accounts) || !accounts.length) throw new Error("The wallet returned no account.");
    if (!(await adopt(entry, accounts, my))) return false;
  } catch (e) {
    if (my === seq) patch({ ...blank(), error: friendly(e) });
    throw e;
  }
  if (S.chainId !== NET.chainId) {
    try { await switchToStudionet(); } catch (e) { patch({ error: friendly(e) }); }
  }
  return true;
}

export async function switchToStudionet() {
  const p = S.provider;
  if (!p) throw new Error("No wallet is connected.");
  try {
    await p.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_HEX }] });
  } catch (e) {
    const code = e && e.code;
    if (code === 4001 || /user rejected|user denied/i.test(String((e && e.message) || ""))) throw e;
    // 4902: chain unknown. Some wallets report it as -32603 or with a text message instead.
    await p.request({ method: "wallet_addEthereumChain", params: [{
      chainId: CHAIN_HEX, chainName: NET.name, nativeCurrency: NET.currency,
      rpcUrls: [NET.rpc], blockExplorerUrls: [NET.explorer],
    }] });
    try { await p.request({ method: "wallet_switchEthereumChain", params: [{ chainId: CHAIN_HEX }] }); } catch {}
  }
  const chainId = hexToNum(await p.request({ method: "eth_chainId" }));
  writer = null;
  patch({ chainId });
  if (chainId !== NET.chainId) throw new Error("The wallet is still on another network. Switch to " + NET.name + " in the wallet.");
}

export async function connectBurner() {
  if (S.busy) return false;
  const my = ++seq;
  detach(); writer = null;
  patch({ ...blank(), busy: true });
  try {
    const s = await loadSdk();
    let pk = store.get(KEY_PK);
    if (!/^0x[0-9a-fA-F]{64}$/.test(pk || "")) { pk = newKey(); store.set(KEY_PK, pk); }
    burner = s.createAccount(pk);
    if (my !== seq) return false;
    store.set(KEY_WALLET, "burner");
    patch({ kind: "burner", name: "Test key", icon: "", rdns: "burner", provider: null, address: burner.address, chainId: NET.chainId, busy: false, error: "" });
    return true;
  } catch (e) {
    if (my === seq) patch({ ...blank(), error: friendly(e) });
    throw e;
  }
}
export function newBurnerKey() { store.del(KEY_PK); }

export async function disconnect() {
  seq++;
  const { provider, kind } = S;
  detach(); writer = null; burner = kind === "burner" ? null : burner;
  store.del(KEY_WALLET);
  patch(blank());
  // EIP-1193 has no disconnect. MetaMask-compatible wallets can revoke the site permission.
  if (kind === "injected" && provider) {
    try { await provider.request({ method: "wallet_revokePermissions", params: [{ eth_accounts: {} }] }); } catch {}
  }
}

export async function restore() {
  const remembered = store.get(KEY_WALLET);
  if (!remembered || S.address || S.busy) return;
  if (remembered === "burner") { try { await connectBurner(); } catch {} return; }
  await new Promise(r => setTimeout(r, 300));          // give wallets time to announce themselves
  const entry = wallets().find(w => w.info.rdns === remembered);
  if (!entry || S.address || S.busy) return;
  const my = ++seq;
  try {
    const accounts = await entry.provider.request({ method: "eth_accounts" });   // silent, never prompts
    if (my !== seq) return;
    if (Array.isArray(accounts) && accounts.length) await adopt(entry, accounts, my);
    else store.del(KEY_WALLET);
  } catch {}
}

/* ---------- genlayer-js clients ---------- */
async function loadSdk() {
  if (!sdk) {
    const [m, c] = await Promise.all([import(CONFIG.SDK_URL), import(CONFIG.CHAINS_URL)]);
    if (!c.studionet) throw new Error("genlayer-js/chains does not export studionet. Pin a compatible SDK version in config.js.");
    sdk = { createClient: m.createClient, createAccount: m.createAccount, chain: c.studionet };
  }
  return sdk;
}
export async function readClient() {
  if (!reader) { const s = await loadSdk(); reader = s.createClient({ chain: s.chain }); }
  return reader;
}
export async function writeClient() {
  if (!S.address) throw new Error("Connect a wallet first.");
  const s = await loadSdk();
  if (S.kind === "injected") {
    const live = hexToNum(await S.provider.request({ method: "eth_chainId" }));
    if (live !== NET.chainId) { patch({ chainId: live }); await switchToStudionet(); }
  }
  const key = [S.kind, S.address, S.rdns].join("|");
  if (writer && writerKey === key) return writer;
  const c = S.kind === "burner"
    ? s.createClient({ chain: s.chain, account: burner })
    : s.createClient({ chain: s.chain, account: S.address, provider: S.provider });
  if (S.kind === "injected" && typeof c.connect === "function") { try { await c.connect("studionet"); } catch {} }
  writer = c; writerKey = key;
  return c;
}
