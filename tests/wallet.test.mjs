// Offline tests for frontend/wallet.js using a fake EIP-1193 / EIP-6963 wallet.
// Run:  node tests/wallet.test.mjs
import assert from "node:assert/strict";

const bus = new EventTarget();
const mem = new Map();
globalThis.addEventListener = (...a) => bus.addEventListener(...a);
globalThis.dispatchEvent = e => bus.dispatchEvent(e);
globalThis.window = globalThis;
globalThis.localStorage = { getItem: k => mem.get(k) ?? null, setItem: (k, v) => mem.set(k, String(v)), removeItem: k => mem.delete(k) };

class FakeWallet {
  constructor({ chain = 1, knowsStudionet = false, rejectSwitch = false, delay = 0 } = {}) {
    this.chain = chain; this.known = new Set([1, ...(knowsStudionet ? [61999] : [])]); this.rejectSwitch = rejectSwitch; this.delay = delay;
    this.calls = []; this.handlers = {}; this.accounts = ["0xAbCdEf0123456789aBcDeF0123456789AbCdEf01"];
  }
  on(e, f) { (this.handlers[e] ||= new Set()).add(f); }
  removeListener(e, f) { this.handlers[e]?.delete(f); }
  emit(e, v) { (this.handlers[e] || []).forEach(f => f(v)); }
  listeners() { return Object.values(this.handlers).reduce((n, s) => n + s.size, 0); }
  async request({ method, params = [] }) {
    this.calls.push(method);
    if (this.delay) await new Promise(r => setTimeout(r, this.delay));
    switch (method) {
      case "eth_requestAccounts": case "eth_accounts": return this.accounts;
      case "eth_chainId": return "0x" + this.chain.toString(16);
      case "wallet_switchEthereumChain": {
        if (this.rejectSwitch) throw { code: 4001, message: "User rejected the request." };
        const id = parseInt(params[0].chainId, 16);
        if (!this.known.has(id)) throw { code: 4902, message: "Unrecognized chain ID" };
        this.chain = id; this.emit("chainChanged", params[0].chainId); return null;
      }
      case "wallet_addEthereumChain": this.addParams = params[0]; this.known.add(parseInt(params[0].chainId, 16)); return null;
      case "wallet_revokePermissions": this.revoked = true; return null;
      default: throw new Error("unsupported " + method);
    }
  }
}
const announce = (w, uuid, name, rdns) => bus.addEventListener("eip6963:requestProvider", () =>
  bus.dispatchEvent(Object.assign(new Event("eip6963:announceProvider"), { detail: { info: { uuid, name, rdns, icon: "data:image/svg+xml;base64,AAA" }, provider: w } })));

const W = await import("../frontend/wallet.js");
const a = new FakeWallet(); announce(a, "u-a", "Alpha Wallet", "io.alpha");
const b = new FakeWallet({ chain: 61999 }); announce(b, "u-b", "Beta Wallet", "io.beta");
W.startDiscovery();
assert.deepEqual(W.wallets().map(w => w.info.name), ["Alpha Wallet", "Beta Wallet"]);
assert.equal(W.NET.chainId, 61999);

// 1. connect on a foreign chain: wallet is switched automatically, unknown chain is added first
await W.connectInjected(W.wallets()[0]);
assert.equal(W.state().address, a.accounts[0]); assert.equal(W.state().chainId, 61999); assert.equal(W.state().kind, "injected");
assert.deepEqual(a.calls.filter(c => c.startsWith("wallet_")), ["wallet_switchEthereumChain", "wallet_addEthereumChain", "wallet_switchEthereumChain"]);
assert.equal(a.addParams.chainId, "0xf22f"); assert.deepEqual(a.addParams.rpcUrls, ["https://studio.genlayer.com/api"]);
assert.equal(mem.get("gl_wallet"), "io.alpha"); assert.equal(W.state().icon.startsWith("data:image/"), true);

// 2. events from the wallet are tracked
a.emit("chainChanged", "0x1"); assert.equal(W.state().chainId, 1);
a.emit("accountsChanged", ["0x1111111111111111111111111111111111111111"]); assert.equal(W.state().address, "0x1111111111111111111111111111111111111111");
await W.switchToStudionet(); assert.equal(W.state().chainId, 61999);
a.emit("accountsChanged", []); assert.equal(W.state().address, ""); assert.equal(mem.has("gl_wallet"), false); assert.equal(a.listeners(), 0);

// 3. disconnect revokes permission, clears state and removes listeners
await W.connectInjected(W.wallets()[0]); assert.equal(a.listeners(), 3);
await W.disconnect(); assert.equal(a.revoked, true); assert.equal(W.state().address, ""); assert.equal(a.listeners(), 0); assert.equal(mem.has("gl_wallet"), false);

// 4. switching wallets detaches the previous one
await W.connectInjected(W.wallets()[0]); await W.connectInjected(W.wallets()[1]);
assert.equal(a.listeners(), 0); assert.equal(b.listeners(), 3); assert.equal(W.state().name, "Beta Wallet");
await W.disconnect();

// 5. silent restore after reload never prompts
mem.set("gl_wallet", "io.beta"); b.calls.length = 0;
await W.restore(); assert.equal(W.state().address, b.accounts[0]); assert.equal(b.calls.includes("eth_requestAccounts"), false);
await W.disconnect();

// 6. rejection by the user surfaces a friendly message and leaves nothing connected
const r = new FakeWallet(); r.request = async () => { throw { code: 4001, message: "User rejected the request." }; };
await assert.rejects(() => W.connectInjected({ info: { uuid: "r", name: "R", rdns: "io.r" }, provider: r }));
assert.equal(W.state().address, ""); assert.match(W.state().error, /rejected/i); assert.equal(W.state().busy, false);

// 7. a rejected network switch keeps the wallet connected but reports the problem
const j = new FakeWallet({ chain: 1, knowsStudionet: true, rejectSwitch: true });
await W.connectInjected({ info: { uuid: "j", name: "J", rdns: "io.j" }, provider: j });
assert.equal(W.state().address, j.accounts[0]); assert.equal(W.state().chainId, 1); assert.match(W.state().error, /rejected/i);
await W.disconnect();

// 8. disconnecting while a connection is pending wins the race
const d = new FakeWallet({ chain: 61999, delay: 30 });
const pending = W.connectInjected({ info: { uuid: "d", name: "D", rdns: "io.d" }, provider: d });
await new Promise(r2 => setTimeout(r2, 5)); await W.disconnect(); await pending.catch(() => {});
assert.equal(W.state().address, ""); assert.equal(d.listeners(), 0);

// 9. an injected icon that is not an image data URI is dropped
assert.equal(W.safeIcon("https://evil.example/x.png"), ""); assert.equal(W.safeIcon("javascript:alert(1)"), "");
console.log("wallet tests passed");
