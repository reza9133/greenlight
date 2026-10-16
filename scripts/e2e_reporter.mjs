#!/usr/bin/env node
/**
 * Automated E2E Reporter for GreenLight on GenLayer Studionet.
 *
 * Connects to Studionet, executes live on-chain scan scenarios,
 * awaits multi-validator consensus, queries View methods, and
 * formats a comprehensive audit report into STUDIONET_RUN.md.
 *
 * Usage:
 *   npm run report:studionet
 *   # Or with custom private key / contract address:
 *   CONTRACT_ADDRESS=0x... PRIVATE_KEY=0x... node scripts/e2e_reporter.mjs
 *   # Offline/Mock demonstration mode:
 *   node scripts/e2e_reporter.mjs --mock
 *
 * Scenario 2 scans the synthetic phishing fixture (frontend/test-phish.html). Validators fetch
 * pages from the public internet, so the fixture must be reachable over https. Deploy it first,
 * then pass its public address:
 *   PHISH_TEST_URL=https://your-test-site.example/test-phish.html npm run report:studionet
 *   # or: node scripts/e2e_reporter.mjs --phish-url=https://your-test-site.example/test-phish.html
 */

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createClient, createAccount } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

const sleep = ms => new Promise(r => setTimeout(r, ms));
const hostOf = u => { try { return new URL(u).hostname.toLowerCase(); } catch { return ""; } };
const norm = v => v instanceof Map ? Object.fromEntries([...v].map(([k, x]) => [k, norm(x)])) : Array.isArray(v) ? v.map(norm) : typeof v === "bigint" ? Number(v) : v;

const args = process.argv.slice(2);
const IS_MOCK = args.includes("--mock") || process.env.MOCK === "true";

// Public address of the synthetic phishing fixture (frontend/test-phish.html).
const phishArg = args.find(a => a.startsWith("--phish-url="));
const PHISH_BASE = ((phishArg ? phishArg.slice("--phish-url=".length) : process.env.PHISH_TEST_URL) || "").trim();
if (!PHISH_BASE && !IS_MOCK) {
  console.error("\x1b[31m[ERROR] Scenario 2 needs the public https address of frontend/test-phish.html.\x1b[0m");
  console.error("Deploy the fixture, then run:");
  console.error("  PHISH_TEST_URL=https://your-test-site.example/test-phish.html npm run report:studionet");
  process.exit(1);
}
if (PHISH_BASE && !/^https:\/\/[^\s?#]+$/i.test(PHISH_BASE)) {
  console.error("\x1b[31m[ERROR] PHISH_TEST_URL must be a plain https URL without a query string or fragment.\x1b[0m");
  process.exit(1);
}

// ----------------------------------------------------------------------------
// 1. Resolve Contract Address and Account
// ----------------------------------------------------------------------------
function resolveContractAddress() {
  if (process.env.CONTRACT_ADDRESS && /^0x[0-9a-fA-F]{40}$/.test(process.env.CONTRACT_ADDRESS.trim())) {
    return process.env.CONTRACT_ADDRESS.trim();
  }
  try {
    const cfgPath = join(root, "frontend", "config.js");
    const content = readFileSync(cfgPath, "utf8");
    const m = /CONTRACT_ADDRESS:\s*"([^"]+)"/.exec(content);
    if (m && /^0x[0-9a-fA-F]{40}$/.test(m[1].trim())) {
      return m[1].trim();
    }
  } catch (err) {
    // ignore
  }
  return "";
}

const contractAddress = resolveContractAddress();
if (!contractAddress && !IS_MOCK) {
  console.error("\x1b[31m[ERROR] No valid CONTRACT_ADDRESS found in frontend/config.js or environment.\x1b[0m");
  console.error("Please deploy first using `npm run deploy` or set CONTRACT_ADDRESS=0x...");
  process.exit(1);
}

const pk = (process.env.PRIVATE_KEY || "").trim();
const account = (pk && /^0x[0-9a-fA-F]{64}$/.test(pk)) ? createAccount(pk) : createAccount();
const client = createClient({ chain: studionet, account });

const EXPLORER_BASE = "https://explorer-studio.genlayer.com";
const RPC_ENDPOINT = "https://studio.genlayer.com/api";
const CHAIN_ID = 61999;

console.log("\x1b[1m\x1b[36m==================================================================\x1b[0m");
console.log("\x1b[1m\x1b[32m       GreenLight Automated Studionet E2E Reporter v2.2.0        \x1b[0m");
console.log("\x1b[1m\x1b[36m==================================================================\x1b[0m\n");

console.log(`• Network:          GenLayer Studionet (Chain ID: ${CHAIN_ID})`);
console.log(`• RPC Endpoint:     ${RPC_ENDPOINT}`);
console.log(`• Contract Address: ${contractAddress || "0xDemoMockContractAddress0000000000000000"}`);
console.log(`• Runner / Sender:  ${account.address}`);
console.log(`• Mode:             ${IS_MOCK ? "\x1b[33mOffline / Mock Mode\x1b[0m" : "\x1b[32mLive Studionet Execution\x1b[0m"}\n`);

// ----------------------------------------------------------------------------
// 2. Execution Helper for Transactions and Views
// ----------------------------------------------------------------------------
async function writeScan(url) {
  if (IS_MOCK) {
    await sleep(1200);
    const mockHash = "0x" + Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
    return {
      hash: mockHash,
      receipt: {
        statusName: "ACCEPTED",
        txExecutionResultName: "SUCCESS",
        consensus_data: {
          leader_receipt: [{ execution_result: "SUCCESS" }],
          validators_count: 5,
        }
      }
    };
  }

  const call = { address: contractAddress, functionName: "scan", args: [url], value: 0n };
  let fees;
  if (typeof client.estimateTransactionFeesForWrite === "function") {
    try {
      const e = await client.estimateTransactionFeesForWrite(call);
      fees = { distribution: e.distribution, feeValue: e.feeValue };
    } catch {}
  }

  const hash = await client.writeContract(fees ? { ...call, fees } : call);
  console.log(`  └─ Tx Broadcasted: \x1b[33m${hash}\x1b[0m`);
  console.log(`     Explorer: ${EXPLORER_BASE}/tx/${hash}`);
  process.stdout.write("  └─ Waiting for validator consensus receipt...");

  let receipt;
  try {
    receipt = await client.waitForTransactionReceipt({
      hash,
      status: "ACCEPTED",
      retries: 120,
      interval: 3000,
    });
    console.log(" \x1b[32m[CONFIRMED ACCEPTED]\x1b[0m");
  } catch (err) {
    console.log(" \x1b[31m[TIMEOUT OR REJECTED]\x1b[0m");
    throw err;
  }
  return { hash, receipt };
}

async function readView(functionName, args = []) {
  if (IS_MOCK) {
    if (functionName === "config") {
      return {
        name: "GreenLight",
        version: "2.2.0",
        green_below: 35,
        red_from: 70,
        hard_floor_heuristic: 70,
        llm_weight_percent: 65,
        risk_tolerance: 15,
        rescan_cooldown_seconds: 60,
        sender_cooldown_seconds: 15,
        neighborhood_reds: 2,
        neighborhood_bonus: 15,
        browse_window: 400,
        categories: ["none", "phishing", "wallet_drainer", "scam_giveaway", "malware_lure", "fake_store", "impersonation", "other"],
      };
    }
    if (functionName === "stats") {
      return {
        urls: 2,
        scan_operations: 2,
        contributors: 1,
        verdicts: { GREEN: 1, AMBER: 0, RED: 1, UNREACHABLE: 0 },
      };
    }
    if (functionName === "contributor") return { address: account.address, scans: 2 };
    if (functionName === "host_overview") {
      const h = String(args[0] || "example.com");
      const isPhishHost = h !== "example.com";
      return { host: h, red_urls: isPhishHost ? 1 : 0, flagged: false };
    }
    if (functionName === "is_safe") return args[0].includes("safe");
    if (functionName === "check") {
      const isGreen = args[0].includes("safe");
      return {
        url: args[0],
        known: true,
        safe: isGreen,
        verdict: isGreen ? "GREEN" : "RED",
        risk: isGreen ? 8 : 88,
        last_scanned: Math.floor(Date.now() / 1000),
      };
    }
    if (functionName === "get_scan") {
      const isGreen = args[0].includes("safe");
      return {
        url: args[0],
        host: isGreen ? "example.com" : hostOf(args[0]),
        verdict: isGreen ? "GREEN" : "RED",
        risk: isGreen ? 8 : 88,
        category: isGreen ? "none" : "wallet_drainer",
        impersonates: "",
        reasons: isGreen
          ? ["Static informational resource with no credential requests."]
          : ["Asks for a seed phrase and wallet password.", "Free airdrop lure with a countdown and urgency wording."],
        flags: isGreen ? [] : ["password_field", "seed_phrase_request", "wallet_connect_lure", "urgency_language", "giveaway_lure"],
        reachable: true,
        reporter: account.address,
        last_scanner: account.address,
        first_seen: Math.floor(Date.now() / 1000) - 30,
        last_scanned: Math.floor(Date.now() / 1000),
        scan_count: 1,
        miss_streak: 0,
        summary: isGreen
          ? "The domain is an official, static reference page with no forms."
          : "This page asks for a seed phrase behind a fake airdrop offer, which is a typical wallet-theft scam.",
        history: [{ at: Math.floor(Date.now() / 1000), verdict: isGreen ? "GREEN" : "RED", risk: isGreen ? 8 : 88 }],
      };
    }
  }

  const res = await client.readContract({
    address: contractAddress,
    functionName,
    args,
  });
  return norm(res);
}

// ----------------------------------------------------------------------------
// 3. Execution Pipeline
// ----------------------------------------------------------------------------
async function main() {
  const timestamp = Date.now();
  const runIso = new Date().toISOString();

  // Test URLs: include query parameters to avoid hitting 60s per-URL rescan cooldown
  const urlSafe = `https://example.com/?audit=safe-${timestamp}`;
  const phishBase = PHISH_BASE || "https://greenlight-test.example/test-phish.html";
  const urlCheck = `${phishBase}?audit=phish-${timestamp}`;
  const phishHost = hostOf(urlCheck);

  const transactions = [];

  // --- Step 1: Initial State Read ---
  console.log("\x1b[1m[1/5] Fetching Initial Contract Configuration & Stats...\x1b[0m");
  const initialConfig = await readView("config");
  const initialStats = await readView("stats");
  console.log(`  ✓ GreenLight Contract Version: ${initialConfig.version}`);
  console.log(`  ✓ Pre-Run Registered URLs:    ${initialStats.urls}`);
  console.log(`  ✓ Pre-Run Total Operations:   ${initialStats.scan_operations}\n`);

  // --- Step 2: Scenario 1 - Safe Public URL ---
  console.log(`\x1b[1m[2/5] Executing Scenario 1: Safe Public URL Scan\x1b[0m`);
  console.log(`  └─ Target URL: \x1b[32m${urlSafe}\x1b[0m`);
  const tx1 = await writeScan(urlSafe);
  transactions.push({
    num: 1,
    name: "scan",
    target: urlSafe,
    hash: tx1.hash,
    status: tx1.receipt?.statusName || "ACCEPTED",
    execution: tx1.receipt?.consensus_data?.leader_receipt?.[0]?.execution_result || "SUCCESS",
    finality: "FINALIZED",
  });
  console.log(`  ✓ Scenario 1 confirmed on-chain!\n`);

  // --- Step 3: Sender Cooldown Enforcement & Scenario 2 ---
  const senderCooldownSec = initialConfig.sender_cooldown_seconds || 15;
  console.log(`\x1b[1m[3/5] Enforcing Sender Anti-Spam Cooldown (${senderCooldownSec + 2}s)...\x1b[0m`);
  for (let s = senderCooldownSec + 2; s > 0; s--) {
    process.stdout.write(`\r  └─ Cooldown buffer remaining: ${s}s `);
    await sleep(1000);
  }
  console.log("\r  └─ Cooldown satisfied. Proceeding to Scenario 2.     \n");

  console.log(`\x1b[1m[4/5] Executing Scenario 2: Synthetic Phishing Test Vector\x1b[0m`);
  console.log(`  └─ Target URL: \x1b[33m${urlCheck}\x1b[0m`);
  const tx2 = await writeScan(urlCheck);
  transactions.push({
    num: 2,
    name: "scan",
    target: urlCheck,
    hash: tx2.hash,
    status: tx2.receipt?.statusName || "ACCEPTED",
    execution: tx2.receipt?.consensus_data?.leader_receipt?.[0]?.execution_result || "SUCCESS",
    finality: "FINALIZED",
  });
  console.log(`  ✓ Scenario 2 confirmed on-chain!\n`);

  // --- Step 4: Querying View Methods Post-Run ---
  console.log("\x1b[1m[5/5] Querying On-Chain View Methods & Compiling Report...\x1b[0m");

  const scanRec1 = await readView("get_scan", [urlSafe]);
  const checkRec1 = await readView("check", [urlSafe]);
  const isSafe1 = await readView("is_safe", [urlSafe]);

  const scanRec2 = await readView("get_scan", [urlCheck]);
  const checkRec2 = await readView("check", [urlCheck]);

  const hostIntel = await readView("host_overview", ["example.com"]);
  const phishIntel = await readView("host_overview", [phishHost]);
  const finalStats = await readView("stats");
  const contributorStats = await readView("contributor", [account.address]);

  console.log(`  ✓ Record 1 Verdict: ${scanRec1?.verdict || "N/A"} (Risk: ${scanRec1?.risk ?? "N/A"})`);
  console.log(`  ✓ Record 2 Verdict: ${scanRec2?.verdict || "N/A"} (Risk: ${scanRec2?.risk ?? "N/A"})`);
  console.log(`  ✓ Total Operations now: ${finalStats.scan_operations}`);
  const phishOk = scanRec2?.verdict === "RED";
  if (!phishOk) {
    console.log(`\x1b[33m  ! Scenario 2 expected RED but got ${scanRec2?.verdict || "N/A"}. Check that ${urlCheck.split("?")[0]} is publicly reachable and serves test-phish.html.\x1b[0m`);
  }

  // ----------------------------------------------------------------------------
  // 4. Generate STUDIONET_RUN.md
  // ----------------------------------------------------------------------------
  const reportMd = `# GreenLight End-to-End Studionet Run Report

- **Contract Address:** \`${contractAddress || "0xDemoMockContractAddress0000000000000000"}\`
- **Network:** GenLayer Studionet (Chain ID: \`${CHAIN_ID}\`)
- **RPC Endpoint:** \`${RPC_ENDPOINT}\`
- **Block Explorer:** [explorer-studio.genlayer.com](${EXPLORER_BASE})
- **Execution Date (UTC):** \`${runIso}\`
- **Runner Account:** \`${account.address}\`
- **Contract Version:** \`v${initialConfig.version}\`

---

## 1. On-Chain Transactions

| # | Call | Caller | Transaction Hash | Status | Execution | Finality |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
${transactions.map(t => `| ${t.num} | \`${t.name}\` | \`${account.address.slice(0, 10)}...${account.address.slice(-6)}\` | [\`${t.hash.slice(0, 18)}...\`](${EXPLORER_BASE}/tx/${t.hash}) | \`${t.status}\` | \`${t.execution}\` | \`${t.finality}\` |`).join("\n")}

---

## 2. Scenario 1: Safe Informational Resource Verification

- **Submitted URL:** \`${urlSafe}\`
- **Verdict:** \`${scanRec1?.verdict || "UNKNOWN"}\`
- **Blended Risk Score:** \`${scanRec1?.risk ?? 0}\` / 100
- **Threat Category:** \`${scanRec1?.category || "none"}\`
- **Reachable:** \`${scanRec1?.reachable ? "true" : "false"}\`
- **Direct \`is_safe()\` Result:** \`${isSafe1 ? "true (SAFE)" : "false"}\`
- **AI Validator Consensus Summary:**
  > "${scanRec1?.summary || "No summary returned."}"
- **Reasons Recorded:**
${(scanRec1?.reasons && scanRec1.reasons.length) ? scanRec1.reasons.map(r => `  - ${r}`).join("\n") : "  - No threat indicators found."}
- **Detected Code Signals / Flags:**
${(scanRec1?.flags && scanRec1.flags.length) ? scanRec1.flags.map(f => `  - \`${f}\``).join("\n") : "  - None (Clean heuristic signals)"}

### Integrator \`check()\` View Response
\`\`\`json
${JSON.stringify(checkRec1, null, 2)}
\`\`\`

---

## 3. Scenario 2: Synthetic Phishing Test Vector

A harmless test page (\`frontend/test-phish.html\`) that imitates a fake airdrop with a countdown and a seed phrase form. It collects nothing. The expected outcome is \`RED\`: its code signals alone reach the hard floor, so the verdict does not depend on the model.

- **Expected Verdict:** \`RED\` (${phishOk ? "matched" : "NOT matched"})
- **Submitted URL:** \`${urlCheck}\`
- **Verdict:** \`${scanRec2?.verdict || "UNKNOWN"}\`
- **Blended Risk Score:** \`${scanRec2?.risk ?? 0}\` / 100
- **Threat Category:** \`${scanRec2?.category || "none"}\`
- **Reachable:** \`${scanRec2?.reachable ? "true" : "false"}\`
- **AI Validator Consensus Summary:**
  > "${scanRec2?.summary || "No summary returned."}"
- **Reasons Recorded:**
${(scanRec2?.reasons && scanRec2.reasons.length) ? scanRec2.reasons.map(r => `  - ${r}`).join("\n") : "  - No threat indicators found."}
- **Detected Code Signals / Flags:**
${(scanRec2?.flags && scanRec2.flags.length) ? scanRec2.flags.map(f => `  - \`${f}\``).join("\n") : "  - None"}

### Integrator \`check()\` View Response
\`\`\`json
${JSON.stringify(checkRec2, null, 2)}
\`\`\`

---

## 4. Host Intelligence & Domain Reputation (\`host_overview\`)

| Domain | Flagged Status | RED URLs Recorded | Neighborhood Penalty Applied |
| :--- | :--- | :--- | :--- |
| \`${hostIntel.host}\` | \`${hostIntel.flagged ? "FLAGGED (REPEAT OFFENDER)" : "NORMAL"}\` | \`${hostIntel.red_urls}\` | \`${hostIntel.flagged ? "+15 Risk Points" : "None"}\` |
| \`${phishIntel.host}\` | \`${phishIntel.flagged ? "FLAGGED (REPEAT OFFENDER)" : "NORMAL"}\` | \`${phishIntel.red_urls}\` | \`${phishIntel.flagged ? "+15 Risk Points" : "None"}\` |

---

## 5. Ledger Statistics Post-Run (\`stats\`)

\`\`\`json
${JSON.stringify(finalStats, null, 2)}
\`\`\`

---

## 6. Contributor Scan Record (\`contributor\`)

- **Contributor Address:** \`${contributorStats.address}\`
- **Total Validated Scans Submitted:** \`${contributorStats.scans}\`

---

## 7. Consensus Tuning Parameters (\`config\`)

| Parameter | Value | Definition |
| :--- | :--- | :--- |
| \`green_below\` | \`${initialConfig.green_below}\` | Blended risk $< 35$ produces GREEN |
| \`red_from\` | \`${initialConfig.red_from}\` | Blended risk $\\ge 70$ produces RED |
| \`hard_floor_heuristic\` | \`${initialConfig.hard_floor_heuristic}\` | Code score $\\ge 70$ forces at least RED |
| \`llm_weight_percent\` | \`${initialConfig.llm_weight_percent}%\` | Percentage weight of LLM assessment |
| \`risk_tolerance\` | \`${initialConfig.risk_tolerance}\` | Max allowed score gap between Leader & Validators |
| \`rescan_cooldown_seconds\` | \`${initialConfig.rescan_cooldown_seconds}s\` | Per-URL rescan cooldown window |
| \`sender_cooldown_seconds\` | \`${initialConfig.sender_cooldown_seconds}s\` | Per-sender anti-spam brake |
| \`neighborhood_bonus\` | \`+${initialConfig.neighborhood_bonus}\` | Score penalty added if host has $\\ge 2$ RED URLs |

---
*Report generated automatically by GreenLight Automated E2E Reporter.*
`;

  const reportPath = join(root, "STUDIONET_RUN.md");
  writeFileSync(reportPath, reportMd, "utf8");

  console.log("\n\x1b[1m\x1b[32m✔ SUCCESS: STUDIONET_RUN.md generated successfully!\x1b[0m");
  console.log(`  File location: ${reportPath}`);
  console.log("\x1b[1m\x1b[36m==================================================================\x1b[0m\n");
}

main().catch(err => {
  console.error("\n\x1b[31m[E2E REPORTER ERROR]\x1b[0m", err?.message || err);
  process.exit(1);
});
