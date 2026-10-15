// Deploy contracts/green_light.py to GenLayer Studionet and write the address into frontend/config.js.
//
//   npm install
//   npm run deploy                       (generates a throwaway deployer account)
//   PRIVATE_KEY=0x... npm run deploy     (use your own account)
//
// The contract has no owner, so the deployer account has no special rights afterwards.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createClient, createAccount } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const code = new Uint8Array(readFileSync(join(root, "contracts", "green_light.py")));
const pk = (process.env.PRIVATE_KEY || "").trim();
if (pk && !/^0x[0-9a-fA-F]{64}$/.test(pk)) { console.error("PRIVATE_KEY must be 0x followed by 64 hex characters."); process.exit(1); }

const account = pk ? createAccount(pk) : createAccount();
const client = createClient({ chain: studionet, account });
console.log("Deployer:", account.address);
console.log("Submitting the contract to Studionet. Validators run it, so this can take a minute or two...");

try {
  if (typeof client.initializeConsensusSmartContract === "function") await client.initializeConsensusSmartContract();
  const hash = await client.deployContract({ code, args: [] });
  console.log("Transaction:", hash);
  const receipt = await client.waitForTransactionReceipt({ hash, status: "ACCEPTED", retries: 200, interval: 3000 });
  const leader = receipt && receipt.consensus_data && receipt.consensus_data.leader_receipt && receipt.consensus_data.leader_receipt[0];
  if (leader && leader.execution_result && leader.execution_result !== "SUCCESS") throw new Error("The contract constructor failed. Receipt: " + JSON.stringify(receipt).slice(0, 800));
  const address = (receipt.data && receipt.data.contract_address) || (receipt.txDataDecoded && receipt.txDataDecoded.contractAddress);
  if (!/^0x[0-9a-fA-F]{40}$/.test(String(address))) throw new Error("Deployment finished but no contract address was found in the receipt. Open the transaction in Studio and copy the address into frontend/config.js.");

  const cfg = join(root, "frontend", "config.js");
  const text = readFileSync(cfg, "utf8");
  if (!/CONTRACT_ADDRESS:\s*"[^"]*"/.test(text)) throw new Error("Could not find CONTRACT_ADDRESS in frontend/config.js. Set it by hand to " + address);
  writeFileSync(cfg, text.replace(/CONTRACT_ADDRESS:\s*"[^"]*"/, 'CONTRACT_ADDRESS: "' + address + '"'));
  console.log("\nDeployed at:", address);
  console.log("frontend/config.js updated. Run `npm run serve` and open http://localhost:8080");
} catch (e) {
  console.error("\nDeployment failed:", e && e.message ? e.message : e);
  process.exit(1);
}
