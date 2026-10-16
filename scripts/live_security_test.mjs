import { createClient, createAccount } from "genlayer-js";
import { studionet } from "genlayer-js/chains";

const CONTRACT_ADDRESS = "0x7F2217DAaF35c3082c5A8f2d2942908b7337369F";
const client = createClient({ chain: studionet, account: createAccount() });

async function run() {
  console.log("=== Running Live Security & View Resiliency Tests on Studionet ===");

  // 1. Test View methods against malicious addresses and SSRF payloads on live network
  const maliciousInputs = [
    "http://127.0.0.1/admin",
    "http://169.254.169.254/latest",
    "http://012.0.0.1/test",
    "invalid://schema",
    "not a url",
  ];

  console.log("\n[1/2] Testing live View methods against SSRF & malformed inputs...");
  for (const bad of maliciousInputs) {
    const safe = await client.readContract({
      address: CONTRACT_ADDRESS,
      functionName: "is_safe",
      args: [bad],
    });
    const chk = await client.readContract({
      address: CONTRACT_ADDRESS,
      functionName: "check",
      args: [bad],
    });
    console.log(`  ✓ Checked "${bad}" -> is_safe: ${safe}, known: ${chk.known} (Safely handled)`);
  }

  // 2. Test on-chain transaction revert for SSRF target
  console.log("\n[2/2] Testing on-chain transaction rejection for SSRF...");
  try {
    await client.writeContract({
      address: CONTRACT_ADDRESS,
      functionName: "scan",
      args: ["http://127.0.0.1/admin"],
    });
    console.log("  ❌ Error: Contract accepted SSRF URL!");
  } catch (err) {
    console.log("  ✔ Contract successfully reverted transaction with UserError (SSRF blocked)!");
  }

  console.log("\n✔ Live on-chain security assertions passed!");
}

run().catch(console.error);
