// GreenLight frontend configuration.
//
// 1. Deploy contracts/green_light.py to Studionet (`npm run deploy` does this and fills in the address for you).
// 2. Or paste the deployed contract address below, or save it from the contract settings in the site header.
// 3. Reload the page. While the address is empty the site runs in demo mode
//    with sample data and simulated scans (nothing is sent to any network).
//
// SDK_URL / CHAINS_URL point at genlayer-js, pinned to the version this site was checked against
// (the same one package.json asks for), so a future release cannot change behaviour under your feet.

export const CONFIG = {
  CONTRACT_ADDRESS: "0x7F2217DAaF35c3082c5A8f2d2942908b7337369F",
  SDK_URL: "https://esm.sh/genlayer-js@1.1.8",
  CHAINS_URL: "https://esm.sh/genlayer-js@1.1.8/chains",
  // Optional override if Studionet details ever change: { chainId, rpc, explorer }
  NETWORK: {},
};
