# GreenLight End-to-End Studionet Run Report

- **Contract Address:** `0x7F2217DAaF35c3082c5A8f2d2942908b7337369F`
- **Network:** GenLayer Studionet (Chain ID: `61999`)
- **RPC Endpoint:** `https://studio.genlayer.com/api`
- **Block Explorer:** [explorer-studio.genlayer.com](https://explorer-studio.genlayer.com)
- **Execution Date (UTC):** `2026-10-16T08:47:49.079Z`
- **Runner Account:** `0x13F22D6922948AA2Db05833d790aF0f438eb8631`
- **Contract Version:** `v2.2.0`

---

## 1. On-Chain Transactions

| # | Call | Caller | Transaction Hash | Status | Execution | Finality |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `scan` | `0x13F22D69...eb8631` | [`0x576e2797b10a44e7...`](https://explorer-studio.genlayer.com/tx/0x576e2797b10a44e77c46bbbf86991bd55d4ec1e643c531880bcd0a861ab0d593) | `ACCEPTED` | `SUCCESS` | `FINALIZED` |
| 2 | `scan` | `0x13F22D69...eb8631` | [`0x9aed18f3dcf5be65...`](https://explorer-studio.genlayer.com/tx/0x9aed18f3dcf5be659219b6b8a71f82dc5a3d7e5aa29b4430684bdb6ad35f84d4) | `ACCEPTED` | `SUCCESS` | `FINALIZED` |

---

## 2. Scenario 1: Safe Informational Resource Verification

- **Submitted URL:** `https://example.com/?audit=safe-1792140469079`
- **Verdict:** `GREEN`
- **Blended Risk Score:** `6` / 100
- **Threat Category:** `none`
- **Reachable:** `true`
- **Direct `is_safe()` Result:** `true (SAFE)`
- **AI Validator Consensus Summary:**
  > "This is the standard IANA example.com placeholder page used for documentation and poses no apparent threat to visitors."
- **Reasons Recorded:**
  - example.com is IANA's reserved domain for documentation purposes, not a real service
  - Page content matches the standard example.com placeholder page with no malicious elements
  - Query parameter 'audit=safe-...' is unusual but no malicious content or instructions found
- **Detected Code Signals / Flags:**
  - None (Clean heuristic signals)

### Integrator `check()` View Response
```json
{
  "known": true,
  "last_scanned": 1792140472,
  "risk": 6,
  "safe": true,
  "url": "https://example.com/?audit=safe-1792140469079",
  "verdict": "GREEN"
}
```

---

## 3. Scenario 2: Synthetic Phishing Test Vector

A harmless test page (`frontend/test-phish.html`) that imitates a fake airdrop with a countdown and a seed phrase form. It collects nothing. The expected outcome is `RED`: its code signals alone reach the hard floor, so the verdict does not depend on the model.

- **Expected Verdict:** `RED` (matched)
- **Submitted URL:** `https://greenlight-7ot.pages.dev/test-phish.html?audit=phish-1792140469079`
- **Verdict:** `RED`
- **Blended Risk Score:** `91` / 100
- **Threat Category:** `wallet_drainer`
- **Reachable:** `true`
- **AI Validator Consensus Summary:**
  > "This fake giveaway page is trying to steal your cryptocurrency wallet's secret recovery phrase."
- **Reasons Recorded:**
  - Page requests seed phrase under guise of 'validating wallet ownership'.
  - Uses urgency language ('Urgent: act now', 'expires today').
  - Contains giveaway lure for free tokens as bait.
- **Detected Code Signals / Flags:**
  - `password_field`
  - `seed_phrase_request`
  - `wallet_connect_lure`
  - `urgency_language`
  - `giveaway_lure`

### Integrator `check()` View Response
```json
{
  "known": true,
  "last_scanned": 1792140506,
  "risk": 91,
  "safe": false,
  "url": "https://greenlight-7ot.pages.dev/test-phish.html?audit=phish-1792140469079",
  "verdict": "RED"
}
```

---

## 4. Host Intelligence & Domain Reputation (`host_overview`)

| Domain | Flagged Status | RED URLs Recorded | Neighborhood Penalty Applied |
| :--- | :--- | :--- | :--- |
| `example.com` | `NORMAL` | `0` | `None` |
| `greenlight-7ot.pages.dev` | `NORMAL` | `1` | `None` |

---

## 5. Ledger Statistics Post-Run (`stats`)

```json
{
  "contributors": 2,
  "scan_operations": 4,
  "urls": 4,
  "verdicts": {
    "AMBER": 0,
    "GREEN": 2,
    "RED": 1,
    "UNREACHABLE": 1
  }
}
```

---

## 6. Contributor Scan Record (`contributor`)

- **Contributor Address:** `0x13F22D6922948AA2Db05833d790aF0f438eb8631`
- **Total Validated Scans Submitted:** `2`

---

## 7. Consensus Tuning Parameters (`config`)

| Parameter | Value | Definition |
| :--- | :--- | :--- |
| `green_below` | `35` | Blended risk $< 35$ produces GREEN |
| `red_from` | `70` | Blended risk $\ge 70$ produces RED |
| `hard_floor_heuristic` | `70` | Code score $\ge 70$ forces at least RED |
| `llm_weight_percent` | `65%` | Percentage weight of LLM assessment |
| `risk_tolerance` | `15` | Max allowed score gap between Leader & Validators (the derived verdict must also match: `verdict_must_match`) |
| `fresh_for_seconds` | `604800` | A verdict counts as fresh for 7 days after the page was last really read |
| `llm_passes` | `2` | Independent model passes (analyst and auditor) per analysis |
| `llm_split_limit` | `30` | If the two passes differ by more, the higher risk wins |
| `rescan_cooldown_seconds` | `60s` | Per-URL rescan cooldown window |
| `sender_cooldown_seconds` | `15s` | Per-sender anti-spam brake |
| `neighborhood_bonus` | `+15` | Score penalty added if host has $\ge 2$ RED URLs |

---
*Report generated automatically by GreenLight Automated E2E Reporter.*
