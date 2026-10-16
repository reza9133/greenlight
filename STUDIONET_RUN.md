# GreenLight End-to-End Studionet Run Report

- **Contract Address:** `0x265d869b6145fBcc34A979B9c279DBbB576EBFf4`
- **Network:** GenLayer Studionet (Chain ID: `61999`)
- **RPC Endpoint:** `https://studio.genlayer.com/api`
- **Block Explorer:** [explorer-studio.genlayer.com](https://explorer-studio.genlayer.com)
- **Execution Date (UTC):** `2026-10-16T18:46:31.694Z`
- **Runner Account:** `0xEA4455812D5b40A7Aa357Ff80Ef2651253B311c5`
- **Contract Version:** `v2.2.0`

---

## 1. On-Chain Transactions

| # | Call | Caller | Transaction Hash | Status | Execution | Finality |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `scan` | `0xEA445581...B311c5` | [`0x35d8ae18b6533a23...`](https://explorer-studio.genlayer.com/tx/0x35d8ae18b6533a23b9eb074f717a910d6a69113c003075fcb023b38970b4c873) | `ACCEPTED` | `SUCCESS` | `FINALIZED` |
| 2 | `scan` | `0xEA445581...B311c5` | [`0x1c040238f7cc3cce...`](https://explorer-studio.genlayer.com/tx/0x1c040238f7cc3cce48816a3c2b77aa7db5fc1bb696d2b5056dc9996168f2ac4c) | `ACCEPTED` | `SUCCESS` | `FINALIZED` |

---

## 2. Scenario 1: Safe Informational Resource Verification

- **Submitted URL:** `https://example.com/?audit=safe-1792176391694`
- **Verdict:** `GREEN`
- **Blended Risk Score:** `0` / 100
- **Threat Category:** `none`
- **Reachable:** `true`
- **Direct `is_safe()` Result:** `true (SAFE)`
- **AI Validator Consensus Summary:**
  > "This is the standard example.com placeholder page used for documentation, so it poses no scam or phishing risk."
- **Reasons Recorded:**
  - example.com is the IANA-reserved documentation domain, inherently non-malicious
  - Page content is standard placeholder text with no forms, downloads, or wallet hooks
  - No code-computed risk signals detected
- **Detected Code Signals / Flags:**
  - None (Clean heuristic signals)

### Integrator `check()` View Response
```json
{
  "age_seconds": 70,
  "expires_at": 1792781195,
  "fresh": true,
  "known": true,
  "last_scanned": 1792176395,
  "needs_rescan": false,
  "risk": 0,
  "safe": true,
  "url": "https://example.com/?audit=safe-1792176391694",
  "verdict": "GREEN",
  "verified_at": 1792176395
}
```

---

## 3. Scenario 2: Synthetic Phishing Test Vector

A harmless test page (`frontend/test-phish.html`) that imitates a fake airdrop with a countdown and a seed phrase form. It collects nothing. The expected outcome is `RED`: its code signals alone reach the hard floor, so the verdict does not depend on the model.

- **Expected Verdict:** `RED` (matched)
- **Submitted URL:** `https://greenlight-7ot.pages.dev/test-phish.html?audit=phish-1792176391694`
- **Verdict:** `RED`
- **Blended Risk Score:** `89` / 100
- **Threat Category:** `wallet_drainer`
- **Reachable:** `true`
- **AI Validator Consensus Summary:**
  > "The page pretends to be an ExampleSwap airdrop but asks for your wallet seed phrase with urgent, fake giveaway language."
- **Reasons Recorded:**
  - Requests your 12‑word seed phrase
  - Urgent giveaway language urges immediate action
  - Form is a fake test page, not a legitimate service
- **Detected Code Signals / Flags:**
  - `password_field`
  - `seed_phrase_request`
  - `wallet_connect_lure`
  - `urgency_language`
  - `giveaway_lure`

### Integrator `check()` View Response
```json
{
  "age_seconds": 27,
  "expires_at": 1792781241,
  "fresh": true,
  "known": true,
  "last_scanned": 1792176441,
  "needs_rescan": false,
  "risk": 89,
  "safe": false,
  "url": "https://greenlight-7ot.pages.dev/test-phish.html?audit=phish-1792176391694",
  "verdict": "RED",
  "verified_at": 1792176441
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
    "AMBER": 1,
    "GREEN": 2,
    "RED": 1,
    "UNREACHABLE": 0
  }
}
```

---

## 6. Contributor Scan Record (`contributor`)

- **Contributor Address:** `0xEA4455812D5b40A7Aa357Ff80Ef2651253B311c5`
- **Total Validated Scans Submitted:** `2`

---

## 7. Consensus Tuning Parameters (`config`)

| Parameter | Value | Definition |
| :--- | :--- | :--- |
| `green_below` | `35` | Blended risk $< 35$ produces GREEN |
| `red_from` | `70` | Blended risk $\ge 70$ produces RED |
| `hard_floor_heuristic` | `70` | Code score $\ge 70$ forces at least RED |
| `llm_weight_percent` | `65%` | Percentage weight of LLM assessment |
| `risk_tolerance` | `15` | Max allowed score gap between Leader & Validators |
| `rescan_cooldown_seconds` | `60s` | Per-URL rescan cooldown window |
| `sender_cooldown_seconds` | `15s` | Per-sender anti-spam brake |
| `neighborhood_bonus` | `+15` | Score penalty added if host has $\ge 2$ RED URLs |

---
*Report generated automatically by GreenLight Automated E2E Reporter.*
