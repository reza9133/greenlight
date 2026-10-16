# GreenLight End-to-End Studionet Run Report

- **Contract Address:** `0x7F2217DAaF35c3082c5A8f2d2942908b7337369F`
- **Network:** GenLayer Studionet (Chain ID: `61999`)
- **RPC Endpoint:** `https://studio.genlayer.com/api`
- **Block Explorer:** [explorer-studio.genlayer.com](https://explorer-studio.genlayer.com)
- **Execution Date (UTC):** `2026-10-16T07:04:10.048Z`
- **Runner Account:** `0xE5a67664c913c53A3f7395D8213CA2F8F793315c`
- **Contract Version:** `v2.1.0`

---

## 1. On-Chain Transactions

| # | Call | Caller | Transaction Hash | Status | Execution | Finality |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `scan` | `0xE5a67664...93315c` | [`0xe3cc6abcbbf959ca...`](https://explorer-studio.genlayer.com/tx/0xe3cc6abcbbf959ca97d6c9245dcb8a5ee275f4ba56ee62e6d5afc79e979bde70) | `ACCEPTED` | `SUCCESS` | `FINALIZED` |
| 2 | `scan` | `0xE5a67664...93315c` | [`0x3e4db37cd6de4cbe...`](https://explorer-studio.genlayer.com/tx/0x3e4db37cd6de4cbed4f931098e9ce0d6472f0676f5e1623964a9d38e72485bf0) | `ACCEPTED` | `SUCCESS` | `FINALIZED` |

---

## 2. Scenario 1: Safe Informational Resource Verification

- **Submitted URL:** `https://example.com/?audit=safe-1792134250048`
- **Verdict:** `GREEN`
- **Blended Risk Score:** `6` / 100
- **Threat Category:** `none`
- **Reachable:** `true`
- **Direct `is_safe()` Result:** `true (SAFE)`
- **AI Validator Consensus Summary:**
  > "This is a legitimate example domain used for documentation, not a real website or service."
- **Reasons Recorded:**
  - Official example domain used for documentation purposes
  - Clear disclaimer stating it's not a real service
  - No malicious content or suspicious elements detected
- **Detected Code Signals / Flags:**
  - None (Clean heuristic signals)

### Integrator `check()` View Response
```json
{
  "known": true,
  "last_scanned": 1792134253,
  "risk": 6,
  "safe": true,
  "url": "https://example.com/?audit=safe-1792134250048",
  "verdict": "GREEN"
}
```

---

## 3. Scenario 2: Dynamic Endpoint Inspection

- **Submitted URL:** `https://httpbin.org/status/200?audit=verify-1792134250048`
- **Verdict:** `UNREACHABLE`
- **Blended Risk Score:** `0` / 100
- **Threat Category:** `none`
- **Reachable:** `false`
- **AI Validator Consensus Summary:**
  > "The page could not be fetched, so no verdict about its content is possible."
- **Reasons Recorded:**
  - The page could not be fetched (network error, empty body or HTTP status 400 or higher).
- **Detected Code Signals / Flags:**
  - None

### Integrator `check()` View Response
```json
{
  "known": true,
  "last_scanned": 1792134286,
  "risk": 0,
  "safe": false,
  "url": "https://httpbin.org/status/200?audit=verify-1792134250048",
  "verdict": "UNREACHABLE"
}
```

---

## 4. Host Intelligence & Domain Reputation (`host_overview`)

| Domain | Flagged Status | RED URLs Recorded | Neighborhood Penalty Applied |
| :--- | :--- | :--- | :--- |
| `example.com` | `NORMAL` | `0` | `None` |

---

## 5. Ledger Statistics Post-Run (`stats`)

```json
{
  "contributors": 1,
  "scan_operations": 2,
  "urls": 2,
  "verdicts": {
    "AMBER": 0,
    "GREEN": 1,
    "RED": 0,
    "UNREACHABLE": 1
  }
}
```

---

## 6. Contributor Scan Record (`contributor`)

- **Contributor Address:** `0xE5a67664c913c53A3f7395D8213CA2F8F793315c`
- **Total Validated Scans Submitted:** `2`

---

## 7. Consensus Tuning Parameters (`config`)

| Parameter | Value | Definition |
| :--- | :--- | :--- |
| `green_below` | `35` | Blended risk $< 35$ produces GREEN |
| `red_from` | `70` | Blended risk $\ge 70$ produces RED |
| `hard_floor_heuristic` | `70` | Code score $\ge 70$ forces at least RED |
| `llm_weight_percent` | `65%` | Percentage weight of LLM assessment |
| `risk_tolerance` | `20` | Max allowed score gap between Leader & Validators |
| `rescan_cooldown_seconds` | `60s` | Per-URL rescan cooldown window |
| `sender_cooldown_seconds` | `15s` | Per-sender anti-spam brake |
| `neighborhood_bonus` | `+15` | Score penalty added if host has $\ge 2$ RED URLs |

---
*Report generated automatically by GreenLight Automated E2E Reporter.*
