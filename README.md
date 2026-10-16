# GreenLight (v2.1.0)

An on-chain **URL trust registry** judged by GenLayer AI validators, engineered for **Studionet**.

**Deployed Contract (Studionet):** `0x7F2217DAaF35c3082c5A8f2d2942908b7337369F`

GreenLight enables decentralized, verifiable web safety. Anyone can ask the network to scan a web address. The leader validator fetches the page, computes objective heuristics in deterministic code, asks an LLM for a risk assessment and plain-language summary, and blends both into an on-chain score. Independent network validators re-execute the entire pipeline and accept the leader only if their independent scores land within a strict mathematical tolerance (Equivalence Principle).

The resulting verdict is stored immutably on-chain and can be queried by users, Web3 applications, and other Intelligent Contracts at zero gas cost.

---

## Verdict Classifications

| Verdict | Risk Score | Security Meaning |
| :--- | :--- | :--- |
| `GREEN` | `0` to `34` | No meaningful risk or phishing indicators found |
| `AMBER` | `35` to `69` | Unclear, promotional, or mildly suspicious characteristics |
| `RED` | `70` to `100` | High confidence phishing, wallet drainer, fake store, or exploit lure |
| `UNREACHABLE` | `None` | The web page could not be fetched (HTTP 4xx/5xx, timeout, or DNS failure) |

---

## Architecture & Consensus Flow

```text
User Transaction: scan(url)
           │
           ▼
[1] Security Screening & Normalization
    ├── Reject internal domains (.local, .internal, .lan, .corp)
    ├── Block RFC 1918 private IPs (10.x, 172.16-31.x, 192.168.x, 127.x)
    ├── Block cloud metadata endpoints (169.254.169.254, 100.64.x)
    └── Block wildcard DNS resolvers (nip.io, sslip.io, vcap.me)
           │
           ▼
[2] Leader Non-Deterministic Fetch
    └── HTTP GET (with fallback to headless rendering)
           │
           ▼
[3] Dual-Layer Analysis (gl.vm.run_nondet_unsafe)
    ├── Layer A: Deterministic Code Heuristics (14 Signals)
    │   ├── Form destinations (cross-origin credential posting)
    │   ├── Lure language (mnemonic/seed phrase, urgency, giveaway)
    │   └── URL signals (punycode, bare IP, risky TLDs, no HTTPS)
    └── Layer B: AI Validator Reasoning
        └── LLM returns estimated risk (0-100), category, and summary
           │
           ▼
[4] Deterministic Score Blending
    ├── Score = (LLM * 65% + Heuristics * 35%)
    ├── Hard Floor Rule: Code Heuristics >= 70 forces verdict to RED
    └── Repeat Offender Bonus: Host with >= 2 RED URLs adds +15 points
           │
           ▼
[5] Multi-Validator Equivalence Verification
    ├── Reachability agreement check
    ├── Identical URL-derived flags check
    ├── Risk score tolerance check (|Leader - Validator| <= 20)
    └── Structural consistency check
           │
           ▼
[6] Immutable On-Chain Storage
    └── Feed updated, history logged (up to 8 checks), counters incremented
```

---

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Run all test suites (Unit, Adversarial & Exploit, Wallet Layer)
npm test

# 3. Deploy to GenLayer Studionet (generates throwaway key or uses PRIVATE_KEY=0x...)
npm run deploy

# 4. Generate on-chain E2E report (broadcasts real scans & writes STUDIONET_RUN.md).
#    Scenario 2 scans the synthetic phishing fixture, so deploy frontend/test-phish.html
#    to a public https address first (see "Synthetic Phishing Test Vector" below).
PHISH_TEST_URL=https://your-test-site.example/test-phish.html npm run report:studionet

# 5. Serve the frontend locally (or deploy static files to Cloudflare Pages)
npm run serve
```

---

## Repository Structure

```text
contracts/
  green_light.py         Intelligent Contract (Python, contract v2.1.0)
frontend/
  index.html             Modern responsive markup with custom SVG branding
  test-phish.html        Harmless synthetic phishing page used as the RED test vector
  styles.css             Cyber-Emerald dark theme, glassmorphism, animations
  app.js                 Router, page views, contract calls, interactive simulator
  wallet.js              EIP-6963 discovery, network auto-switch, burner key
  config.js              Contract address, pinned SDK URLs, chain parameters
scripts/
  deploy.mjs             Studionet deployment script, updates config.js automatically
  e2e_reporter.mjs       Automated E2E runner: broadcasts scans and writes STUDIONET_RUN.md
tests/
  test_green_light.py    Core contract logic unit tests (with GenVM stub)
  adversarial_suite.py   Security & exploit test suite (Prompt injection, ReDoS, SSRF, takedown)
  wallet.test.mjs        EIP-6963 & EIP-1193 multi-wallet integration tests
  ui_smoke.py            Full-browser smoke tests (Playwright)
  run_all_tests.py       Unified test runner orchestrating all test suites
```

---

## Security Mitigations & Hardening

| Threat / Attack Vector | Mitigation in GreenLight v2.1.0 | Test Verification |
| :--- | :--- | :--- |
| **Prompt Injection Attacks** | Untrusted page content is isolated inside fenced tags. A deterministic hard floor enforces that any page triggering code heuristics >= 70 is locked to `RED`, regardless of LLM score. | `tests/adversarial_suite.py` [3/6] |
| **ReDoS (Regex Denial of Service)** | HTML stripping uses a single-pass linear state machine without nested regex quantifiers. Hostile pages with 100,000 unclosed tags are processed in linear time (the test asserts < 1.0s per payload). | `tests/adversarial_suite.py` [2/6] |
| **SSRF & Private IP Evasion** | Rejects literal hosts only (a public domain that resolves to a private address is not detected by the contract; fetching is delegated to the GenVM web module). Blocks private IPv4 ranges, AWS/GCP metadata endpoints, CGNAT, benchmark ranges, octal-padded IPs (`012.0.0.1`), dotless decimal IPs, and wildcard DNS domains (`nip.io`, `sslip.io`, `vcap.me`). | `tests/adversarial_suite.py` [1/6] |
| **Malicious Page Takedown** | If an attacker takes a malicious page offline after a `RED` verdict, GreenLight preserves the `RED` verdict across the 1st and 2nd unreachable scans. Only 3 consecutive unreachable scans transition to `UNREACHABLE`. | `tests/adversarial_suite.py` [5/6] |
| **Consensus Disruption / Forgery** | Validators strictly compare URL-derived flags, reachability, and risk score tolerance (<= 20). Inconsistent leader fields trigger automatic leader rotation. | `tests/adversarial_suite.py` [4/6] |
| **Unbounded History Growth** | Per-URL scan history is a sliding window that keeps only the last 8 entries (`HISTORY_KEEP`), preventing unbounded storage growth. | `tests/adversarial_suite.py` [5/6] |
| **View Method Failures** | View methods (`is_safe`, `check`, `get_scan`, `host_overview`) gracefully catch invalid or malformed inputs without reverting. | `tests/adversarial_suite.py` [6/6] |

---

## Known Limitations

GreenLight is a heuristic and AI-assisted signal, not a guarantee. Be aware of these trade-offs:

- **Cloaking.** A site can show clean content to validators and malicious content to real visitors. A `GREEN` verdict means "looked safe when scanned", so integrators should check `last_scanned` against their own freshness rule.
- **Shared hosts.** The repeat-offender bonus (+15 when a host has 2 or more `RED` URLs) is applied per host. On user-content hosts, an attacker could raise the score of other URLs on the same host.
- **Spam brake.** The 15s per-sender cooldown can be bypassed with several addresses. The 60s per-URL cooldown still applies.
- **Consensus tolerance.** Validators accept a leader score within +/-20. Near a verdict boundary, two validators can therefore land on different verdicts and still agree.
- **Empty pages.** A page that returns an empty body (even with HTTP 200) is treated as `UNREACHABLE`, because there is nothing to analyse.
- **DNS-based SSRF.** Only literal private hosts are rejected (see the table above).

## Synthetic Phishing Test Vector

`frontend/test-phish.html` imitates a fake airdrop (countdown, urgency wording, seed phrase and password fields) so the scanner has a known-bad page to judge. It is a test fixture: its form is not connected to anything, it runs no network code, it names no real brand, and it says so on the page.

Its code signals alone add up to at least 70 (password field, seed phrase request, wallet lure, urgency, giveaway), so the hard floor forces `RED` whatever the model answers. `tests/test_green_light.py` checks this offline.

To record it on-chain, publish the file at a public https address and run the reporter with that address:

```bash
PHISH_TEST_URL=https://your-test-site.example/test-phish.html npm run report:studionet
```

Validators fetch pages from the public internet, so `localhost` and private addresses cannot be used. Host the fixture on a separate throwaway site rather than on your main domain, because browsers and hosting providers may flag any page that looks like phishing. Remove it after the run if you like.

---

## Test Suites

GreenLight comes with automated test suites covering unit logic, adversarial security, wallet integration, and end-to-end browser workflows:

```bash
# Run all test suites
python3 tests/run_all_tests.py

# Or via npm:
npm test

# Run individual suites:
npm run test:unit          # Core unit tests
npm run test:adversarial   # Security, exploit, and prompt injection tests
npm run test:wallet        # EIP-6963 wallet provider tests
```

---

## Contract API

### Write Methods

| Method | Parameters | Description |
| :--- | :--- | :--- |
| `scan(url)` | `url: str` | Normalizes the URL, runs multi-validator consensus, and stores the verdict on-chain. URLs have a 60s cooldown; senders have a 15s spam brake. |

### View Methods (Zero Gas Cost)

| Method | Parameters | Returns | Description |
| :--- | :--- | :--- | :--- |
| `is_safe(url)` | `url: str` | `bool` | Returns `true` only if the stored verdict is `GREEN`. Safely returns `false` on unknown or malformed URLs. |
| `check(url)` | `url: str` | `dict` | Compact integrator answer: `{known, safe, verdict, risk, last_scanned}`. |
| `get_scan(url)` | `url: str` | `dict \| null` | Full record including category, impersonated brand, reasons, flags, and 8-entry history. |
| `browse(...)` | `verdict, query, scanner, offset, limit` | `dict` | Filtered newest-first pagination over the latest feed window. |
| `recent(offset, limit)` | `offset: int, limit: int` | `dict` | Unfiltered newest-first list (limit capped at 25). |
| `host_overview(host)` | `host: str` | `dict` | Returns RED URL count on a domain and whether it receives a repeat-offender penalty. |
| `stats()` | `None` | `dict` | Total URLs indexed, scan operations, unique contributors, and verdict distribution. |
| `contributor(address)` | `address: str` | `dict` | Scans submitted by a given wallet address. |
| `config()` | `None` | `dict` | Contract version, scoring thresholds, and tuning parameters. |

---

## Integrating From Another Intelligent Contract

```python
from genlayer import *
import typing

@gl.contract_interface
class GreenLightRegistry:
    class View:
        def is_safe(self, url: str) -> bool: ...
        def check(self, url: str) -> typing.Any: ...
    class Write:
        def scan(self, url: str) -> None: ...

# Example: Guarding links submitted to your contract
registry = GreenLightRegistry(Address("0x7F2217DAaF35c3082c5A8f2d2942908b7337369F"))
if not registry.view().is_safe(external_link):
    raise gl.vm.UserError("[SECURITY] Link is not verified safe by GreenLight")
```

---

## Cloudflare Pages Deployment

The `frontend/` directory is 100% static HTML, CSS, and native ES modules. It requires no build step and deploys seamlessly on Cloudflare Pages:

1. Push your repository to GitHub.
2. In the Cloudflare Dashboard, go to **Workers & Pages** > **Create application** > **Pages** > **Connect to Git**.
3. Select your repository.
4. Set **Build output directory** to: `frontend`
5. Leave the **Build command** empty.
6. Click **Save and Deploy**. Your site will be live instantly worldwide with global CDN edge caching!
