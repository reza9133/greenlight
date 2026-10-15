"""Browser smoke test for the GreenLight frontend (needs: pip install playwright; playwright install chromium).

Runs the real site in headless Chromium twice:
  1. demo mode (no contract address)
  2. live mode against a fake genlayer-js SDK, so the wallet, scan, check, registry and
     "My scans" flows run end to end without a network.
Run:  python3 tests/ui_smoke.py
"""
import functools
import http.server
import pathlib
import threading

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent / "frontend"
ADDR = "0x" + "c" * 40
BASE = None

FAKE_SDK = """
let scanned = null;
const mkrec = url => ({ url, host: url.split("/")[2], verdict: "GREEN", risk: 5, category: "none", impersonates: "", reasons: [], flags: [], reachable: true,
  reporter: "0x" + "1".repeat(40), last_scanner: "0x" + "1".repeat(40), first_seen: 1, last_scanned: 1, scan_count: 1, miss_streak: 0, summary: "", history: [] });
const MULTI = [];
for (let i = 0; i < 14; i++) MULTI.push(mkrec([0, 3, 5, 8].includes(i) ? "https://other" + i + ".example/?r=multi.example" : "https://multi.example/p" + i));
export const createAccount = () => ({ address: "0x" + "1".repeat(40) });
export const createClient = () => ({
  async readContract({ functionName, args }) {
    const has = !!scanned;
    if (functionName === "get_scan") return has && args[0] === scanned.url ? scanned : null;
    if (functionName === "stats") return { urls: has ? 1 : 0, scan_operations: has ? 1 : 0, contributors: has ? 1 : 0, verdicts: { GREEN: has ? 1 : 0, AMBER: 0, RED: 0, UNREACHABLE: 0 } };
    if (functionName === "browse" && args[1] === "multi.example") {   // raw pages contain URLs of other hosts that merely mention this one
      const [, , , offset, limit] = args;
      return { items: MULTI.slice(offset, offset + limit), more: offset + limit < MULTI.length, truncated: false };
    }
    if (functionName === "browse" || functionName === "recent") return { items: has ? [scanned] : [], more: false, truncated: false, total: has ? 1 : 0 };
    if (functionName === "contributor") return { address: args[0], scans: has ? 1 : 0 };
    if (functionName === "host_overview") return { host: args[0], red_urls: 0, flagged: false };
    throw new Error("unexpected read " + functionName);
  },
  async writeContract({ args }) {
    const now = Math.floor(Date.now() / 1000);
    scanned = { url: args[0], host: args[0].split("/")[2], verdict: "GREEN", risk: 12, category: "none", impersonates: "", reasons: ["Plain page."], flags: [],
      reachable: true, reporter: "0x" + "1".repeat(40), last_scanner: "0x" + "1".repeat(40), first_seen: now, last_scanned: now, scan_count: 1, miss_streak: 0,
      summary: "Looks like an ordinary reading page.", history: [{ at: now, verdict: "GREEN", risk: 12 }] };
    return "0x" + "ab".repeat(32);
  },
  async waitForTransactionReceipt() { await new Promise(r => setTimeout(r, 300)); return { statusName: "ACCEPTED", consensus_data: { leader_receipt: [{ execution_result: "SUCCESS" }] } }; },
});
"""
FAKE_CHAINS = "export const studionet = { id: 61999 };"

# Same SDK, but reads of host_overview / stats / contributor are slow, and a host_overview read makes the "user"
# click away (to window.__navAway) while it is still in flight.
SLOW_SDK = FAKE_SDK.replace(
    "async readContract({ functionName, args }) {",
    """async readContract({ functionName, args }) {
    if (functionName === "browse" && args[1] === "multi.example") await new Promise(r => setTimeout(r, 400));
    if (functionName === "host_overview" && window.__navAway) setTimeout(() => { location.hash = window.__navAway; }, 50);
    if (["host_overview", "stats", "contributor"].includes(functionName)) await new Promise(r => setTimeout(r, 900));""")
assert SLOW_SDK != FAKE_SDK


def serve():
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args, **kwargs):
            pass

    handler = functools.partial(Quiet, directory=str(ROOT))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def new_page(browser, errors, viewport=None, live=False, sdk=None):
    ctx = browser.new_context(viewport=viewport or {"width": 1200, "height": 900})
    page = ctx.new_page()
    page.on("pageerror", lambda e: errors.append("pageerror: " + str(e)))
    page.on("console", lambda m: errors.append("console: " + m.text) if m.type == "error" and "ERR_" not in m.text and "Failed to load resource" not in m.text else None)
    # fonts and other third-party hosts are not reachable in CI; the site must work without them
    page.route("https://fonts.googleapis.com/**", lambda r: r.abort())
    page.route("https://fonts.gstatic.com/**", lambda r: r.abort())
    if live:
        page.add_init_script(f'localStorage.setItem("gl_contract", "{ADDR}")')
        page.route("https://esm.sh/**", lambda r: r.fulfill(status=200, headers={"content-type": "application/javascript", "access-control-allow-origin": "*"},
                                                           body=FAKE_CHAINS if r.request.url.endswith("/chains") else (sdk or FAKE_SDK)))
    return page


def demo(browser):
    errors = []
    page = new_page(browser, errors)
    page.goto(BASE + "/")
    page.wait_for_selector(".hero")
    assert page.inner_text("#mode") == "Demo mode"
    page.wait_for_selector("#stats b")
    # home check box -> check page for an unknown URL
    page.fill("#hu", "https://never-seen.example/page")
    page.click("#hf button")
    page.wait_for_selector("#chk .callout")
    assert "No validator has inspected" in page.inner_text("#chk")
    # check page for a known demo URL shows the AI summary and a permalink button
    page.goto(BASE + "/#/check/" + "https%3A%2F%2Fclaim-airdrop-now.example%2Fwallet")
    page.wait_for_selector(".result")
    txt = page.inner_text("#chk")
    assert "RED" in txt and "Asks visitors to type a recovery phrase" in txt and page.locator("#cp").count() == 1
    # registry: server-style filters
    page.goto(BASE + "/#/registry")
    page.wait_for_selector(".row")
    assert page.locator(".row").count() == 4
    assert not page.locator("#more").is_visible()                      # nothing more to load: the button must really be hidden
    page.select_option("#fv", "RED")
    page.wait_for_function("document.querySelectorAll('.row').length === 2")
    page.select_option("#fv", "")
    page.fill("#q", "orchard")
    page.wait_for_function("document.querySelectorAll('.row').length === 1")
    page.fill("#q", "zzzz-nothing")
    page.wait_for_selector("#list .note")
    # host page, my scans (needs wallet), playground, docs, how, integrate
    page.goto(BASE + "/#/host/claim-airdrop-now.example")
    page.wait_for_selector(".row")
    page.goto(BASE + "/#/me")
    page.wait_for_selector("#meh .callout")
    for route in ("playground", "docs/overview", "docs/signals", "docs/consensus", "docs/security", "docs/wallets", "docs/deploy", "how", "integrate"):
        page.goto(BASE + "/#/" + route)
        page.wait_for_selector("main h1")
    page.goto(BASE + "/#/docs/deploy")
    page.wait_for_selector("main h1")
    assert "npm run deploy" in page.inner_text("main")
    # names inherited from Object.prototype must not break routing or the docs menu
    for bad in ("constructor", "__proto__", "toString"):
        page.goto(BASE + "/#/" + bad)
        page.wait_for_selector(".hero")
    page.goto(BASE + "/#/docs/constructor")
    page.wait_for_selector("main h1")
    assert page.inner_text("main h1") == "Architecture Overview"
    # scan page in demo mode produces a simulated verdict
    page.goto(BASE + "/#/scan")
    page.fill("#u", "https://example.org/some/page")
    page.click("#go")
    page.wait_for_selector("#out .result", timeout=15000)
    # an internationalised host and a non-ASCII path become punycode / percent-encoding (the contract only takes printable ASCII)
    page.fill("#u", "https://\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444/\u0441\u0442\u0440\u0430\u043d\u0438\u0446\u0430")
    page.click("#go")
    page.wait_for_function("document.querySelector('#out .result b') && document.querySelector('#out .result b').textContent.startsWith('https://xn--')", timeout=15000)
    assert "%D1%81" in page.inner_text("#out .result b"), page.inner_text("#out .result b")
    page.fill("#u", "https://example.org/two words")                    # a space inside is a pasted sentence, not a URL
    page.click("#go")
    page.wait_for_selector("#out .err")
    # settings dialog saves a valid address and rejects a bad one
    page.click("#mode")
    assert not page.locator("#cr").is_visible()                        # no saved address, so no "use config.js again" button
    page.fill("#ca", "nope")
    page.click("#cs")
    assert "0x" in page.inner_text("#ce")
    page.keyboard.press("Escape")
    # wallet dialog opens and offers the test key
    page.click("#wbtn")
    page.wait_for_selector("#wm[open]")
    assert page.locator('.wopt[data-u="burner"]').count() == 1
    assert not errors, errors
    page.context.close()

    # mobile layout: nav hidden until the menu button is pressed, no sideways scroll
    errors = []
    page = new_page(browser, errors, viewport={"width": 390, "height": 800})
    page.goto(BASE + "/")
    page.wait_for_selector(".hero")
    assert not page.locator("#nav").is_visible()
    page.click("#nb")
    assert page.locator("#nav").is_visible()
    page.click('nav a[data-k="registry"]')
    page.wait_for_selector(".row")
    assert not page.locator("#nav").is_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth + 1"), "horizontal overflow on mobile"
    assert not errors, errors
    page.context.close()


def live(browser):
    errors = []
    page = new_page(browser, errors, live=True)
    page.goto(BASE + "/")
    page.wait_for_selector(".hero")
    assert page.inner_text("#mode").startswith("Studionet 0xcccc")
    page.goto(BASE + "/#/scan")
    page.wait_for_selector("#gate .callout")                         # asks for a wallet before a scan
    page.click("#gc")
    page.click('.wopt[data-u="burner"]')
    page.wait_for_selector("#wm:not([open])", state="attached")
    page.wait_for_selector("#gate code")
    page.fill("#u", "https://orchard-notes.example/guides#top")      # fragment is dropped, not rejected
    page.click("#go")
    page.wait_for_selector("#out .result", timeout=20000)
    out = page.inner_text("#out")
    assert "GREEN" in out and "ordinary reading page" in out and "Permanent Link" in out and "0xabab...abab" in out
    # the permanent link opens the stored record
    page.click("#out a.ghost")
    page.wait_for_selector("#chk .result")
    # an immediate rescan is blocked before any transaction is sent
    page.goto(BASE + "/#/scan/" + "https%3A%2F%2Forchard-notes.example%2Fguides")
    page.wait_for_selector("#gate code")
    assert page.input_value("#u") == "https://orchard-notes.example/guides"      # prefilled from the link
    page.click("#go")
    page.wait_for_selector("#out .err")
    assert "scanned moments ago" in page.inner_text("#out")
    # registry and my scans see the stored record
    page.goto(BASE + "/#/registry")
    page.wait_for_selector(".row")
    assert page.locator(".row").count() == 1
    page.goto(BASE + "/#/me")
    page.wait_for_selector(".row")
    assert "1 total scans recorded" in page.inner_text("#meh")
    # host page: rows the client filter drops must not shift the next page (no duplicates, nothing skipped)
    page.goto(BASE + "/#/host/multi.example")
    page.wait_for_function("document.querySelectorAll('.row').length === 6")
    page.click("#more")
    page.wait_for_function("document.querySelectorAll('.row').length === 10")
    keys = page.eval_on_selector_all(".row", "els => els.map(e => e.dataset.s)")
    assert len(set(keys)) == 10, keys
    # disconnect works
    page.click("#wbtn")
    page.click('[data-a="out"]')
    page.wait_for_function("document.querySelector('#wbtn').textContent.includes('Connect wallet')")
    assert not errors, errors
    page.context.close()


def races(browser):
    """The user leaves a page while its contract read is still in flight. The old page's code must not touch the new page."""
    # Host page -> Registry: the host pager used to attach itself to the Registry's list and overwrite it with host rows
    errors = []
    page = new_page(browser, errors, live=True, sdk=SLOW_SDK)
    page.add_init_script("window.__navAway = '#/registry'")
    page.goto(BASE + "/#/host/multi.example")
    page.wait_for_function("location.hash === '#/registry'")
    page.wait_for_selector("#fv")
    page.wait_for_timeout(2500)
    assert page.locator("#list .row").count() == 0, page.inner_text("#list")
    assert "No matching URLs found" in page.inner_text("#list")
    assert not errors, errors
    page.context.close()

    # My scans -> How it works: contributor() resolving later used to throw "Cannot set properties of null"
    errors = []
    page = new_page(browser, errors, live=True, sdk=SLOW_SDK)
    page.add_init_script('localStorage.setItem("gl_wallet", "burner")')
    page.goto(BASE + "/#/me")
    page.wait_for_selector("#meh")
    page.evaluate("setTimeout(() => { location.hash = '#/how'; }, 150)")
    page.wait_for_selector(".flow")
    page.wait_for_timeout(2000)
    assert not errors, errors
    page.context.close()


if __name__ == "__main__":
    srv = serve()
    BASE = "http://127.0.0.1:%d" % srv.server_address[1]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        demo(browser)
        print("demo mode ok")
        live(browser)
        print("live mode ok")
        races(browser)
        print("navigation races ok")
        browser.close()
    print("ui smoke tests passed")
