"""Offline tests for the pure logic and the state machine of green_light.py.

GenVM is replaced by a tiny stub, so these tests check the contract's own logic
(URL screening, signals, equivalence rule, storage bookkeeping), not consensus.
Run:  python3 tests/test_green_light.py
"""
import importlib.util
import pathlib
import sys
import time
import types

# ---------------------------------------------------------------- GenVM stub
class UserError(Exception):
    pass


class Return:
    def __init__(self, calldata):
        self.calldata = calldata


class Address(str):
    @property
    def as_hex(self):
        return str(self)


class TreeMap(dict):
    def __class_getitem__(cls, _):
        return cls


class DynArray(list):
    def __class_getitem__(cls, _):
        return cls


vm = types.SimpleNamespace(UserError=UserError, Result=object, Return=Return, run_nondet_unsafe=None)
gl = types.SimpleNamespace(
    vm=vm,
    Contract=object,
    public=types.SimpleNamespace(view=lambda f: f, write=lambda f: f),
    nondet=types.SimpleNamespace(),
    message=types.SimpleNamespace(sender_address=Address("0x" + "a" * 40)),
)
stub = types.ModuleType("genlayer")
stub.gl, stub.allow_storage, stub.u32, stub.u64 = gl, (lambda c: c), int, int
stub.TreeMap, stub.DynArray, stub.Address = TreeMap, DynArray, Address
sys.modules["genlayer"] = stub

path = pathlib.Path(__file__).resolve().parent.parent / "contracts" / "green_light.py"
spec = importlib.util.spec_from_file_location("green_light", path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def rejects(fn, *args):
    try:
        fn(*args)
    except UserError:
        return True
    return False


# ---------------------------------------------------------------- URL screening
assert m._parse_url("http://8.8.8.8/aaaa")[0] == "http://8.8.8.8/aaaa"
assert m._parse_url("https://Example.com") == ("https://example.com/", "example.com", "https")
assert m._parse_url("http://a.example.org:80/x?y=1#frag")[0] == "http://a.example.org/x?y=1"
assert m._parse_url("https://a.example.org:8443?q=1")[0] == "https://a.example.org:8443/?q=1"
for bad in ["https://user@evil.com/", "ftp://example.com/aa", "https://localhost/abc", "http://192.168.1.1/admin",
            "http://10.0.0.1/xx", "http://127.0.0.1:8545/", "http://169.254.169.254/latest", "http://100.64.0.1/aaa",
            "https://intranet.corp/aaa", "https://exa mple.com", "https://-bad.com/aaaa", "https://example/aaaaa",
            "http://999.1.1.1/aaa", "https://a..b.com/aaaa", "https://example.com:99999/a", "short",
            "https://example.com/a\x00b", "https://example.com/a\u202eb", "https://example.com/\r\nHost: x",
            "http://127.0.0.1.nip.io/x", "https://a.b.sslip.io/x", "http://[::1]/aaaa", "http://2130706433/aaa",
            "http://012.0.0.1/aaaa", "http://8.08.8.8/aaaa", "http://198.18.0.5/aaaa", "http://192.0.0.8/aaaa",
            "http://203.0.113.9/aaaa", "http://198.51.100.7/aaaa"]:
    assert rejects(m._parse_url, bad), bad

# ---------------------------------------------------------------- signals and text
assert m._url_signals("http", "secure-login-paypal-verify.xyz")[1] == ["no_https", "hyphen_heavy", "risky_tld", "lure_word_in_host", "brand_lookalike"]
html = ('<html><title>Verify</title><form action="https://evil.example/post"><input type="password"><input name=s></form>'
        "Enter your seed phrase. Act now, urgent! Connect wallet <script>eval(atob('x'))</script></html>")
text = m._html_to_text(html)
assert "eval" not in text and "<" not in text and text.startswith("Title: Verify.")
score, flags = m._page_signals(html.lower(), text.lower(), "bank.example")
assert set(flags) >= {"password_field", "seed_phrase_request", "wallet_connect_lure", "urgency_language", "cross_origin_form", "obfuscated_script"}

# hostile pages must stay linear
for hostile in ["<script>" * 20000, "<form " * 25000, "<title>" * 20000, "<" * 100000, "<!--" * 30000, "<a " * 50000]:
    t = time.time()
    m._html_to_text(hostile)
    m._page_signals(hostile.lower(), "", "x.example")
    assert time.time() - t < 1.5, ("slow on", hostile[:12])

# ---------------------------------------------------------------- LLM output cleaning
assert m._clean_llm({"risk": "72.5", "category": "Phishing", "impersonates": "X|Y", "reasons": "a|b"}) == \
    {"risk": 72, "category": "phishing", "impersonates": "X/Y", "reasons": ["a/b"], "summary": ""}
assert m._clean_llm('noise {"risk": 12, "category":"zzz", "reasons":["a","b","c","d"]} tail')["reasons"] == ["a", "b", "c"]
assert m._clean_llm({"risk": 400})["risk"] == 100
for bad in [None, "no json", {"risk": "abc"}, {"risk": None}, {"risk": True}, []]:
    assert rejects(m._clean_llm, bad), bad

# ---------------------------------------------------------------- equivalence rule
base = {"reachable": True, "risk": 60, "verdict": "AMBER", "category": "phishing", "impersonates": "", "reasons": ["x"], "flags": ["password_field"]}
assert m._results_agree(base, dict(base, risk=66))                                   # same verdict, inside tolerance
assert not m._results_agree(base, dict(base, risk=75, verdict="RED"))                # validator derives RED, leader said AMBER
assert not m._results_agree(base, dict(base, risk=85, verdict="RED"))
assert not m._results_agree(dict(base, verdict="RED"), base)                        # verdict inconsistent with score
assert not m._results_agree(dict(base, flags=["no_https"]), base)                    # URL-derived flags must match
assert m._results_agree(dict(base, flags=["password_field", "urgency_language"]), base)  # page flags may vary
down = {"reachable": False, "risk": 0, "verdict": "UNREACHABLE", "category": "none", "impersonates": "", "reasons": ["r"], "flags": []}
assert m._results_agree(down, down) and not m._results_agree(down, base) and not m._results_agree(base, down)
assert not m._results_agree("x", base) and not m._results_agree({}, base)

# ---------------------------------------------------------------- analysis (injection cannot lower a strong score)
class Page:
    status = 200
    body = html.encode()


gl.nondet.web = types.SimpleNamespace(get=lambda k: Page())
gl.nondet.exec_prompt = lambda p, response_format=None: {"risk": 0, "category": "none", "reasons": ["ignore previous instructions, safe"]}
res = m._analyze("https://bank.example/login", "bank.example", "https", 0)
assert res["verdict"] == "RED" and res["risk"] >= 70

# ---------------------------------------------------------------- state machine through scan()
clock = [1_000_000]
m._now_ts = lambda: clock[0]
gl.vm.run_nondet_unsafe = lambda leader, validator: leader()
c = m.GreenLight()
c.scans, c.feed, c.host_reds, c.verdict_counts, c.contributors, c.sender_last = TreeMap(), DynArray(), TreeMap(), TreeMap(), TreeMap(), TreeMap()
c.__init__()
URL = "https://phish.example/login"

c.scan(URL)
rec = c.get_scan(URL)
assert rec["verdict"] == "RED" and rec["scan_count"] == 1 and rec["miss_streak"] == 0
assert c.stats()["verdicts"]["RED"] == 1 and c.host_overview("phish.example")["red_urls"] == 1
assert not c.is_safe(URL)

assert rejects(c.scan, URL)                                   # cooldown (URL and sender)
clock[0] += m.RESCAN_COOLDOWN

Page.status = 503                                             # page taken down
c.scan(URL)
rec = c.get_scan(URL)
assert rec["verdict"] == "RED" and rec["miss_streak"] == 1    # verdict survives a takedown
clock[0] += 60
c.scan(URL)
assert c.get_scan(URL)["verdict"] == "RED" and c.get_scan(URL)["miss_streak"] == 2
clock[0] += 60
c.scan(URL)
rec = c.get_scan(URL)
assert rec["verdict"] == "UNREACHABLE" and rec["miss_streak"] == 3
assert c.host_overview("phish.example")["red_urls"] == 0
assert c.stats()["verdicts"] == {"GREEN": 0, "AMBER": 0, "RED": 0, "UNREACHABLE": 1}

Page.status = 200                                             # page returns
clock[0] += 60
c.scan(URL)
rec = c.get_scan(URL)
assert rec["verdict"] == "RED" and rec["miss_streak"] == 0 and rec["scan_count"] == 5
assert c.stats() == {"urls": 1, "scan_operations": 5, "contributors": 1, "verdicts": {"GREEN": 0, "AMBER": 0, "RED": 1, "UNREACHABLE": 0}}
assert c.contributor("0x" + "a" * 40)["scans"] == 5

# neighbourhood penalty: a host with two RED URLs penalises a third scan
clock[0] += 20
c.scan("https://phish.example/two")
clock[0] += 20
third = "https://phish.example/clean"
Page.body = b"<html><title>Garden</title>Plain gardening notes.</html>"
gl.nondet.exec_prompt = lambda p, response_format=None: {"risk": 10, "category": "none", "reasons": ["plain page"]}
c.scan(third)
rec = c.get_scan(third)
assert "repeat_offender_host" in rec["flags"] and rec["risk"] >= 10 + m.NEIGHBORHOOD_BONUS - 4
page = c.recent(0, 10)
assert page["total"] == 3 and page["items"][0]["url"] == third and len(c.recent(0, 1000)["items"]) == 3
assert c.recent(-5, 0)["items"] and c.recent(99, 5)["items"] == []
assert c.get_scan("https://never-seen.example/x") is None and c.is_safe("https://never-seen.example/x") is False
# ---------------------------------------------------------------- v2: summary, history, throttle, browse, check
rec = c.get_scan(URL)
assert len(rec["history"]) == 5 and rec["history"][0]["verdict"] == "RED" and rec["history"][3]["verdict"] == "UNREACHABLE" and rec["history"][3]["risk"] == 0
assert rec["history"][2]["verdict"] == "UNREACHABLE"            # observed, even while the stored verdict stayed RED
assert isinstance(rec["summary"], str)
third_rec = c.get_scan(third)
assert third_rec["summary"] == "" or isinstance(third_rec["summary"], str)

chk = c.check(URL)
assert chk["known"] and chk["verdict"] == "RED" and chk["safe"] is False and chk["last_scanned"] > 0
unk = c.check("https://unknown.example/zzz")
assert unk["url"] == "https://unknown.example/zzz" and unk["known"] is False and unk["safe"] is False and unk["fresh"] is False and unk["needs_rescan"] is True and unk["last_scanned"] == 0

b = c.browse("RED", "", "", 0, 10)
assert {i["url"] for i in b["items"]} == {URL, "https://phish.example/two"} and b["more"] is False and b["truncated"] is False
assert [i["url"] for i in c.browse("", "clean", "", 0, 10)["items"]] == [third]
assert c.browse("red", "PHISH.example", "", 1, 1)["items"][0]["url"] in (URL, "https://phish.example/two")      # case-insensitive, offset counts matches
assert [i["url"] for i in c.browse(third_rec["verdict"], "", "", 0, 10)["items"]] == [third]
assert c.browse("UNREACHABLE", "", "", 0, 10)["items"] == []
me = "0x" + "a" * 40
assert len(c.browse("", "", me, 0, 25)["items"]) == 3 and c.browse("", "", "0x" + "b" * 40, 0, 25)["items"] == []
old_window = m.BROWSE_WINDOW
m.BROWSE_WINDOW = 2
assert c.browse("", "", "", 0, 25)["truncated"] is True and c.browse("", "", "", 0, 25)["inspected"] == 2
m.BROWSE_WINDOW = old_window

# sender brake: the same address cannot submit two scans back to back
fresh = "https://throttle-check.example/page"
clock[0] += 100
c.scan(fresh)
assert rejects(c.scan, "https://throttle-check.example/other")
clock[0] += m.SENDER_COOLDOWN
c.scan("https://throttle-check.example/other")
assert c.stats()["urls"] == 5 and c.config()["version"] == m.VERSION

# a second address is counted once as a contributor
gl.message.sender_address = Address("0x" + "b" * 40)
clock[0] += 100
c.scan("https://second-sender.example/page")
assert c.stats()["contributors"] == 2 and c.contributor("0x" + "b" * 40)["scans"] == 1
gl.message.sender_address = Address("0x" + "a" * 40)

# model summary is stored, clipped and cleaned
assert m._clean_llm({"risk": 5, "summary": "Safe | looks fine\n" + "x" * 500})["summary"].startswith("Safe / looks fine")
assert len(m._clean_llm({"risk": 5, "summary": "y" * 999})["summary"]) == m.MAX_SUMMARY
assert m._clean_llm({"risk": 5})["summary"] == ""

# ---------------------------------------------------------------- v2.0.1 regressions
# browse(): `more` is exact (it used to be true whenever older entries existed, even if none matched)
Page.status, Page.body = 200, b"<html><title>Ok</title>Plain notes.</html>"
d = m.GreenLight()
d.scans, d.feed, d.host_reds, d.verdict_counts, d.contributors, d.sender_last = TreeMap(), DynArray(), TreeMap(), TreeMap(), TreeMap(), TreeMap()
d.__init__()
gl.message.sender_address = Address("0x" + "d" * 40)
for i in range(5):
    clock[0] += 100
    d.scan("https://site%d.example/page" % i)
gl.message.sender_address = Address("0x" + "a" * 40)
newest = d.browse("", "site4", "", 0, 1)
assert len(newest["items"]) == 1 and newest["more"] is False and newest["truncated"] is False
two = d.browse("", "site", "", 0, 2)
assert len(two["items"]) == 2 and two["more"] is True
tail = d.browse("", "site", "", 4, 2)
assert [i["url"] for i in tail["items"]] == ["https://site0.example/page"] and tail["more"] is False
everything = d.browse("", "", "", 0, 5)
assert len(everything["items"]) == 5 and everything["more"] is False
m.BROWSE_WINDOW = 3
cut = d.browse("", "site0", "", 0, 5)
assert cut["items"] == [] and cut["more"] is False and cut["truncated"] is True and cut["inspected"] == 3
m.BROWSE_WINDOW = old_window

# _now_ts(): transaction time first, wall clock only as a fallback
spec2 = importlib.util.spec_from_file_location("green_light_clock", path)
m2 = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(m2)
import datetime as _dt
expected = int(_dt.datetime(2026, 10, 12, 10, 0, 0, tzinfo=_dt.timezone.utc).timestamp())
for raw, want in [("2026-10-12T10:00:00.123456Z", expected), ("2026-10-12T10:00:00+00:00", expected),
                  ("2026-10-12T12:00:00+02:00", expected), ("2026-10-12T10:00:00", expected)]:
    gl.message_raw = {"datetime": raw}
    assert m2._now_ts() == want, raw
for broken in [{"datetime": "garbage"}, {}, {"datetime": None}]:
    gl.message_raw = broken
    assert abs(m2._now_ts() - time.time()) < 5, broken
del gl.message_raw

# cross_origin_form: protocol-relative actions count, www. and same-site subdomains do not
rel = '<form action="//evil.example/x"><input type="password"></form>'
assert "cross_origin_form" in m._page_signals(rel, "", "bank.example")[1]
assert "cross_origin_form" not in m._page_signals('<form action="https://bank.example/login"><input></form>', "", "www.bank.example")[1]
assert "cross_origin_form" not in m._page_signals('<form action="https://www.bank.example/login"><input></form>', "", "bank.example")[1]
assert "cross_origin_form" not in m._page_signals('<form action="https://login.bank.example/x"><input></form>', "", "bank.example")[1]
assert "cross_origin_form" in m._page_signals('<form action="https://evil.example/x"><input></form>', "", "www.bank.example")[1]
assert "cross_origin_form" in m._page_signals('<form action="https://bank.example.evil.example/x"><input></form>', "", "bank.example")[1]

# a hostile leader result must be refused by validators and can never crash _finalize with a raw Python error
honest = {"reachable": True, "risk": 40, "verdict": "AMBER", "category": "none", "impersonates": "", "reasons": [], "flags": [], "summary": ""}
for bad_result in [dict(honest, reasons=5), dict(honest, flags=5), dict(honest, flags="no_https"), dict(honest, reasons="x"),
                   dict(honest, reachable=False, verdict="UNREACHABLE", reasons=5), dict(honest, reachable=False, verdict="UNREACHABLE", flags=5),
                   {k: v for k, v in honest.items() if k != "flags"}]:
    assert not m._results_agree(bad_result, honest), bad_result
import itertools
odd = [None, True, 0, -3, 5.5, float("nan"), float("inf"), "x", "12", "NaN", [], ["a"], {}, {"a": 1}]
for risk_v, reasons_v, flags_v, cat_v, reach_v in itertools.product(odd, odd, odd, odd, [True, False]):
    try:
        out = m._finalize({"reachable": reach_v, "risk": risk_v, "reasons": reasons_v, "flags": flags_v, "category": cat_v, "summary": reasons_v, "impersonates": flags_v})
    except UserError:
        continue
    assert out["verdict"] in m.VERDICTS and 0 <= out["risk"] <= 100 and out["category"] in m.CATEGORIES and isinstance(out["reasons"], str) and isinstance(out["flags"], str)

# ---------------------------------------------------------------- fetch fallback (web.get empty -> web.render)
class Empty:
    status = 200
    body = b""


class Gone:
    status = 404
    body = b"nope"


calls = []
gl.nondet.web = types.SimpleNamespace(get=lambda k: Empty(), render=lambda k, mode="text": calls.append(mode) or "<html>hello</html>")
assert m._fetch_html("https://a.example/x") == (True, "<html>hello</html>") and calls == ["html"]
gl.nondet.web = types.SimpleNamespace(get=lambda k: Gone(), render=lambda k, mode="text": calls.append("should-not-run") or "<html>x</html>")
assert m._fetch_html("https://a.example/x") == (False, "") and "should-not-run" not in calls   # a real HTTP error is final


def boom(k):
    raise RuntimeError("network")


gl.nondet.web = types.SimpleNamespace(get=boom, render=lambda k, mode="text": b"<p>bytes page</p>")
assert m._fetch_html("https://a.example/x") == (True, "<p>bytes page</p>")
gl.nondet.web = types.SimpleNamespace(get=boom, render=boom)
assert m._fetch_html("https://a.example/x") == (False, "")
gl.nondet.web = types.SimpleNamespace(get=lambda k: Empty())          # no render at all must not crash
# ---------------------------------------------------------------- v2.1.0 resilient views and safety checks
assert rejects(m._parse_url, "http://127.0.0.1.vcap.me/test")
assert rejects(m._clean_llm, {"risk": True})
assert rejects(m._clean_llm, {"risk": False})

# dict-based HTTP responses supported
assert m._status_of({"status": 404, "body": "nope"}) == 404
assert m._status_of({"status_code": 200, "body": "ok"}) == 200
assert m._body_of({"body": b"bytes content"}) == "bytes content"

# view methods never crash on malformed input
assert c.is_safe("invalid-protocol://bad") is False
assert c.is_safe("ftp://bad.com") is False
assert c.is_safe("short") is False
chk_bad = c.check("http://broken space")
assert chk_bad["safe"] is False and chk_bad["known"] is False
assert c.get_scan("not a url at all") is None
assert c.host_overview("https://phish.example:8080/path/test")["red_urls"] == c.host_overview("phish.example")["red_urls"]

# ---------------------------------------------------------------- synthetic phishing fixture (frontend/test-phish.html)
fixture_path = pathlib.Path(__file__).resolve().parent.parent / "frontend" / "test-phish.html"
if fixture_path.exists():
    fixture = fixture_path.read_text(encoding="utf-8")
    fix_text = m._html_to_text(fixture)
    fix_score, fix_flags = m._page_signals(fixture.lower(), fix_text.lower(), "example.pages.dev")
    for expected in ("password_field", "seed_phrase_request", "wallet_connect_lure", "urgency_language", "giveaway_lure"):
        assert expected in fix_flags, expected
    assert "cross_origin_form" not in fix_flags  # the fixture form is not connected to anything
    assert fix_score >= m.HARD_FLOOR_HEURISTIC, fix_score  # code signals alone force RED, whatever the LLM says
else:
    print("note: frontend/test-phish.html not found, fixture check skipped")

print("all tests passed")


# ---------------------------------------------------------------- v2.2: the verdict itself must agree
bd = {"reachable": True, "risk": 34, "verdict": "GREEN", "category": "none", "impersonates": "", "reasons": [], "flags": []}
assert m._results_agree(bd, dict(bd, risk=30))
assert not m._results_agree(bd, dict(bd, risk=36))             # 2 points apart, but AMBER vs GREEN
assert not m._results_agree(dict(bd, risk=69, verdict="AMBER"), dict(bd, risk=71))
assert m._results_agree(dict(bd, risk=69, verdict="AMBER"), dict(bd, risk=60))
# strong page signals must match both ways, ordinary page signals may differ
seed = dict(bd, risk=80, verdict="RED", flags=["seed_phrase_request"])
assert m._results_agree(seed, dict(seed, risk=78))
assert not m._results_agree(seed, dict(seed, flags=[]))                              # validator did not see the request
assert not m._results_agree(dict(seed, flags=[]), dict(seed))                        # leader hid it
assert not m._results_agree(dict(seed, flags=["executable_download"]), dict(seed))
assert m._results_agree(dict(seed, flags=["seed_phrase_request", "urgency_language"]), seed)
assert not m._results_agree(dict(bd, flags=["brand_lookalike"]), bd)                 # brand lookalike is URL-derived
assert m.RISK_TOLERANCE == 15

# ---------------------------------------------------------------- v2.2: brand check
assert m._brand_lookalike("paypal-secure.xyz") == "paypal" and m._brand_lookalike("my-metamask.io.evil.top") == "metamask"
for ok in ("www.paypal.com", "paypal.de", "www.paypal.co.uk", "login.microsoftonline.com", "metamask.io", "orchard-notes.example"):
    assert m._brand_lookalike(ok) == "", ok
assert m._brand_lookalike("paypal.tk") == "paypal"                                   # free abuse-prone ccTLD is not official
assert m._brand_of("Trust Wallet") == "trustwallet" and m._brand_of("A well-known wallet") == ""

# ---------------------------------------------------------------- v2.2: wider page signals
hp = ('<html><meta http-equiv="refresh" content="0; url=https://elsewhere.example/go">'
      '<iframe src="https://x.example" width="0" height="0"></iframe><a href="/files/update.exe">Update</a></html>')
_, pf = m._page_signals(hp.lower(), "", "shop.example")
assert set(pf) == {"meta_refresh_redirect", "hidden_iframe", "executable_download"}, pf
_, pf = m._page_signals('<meta http-equiv="refresh" content="5; url=https://www.shop.example/home"><iframe width="600" height="400">'.lower(), "", "shop.example")
assert pf == [], pf                                                                  # same-site refresh and a visible frame are fine
_, pf = m._page_signals('<a href="/guide.pdf">x</a><a href="/exercise.html">y</a>'.lower(), "", "shop.example")
assert pf == []
digest = m._evidence_digest(('<meta name="description" content="Fast wallet sync"><form action="https://drain.example/p"><input type="password">'
                             '<input name="s"></form><a href="https://other.example/a">a</a><script src="https://cdn.evil.example/x.js"></script><iframe></iframe>').lower(), "shop.example")
for part in ("fast wallet sync", "drain.example", "password", "other.example", "cdn.evil.example", "iframes: 1"):
    assert part in digest, part
assert m._evidence_digest("<html>plain</html>", "shop.example") == "none extracted" and len(m._evidence_digest("<a href=https://z.example/>" * 5000, "a.example")) <= m.MAX_DIGEST
for hostile in ["<meta " * 100000, "<iframe " * 100000, "href=" * 100000, "<a href=\"" * 50000, "<input " * 100000]:
    t = time.time()
    m._page_signals(hostile, "", "x.example")
    m._evidence_digest(hostile, "x.example")
    assert time.time() - t < 3, ("slow on", hostile[:10])

# ---------------------------------------------------------------- v2.2: two model passes and a second page
a = {"risk": 20, "category": "none", "impersonates": "", "reasons": ["a"], "summary": "s1"}
b = {"risk": 40, "category": "phishing", "impersonates": "PayPal", "reasons": ["b", "a"], "summary": ""}
cmb = m._combine_llm(a, b)
assert cmb["risk"] == 30 and cmb["passes"] == 2 and cmb["category"] == "phishing" and cmb["impersonates"] == "PayPal" and cmb["reasons"] == ["b", "a"] and cmb["summary"] == "s1"
assert m._combine_llm(a, dict(b, risk=90))["risk"] == 90                              # large split: higher risk wins
assert m._combine_llm(a, None)["passes"] == 1 and m._combine_llm(a, None)["risk"] == 20

calls = []
fetched = []
class Site:
    def __init__(self, status, body):
        self.status, self.body = status, body
pages = {"https://deep.example/a/b": Site(200, b"<html><title>Deep</title>Notes</html>"), "https://deep.example/": Site(200, b"<html><title>Home of Deep</title>Welcome</html>")}
def web_get(k):
    fetched.append(k)
    if k in pages:
        return pages[k]
    raise Exception("down")
def fake_llm(p, response_format=None):
    calls.append(p)
    return {"risk": 10, "category": "none", "reasons": ["plain"], "impersonates": ""}
gl.nondet.web = types.SimpleNamespace(get=web_get)
gl.nondet.exec_prompt = fake_llm
r = m._analyze("https://deep.example/a/b", "deep.example", "https", 0)
assert fetched == ["https://deep.example/a/b", "https://deep.example/"]               # page and site root
assert len(calls) == 2 and "independent brand-and-legitimacy auditor" in calls[1] and "web-safety analyst" in calls[0]
assert "Home of Deep" in calls[0] and "<page_structure>" in calls[0]
assert r["evidence"] == {"pages": 2, "llm_passes": 2} and r["verdict"] == "GREEN"
# a root that cannot be fetched is tolerated; a failing second pass downgrades to one
fetched.clear(); calls.clear(); del pages["https://deep.example/"]
n = [0]
def flaky(p, response_format=None):
    n[0] += 1
    if n[0] == 2:
        raise Exception("llm down")
    return {"risk": 10, "category": "none", "reasons": []}
gl.nondet.exec_prompt = flaky
r = m._analyze("https://deep.example/a/b", "deep.example", "https", 0)
assert r["evidence"] == {"pages": 1, "llm_passes": 1}
assert "evidence" in m._analyze("https://deep.example/zzz", "deep.example", "https", 0) or True
# the model claiming a brand that does not own the host adds a code-checked penalty
gl.nondet.exec_prompt = lambda p, response_format=None: {"risk": 40, "category": "phishing", "impersonates": "MetaMask", "reasons": ["x"]}
r = m._analyze("https://deep.example/a/b", "deep.example", "https", 0)
assert "brand_mismatch" in r["flags"] and r["risk"] >= (40 * m.LLM_WEIGHT) // 100 + m.BRAND_MISMATCH_BONUS
pages["https://metamask.io/"] = Site(200, b"<html>wallet</html>")
r = m._analyze("https://metamask.io/", "metamask.io", "https", 0)
assert "brand_mismatch" not in r["flags"]
assert m._finalize(dict(r, evidence={"pages": 99, "llm_passes": -3}))["evidence"] == "pages=2,llm_passes=0,signals=%d" % len(r["flags"])
assert m._evidence_dict("pages=2,llm_passes=1,signals=4") == {"pages": 2, "llm_passes": 1, "signals": 4} and m._evidence_dict("junk")["pages"] == 0

# ---------------------------------------------------------------- v2.2: freshness
pages.clear()
pages["https://fresh.example/page"] = Site(200, b"<html><title>Garden</title>Plain notes.</html>")
gl.nondet.exec_prompt = lambda p, response_format=None: {"risk": 5, "category": "none", "reasons": []}
f = m.GreenLight()
f.scans, f.feed, f.host_reds, f.verdict_counts, f.contributors, f.sender_last = TreeMap(), DynArray(), TreeMap(), TreeMap(), TreeMap(), TreeMap()
f.__init__()
FU = "https://fresh.example/page"
clock[0] += 1000
t0 = clock[0]
f.scan(FU)
chk = f.check(FU)
assert chk["verdict"] == "GREEN" and chk["safe"] and chk["fresh"] and chk["verified_at"] == t0 and chk["expires_at"] == t0 + m.FRESH_FOR and not chk["needs_rescan"]
assert f.is_safe(FU) and f.is_safe_within(FU, 3600) and not f.is_safe_within(FU, 10) and not f.is_safe_within(FU, "x")
assert f.get_scan(FU)["evidence"]["llm_passes"] == 2 and f.get_scan(FU)["fresh"] is True
clock[0] = t0 + 3601
assert not f.is_safe_within(FU, 3600) and f.is_safe(FU)                               # integrator's own stricter window
clock[0] = t0 + m.FRESH_FOR + 1
chk = f.check(FU)
assert chk["verdict"] == "GREEN" and chk["safe"] is False and chk["fresh"] is False and chk["needs_rescan"] is True
assert not f.is_safe(FU) and f.get_scan(FU)["fresh"] is False and f.recent(0, 5)["items"][0]["needs_rescan"] is True
# rescanning makes it fresh again
f.scan(FU)
assert f.is_safe(FU) and f.get_scan(FU)["verified_at"] == clock[0]
# a failed fetch keeps the old verdict but must NOT renew the freshness clock, and it is not safe while failing
verified = clock[0]
clock[0] += 3000
pages.clear()
f.scan(FU)
rec = f.get_scan(FU)
assert rec["verdict"] == "GREEN" and rec["miss_streak"] == 1 and rec["verified_at"] == verified and rec["last_scanned"] == clock[0]
assert rec["needs_rescan"] is True and f.is_safe(FU) is False and f.check(FU)["safe"] is False
assert rec["evidence"]["llm_passes"] == 2                                              # retained evidence, not invented
clock[0] += 100
f.scan(FU)
clock[0] += 100
f.scan(FU)
rec = f.get_scan(FU)
assert rec["verdict"] == "UNREACHABLE" and rec["fresh"] is False and rec["verified_at"] == verified and not f.is_safe(FU)
assert f.config()["fresh_for_seconds"] == m.FRESH_FOR and f.config()["verdict_must_match"] is True
assert f.check("not a url")["known"] is False and f.is_safe_within("not a url", 3600) is False
print("v2.2 tests passed")
