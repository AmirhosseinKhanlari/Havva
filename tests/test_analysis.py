import os
import plistlib
import tempfile
import zipfile
from pathlib import Path

os.environ.setdefault("CVE_LOOKUP", "0")  # keep analysis tests offline (no OSV calls)

from pipeline.analysis import analyze_ipa, analyze_one
from pipeline.db import Database
from pipeline.models import WorkState


def _make_ipa(path: Path) -> None:
    info = {
        "CFBundleIdentifier": "com.test.app",
        "CFBundleExecutable": "Test",
        "CFBundleShortVersionString": "1.2.3",
        "NSCameraUsageDescription": "We need the camera",
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSPinnedDomains": {"api.test.com": {}},
            "NSExceptionDomains": {"legacy.test.com": {}},
        },
    }
    fake_bin = (b"garbage\x00\xf9\xfe"  # non-utf8 bytes to exercise binary-safe strings
                b"https://api.example.com/v1/login "
                b"AKIAABCDEFGHIJKLMNOP "
                b"_strcpy _memcpy CC_MD5 UIWebView "  # insecure-API rule hits
                b"SecTrustEvaluate DCAppAttestService TrustKit\x00")
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/Test.app/Info.plist", plistlib.dumps(info))
        z.writestr("Payload/Test.app/Test", fake_bin)
        z.writestr("Payload/Test.app/Frameworks/TrustKit.framework/TrustKit", b"x")
        z.writestr("Payload/Test.app/Frameworks/Alamofire.framework/Alamofire", b"x")


def test_analyze_ipa_extracts_all_sections():
    d = Path(tempfile.mkdtemp())
    ipa = d / "test.decrypted.ipa"
    _make_ipa(ipa)
    r = analyze_ipa(str(ipa))

    assert r["info_plist"]["summary"]["CFBundleIdentifier"] == "com.test.app"
    assert "NSCameraUsageDescription" in r["info_plist"]["permissions"]

    assert r["ats"]["present"] is True
    assert r["ats"]["allows_arbitrary_loads"] is True
    assert "api.test.com" in r["ats"]["pinned_domains"]
    assert "legacy.test.com" in r["ats"]["exception_domains"]

    assert "TrustKit.framework" in r["frameworks"]["embedded"]
    assert "Alamofire.framework" in r["frameworks"]["embedded"]
    assert "TrustKit" in r["sdks"]
    assert "Alamofire" in r["sdks"]

    assert "SecTrustEvaluate" in r["crypto_hints"]
    assert "DCAppAttestService" in r["crypto_hints"]

    labels = {f["type"] for f in r["secrets"]["findings"]}
    assert "AWS access key" in labels
    assert any("api.example.com" in u for u in r["secrets"]["urls"])

    assert len(r["file_tree"]) >= 4

    # new deep-scan sections (gaps closed vs MobSF)
    assert "binary_protections" in r and isinstance(r["binary_protections"], dict)
    # insecure-C + weak-hash + webview tokens are in the fake binary
    cats = {f["category"] for f in r["insecure_apis"]}
    assert "Insecure C functions" in cats
    assert "Weak hashing (MD5/SHA1)" in cats
    assert r["security_score"]["grade"] in ("A", "B", "C", "D", "F")
    assert 0 <= r["security_score"]["score"] <= 100


def test_email_filtering_drops_noise():
    from pipeline.analysis import emails_domains
    blob = (b"contact@real.com support@company.io logo@2x.png %@.svc.com "
            b"api.myservice.net cdn.test.org")
    ed = emails_domains(blob)
    assert "contact@real.com" in ed["emails"]
    assert "support@company.io" in ed["emails"]
    assert not any("2x.png" in e for e in ed["emails"])
    assert not any("%" in e for e in ed["emails"])
    assert "api.myservice.net" in ed["domains"]


def test_analyze_one_persists_to_db():
    d = Path(tempfile.mkdtemp())
    ipa = d / "test.decrypted.ipa"
    _make_ipa(ipa)
    db = Database(d / "t.db")
    db.upsert_app("999", "us", bundle_id="com.test.app")
    db.save_acquisition("999", WorkState.POSITIVE, ipa_path=str(ipa))

    report = analyze_one(db, "999")
    assert report["info_plist"]["summary"]["CFBundleIdentifier"] == "com.test.app"

    row = db.get_analysis("999")
    assert row is not None
    import json
    assert json.loads(row["sdks"]) and "TrustKit" in json.loads(row["sdks"])


def test_analyze_one_requires_acquisition():
    db = Database(Path(tempfile.mkdtemp()) / "t.db")
    db.upsert_app("nope", "us")
    try:
        analyze_one(db, "nope")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "not acquired" in str(e)


# ---- audit fixes: evidence blob / symbol matching / scoring / secrets --------

def test_sym_hits_whole_symbol_boundaries():
    from pipeline.analysis import _sym_hits
    ev = (b"                 U _getschedparam\n U _gets\n U _CC_MD5\n U _random_x\n"
          b" U _rand\n_OBJC_CLASS_$_UIWebView\n U _objc_msgSend$foo\n")
    hits = _sym_hits(ev, [b"_gets", b"CC_MD5", b"_random", b"_rand", b"UIWebView", b"_strcpy"])
    assert hits == ["CC_MD5", "UIWebView", "_gets", "_rand"]
    assert _sym_hits(b" U _getschedparam\n", [b"_gets"]) == []     # no substring collision
    assert _sym_hits(b" U _random_x\n", [b"_random"]) == []
    assert _sym_hits(b"", [b"_gets"]) == []


def test_symbol_rules_fire_on_nm_output_not_only_strings():
    from pipeline.analysis import binary_type, crypto_hints, insecure_apis
    nm = (b"0000000100000000 T _main\n                 U _objc_msgSend\n"
          b"                 U _CC_MD5\n                 U _strcpy\n"
          b"                 U _kSecAttrAccessibleAlways\n                 U _SecTrustEvaluate\n")
    assert binary_type({}, nm) == "Objective-C"
    assert binary_type({}, b" U _swift_release\n") == "Swift"
    assert binary_type({}, b"just strings") == "unknown"
    cats = {f["category"]: f["matches"] for f in insecure_apis(nm)}
    assert cats["Weak hashing (MD5/SHA1)"] == ["CC_MD5"]
    assert cats["Insecure C functions"] == ["_strcpy"]
    assert cats["Weak Keychain accessibility (kSecAttrAccessibleAlways)"] == ["kSecAttrAccessibleAlways"]
    assert "SecTrustEvaluate" in crypto_hints(nm)
    assert "kSecAttrAccessibleAlways" in crypto_hints(nm)


def test_sdk_fingerprints_do_not_fire_on_bare_english_words():
    from pipeline.analysis import fingerprint_sdks
    blob = b"Adjust Brightness\nSplit view\nBranch office\nHeap size\nLottie\nAmplitude\nIntercom\nSingular"
    found = fingerprint_sdks({"embedded": [], "linked": []}, blob)
    assert not ({"Adjust", "Split", "Branch", "Heap", "Lottie", "Amplitude", "Intercom", "Singular"} & set(found))
    blob2 = b"ADJConfig AMPAmplitude SingularSDK ITMIntercom LOTAnimationView BNCConfig"
    found2 = fingerprint_sdks({"embedded": [], "linked": []}, blob2)
    assert {"Adjust", "Amplitude", "Singular", "Intercom", "Lottie", "Branch"} <= set(found2)


def test_security_score_na_when_no_binary_examined():
    from pipeline.analysis import security_score
    s = security_score({"binary_examined": False, "insecure_apis": [{"category": "x", "severity": "high"}]})
    assert s["score"] is None and s["grade"] == "n/a" and s["deductions"] == []
    ok = security_score({"binary_examined": True, "insecure_apis": []})
    assert ok["score"] == 100 and ok["grade"] == "A"


def test_analyze_ipa_without_executable_reports_na():
    d = Path(tempfile.mkdtemp())
    ipa = d / "noexe.decrypted.ipa"
    with zipfile.ZipFile(ipa, "w") as z:
        z.writestr("Payload/X.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "c.x"}))
        z.writestr("Payload/X.app/asset.png", b"png")
    r = analyze_ipa(str(ipa))
    assert r["binary_examined"] is False
    assert r["security_score"]["score"] is None and r["security_score"]["grade"] == "n/a"
    assert r["binary_type"] == "unknown"


def test_analyze_ipa_marks_binary_examined():
    d = Path(tempfile.mkdtemp())
    ipa = d / "test.decrypted.ipa"
    _make_ipa(ipa)
    r = analyze_ipa(str(ipa))
    assert r["binary_examined"] is True
    assert r["security_score"]["score"] is not None


def test_public_keys_are_info_and_ips_filtered():
    from pipeline.analysis import scan_secrets
    blob = (b"AIzaSyA1234567890123456789012345678901234 pk_live_abcdefghijklmnopqrstu "
            b"v2.3.0.0 1.2.0.0 10.0.0.1 192.168.1.5 1.2.3.4.5 a1.2.3.4 AKIAABCDEFGHIJKLMNOP")
    f = scan_secrets(blob)["findings"]
    sev = {x["type"]: x["severity"] for x in f}
    assert sev["Google API key"] == "info"
    assert sev["Stripe pub key"] == "info"
    assert sev["AWS access key"] == "high"
    assert sev["Hardcoded IP"] == "low"
    ips = sorted(x["value"] for x in f if x["type"] == "Hardcoded IP")
    assert ips == ["10.0.0.1", "192.168.1.5"]
    # info findings never deduct from the score
    from pipeline.analysis import security_score
    s = security_score({"binary_examined": True, "secrets": {"findings": f}})
    secret_cuts = [d for d in s["deductions"] if "secret" in d["reason"]]
    assert len(secret_cuts) == 1 and "1 high-severity secret" in secret_cuts[0]["reason"]


# ---- iap_static precision ----------------------------------------------------

def test_iap_static_sk2_needs_strong_or_two_generic_tokens():
    from pipeline import iap_static
    one = iap_static.analyze(b"SKPaymentQueue SubscriptionInfo")
    assert one["sk2_strong"] is False and one["storekit_version"] == "1"
    assert one["offering"] == "latent"
    two = iap_static.analyze(b"SubscriptionInfo RenewalInfo")
    assert two["sk2_strong"] is True and two["storekit_version"] == "2"
    assert two["offering"] == "code-detected"
    jws = iap_static.analyze(b"jwsRepresentation")
    assert jws["sk2_strong"] is True and jws["validation"]["location"] == "storekit2-jws"
    lone_apptx = iap_static.analyze(b"AppTransaction")
    assert lone_apptx["sk2_strong"] is False and lone_apptx["offering"] == "none"


def test_iap_static_sk1_finding_wording_and_storekit_cfg():
    from pipeline import iap_static
    r = iap_static.analyze(b"SKPaymentQueue SKPaymentTransaction", app_store_has_iap=True,
                           bundle_files=["Payload/A.app/Products.storekit", "Payload/A.app/x.png"])
    cats = [f["category"] for f in r["findings"]]
    assert any("own backend cannot be excluded" in c for c in cats)
    assert any(".storekit" in c for c in cats)
    assert r["storekit_config_files"] == ["Payload/A.app/Products.storekit"]


def test_analyze_ipa_passes_full_namelist_for_storekit_cfg():
    d = Path(tempfile.mkdtemp())
    ipa = d / "sk.decrypted.ipa"
    info = {"CFBundleIdentifier": "c.sk", "CFBundleExecutable": "SK"}
    with zipfile.ZipFile(ipa, "w") as z:
        z.writestr("Payload/SK.app/Info.plist", plistlib.dumps(info))
        z.writestr("Payload/SK.app/SK", b"SKPaymentQueue SKProductsRequest")
        z.writestr("Payload/SK.app/Config/Products.storekit", b"{}")
    r = analyze_ipa(str(ipa))
    assert r["iap"]["storekit_config_files"] == ["Payload/SK.app/Config/Products.storekit"]


# ---- storage_scan -------------------------------------------------------------

def test_storage_scan_continues_past_unreadable_sqlite():
    import sqlite3
    from pipeline.storage_scan import scan_container, verdict_of
    root = Path(tempfile.mkdtemp())
    (root / "Library").mkdir()
    (root / "Library/enc.sqlite").write_bytes(b"\x00\xffSQLCipher-garbage" * 40)   # not a DB
    con = sqlite3.connect(root / "Library/real.sqlite")
    con.execute("CREATE TABLE users (id INTEGER, userPassword TEXT, note TEXT)")
    con.execute("INSERT INTO users VALUES (1, 'hunter2', 'mail me at a@b.co or see logo@2x.png')")
    con.commit(); con.close()
    findings, stores = scan_container(root)
    types = [f["type"] for f in findings]
    assert any("not readable" in t for t in types)
    assert any("sensitive column" in t and "userPassword" in t for t in types)
    assert all(f["severity"] == "info" for f in findings if "not readable" in f["type"])
    assert verdict_of(findings)[0] == "credentials_exposed"   # userPassword column is a credential key


def test_storage_sensitive_key_boundaries_and_email_noise():
    from pipeline.storage_scan import _SENSITIVE_KEY, _find_email, verdict_of
    assert not _SENSITIVE_KEY.search("secretary")
    assert not _SENSITIVE_KEY.search("pinned") and not _SENSITIVE_KEY.search("spinning")
    assert not _SENSITIVE_KEY.search("ssnumber")
    for ok in ("clientSecret", "client_secret", "userPassword", "pin", "ssn", "PIN_CODE", "cvv2", "passwords"):
        assert _SENSITIVE_KEY.search(ok), ok
    assert _find_email("logo@2x.png icon@3x %@.com") is None
    assert _find_email("reach me: real@example.org") == "real@example.org"
    assert verdict_of([{"severity": "low"}])[0] == "data_only"
    assert verdict_of([{"severity": "info"}])[0] == "data_only"
    assert verdict_of([])[0] == "clean"


# ---- ats_runtime --------------------------------------------------------------

def _ats_env(monkeypatch, probe):
    import pipeline.ats_runtime as ar
    d = Path(tempfile.mkdtemp())
    monkeypatch.setattr(ar, "_cache", lambda: d / "ats_cache.json")
    monkeypatch.setattr(ar, "_nscurl_default", probe)
    monkeypatch.setenv("ATS_LOOKUP", "1")
    return ar


def test_ats_unreachable_hosts_not_cached_not_tested(monkeypatch):
    ar = _ats_env(monkeypatch, lambda d: None)
    res = ar.assess({}, ["dead.example"], [{"domain": "dead.example", "insecure_http": True,
                                            "min_tls": "TLSv1.2", "forward_secrecy": True}], False)
    assert res["n_tested"] == 0 and res["n_unreachable"] == 1
    assert res["verdict"] == "untested"           # never "justified" from unreachable hosts
    assert ar._load() == {}                       # None is never cached


def test_ats_weakening_labels(monkeypatch):
    ar = _ats_env(monkeypatch, lambda d: True)
    exc = [{"domain": "weak.example", "insecure_http": True, "min_tls": "TLSv1.2", "forward_secrecy": True},
           {"domain": "ct.example", "insecure_http": False, "min_tls": "TLSv1.2", "forward_secrecy": True}]
    res = ar.assess({}, ["weak.example", "ct.example", "plain.example"], exc, False)
    kinds = {u["domain"]: u["kind"] for u in res["unnecessary_weakenings"]}
    assert kinds == {"weak.example": "exception"}    # the neutral exception is not flagged
    eff = {c["domain"]: c["exception_effect"] for c in res["domains"]}
    assert eff == {"weak.example": "weakening", "ct.example": "neutral", "plain.example": None}
    assert res["verdict"] == "unnecessary_weakening"
    # Under NSAllowsArbitraryLoads=YES a scoped exception that re-enables ATS strengthens.
    res2 = ar.assess({}, ["ct.example", "plain.example"], exc[1:], True)
    assert res2["strengthening_exceptions"] == ["ct.example"]
    assert [u["domain"] for u in res2["unnecessary_weakenings"]] == ["plain.example"]
    assert ar._load() == {"weak.example": True, "ct.example": True, "plain.example": True}


def test_ats_justified_only_when_reachable_host_fails(monkeypatch):
    ar = _ats_env(monkeypatch, lambda d: False)
    res = ar.assess({}, ["legacy.example"], [{"domain": "legacy.example", "insecure_http": False,
                                              "min_tls": "TLSv1.0", "forward_secrecy": True}], False)
    assert res["verdict"] == "justified" and res["n_tested"] == 1


# ---- cve ----------------------------------------------------------------------

def test_cve_repo_mapping_is_exact():
    from pipeline.cve import _repo_for
    assert _repo_for("Alamofire.framework") == "Alamofire/Alamofire"
    assert _repo_for("AlamofireImage") == "Alamofire/AlamofireImage"
    assert _repo_for("SDWebImageSwiftUI") == "SDWebImage/SDWebImageSwiftUI"
    assert _repo_for("gRPC-C++") == "grpc/grpc" and _repo_for("gRPC-Core") == "grpc/grpc"
    assert _repo_for("MyAlamofireWrapper") is None       # never by substring


def test_cve_severity_from_cvss_and_no_version(monkeypatch):
    from pipeline import cve
    assert cve.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cve.cvss3_base_score("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N") == 5.9
    assert cve.severity_from_score(9.8) == "critical"
    assert cve.severity_from_score(7.5) == "high"
    assert cve.severity_from_score(5.9) == "medium"
    assert cve.severity_from_score(3.3) == "low"
    assert cve.osv_severity({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"}]}) == "low"
    assert cve.osv_severity({"database_specific": {"severity": "MODERATE"}}) == "medium"
    assert cve.osv_severity({}) == "unknown"
    # curated advisories need a known version; the fabricated id is gone
    assert cve._curated_for("AFNetworking", "") == []
    ids = [a["id"] for a in cve._curated_for("AFNetworking", "2.5.0")]
    assert ids == ["CVE-2015-1840"]
    monkeypatch.setenv("CVE_LOOKUP", "0")
    monkeypatch.setattr(cve, "_cache_path", lambda: Path(tempfile.mkdtemp()) / "c.json")
    out = cve.enrich([{"name": "AFNetworking", "version": ""}, {"name": "AFNetworking", "version": "2.5.0"},
                      {"name": "Whatever", "version": "1.0"}])
    assert out[0]["cves"] == [] and out[0]["cve_status"] == "version unknown"
    assert out[1]["cve_status"] == "checked" and out[1]["cves"]
    assert out[2]["cve_status"] == "unmapped"


def test_cve_osv_non_2xx_not_cached(monkeypatch):
    from pipeline import cve

    class _R:
        ok, status_code = False, 429
        def json(self): return {}

    import requests
    monkeypatch.setattr(requests, "post", lambda *a, **k: _R())
    cache = {}
    assert cve._osv_swift("Alamofire/Alamofire", "5.0.0", cache) == []
    assert cache == {}

    class _OK:
        ok, status_code = True, 200
        def json(self):
            return {"vulns": [{"id": "GHSA-x", "summary": "s",
                               "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                               "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "5.1.0"}]}]}]}]}
    monkeypatch.setattr(requests, "post", lambda *a, **k: _OK())
    v = cve._osv_swift("Alamofire/Alamofire", "5.0.0", cache)
    assert v[0]["severity"] == "critical" and v[0]["fixed"] == "5.1.0"
    assert "pkg:swift/github.com/Alamofire/Alamofire@5.0.0" in cache
