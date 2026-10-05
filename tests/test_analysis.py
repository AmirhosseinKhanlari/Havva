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
