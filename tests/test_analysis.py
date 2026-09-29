import plistlib
import tempfile
import zipfile
from pathlib import Path

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
