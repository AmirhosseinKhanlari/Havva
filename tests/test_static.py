"""Tests for the static classifier's pure detection logic."""

from pipeline.models import PinLayer, TlsStack
from pipeline.static_classify import ExtractedApp, classify


def test_trustkit_library_pinning():
    app = ExtractedApp(symbols="_OBJC_CLASS_$_TSKPinningValidator\nTrustKit")
    p = classify(app)
    assert p.pins_flag and p.pin_layer is PinLayer.L3_LIBRARY
    assert p.pin_library == "TrustKit"


def test_native_pinning_needs_two_signals():
    one = classify(ExtractedApp(symbols="SecTrustEvaluate"))
    assert not one.pins_flag  # single native API is not enough
    two = classify(ExtractedApp(symbols="SecTrustEvaluateWithError\nSecTrustCopyPublicKey"))
    assert two.pins_flag and two.pin_layer is PinLayer.L4_SECTRUST


def test_boringssl_counts_as_native_pinning():
    p = classify(ExtractedApp(strings="SSL_set_custom_verify present"))
    assert p.pins_flag and p.pin_layer is PinLayer.L4_SECTRUST


def test_ats_nspinned_domains():
    app = ExtractedApp(info_plist={"NSAppTransportSecurity": {"NSPinnedDomains": {"x": {}}}})
    p = classify(app)
    assert p.pins_flag and p.pin_layer is PinLayer.L1_ATS


def test_no_pinning_when_nothing_matches():
    p = classify(ExtractedApp(strings="just some app strings"))
    assert not p.pins_flag and p.pin_layer is PinLayer.NONE


def test_flutter_tls_stack_detected():
    p = classify(ExtractedApp(frameworks=["Flutter.framework"], strings="io.flutter"))
    assert p.tls_stack is TlsStack.FLUTTER


def test_library_pinning_wins_over_native():
    # An app with both a library and native APIs is classified at the library layer.
    app = ExtractedApp(symbols="AFSecurityPolicy\nSecTrustEvaluate\nSecTrustCopyPublicKey")
    p = classify(app)
    assert p.pin_layer is PinLayer.L3_LIBRARY and p.pin_library == "AFNetworking"


def test_appattest_from_symbols_and_entitlement():
    a = classify(ExtractedApp(symbols="DCAppAttestService"))
    assert a.appattest_flag
    b = classify(ExtractedApp(entitlements={
        "com.apple.developer.devicecheck.appattest-environment": "production"}))
    assert b.appattest_flag


def test_anti_tamper_and_jailbreak_hints():
    app = ExtractedApp(strings="/Applications/Cydia.app\nIOSSecuritySuite\nPT_DENY_ATTACH")
    p = classify(app)
    assert p.anti_tamper_hints and p.jailbreak_detection_hints and p.anti_debug_hints


def test_networkextension_flag():
    p = classify(ExtractedApp(entitlements={
        "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"]}))
    assert p.networkextension_flag


def test_matched_patterns_recorded():
    p = classify(ExtractedApp(symbols="TSKPinningValidator"))
    assert any(k.startswith("pinlib:") for k in p.matched_patterns)
