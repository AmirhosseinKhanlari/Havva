"""Tests for the static classifier's pure detection logic."""

from pipeline.models import PinLayer, TlsStack
from pipeline.static_classify import ExtractedApp, classify


def test_trustkit_library_pinning():
    app = ExtractedApp(symbols="_OBJC_CLASS_$_TSKPinningValidator\nTrustKit")
    p = classify(app)
    assert p.pins_flag and p.pin_layer is PinLayer.L3_LIBRARY
    assert p.pin_library == "TrustKit"
    # TrustKit is config-driven, so presence counts, but it is recorded separately.
    assert p.matched_patterns["pin_layer_detail"] == ["l3_library_trustkit"]
    assert p.matched_patterns["tls_libs"] == ["TrustKit"]


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


def test_library_presence_alone_is_not_pinning():
    # Alamofire / AFNetworking ship pinning support that most apps never
    # configure: presence is informational (tls_libs), not pins_flag.
    af = classify(ExtractedApp(symbols="AFSecurityPolicy\nAFHTTPSessionManager"))
    assert not af.pins_flag and af.pin_layer is PinLayer.NONE
    assert af.matched_patterns["tls_libs"] == ["AFNetworking"]
    assert not any(k.startswith("pinlib:") for k in af.matched_patterns)
    al = classify(ExtractedApp(frameworks=["Alamofire.framework"],
                               symbols="$s9Alamofire17ServerTrustManagerC"))
    assert not al.pins_flag
    assert al.matched_patterns["tls_libs"] == ["Alamofire"]


def test_alamofire_pins_only_with_evaluator_config_in_main_binary():
    cfg = classify(ExtractedApp(
        frameworks=["Alamofire.framework"],
        symbols="$s9Alamofire32PinnedCertificatesTrustEvaluatorC"))
    assert cfg.pins_flag and cfg.pin_layer is PinLayer.L3_LIBRARY and cfg.pin_library == "Alamofire"
    assert cfg.matched_patterns["pin_layer_detail"] == ["l3_library_alamofire"]
    # AF4 mangled enum case counts too.
    af4 = classify(ExtractedApp(
        frameworks=["Alamofire.framework"],
        symbols="$s9Alamofire17ServerTrustPolicyO15pinCertificatesyACSaySo17SecCertificateRefaG"))
    assert af4.pins_flag and af4.pin_library == "Alamofire"
    # The evaluator class inside the Alamofire framework binary itself (not the
    # main executable) does not count: every Alamofire build carries it.
    fw_only = classify(ExtractedApp(
        frameworks=["Alamofire.framework"],
        main_symbols="$s9Alamofire7SessionC", main_strings="app strings",
        symbols="$s9Alamofire7SessionC\n$s9Alamofire32PinnedCertificatesTrustEvaluatorC"))
    assert not fw_only.pins_flag
    assert fw_only.matched_patterns["tls_libs"] == ["Alamofire"]
    # Statically linked Alamofire (no .framework): the evaluator classes are in
    # the main binary by linkage alone, so bundled pinned material is required.
    static_nocert = classify(ExtractedApp(
        strings="_TtC9Alamofire32PinnedCertificatesTrustEvaluator\nAlamofire"))
    assert not static_nocert.pins_flag
    assert "pinlib_candidate:Alamofire" in static_nocert.matched_patterns
    static_cert = classify(ExtractedApp(
        strings="_TtC9Alamofire32PinnedCertificatesTrustEvaluator\nAlamofire",
        cert_files=["api.der"]))
    assert static_cert.pins_flag and static_cert.pin_library == "Alamofire"
    assert "cert:api.der" in static_cert.matched_patterns["pinlib:Alamofire"]


def test_afnetworking_pins_with_mode_or_policy_plus_certs():
    mode = classify(ExtractedApp(symbols="AFSecurityPolicy\nAFSSLPinningModePublicKey"))
    assert mode.pins_flag and mode.pin_library == "AFNetworking"
    no_certs = classify(ExtractedApp(strings="AFSecurityPolicy\nsetSecurityPolicy:"))
    assert not no_certs.pins_flag
    with_certs = classify(ExtractedApp(strings="AFSecurityPolicy\nsetSecurityPolicy:",
                                       cert_files=["api.cer"]))
    assert with_certs.pins_flag and with_certs.pin_library == "AFNetworking"
    assert "cert:api.cer" in with_certs.matched_patterns["pinlib:AFNetworking"]


def test_generic_pinned_material_only_without_tls_library():
    hand = classify(ExtractedApp(strings="pinnedCertificates"))
    assert hand.pins_flag and hand.pin_library == "generic-pinned-material"
    # "pinnedCertificates" is a property of Alamofire/AFNetworking themselves.
    lib = classify(ExtractedApp(symbols="AFSecurityPolicy", strings="pinnedCertificates"))
    assert not lib.pins_flag


def test_pinning_plugins_count_by_presence():
    p = classify(ExtractedApp(strings="react-native-ssl-pinning"))
    assert p.pins_flag and p.pin_library == "ReactNativeSSLPinning"
    bt = classify(ExtractedApp(strings="_TtC13BraintreeCore23BTAPIPinnedCertificates"))
    assert bt.pins_flag and bt.pin_library == "Braintree"


def test_library_pinning_wins_over_native():
    # An app with both a configured library and native APIs is classified at
    # the library layer.
    app = ExtractedApp(symbols="TSKPinningValidator\nSecTrustEvaluate\nSecTrustCopyPublicKey")
    p = classify(app)
    assert p.pin_layer is PinLayer.L3_LIBRARY and p.pin_library == "TrustKit"
    # ...but an unconfigured library does not shadow real native evidence.
    app2 = ExtractedApp(symbols="AFSecurityPolicy\nSecTrustEvaluate\nSecTrustCopyPublicKey")
    p2 = classify(app2)
    assert p2.pins_flag and p2.pin_layer is PinLayer.L4_SECTRUST and p2.pin_library == ""


def test_appattest_from_symbols_and_entitlement():
    ent_key = "com.apple.developer.devicecheck.appattest-environment"
    a = classify(ExtractedApp(symbols="DCAppAttestService"))
    assert a.appattest_flag and a.appattest_level == "referenced"
    assert a.matched_patterns["appattest_symbols"] == ["DCAppAttestService"]
    assert "appattest_entitlement" not in a.matched_patterns
    assert "appattest" in a.matched_patterns          # compat key kept
    b = classify(ExtractedApp(entitlements={ent_key: "production"}))
    assert b.appattest_flag and b.appattest_level == "production"
    assert b.matched_patterns["appattest_entitlement"] == [f"{ent_key}=production"]
    assert "appattest_symbols" not in b.matched_patterns
    c = classify(ExtractedApp(symbols="DCAppAttestService", entitlements={ent_key: "development"}))
    assert c.appattest_level == "adopted"
    assert set(c.matched_patterns) >= {"appattest", "appattest_symbols", "appattest_entitlement"}


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
