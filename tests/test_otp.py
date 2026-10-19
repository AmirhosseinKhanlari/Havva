"""Unit tests for the pure OTP parsing/selection (no Gmail / network)."""
from pipeline.otp import (CLOCK_SKEW_MS, _candidate_messages, _extract_code,
                          _first_code, _select_message)


def test_google_g_code():
    assert _extract_code("G-456789 is your Google verification code.") == "456789"


def test_code_near_keyword():
    assert _extract_code("Your verification code is 123456. Do not share.") == "123456"
    assert _extract_code("Tinder code: 4821") == "4821"
    assert _extract_code("Enter OTP 7788 to continue") == "7788"


def test_standalone_prefers_six_digits():
    assert _extract_code("Enter 998877 to continue, ref 55") == "998877"


def test_skips_four_digit_year():
    # keyword path wins over the 2026 year
    assert _extract_code("Copyright 2026 Example. Code 135790.") == "135790"
    # pure standalone: the year is skipped, the 6-digit code is taken
    assert _extract_code("(c) 2026  888999") == "888999"


def test_none_when_no_code():
    assert _extract_code("No numbers here") is None
    assert _extract_code("") is None
    assert _extract_code(None) is None


def test_real_google_voice_forward_body():
    body = ("New text message from +1 650 555 0101\n\n"
            "Your Lyft code is 904152. Reply STOP to unsubscribe.\n\n"
            "To respond to this text message, reply to this email.")
    assert _extract_code(body) == "904152"


def test_select_newest_after():
    msgs = [{"internalDate": "100", "from": "a", "body": "x"},
            {"internalDate": "300", "from": "b", "body": "y"},
            {"internalDate": "50", "from": "c", "body": "z"}]
    assert _select_message(msgs, 60)["internalDate"] == "300"


def test_select_filters_out_before_after():
    # older than `after` by more than the clock-skew margin -> excluded
    msgs = [{"internalDate": "100", "from": "a", "body": "x"}]
    assert _select_message(msgs, 200 + CLOCK_SKEW_MS) is None


def test_select_sender_filter():
    msgs = [{"internalDate": "300", "from": "spam@x.com", "body": "y"},
            {"internalDate": "200", "from": "notify@voice.google.com", "body": "z"}]
    pick = _select_message(msgs, 60, sender_filter="voice.google.com")
    assert pick["internalDate"] == "200"


def test_select_empty():
    assert _select_message([], 0) is None


# ---- audit fixes: year filter on the keyword path, "pin", newest-first walk ----

def test_keyword_path_skips_four_digit_year():
    assert _extract_code("Use 1234 to verify. Sent at 2024") == "1234"
    # keyword directly before a year: skip it and keep looking
    assert _extract_code("Your code (c) 2024: 5566") == "5566"
    assert _extract_code("Verification sent 2025") is None


def test_pin_keyword():
    assert _extract_code("Your account PIN is 4821.") == "4821"


def test_first_code_walks_past_unrelated_newer_message():
    msgs = [{"internalDate": "300", "from": "voice", "body": "Thanks for signing up!"},
            {"internalDate": "200", "from": "voice", "body": "Your code is 778899"}]
    # the newest message has no code; the older one must still be used
    assert _first_code(msgs, 100) == "778899"
    # ...while _select_message still reports the newest for callers that need it
    assert _select_message(msgs, 100)["internalDate"] == "300"


def test_first_code_prefers_newest_with_code():
    msgs = [{"internalDate": "200", "from": "v", "body": "code 111111"},
            {"internalDate": "300", "from": "v", "body": "code 222222"}]
    assert _first_code(msgs, 0) == "222222"


def test_clock_skew_margin_on_after():
    after = 1_000_000
    msgs = [{"internalDate": str(after - CLOCK_SKEW_MS + 1), "from": "v", "body": "code 4455"}]
    assert _first_code(msgs, after) == "4455"
    too_old = [{"internalDate": str(after - CLOCK_SKEW_MS - 1), "from": "v", "body": "code 4455"}]
    assert _first_code(too_old, after) is None
    assert _candidate_messages(too_old, after) == []
