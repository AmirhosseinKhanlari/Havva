"""Unit tests for the pure OTP parsing/selection (no Gmail / network)."""
from pipeline.otp import _extract_code, _select_message


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
    msgs = [{"internalDate": "100", "from": "a", "body": "x"}]
    assert _select_message(msgs, 200) is None


def test_select_sender_filter():
    msgs = [{"internalDate": "300", "from": "spam@x.com", "body": "y"},
            {"internalDate": "200", "from": "notify@voice.google.com", "body": "z"}]
    pick = _select_message(msgs, 60, sender_filter="voice.google.com")
    assert pick["internalDate"] == "200"


def test_select_empty():
    assert _select_message([], 0) is None
