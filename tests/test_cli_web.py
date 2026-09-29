import sys

import pipeline.cli as cli


def test_web_subcommand_registered(monkeypatch):
    called = {}
    import pipeline.web.__main__ as webmain
    monkeypatch.setattr(webmain, "main", lambda: called.setdefault("ran", True))
    monkeypatch.setattr(sys, "argv", ["pipeline", "web"])
    rc = cli.main()
    assert called.get("ran") is True
    assert rc == 0
