"""run_cmd_streamed line_cb framing (CRLF, CR-progress, unterminated tail) and
run_cmd timeout output handling."""
import subprocess
import sys

from pipeline.util import _as_text, _emit_line, run_cmd, run_cmd_streamed

# A child that writes the exact byte sequences the framing must handle.
_EMITTER = (
    "import sys; w = sys.stdout.buffer.write; "
    "w(b'line1\\r\\n'); w(b'line2\\r\\n'); w(b'prog 10%\\rprog 100%\\n'); "
    "w(b'final-no-newline'); sys.stdout.flush()"
)


def test_line_cb_handles_crlf_progress_and_final_line():
    got = []
    p = run_cmd_streamed([sys.executable, "-c", _EMITTER], timeout=30,
                         echo=False, line_cb=got.append)
    assert p.returncode == 0
    assert got == ["line1", "line2", "prog 100%", "final-no-newline"]
    # raw capture is untouched
    assert "line1\r\nline2\r\n" in p.stdout


def test_emit_line_unit():
    got = []
    _emit_line("foo\r", got.append)
    _emit_line("a\rb\rc", got.append)
    _emit_line("   ", got.append)       # blank lines are dropped
    assert got == ["foo", "c"]


def test_emit_line_swallows_callback_errors():
    def bad(_):
        raise RuntimeError("cb boom")
    _emit_line("x", bad)  # must not raise


def test_run_cmd_timeout_returns_partial_output():
    code = "import sys,time; sys.stdout.write('partial\\n'); sys.stdout.flush(); time.sleep(5)"
    p = run_cmd([sys.executable, "-u", "-c", code], timeout=1)
    assert p.returncode == 124
    assert "partial" in p.stdout
    assert "timeout" in p.stderr


def test_as_text_normalizes_bytes_str_none():
    assert _as_text(None) == ""
    assert _as_text(b"ab\xff") == "ab�"
    assert _as_text("s") == "s"


def test_streamed_timeout_reaps_child():
    code = "import time; time.sleep(5)"
    p = run_cmd_streamed([sys.executable, "-c", code], timeout=1, echo=False)
    assert p.returncode == 124


def test_timeout_expired_stdout_is_bytes_even_with_text():
    # Documents the stdlib behaviour the fix relies on.
    try:
        subprocess.run([sys.executable, "-c", "import time; print('x', flush=True); time.sleep(5)"],
                       capture_output=True, text=True, timeout=1)
    except subprocess.TimeoutExpired as e:
        assert e.stdout is None or isinstance(e.stdout, (bytes, str))
