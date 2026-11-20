import contextlib
import io
import sys
import unittest
from unittest.mock import patch

from rich.console import Console

from eugene import app
from eugene.doctor import Doctor
from eugene.report import Report


class _SilentLive:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class AppTests(unittest.TestCase):
    def test_initial_live_view_has_a_chain(self):
        view = app.live_view(Doctor().snapshot(), Console(width=100))
        self.assertIsNotNone(view)

    def test_worker_exception_returns_error_exit_code(self):
        class BrokenDoctor:
            def __init__(self, *args, **kwargs):
                self.report = Report()

            def run(self):
                raise RuntimeError("probe crashed")

            def snapshot(self):
                return self.report

        stderr = io.StringIO()
        with patch.object(sys, "argv", ["eugene", "--lang", "en"]), \
                patch.object(app, "Doctor", BrokenDoctor), \
                patch.object(app, "Live", _SilentLive), \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(app.main(), 2)
        self.assertIn("probe crashed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
