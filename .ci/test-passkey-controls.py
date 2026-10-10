#!/usr/bin/env python3
"""Inert evidence-parser and byte-for-byte restoration regressions."""
import importlib.util
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("controls", Path(__file__).with_name("passkey-controls.py"))
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)


def output(result="FAILED", marker="exact assertion", pid=" (1234)"):
    summary = "FAILED. 0 passed; 1 failed" if result == "FAILED" else "ok. 1 passed; 0 failed"
    return (f"thread '{controls.TEST}'{pid} panicked at src/{controls.TARGET}.rs:42:5:\n"
            f"{marker}\ntest {controls.TEST} ... {result}\n"
            f"test result: {summary}; 0 ignored; 0 measured; 0 filtered out\n")


class Controls(unittest.TestCase):
    def test_real_named_panic_formats_pass(self):
        for pid in ["", " (1234)"]:
            self.assertTrue(controls.assertion(101, output(pid=pid), "exact assertion"))

    def test_false_or_unrelated_failures_refuse(self):
        for status, report in [
            (1, output()), (101, output(marker="wrong assertion")),
            (101, output().replace(controls.TEST, "other_test")),
            (101, output().replace("src/", "tests/")),
            (101, output() + "error[E0308]: type mismatch"),
            (101, output() + "could not compile crate"),
            (101, output().replace("0 passed; 1 failed", "0 passed; 2 failed")),
        ]:
            self.assertFalse(controls.assertion(status, report, "exact assertion"))

    def test_baseline_requires_exact_successful_selection(self):
        self.assertTrue(controls.baseline(0, output("ok")))
        for status, report in [(101, output("ok")), (0, ""), (0, output())]:
            self.assertFalse(controls.baseline(status, report))

    def test_source_restores_after_success_failure_and_exception(self):
        for outcome in [(101, output()), (101, "compile failed"), RuntimeError("transport")]:
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "source.rs"
                original = b"guard provider\n"
                source.write_bytes(original)
                with patch.object(controls, "SOURCE", str(source)), patch.object(
                    controls, "CONTROLS", ((b"guard provider", b"guard", "exact assertion"),)
                ), patch.object(controls, "run", side_effect=[(0, output("ok")), outcome]):
                    if isinstance(outcome, RuntimeError):
                        with self.assertRaises(RuntimeError):
                            controls.main()
                    elif outcome[1] == "compile failed":
                        with self.assertRaises(SystemExit):
                            controls.main()
                    else:
                        controls.main()
                self.assertEqual(source.read_bytes(), original)

    def test_source_drift_refuses_without_running_cargo(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.rs"
            source.write_bytes(b"different source")
            with patch.object(controls, "SOURCE", str(source)), patch.object(controls, "run") as run:
                with self.assertRaises(SystemExit):
                    controls.main()
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
