import unittest
from validate_results import validate


class ResultsTest(unittest.TestCase):
    valid = "RESULT|a|PASS|ok\nRESULT|b|PASS|ok\nSUMMARY|pass=2|fail=0\n"

    def test_complete_success(self):
        self.assertEqual(len(validate(self.valid, {"a", "b"})), 2)

    def test_invalid_runs(self):
        for output in [
            "", "SUMMARY|pass=0|fail=1\n",
            "RESULT|a|PASS|ok\nSUMMARY|pass=1|fail=0\n",
            self.valid.replace("RESULT|b", "RESULT|a"),
            self.valid.replace("pass=2", "pass=3"),
            self.valid.replace("pass=2", "pass=bad"),
            self.valid + "SUMMARY|pass=2|fail=0\n",
            self.valid.replace("b|PASS", "b|SKIP").replace("pass=2|fail=0", "pass=1|fail=1"),
            self.valid.replace("b|PASS", "b|FAIL").replace("pass=2|fail=0", "pass=1|fail=1"),
        ]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                validate(output, {"a", "b"})

    def test_transport_failure_overrides_success(self):
        with self.assertRaises(ValueError):
            validate(self.valid, {"a", "b"}, 1)
