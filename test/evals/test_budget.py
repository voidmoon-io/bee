import unittest
from ax import check_budget


class BudgetTests(unittest.TestCase):
    def test_existing_lower_cap_is_accepted(self):
        check_budget({'limit': 10, 'limit_remaining': 9.5, 'limit_reset': None}, 20)

    def test_unknown_unlimited_resetting_exhausted_or_excessive_caps_fail(self):
        for fields in ({}, {'limit': None}, {'limit': 21}, {'limit_reset': 'daily'},
                       {'limit_remaining': 0}, {'limit_remaining': 11}, {'limit': float('nan')}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                check_budget({'limit': 10, 'limit_remaining': 9, 'limit_reset': None, **fields}
                             if fields else {}, 20)
        for budget in (0, -1, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                check_budget({'limit': 10, 'limit_remaining': 9, 'limit_reset': None}, budget)
