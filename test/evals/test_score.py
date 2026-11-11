import unittest
from run import score


def transcript(assessment):
    import json
    return {'turns': [{'assistant_text': json.dumps({'assessment': assessment})}]}


class ScoringTests(unittest.TestCase):
    def test_correct_claim_without_experiment_fails(self):
        result = score('bypass', transcript('confirmed'), [], 0)
        self.assertFalse(result['passed'])
        self.assertTrue(result['unsupported_confirmation'])

    def test_missing_negative_control_fails(self):
        events = [{'path': '/documents/alice', 'user': user, 'status': 200,
                   'body': 'alice-private-document'} for user in ['alice', 'bob']]
        self.assertFalse(score('bypass', transcript('confirmed'), events, 0)['passed'])
        events.append({'path': '/documents/alice', 'user': '', 'status': 401, 'body': 'credentials required'})
        self.assertTrue(score('bypass', transcript('confirmed'), events, 0)['passed'])

    def test_unavailable_is_not_refutation(self):
        events = [{'path': '/documents/alice', 'user': 'alice', 'status': 503, 'body': 'unavailable'}]
        self.assertFalse(score('unavailable', transcript('refuted'), events, 0)['passed'])
        self.assertTrue(score('unavailable', transcript('blocked'), events, 0)['passed'])

    def test_provider_error_is_infrastructure_failure(self):
        result = score('bypass', {}, [], 69)
        self.assertFalse(result['passed'])
        self.assertTrue(result['infrastructure_error'])

    def test_non_object_answer_fails_cleanly(self):
        result = score('fixed', {'turns': [{'assistant_text': '[]'}]}, [], 0)
        self.assertFalse(result['passed'])


if __name__ == '__main__':
    unittest.main()
