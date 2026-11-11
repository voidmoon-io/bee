import copy
import json
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import Request, build_opener, ProxyHandler
from unittest.mock import patch

import corpus_v2
import submission
from run import score


class SubmissionTests(unittest.TestCase):
    def setUp(self):
        self.events = [{'path': '/documents/alice', 'user': user, 'status': code, 'body': body}
                       for user, code, body in [('alice', 200, 'alice-private-document'),
                                                ('bob', 200, 'alice-private-document'),
                                                ('', 401, 'credentials required')]]
        self.sources = {'target.py': 'def handle():\n    pass\n'}
        self.answer = {'assessment': 'confirmed', 'rationale': 'Observed cross-user read',
                       'requests': [1, 2, 3], 'sources': [{'path': 'target.py', 'start': 1, 'end': 2}],
                       'limitations': 'Local fixture only'}

    def test_real_receipt_rejects_then_accepts_and_refuses_conflict(self):
        receiver = submission.Receiver(self.events, self.sources)
        self.addCleanup(receiver.close)
        opener = build_opener(ProxyHandler({}))
        def post(value):
            try:
                response = opener.open(Request(receiver.url + '/assessment', data=json.dumps(value).encode()), timeout=5)
            except HTTPError as error:
                response = error
            with response:
                return response.status, json.load(response)
        self.assertEqual(post({'assessment': 'confirmed'})[0], 400)
        self.assertEqual(post(self.answer)[0], 200)
        self.assertEqual(post(self.answer)[0], 200)
        self.assertEqual(post(dict(self.answer, assessment='refuted'))[0], 400)
        self.assertEqual(submission.accepted(receiver.attempts, self.events, self.sources), self.answer)
        with opener.open(receiver.url + '/observations') as response:
            self.assertEqual([x['id'] for x in json.load(response)], [1, 2, 3])
        receiver.attempts[-1]['accepted'] = True
        with self.assertRaises(ValueError):
            submission.accepted(receiver.attempts, self.events, self.sources)

    def test_invalid_and_fabricated_references(self):
        for field, value in [('requests', [4]), ('requests', [True]), ('requests', [1, 1]),
                             ('sources', []), ('sources', [{'path': '../key', 'start': 1, 'end': 2}]),
                             ('sources', [{'path': 'target.py', 'start': 1, 'end': 3}]),
                             ('rationale', ''), ('assessment', 'maybe')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                submission.validate(dict(self.answer, **{field: value}), self.events, self.sources)
        attempt = {'value': self.answer, 'observed_requests': 1, 'accepted': True}
        with self.assertRaises(ValueError):
            submission.accepted([attempt], self.events, self.sources)

    def test_prose_cannot_override_receipt_and_incomplete_cannot_pass(self):
        transcript = {'status': {'status': 'completed'}, 'turns': [{'assistant_text': 'Prose, not JSON.'}]}
        result = score('bypass', transcript, self.events, 0, submitted=self.answer)
        self.assertTrue(result['passed'])
        self.assertEqual(result['diagnostics']['answer_format'], 'submission')
        self.assertFalse(score('bypass', transcript, self.events, 0, submitted={})['passed'])
        transcript['status']['status'] = 'timeout'
        self.assertFalse(score('bypass', transcript, self.events, 0, submitted=self.answer)['passed'])
        transcript['status']['status'] = 'completed'
        self.assertEqual(score('bypass', transcript, self.events[:1], 0, submitted=self.answer)['diagnostics']['outcome'], 'unsupported_confirmation')


class HarderCorpusTests(unittest.TestCase):
    def test_all_variants_run_and_require_discriminating_controls(self):
        corpus_v2.validate_frozen()
        for task in corpus_v2.tasks('development'):
            with self.subTest(variant=task['variant']):
                observed = corpus_v2.verify(task)
                self.assertTrue(all(corpus_v2.coverage(task, observed).values()))
                self.assertFalse(all(corpus_v2.coverage(task, []).values()))
                if task['variant'] != 'unavailable':
                    for index in range(5):
                        self.assertFalse(all(corpus_v2.coverage(task, observed[:index] + observed[index+1:]).values()))
                    equivalent = copy.deepcopy(observed)
                    equivalent[1]['path'] = '/export?id=a17'
                    self.assertTrue(all(corpus_v2.coverage(task, equivalent).values()))
                    wrong_route = copy.deepcopy(observed)
                    wrong_route[1]['path'] = '/document?id=quarterly'
                    self.assertFalse(corpus_v2.coverage(task, wrong_route)['attack'])
        with self.assertRaises(ValueError):
            corpus_v2.tasks('holdout')

    def test_oracle_rejects_wrong_label_and_unreachable_helper_stays_unreachable(self):
        task = corpus_v2.tasks('development')[0]
        protected = corpus_v2.files(corpus_v2.tasks('development')[1])
        with patch.object(corpus_v2, 'files', return_value=protected):
            with self.assertRaisesRegex(ValueError, 'oracle mismatch'):
                corpus_v2.verify(task)
        task = corpus_v2.tasks('development')[2]
        runtime = corpus_v2.Runtime(task)
        self.addCleanup(runtime.close)
        opener = build_opener(ProxyHandler({}))
        with self.assertRaises(HTTPError) as error:
            opener.open(Request(runtime.url + '/preview?id=quarterly', headers={'X-User': 'bob'}))
        self.assertEqual(error.exception.code, 404)
        error.exception.close()
