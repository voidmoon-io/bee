import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import ax
import corpus
from run import score


class CorpusTests(unittest.TestCase):
    def test_frozen_family_split_and_source_hashes(self):
        inventory = corpus.validate_frozen()
        development = {t['family'] for t in inventory['splits']['development']}
        holdout = {t['family'] for t in inventory['splits']['holdout']}
        self.assertFalse(development & holdout)
        self.assertEqual(sum(map(len, inventory['splits'].values())), 12)
        with patch.object(corpus, 'VERSION', 2):
            with self.assertRaisesRegex(ValueError, 'frozen'):
                corpus.validate_frozen()

    def test_runtime_oracles_and_agent_evidence_are_separate(self):
        for split in corpus.SPLITS:
            for task in corpus.tasks(split):
                with self.subTest(task=task):
                    observations = corpus.verify(task)
                    self.assertTrue(all(corpus.coverage(task, observations).values()))
                    self.assertFalse(any(corpus.coverage(task, []).values()))
                    text = json.dumps({'assessment': task['expected']})
                    transcript = {'status': {'status': 'completed'}, 'turns': [{'assistant_text': text}]}
                    case = {'confirmed': 'bypass', 'refuted': 'fixed', 'blocked': 'unavailable'}[task['expected']]
                    self.assertTrue(score(case, transcript, observations, 0,
                                          corpus.coverage(task, observations))['passed'])
                    self.assertFalse(score(case, transcript, [], 0,
                                           corpus.coverage(task, []))['passed'])
                    if task['variant'] != 'unavailable':
                        self.assertFalse(score(case, transcript, observations[:1], 0,
                                               corpus.coverage(task, observations[:1]))['passed'])

    def test_semantically_equivalent_probes_count(self):
        access = corpus.tasks('development')[0]
        observed = [{'path': '/doc', 'user': user, 'status': status, 'body': body}
                    for user, status, body in [('alice', 200, 'private-marker'),
                                              ('bob', 200, 'private-marker'),
                                              ('', 401, 'credentials required')]]
        self.assertTrue(all(corpus.coverage(access, observed).values()))
        self.assertFalse(corpus.coverage(access, observed[1:])['ready'])
        containment = corpus.tasks('development')[4]
        observed = [{'path': path, 'status': status, 'body': body} for path, status, body in
                    [('/?name=./hello.txt', 200, 'hello'), ('/?name=../private.txt', 200, 'private-marker'),
                     ('/?name=definitely-absent', 404, 'not found')]]
        self.assertTrue(all(corpus.coverage(containment, observed).values()))
        arguments = corpus.tasks('holdout')[1]
        observed = [{'path': path, 'status': 200, 'body': body} for path, body in
                    [('/', 'hello'), ('/?text=--file=./private.txt', '--file=./private.txt'),
                     ('/?text=sentinel', 'sentinel')]]
        self.assertTrue(all(corpus.coverage(arguments, observed).values()))
        self.assertFalse(corpus.coverage(arguments, observed[:2])['control'])

    def test_oracle_detects_broken_runtime(self):
        task = corpus.tasks('development')[0]
        with patch.object(corpus, 'source', return_value='def handle(path, headers, root):\n    return 200, "pretend"\n'):
            with self.assertRaisesRegex(ValueError, 'oracle mismatch'):
                corpus.verify(task)

    def test_agent_material_does_not_label_variants(self):
        for split in corpus.SPLITS:
            for task in corpus.tasks(split):
                material = corpus.source(task['family'], task['variant']) + corpus.task_text(task, 'http://127.0.0.1:1234')
                for label in ('false_lead', 'patched', 'vulnerable', 'expected', 'holdout'):
                    self.assertNotIn(label, material)
                compile(corpus.source(task['family'], task['variant']), 'target.py', 'exec')

    def test_ax_payload_is_complete_and_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / 'remote'
            subprocess.run([sys.executable, '-c', ax.upload_script(str(destination))], check=True)
            for name, encoded in ax.evaluator_payload().items():
                self.assertEqual((destination / name).read_bytes(), base64.b64decode(encoded))
            subprocess.run([sys.executable, '-c', 'import corpus; corpus.validate_frozen()'],
                           cwd=destination, check=True)
            subprocess.run([sys.executable, str(destination / 'run.py'), '--help'],
                           check=True, capture_output=True)


if __name__ == '__main__':
    unittest.main()
