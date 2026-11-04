import copy
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

from playbooks import fingerprint, load, selected
from report import GATE, digest, experiment_contract, generate, summarize
from run import CASES, DIAGNOSTIC_VERSION, score


def fixture(root, mode='mock-pipeline-only'):
    manifest = {'report_schema': 1, 'gate': GATE, 'playbooks': selected(None, None, 'endpoint'),
                'bee_sha256': 'binary', 'runner_sha256': digest(Path(__file__).with_name('run.py')),
                'report_sha256': digest(Path(__file__).with_name('report.py')),
                'provider_sha256': 'provider', 'corpus': 'endpoint', 'split': None,
                'corpus_sha256': None, 'inventory_sha256': None, 'tasks': None,
                'mode': mode, 'repeats': 1, 'turn_limit': 8, 'timeout_secs': 90,
                'tools': ['bash', 'feedback'], 'finish': False, 'diagnostic_version': DIAGNOSTIC_VERSION}
    rows = []
    for case, expected in CASES.items():
        for arm in ('baseline', 'candidate'):
            directory = root / f'00-{case}-{arm}'
            directory.mkdir(parents=True)
            scenario = {'id': case, 'system_prompt': manifest['playbooks'][arm]['prompt'],
                        'task': 'Investigate http://127.0.0.1:1234/documents/alice',
                        'turn_limit': 8, 'timeout_secs': 90, 'tools': ['bash', 'feedback'], 'finish': False}
            (directory / 'scenario.toml').write_text('[scenario]\n' + '\n'.join(f'{k} = {json.dumps(v)}' for k,v in scenario.items()))
            transcript = {'model_id': 'mock', 'status': {'status': 'completed'},
                          'turns': [{'assistant_text': json.dumps({'assessment': expected})}]}
            events = [{'path': '/documents/alice', 'user': user, 'status': status, 'body': body}
                      for user, status, body in [('alice', 200, 'alice-private-document'),
                                                ('', 401, 'credentials required'),
                                                ('bob', 200 if case == 'bypass' else 403,
                                                 'alice-private-document' if case == 'bypass' else 'forbidden')]]
            if case == 'unavailable':
                events = [{'path': '/documents/alice', 'user': 'alice', 'status': 503, 'body': 'fixture unavailable'}]
            (directory / 'transcript.json').write_text(json.dumps(transcript))
            (directory / 'requests.json').write_text(json.dumps(events))
            contract = {k: v for k, v in scenario.items() if k != 'system_prompt'}
            contract['task'] = contract['task'].replace('http://127.0.0.1:1234', '<target>')
            row = score(case, transcript, events, 0)
            row.update(task_id=case, case=case, repetition=0, arm=arm, model_id='mock',
                       contract=experiment_contract(manifest), task_contract_sha256=fingerprint(contract),
                       playbook_sha256=manifest['playbooks'][arm]['sha256'], target_url='http://127.0.0.1:1234',
                       artifact_sha256={name: digest(directory / name) for name in
                                        ('scenario.toml', 'transcript.json', 'requests.json')})
            (directory / 'score.json').write_text(json.dumps(row))
            rows.append(row)
    (root / 'manifest.json').write_text(json.dumps(manifest))
    return manifest, rows


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.manifest, self.rows = fixture(self.source)

    def test_full_report_is_immutable_and_mock_never_recommends(self):
        before = {str(p): p.read_bytes() for p in self.source.rglob('*') if p.is_file()}
        report = generate(self.source, self.root / 'report')
        self.assertEqual(report['recommendation'], 'mock_pipeline_only')
        self.assertEqual((report['wins'], report['ties'], report['losses'], report['excluded_pairs']), (0, 2, 0, 1))
        self.assertFalse(report['errors'])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.source.rglob('*') if p.is_file()})
        with self.assertRaises(FileExistsError):
            generate(self.source, self.root / 'report')
        with self.assertRaises(ValueError):
            generate(self.source, self.source / 'report')

    def test_missing_duplicate_and_mismatched_inputs_invalidate(self):
        mutations = [lambda rows: rows.pop(), lambda rows: rows.append(copy.deepcopy(rows[0])),
                     lambda rows: rows[0]['contract'].update(bee_sha256='other'),
                     lambda rows: rows[0].update(model_id='other'),
                     lambda rows: rows[0].update(task_contract_sha256='other'),
                     lambda rows: rows[0].update(playbook_sha256='other')]
        for mutation in mutations:
            rows = copy.deepcopy(self.rows)
            mutation(rows)
            self.assertEqual(summarize(self.manifest, rows)['recommendation'], 'invalid_comparison')
        self.assertEqual(summarize(self.manifest, [])['recommendation'], 'invalid_comparison')

    def test_evidence_and_scores_are_rechecked(self):
        path = self.source / '00-bypass-candidate' / 'requests.json'
        path.write_text('[]')
        result = generate(self.source, self.root / 'changed')
        self.assertEqual(result['recommendation'], 'invalid_comparison')
        self.assertTrue(any('artifact missing or changed' in e for e in result['errors']))
        row_path = path.with_name('score.json')
        row = json.loads(row_path.read_text())
        row['artifact_sha256']['requests.json'] = digest(path)
        row_path.write_text(json.dumps(row))
        result = generate(self.source, self.root / 'changed-hash')
        self.assertTrue(any('saved score differs' in e for e in result['errors']))

    def test_submission_report_replays_receipts_and_checks_cited_evidence(self):
        import submission
        self.manifest.update(answer_protocol=submission.VERSION,
                             submission_sha256=digest(Path(submission.__file__)))
        (self.source / 'manifest.json').write_text(json.dumps(self.manifest))
        for path in self.source.glob('*/score.json'):
            directory = path.parent
            row = json.loads(path.read_text())
            events = json.loads((directory / 'requests.json').read_text())
            transcript = json.loads((directory / 'transcript.json').read_text())
            transcript['turns'][0]['assistant_text'] = 'Unstructured final prose'
            (directory / 'transcript.json').write_text(json.dumps(transcript))
            answer = {'assessment': CASES[row['case']], 'rationale': 'Observed behavior',
                      'requests': list(range(1, len(events) + 1)), 'sources': [], 'limitations': 'Fixture only'}
            attempts = [{'value': answer, 'observed_requests': len(events), 'accepted': True}]
            (directory / 'submissions.json').write_text(json.dumps(attempts))
            import tomllib
            scenario = tomllib.loads((directory / 'scenario.toml').read_text())['scenario']
            scenario['task'] += ' Submit at http://127.0.0.1:4321/assessment'
            (directory / 'scenario.toml').write_text('[scenario]\n' + '\n'.join(f'{k} = {json.dumps(v)}' for k, v in scenario.items()))
            contract = {k: v for k, v in scenario.items() if k != 'system_prompt'}
            contract['task'] = contract['task'].replace(row['target_url'], '<target>').replace('http://127.0.0.1:4321', '<receipt>')
            row.update(score(row['case'], transcript, events, 0, submitted=answer))
            row.update(contract=experiment_contract(self.manifest), receipt_url='http://127.0.0.1:4321',
                       task_contract_sha256=fingerprint(contract))
            row['artifact_sha256'] = {name: digest(directory / name) for name in
                                     ('scenario.toml', 'transcript.json', 'requests.json', 'submissions.json')}
            path.write_text(json.dumps(row))
        result = generate(self.source, self.root / 'receipt-report')
        self.assertFalse(result['errors'])
        directory = self.source / '00-bypass-candidate'
        receipt = directory / 'submissions.json'
        attempts = json.loads(receipt.read_text())
        attempts[0]['value']['requests'] = [1]
        receipt.write_text(json.dumps(attempts))
        row = json.loads((directory / 'score.json').read_text())
        row['artifact_sha256']['submissions.json'] = digest(receipt)
        (directory / 'score.json').write_text(json.dumps(row))
        result = generate(self.source, self.root / 'receipt-tamper')
        self.assertEqual(result['recommendation'], 'invalid_comparison')
        self.assertTrue(any('saved score differs' in e for e in result['errors']))

    def live(self, repeats=2):
        manifest, rows = copy.deepcopy((self.manifest, self.rows))
        manifest.update(mode='live', repeats=repeats, split='holdout')
        rows = [dict(copy.deepcopy(row), repetition=i) for i in range(repeats) for row in rows]
        for row in rows:
            row['contract'] = experiment_contract(manifest)
        return manifest, rows

    def test_format_only_gain_is_not_quality_improvement(self):
        manifest, rows = self.live()
        for row in rows:
            if row['arm'] == 'baseline':
                row['passed'] = False
                row['diagnostics']['format_compliant'] = False
        result = summarize(manifest, rows)
        self.assertEqual(result['wins'], 0)
        self.assertEqual(result['recommendation'], 'insufficient_evidence')

    def test_regressions_block_and_live_signal_requires_review(self):
        manifest, rows = self.live()
        for row in rows:
            if row['arm'] == 'baseline' and row['case'] == 'bypass':
                row['diagnostics'].update(quality_success=False, outcome='inconclusive')
        self.assertEqual(summarize(manifest, rows)['recommendation'],
                         'holdout_signal_requires_review_and_regression_checks')
        rows[3]['diagnostics'].update(quality_success=False, outcome='unsupported_confirmation')
        result = summarize(manifest, rows)
        self.assertEqual(result['recommendation'], 'retain_baseline')
        self.assertEqual(len(result['new_harmful_outcomes']), 1)

    def test_provider_failure_excludes_pair_and_blocks_signal(self):
        manifest, rows = self.live()
        rows[0]['diagnostics'].update(quality_success=False, outcome='inconclusive')
        rows[3]['diagnostics'].update(quality_success=False, quality_eligible=False, outcome='excluded')
        result = summarize(manifest, rows)
        self.assertEqual(result['recommendation'], 'insufficient_evidence')
        self.assertEqual(result['excluded_pairs'], 3)

    def test_playbook_version_and_content_are_bound(self):
        path = self.root / 'playbook.json'
        path.write_text(json.dumps({'id': 'candidate', 'version': '1', 'prompt': 'Check controls.'}))
        one = load(path)
        path.write_text(json.dumps({'id': 'candidate', 'version': '1', 'prompt': 'Skip controls.'}))
        self.assertNotEqual(one['sha256'], load(path)['sha256'])
        for value in ({'id': 'x'}, {'id': 'x', 'version': '1', 'prompt': ''}):
            path.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                load(path)

    def test_failed_execution_retains_a_score_and_cannot_support_comparison(self):
        binary = self.root / 'failed-bee'
        binary.write_text('#!/bin/sh\nexit 70\n')
        binary.chmod(0o700)
        output = self.root / 'failed-run'
        process = subprocess.run([sys.executable, str(Path(__file__).with_name('run.py')),
                                  '--bee', str(binary), '--mock', '--output', str(output)],
                                 capture_output=True, text=True)
        self.assertEqual(process.returncode, 2, process.stderr)
        rows = json.loads((output / 'results.json').read_text())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['diagnostics']['execution'], 'setup_failure')
        self.assertIsNone(rows[0]['artifact_sha256']['transcript.json'])
        self.assertEqual(generate(output, self.root / 'failed-report')['recommendation'], 'invalid_comparison')


if __name__ == '__main__':
    unittest.main()
