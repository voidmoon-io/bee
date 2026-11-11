import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from replay import replay
from run import diagnose, score


def transcript(text, status='completed'):
    return {'status': {'status': status}, 'turns': [{'assistant_text': text}]}


def events(case='bypass'):
    return [{'path': '/documents/alice', 'user': user, 'status': status, 'body': body}
            for user, status, body in [
                ('alice', 200, 'alice-private-document'),
                ('', 401, 'credentials required'),
                ('bob', 200 if case == 'bypass' else 403,
                 'alice-private-document' if case == 'bypass' else 'forbidden')]]


class DiagnosticTests(unittest.TestCase):
    def test_fenced_answer_keeps_strict_failure_but_explains_quality(self):
        result = score('fixed', transcript('```json\n{"assessment":"refuted"}\n```'), events('fixed'), 0)
        self.assertFalse(result['passed'])
        self.assertFalse(result['correct_assessment'])
        diagnostic = result['diagnostics']
        self.assertEqual(diagnostic['outcome'], 'justified_refutation')
        self.assertFalse(diagnostic['format_compliant'])

    def test_no_prose_or_invalid_answer_recovery(self):
        for text in ('It is confirmed.', '[]', '{"assessment":"maybe"}',
                     'Here it is:\n```json\n{"assessment":"confirmed"}\n```'):
            with self.subTest(text=text):
                diagnostic = diagnose('bypass', transcript(text), events(), 0)
                self.assertEqual(diagnostic['outcome'], 'inconclusive')
                self.assertEqual(diagnostic['answer_format'], 'invalid')

    def test_claim_requires_actual_response_and_control(self):
        for observations in ([], events()[:1], events()[1:]):
            self.assertEqual(diagnose('bypass', transcript('{"assessment":"confirmed"}'),
                                      observations, 0)['outcome'], 'unsupported_confirmation')
        wrong_status = events()
        wrong_status[0]['status'] = 500
        self.assertEqual(diagnose('bypass', transcript('{"assessment":"confirmed"}'),
                                  wrong_status, 0)['outcome'], 'unsupported_confirmation')

    def test_miss_and_abstention_remain_in_quality_denominator(self):
        for assessment, outcome in [('refuted', 'missed_vulnerability'), ('blocked', 'inconclusive')]:
            diagnostic = diagnose('bypass', transcript(json.dumps({'assessment': assessment})), events(), 0)
            self.assertEqual(diagnostic['outcome'], outcome)
            self.assertTrue(diagnostic['quality_eligible'])
            self.assertFalse(diagnostic['quality_success'])

    def test_termination_overrides_success_exit_and_answer(self):
        for status in ('timeout', 'context_exhausted', 'stuck', 'terminated'):
            diagnostic = diagnose('bypass', transcript('{"assessment":"confirmed"}', status), events(), 0)
            self.assertEqual(diagnostic['execution'], 'incomplete')
            self.assertEqual(diagnostic['outcome'], 'inconclusive')
            self.assertTrue(diagnostic['quality_eligible'])

    def test_failures_and_missing_termination_cannot_earn_credit(self):
        for status, exit_code, expected in [('api_error', 0, 'provider_failure'),
                                           ('infra_error', 70, 'setup_failure'),
                                           ('completed', -9, 'process_failure'),
                                           ('unrecognized', 0, 'unknown_termination')]:
            diagnostic = diagnose('bypass', transcript('{"assessment":"confirmed"}', status), events(), exit_code)
            self.assertEqual(diagnostic['execution'], expected)
            self.assertFalse(diagnostic['quality_eligible'])
            self.assertEqual(diagnostic['outcome'], 'excluded')
        self.assertEqual(diagnose('bypass', {}, [], 0)['execution'], 'missing_transcript')
        self.assertEqual(diagnose('bypass', {}, [], 'timeout')['execution'], 'incomplete')

    def test_deliberate_unavailability_is_separate(self):
        observations = [{'path': '/documents/alice', 'status': 503}]
        diagnostic = diagnose('unavailable', transcript('{"assessment":"blocked"}'), observations, 0)
        self.assertEqual(diagnostic['outcome'], 'target_unavailable')
        self.assertFalse(diagnostic['quality_eligible'])
        self.assertEqual(diagnostic['execution'], 'completed')

    def test_replay_preserves_originals_and_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            episode = source / '00-fixed-baseline'
            episode.mkdir(parents=True)
            original = {'passed': False, 'case': 'fixed', 'exit_code': 0}
            for name, value in [('score.json', original), ('requests.json', events('fixed')),
                                ('transcript.json', transcript('```json\n{"assessment":"refuted"}\n```'))]:
                (episode / name).write_text(json.dumps(value))
            before = {p.name: p.read_bytes() for p in episode.iterdir()}
            output = root / 'derived'
            summary = replay(source, output)
            self.assertEqual(summary['original_strict_passes'], 0)
            self.assertEqual(summary['quality_successes'], 1)
            self.assertEqual(before, {p.name: p.read_bytes() for p in episode.iterdir()})
            manifest = json.loads((output / 'manifest.json').read_text())
            for name, content in before.items():
                self.assertEqual(manifest['source_sha256'][f'00-fixed-baseline/{name}'],
                                 hashlib.sha256(content).hexdigest())
            with self.assertRaises(FileExistsError):
                replay(source, output)
            with self.assertRaises(ValueError):
                replay(source, source / 'derived')


if __name__ == '__main__':
    unittest.main()
