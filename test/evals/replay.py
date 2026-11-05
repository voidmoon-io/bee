#!/usr/bin/env python3
"""Write diagnostic scores from saved eval artifacts without modifying originals."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from run import DIAGNOSTIC_VERSION, diagnose, write_json


def replay(source, output):
    source, output = source.resolve(), output.resolve()
    if output == source or output.is_relative_to(source):
        raise ValueError('output must be outside the source artifact directory')
    manifest_path = source / 'manifest.json'
    if manifest_path.exists() and json.loads(manifest_path.read_text()).get('answer_protocol'):
        raise ValueError('receipt-protocol runs require report.py to validate submissions and cited evidence')
    originals = sorted(source.glob('*/score.json'))
    if not originals:
        raise ValueError('no episode scores found')
    output.mkdir(parents=True, exist_ok=False)
    fingerprints = {}
    rows = []
    for score_path in originals:
        directory = score_path.parent
        data = {}
        for name in ('score.json', 'transcript.json', 'requests.json'):
            path = directory / name
            if not path.exists() and name == 'transcript.json':
                data[name] = {}
                fingerprints[str(path.relative_to(source))] = None
                continue
            raw = path.read_bytes()
            fingerprints[str(path.relative_to(source))] = hashlib.sha256(raw).hexdigest()
            data[name] = json.loads(raw)
        original = data['score.json']
        coverage = None
        if 'task' in original:
            import corpus
            corpus.validate_frozen()
            if original['task'] not in corpus.tasks(original['task']['split']):
                raise ValueError('task does not match frozen corpus')
            coverage = corpus.coverage(original['task'], data['requests.json'])
        rows.append({'run': directory.name, 'original_score': original,
                     'diagnostics': diagnose(original['case'], data['transcript.json'],
                                             data['requests.json'], original['exit_code'], coverage)})
    eligible = [r for r in rows if r['diagnostics']['quality_eligible']]
    summary = {
        'episodes': len(rows),
        'original_strict_passes': sum(bool(r['original_score']['passed']) for r in rows),
        'quality_eligible': len(eligible),
        'quality_successes': sum(r['diagnostics']['quality_success'] for r in eligible),
        'outcomes': dict(Counter(r['diagnostics']['outcome'] for r in rows)),
        'formats': dict(Counter(r['diagnostics']['answer_format'] for r in rows)),
        'note': 'Diagnostic replay, not a new model trial or evidence of playbook improvement.',
    }
    write_json(output / 'results.json', rows)
    write_json(output / 'summary.json', summary)
    write_json(output / 'manifest.json', {
        'diagnostic_version': DIAGNOSTIC_VERSION, 'source': str(source),
        'source_sha256': fingerprints,
        'scorer_sha256': hashlib.sha256(Path(__file__).with_name('run.py').read_bytes()).hexdigest(),
        'replay_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'corpus_sha256': hashlib.sha256(Path(__file__).with_name('corpus.py').read_bytes()).hexdigest()
                         if any('task' in r['original_score'] for r in rows) else None,
    })
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(replay(args.source, args.output), indent=2))
