#!/usr/bin/env python3
"""Validate a matched experiment and write descriptive, non-promoting reports."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import tomllib

from playbooks import fingerprint

GATE = {'version': 1, 'automatic_promotion': False,
        'rule': 'Complete matching pairs; no new unsupported confirmations or misses; '
                'positive quality balance with no losses; repeated live holdout evidence. '
                'Any signal still requires human review and regression checks.'}
MATCH_FIELDS = ('mode', 'bee_sha256', 'runner_sha256', 'provider_sha256', 'corpus',
                'split', 'corpus_sha256', 'inventory_sha256', 'turn_limit', 'timeout_secs',
                'tools', 'finish', 'diagnostic_version', 'answer_protocol', 'submission_sha256')


def experiment_contract(manifest):
    return {key: manifest.get(key) for key in MATCH_FIELDS}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(manifest, rows, errors=None):
    errors = list(errors or [])
    expected_tasks = [t['id'] for t in manifest['tasks']] if manifest['tasks'] else ['bypass', 'fixed', 'unavailable']
    expected = {(repeat, task) for repeat in range(manifest['repeats']) for task in expected_tasks}
    grouped = {}
    models = set()
    for row in rows:
        key = (row.get('repetition'), row.get('task_id'))
        arm = row.get('arm')
        if key not in expected or arm not in ('baseline', 'candidate'):
            errors.append(f'unexpected episode {key}/{arm}')
            continue
        group = grouped.setdefault(key, {})
        if arm in group:
            errors.append(f'duplicate episode {key}/{arm}')
        group[arm] = row
        if row.get('contract') != experiment_contract(manifest):
            errors.append(f'contract mismatch {key}/{arm}')
        if row.get('playbook_sha256') != manifest['playbooks'][arm]['sha256']:
            errors.append(f'playbook mismatch {key}/{arm}')
        if not row.get('model_id'):
            errors.append(f'missing model identity {key}/{arm}')
        else:
            models.add(row['model_id'])
    if len(models) > 1:
        errors.append('model identity differs across episodes')
    pairs = []
    counts = Counter()
    arms = {arm: Counter() for arm in ('baseline', 'candidate')}
    regressions = []
    for key in sorted(expected):
        group = grouped.get(key, {})
        if set(group) != {'baseline', 'candidate'}:
            errors.append(f'missing pair member {key}')
            continue
        baseline, candidate = group['baseline'], group['candidate']
        if baseline.get('task_contract_sha256') != candidate.get('task_contract_sha256') or not baseline.get('task_contract_sha256'):
            errors.append(f'task/budget/tool mismatch {key}')
        a, b = baseline['diagnostics'], candidate['diagnostics']
        for arm, row in group.items():
            d = row['diagnostics']
            arms[arm]['episodes'] += 1
            arms[arm][d['outcome']] += 1
            arms[arm]['strict_passes'] += bool(row['passed'])
            arms[arm]['format_compliant'] += d['format_compliant']
            arms[arm]['evidence_complete'] += d['evidence_complete']
            arms[arm]['quality_eligible'] += d['quality_eligible']
            arms[arm]['quality_successes'] += d['quality_success']
            arms[arm]['tool_calls'] += row.get('tool_calls', 0)
            arms[arm]['tool_output_bytes'] += row.get('tool_output_bytes', 0)
            arms[arm]['elapsed_secs'] += row.get('elapsed_secs', 0)
        for bad in ('unsupported_confirmation', 'missed_vulnerability'):
            if b['outcome'] == bad and a['outcome'] != bad:
                regressions.append({'pair': list(key), 'outcome': bad})
        if not (a['quality_eligible'] and b['quality_eligible']):
            classification = 'excluded'
        else:
            difference = int(b['quality_success']) - int(a['quality_success'])
            classification = 'win' if difference > 0 else 'loss' if difference < 0 else 'tie'
        counts[classification] += 1
        pairs.append({'repetition': key[0], 'task_id': key[1], 'comparison': classification,
                      'baseline': a['outcome'], 'candidate': b['outcome']})
    eligible = counts['win'] + counts['loss'] + counts['tie']
    excluded_failures = any(r['diagnostics']['outcome'] == 'excluded' for r in rows)
    if errors:
        recommendation = 'invalid_comparison'
    elif manifest['mode'] != 'live':
        recommendation = 'mock_pipeline_only'
    elif regressions or counts['loss']:
        recommendation = 'retain_baseline'
    elif excluded_failures or not eligible or counts['win'] == 0 or manifest['repeats'] < 2:
        recommendation = 'insufficient_evidence'
    elif manifest['split'] != 'holdout':
        recommendation = 'development_signal_requires_frozen_holdout'
    else:
        recommendation = 'holdout_signal_requires_review_and_regression_checks'
    return {'version': 1, 'gate': GATE, 'recommendation': recommendation,
            'errors': errors, 'expected_pairs': len(expected), 'complete_pairs': len(pairs),
            'quality_pairs': eligible, 'wins': counts['win'], 'ties': counts['tie'],
            'losses': counts['loss'], 'excluded_pairs': counts['excluded'],
            'new_harmful_outcomes': regressions, 'arms': {k: dict(v) for k, v in arms.items()},
            'pairs': pairs, 'automatic_promotion': False,
            'cost_usd': None,
            'cost_note': 'Unknown; per-episode usage is retained in original scores. Shared provider balance is not per-episode cost.',
            'uncertainty': 'Descriptive counts only. Repeats of a task are correlated, not independent '
                           'projects. This small synthetic corpus cannot establish general hunting effectiveness.'}


def load_rows(source, manifest):
    from run import score
    errors, rows = [], []
    for path in sorted(source.glob('*/score.json')):
        try:
            row = json.loads(path.read_text())
            directory = path.parent
            hashes = row['artifact_sha256']
            required = {'scenario.toml', 'requests.json', 'transcript.json'}
            source_files = {}
            if manifest['corpus'] in ('source', 'source-v2'):
                import importlib
                corpus = importlib.import_module('corpus_v2' if manifest['corpus'] == 'source-v2' else 'corpus')
                source_files = corpus.files(row['task']) if manifest['corpus'] == 'source-v2' else {'target.py': corpus.source(row['task']['family'], row['task']['variant'])}
                required.update(source_files)
            if manifest.get('answer_protocol'):
                required.add('submissions.json')
            if set(hashes) != required:
                raise ValueError('incomplete artifact hash set')
            for name in required:
                artifact = directory / name
                actual = digest(artifact) if artifact.exists() else None
                if actual != hashes[name] or (actual is None and name != 'transcript.json'):
                    raise ValueError(f'artifact missing or changed: {name}')
            transcript = json.loads((directory / 'transcript.json').read_text()) if hashes['transcript.json'] else {}
            if row.get('model_id') != transcript.get('model_id'):
                raise ValueError('model identity differs from transcript')
            scenario = tomllib.loads((directory / 'scenario.toml').read_text())['scenario']
            if scenario['system_prompt'] != manifest['playbooks'][row['arm']]['prompt']:
                raise ValueError('scenario playbook differs from manifest')
            task_contract = {k: v for k, v in scenario.items() if k != 'system_prompt'}
            task_contract['task'] = task_contract['task'].replace(row['target_url'], '<target>')
            if manifest.get('answer_protocol'):
                if not row['receipt_url'].startswith('http://127.0.0.1:') or row['receipt_url'] not in scenario['task']:
                    raise ValueError('invalid receipt URL normalization')
                task_contract['task'] = task_contract['task'].replace(row['receipt_url'], '<receipt>')
            if not row['target_url'].startswith('http://127.0.0.1:') or row['target_url'] not in scenario['task']:
                raise ValueError('invalid target URL normalization')
            if scenario['id'] != row['task_id']:
                raise ValueError('scenario task identity mismatch')
            if fingerprint(task_contract) != row['task_contract_sha256']:
                raise ValueError('scenario contract changed')
            for key in ('turn_limit', 'timeout_secs', 'tools', 'finish'):
                if scenario[key] != manifest[key]:
                    raise ValueError(f'scenario {key} differs from manifest')
            events = json.loads((directory / 'requests.json').read_text())
            submitted = None
            if manifest.get('answer_protocol'):
                import submission
                submitted = submission.accepted(json.loads((directory / 'submissions.json').read_text()), events, source_files) or {}
                events = [events[i - 1] for i in submitted.get('requests', [])]
            coverage = None
            if manifest['corpus'] in ('source', 'source-v2'):
                corpus.validate_frozen()
                if row['task'] not in manifest['tasks'] or row['task'] not in corpus.tasks(manifest['split']):
                    raise ValueError('task differs from frozen inventory')
                case = {'confirmed': 'bypass', 'refuted': 'fixed', 'blocked': 'unavailable'}[row['task']['expected']]
                if row['task_id'] != row['task']['id'] or row['case'] != case:
                    raise ValueError('task label mismatch')
                if any((directory / name).read_text() != code for name, code in source_files.items()):
                    raise ValueError('target source differs from frozen inventory')
                coverage = corpus.coverage(row['task'], events)
            elif row['task_id'] != row['case']:
                raise ValueError('endpoint task label mismatch')
            actual = score(row['case'], transcript, events, row['exit_code'], coverage, submitted)
            if actual['diagnostics'] != row['diagnostics'] or actual['passed'] != row['passed']:
                raise ValueError('saved score differs from raw evidence')
            rows.append(row)
        except (KeyError, ValueError, TypeError, OSError) as error:
            errors.append(f'{path.parent.name}: {error}')
    return rows, errors


def generate(source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    if output == source or output.is_relative_to(source):
        raise ValueError('report output must be outside source artifacts')
    manifest = json.loads((source / 'manifest.json').read_text())
    errors = []
    if manifest.get('report_schema') != 1:
        raise ValueError('run predates paired-report provenance; run a new experiment')
    if manifest.get('gate') != GATE:
        errors.append('review gate changed')
    if manifest['runner_sha256'] != digest(Path(__file__).with_name('run.py')):
        errors.append('scorer/runner version differs from current code')
    if manifest['report_sha256'] != digest(Path(__file__)):
        errors.append('report code differs from frozen experiment')
    if manifest.get('answer_protocol'):
        import submission
        if manifest['answer_protocol'] != submission.VERSION or manifest.get('submission_sha256') != digest(Path(submission.__file__)):
            errors.append('submission protocol differs from frozen experiment')
    if manifest['corpus'] in ('source', 'source-v2'):
        module, inventory = ('corpus_v2.py', 'corpus-v2.json') if manifest['corpus'] == 'source-v2' else ('corpus.py', 'corpus-v1.json')
        for key, name in [('corpus_sha256', module), ('inventory_sha256', inventory)]:
            if manifest[key] != digest(Path(__file__).with_name(name)):
                errors.append(f'{key} differs from current code')
    for arm, playbook in manifest['playbooks'].items():
        if fingerprint({k: playbook[k] for k in ('id', 'version', 'prompt')}) != playbook['sha256']:
            errors.append(f'{arm} playbook hash mismatch')
    rows, artifact_errors = load_rows(source, manifest)
    result = summarize(manifest, rows, errors + artifact_errors)
    result['source_manifest_sha256'] = digest(source / 'manifest.json')
    result['input_score_sha256'] = {str(p.relative_to(source)): digest(p) for p in sorted(source.glob('*/score.json'))}
    output.mkdir(parents=True, exist_ok=False)
    (output / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
    lines = ['# Paired playbook report', '', f"Recommendation: **{result['recommendation']}**", '',
             f"Complete pairs: {result['complete_pairs']}/{result['expected_pairs']}; "
             f"quality pairs: {result['quality_pairs']}; excluded: {result['excluded_pairs']}.", '',
             f"Candidate wins/ties/losses: {result['wins']}/{result['ties']}/{result['losses']}.", '',
             '| Arm | Episodes | Quality successes / eligible | Unsupported confirmations | Misses |',
             '| --- | ---: | ---: | ---: | ---: |']
    for arm, values in result['arms'].items():
        lines.append(f"| {arm} | {values.get('episodes', 0)} | {values.get('quality_successes', 0)} / "
                     f"{values.get('quality_eligible', 0)} | {values.get('unsupported_confirmation', 0)} | "
                     f"{values.get('missed_vulnerability', 0)} |")
    lines += ['', result['uncertainty'], '', 'No automatic promotion or publication.']
    if result['errors']:
        lines += ['', 'Validation errors:', ''] + ['- ' + e for e in result['errors']]
    (output / 'REPORT.md').write_text('\n'.join(lines) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.source, args.output)
    print(result['recommendation'])
    raise SystemExit(1 if result['errors'] else 0)
