#!/usr/bin/env python3
"""Bounded paid smoke scenarios; writes transcripts, progress and durable sessions."""
import argparse
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--key-file', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--scenario', choices=['multi-file', 'fan-out', 'nested', 'limit'])
args = parser.parse_args()
root = Path(__file__).resolve().parent
repo = root.parents[2]
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=True)
fixtures = root / 'fixtures'
env = os.environ.copy()
env['ANTHROPIC_API_KEY'] = args.key_file.read_text().strip()
tasks = {
    'multi-file': 'Use codemode to read alpha.txt and beta.txt, then report each owner and the total open bugs.',
    'fan-out': 'Use codemode to efficiently read all three independent files alpha.txt, beta.txt, gamma.txt and return their bug counts in that order, plus the total. Choose the appropriate batching API from its description.',
    'nested': 'Use codemode with a nested codemode call: the inner script reads alpha.txt and beta.txt and returns their combined bug count; the outer script reads gamma.txt and returns the grand total. This is a test of nested scripts, so actually exercise nesting.',
    'limit': 'Exercise the documented shared inner-call limit: in ONE codemode invocation attempt 33 sequential read_file calls of alpha.txt. Do not split the work into separate invocations or stop before the limit. Report the observed limit/error and retained earlier results. Do not retry the limit probe.',
}
results = []
for name, task in tasks.items():
    if args.scenario and name != args.scenario:
        continue
    scenario = output / f'{name}.toml'
    task += f' All fixture files are under {fixtures}. Afterwards call feedback with a concrete observation about the harness/tools, then summarize in prose.'
    fields = {'id': name, 'policy_path': '/dev/null', 'system_prompt': 'You are validating Bee codemode. Use only the supplied fixtures and tools. Inspect real results; never invent observations. Submit harness feedback with the feedback tool before your final answer.', 'task': task, 'turn_limit': 5, 'timeout_secs': 120, 'tools': ['read_file', 'feedback'], 'finish': False}
    scenario.write_text('[scenario]\n' + '\n'.join(f'{k} = {json.dumps(v)}' for k,v in fields.items()) + '\n')
    command = [str(repo / 'target/debug/bee'), 'run', '--host', '--scenario', str(scenario), '--provider', str(root/'provider.toml'), '--session-dir', str(output/f'{name}-session'), '--session-id', name, '--request-id', name, '--tool-call-limit', '48', '--out', str(output/f'{name}.json')]
    with (output/f'{name}.log').open('w') as log:
        try:
            result = subprocess.run(command, cwd=repo, env=env, stdout=log, stderr=log, timeout=150)
            status = result.returncode
        except subprocess.TimeoutExpired:
            status = 'timeout'
    results.append({'scenario':name,'exit_code':status})
    (output/'results.json').write_text(json.dumps(results,indent=2)+'\n')
    print(name, status, flush=True)
    if status not in (0, 3):
        break  # Stop on setup/provider failure rather than spending on identical failures.
