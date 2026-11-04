#!/usr/bin/env python3
"""Run evals in an existing dedicated AX sandbox; retain artifacts, then suspend."""
import argparse
import base64
import io
import json
import math
from pathlib import Path
import subprocess
import time
import uuid
import zipfile


def check_budget(metadata, budget):
    limit, remaining = metadata.get('limit'), metadata.get('limit_remaining')
    if not math.isfinite(budget) or budget <= 0:
        raise ValueError('budget must be finite and positive')
    if (not isinstance(limit, (int, float)) or not math.isfinite(limit)
            or not 0 < limit <= budget or metadata.get('limit_reset') is not None
            or not isinstance(remaining, (int, float)) or not math.isfinite(remaining)
            or not 0 < remaining <= limit):
        raise ValueError('live run requires a non-resetting provider key cap within the authorized budget and positive remaining allowance')


def evaluator_payload():
    root = Path(__file__).parent
    names = ('run.py', 'submission.py', 'corpus_v2.py', 'corpus-v2.json', 'corpus.py', 'corpus-v1.json', 'playbooks.py', 'report.py',
             'playbooks/baseline-v1.json', 'playbooks/endpoint-guided-v1.json',
             'playbooks/source-guided-v1.json')
    return {name: base64.b64encode((root / name).read_bytes()).decode() for name in names}


def upload_script(remote):
    return ('import base64; from pathlib import Path; '
            f'p=Path({remote!r}); p.mkdir(); '
            f'files={evaluator_payload()!r}; '
            '[(p/name).parent.mkdir(parents=True,exist_ok=True) for name in files]; '
            '[(p/name).write_bytes(base64.b64decode(data)) for name,data in files.items()]')


def detached_script(remote, command, timeout):
    supervisor = ('import json,os,signal,subprocess; from pathlib import Path; '
                  f'p=subprocess.Popen({command!r},start_new_session=True);\n'
                  'try:\n'
                  f'    code=p.wait(timeout={timeout!r})\n'
                  'except subprocess.TimeoutExpired:\n'
                  '    os.killpg(p.pid,signal.SIGKILL); p.wait(); code=124\n'
                  f'Path({remote + "/status.json"!r}).write_text(json.dumps({{"exit_code":code}}))\n')
    return ('import subprocess,sys; '
            f'log=open({remote + "/driver.log"!r},"w"); '
            f'p=subprocess.Popen([sys.executable,"-c",{supervisor!r}],stdin=subprocess.DEVNULL, '
            'stdout=log,stderr=subprocess.STDOUT,start_new_session=True); print(p.pid)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ax', required=True)
    parser.add_argument('--task', required=True, help='Dedicated task; this runner resumes then suspends it')
    parser.add_argument('--bee', default='/workspace/bee-smoke/bee-ax')
    parser.add_argument('--output', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--mock', action='store_true')
    mode.add_argument('--provider', help='Provider TOML already in the remote sandbox')
    mode.add_argument('--vault-openrouter', action='store_true', help='Use the cluster proxy backed by Vault OpenRouter credentials')
    parser.add_argument('--model', default='google/gemini-3.8-flash', help='Model for --vault-openrouter')
    parser.add_argument('--repeats', type=int, default=1)
    parser.add_argument('--corpus', choices=['endpoint', 'source', 'source-v2'], default='endpoint')
    parser.add_argument('--split', choices=['development', 'holdout'], default='development')
    parser.add_argument('--baseline-playbook', type=Path)
    parser.add_argument('--candidate-playbook', type=Path)
    parser.add_argument('--budget-usd', type=float, help='Require an existing non-resetting key cap within this amount; does not change keys')
    parser.add_argument('--max-tokens', type=int, default=2048)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 20:
        parser.error('--repeats must be between 1 and 20')
    if args.budget_usd is not None and not args.vault_openrouter:
        parser.error('--budget-usd requires --vault-openrouter')
    if not 1 <= args.max_tokens <= 32768:
        parser.error('--max-tokens must be between 1 and 32768')
    from playbooks import selected
    playbooks = selected(args.baseline_playbook, args.candidate_playbook, args.corpus)
    args.output.mkdir(parents=True, exist_ok=False)
    remote = '/workspace/bee-evals-' + uuid.uuid4().hex
    def ax(*words, **kwargs):
        return subprocess.run([args.ax, *words], check=True, timeout=kwargs.pop('timeout', 120), **kwargs)
    def ssh(*words, **kwargs):
        return ax('ssh', args.task, '--', *words, **kwargs)
    resumed = False
    try:
        ax('resume', 'task', args.task)
        resumed = True
        if args.vault_openrouter:
            # Validate the existing Vault/ESO/proxy path; never mint a key per run.
            preflight = ('import json,urllib.request; '
                'r=urllib.request.urlopen("http://openrouter-proxy.ax-system.svc.cluster.local/api/v1/key",timeout=15); '
                'd=json.load(r)["data"]; '
                'print(json.dumps({k:d.get(k) for k in ["limit","limit_reset","limit_remaining","usage","expires_at"]}))')
            check = ssh('python3', '-c', preflight, capture_output=True, text=True)
            (args.output / 'openrouter-preflight.json').write_text(check.stdout)
            if args.budget_usd is not None:
                check_budget(json.loads(check.stdout), args.budget_usd)
        ssh('python3', '-c', upload_script(remote))
        for arm, playbook in playbooks.items():
            data = json.dumps({k: playbook[k] for k in ('id', 'version', 'prompt')})
            ssh('python3', '-c', f'from pathlib import Path; Path({remote + "/" + arm + ".json"!r}).write_text({data!r})')
        if args.vault_openrouter:
            config = '[provider]\n' + '\n'.join(f'{k} = {json.dumps(v)}' for k, v in {
                'provider': 'openai-compat', 'model': args.model,
                'base_url': 'http://openrouter-proxy.ax-system.svc.cluster.local/api/v1',
                'api_key_env': 'BEE_API_KEY', 'max_tokens': args.max_tokens}.items()) + '\n'
            args.provider = remote + '/provider.toml'
            ssh('python3', '-c', f'from pathlib import Path; Path({args.provider!r}).write_text({config!r})')
            (args.output / 'provider.toml').write_text(config)
        command = ['python3', remote + '/run.py', '--bee', args.bee, '--output', remote + '/results', '--repeats', str(args.repeats)]
        command += ['--corpus', args.corpus, '--split', args.split]
        command += ['--baseline-playbook', remote + '/baseline.json',
                    '--candidate-playbook', remote + '/candidate.json']
        command += ['--mock'] if args.mock else ['--provider', args.provider]
        # The cluster proxy supplies the actual credential. Never pass a real key here.
        command = ['env', 'BEE_API_KEY=proxy-placeholder', *command]
        episodes = 6 if args.corpus == 'endpoint' else (16 if args.split == 'development' else 8)
        timeout = 110 * episodes * args.repeats + 120
        ssh('python3', '-c', detached_script(remote, command, timeout))
        (args.output / 'ax-remote.json').write_text(json.dumps({'task': args.task, 'remote': remote}) + '\n')
        poll = ('import json; from pathlib import Path; '
                f'p=Path({remote!r}); s=p/"status.json"; r=p/"results"/"results.json"; '
                'print(json.dumps({"status":json.loads(s.read_text()) if s.exists() else None, '
                '"completed":len(json.loads(r.read_text())) if r.exists() else 0}))')
        deadline = time.monotonic() + timeout + 30
        completed = -1
        exit_code = 124
        while time.monotonic() < deadline:
            try:
                state = json.loads(ssh('python3', '-c', poll, capture_output=True, text=True).stdout)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
                time.sleep(5)
                continue
            if state['completed'] != completed:
                completed = state['completed']
                print(f'Completed {completed}/{episodes * args.repeats} episodes', flush=True)
            if state['status'] is not None:
                exit_code = state['status']['exit_code']
                break
            time.sleep(10)
        log = ssh('python3', '-c', f'from pathlib import Path; print(Path({remote + "/driver.log"!r}).read_text())', capture_output=True, text=True)
        (args.output / 'driver.log').write_text(log.stdout)
        # Download without relying on stdin or binary-safe CLI output.
        download = ('import base64,io,zipfile; from pathlib import Path; '
                    f'p=Path({remote!r})/"results"; b=io.BytesIO(); '
                    'z=zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED); '
                    '[z.write(f,str(f.relative_to(p))) for f in p.rglob("*") if f.is_file()]; '
                    'z.close(); print(base64.b64encode(b.getvalue()).decode())')
        archive = ssh('python3', '-c', download, capture_output=True, text=True).stdout
        with zipfile.ZipFile(io.BytesIO(base64.b64decode(archive.strip(), validate=True))) as bundle:
            for name in bundle.namelist():
                target = (args.output / name).resolve()
                if not target.is_relative_to(args.output.resolve()):
                    raise ValueError('unsafe artifact path')
            bundle.extractall(args.output)
        (args.output / 'ax-run.json').write_text(json.dumps({'task': args.task, 'remote': remote, 'exit_code': exit_code}, indent=2)+'\n')
        if args.vault_openrouter:
            check = ssh('python3', '-c', preflight, capture_output=True, text=True)
            (args.output / 'openrouter-postflight.json').write_text(check.stdout)
        return exit_code
    finally:
        if resumed:
            ax('suspend', 'task', args.task)


if __name__ == '__main__':
    raise SystemExit(main())
