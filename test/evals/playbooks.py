"""Explicit, bounded playbook inputs and canonical provenance hashes."""
import hashlib
import json
from pathlib import Path


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def load(path):
    raw = Path(path).read_bytes()
    if len(raw) > 16384:
        raise ValueError('playbook exceeds 16 KiB')
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {'id', 'version', 'prompt'}:
        raise ValueError('playbook requires exactly id, version, prompt')
    if any(not isinstance(value[k], str) or not value[k].strip() for k in value):
        raise ValueError('playbook fields must be nonempty strings')
    return {**value, 'sha256': fingerprint(value)}


def selected(baseline, candidate, corpus):
    root = Path(__file__).parent / 'playbooks'
    return {'baseline': load(baseline or root / 'baseline-v1.json'),
            'candidate': load(candidate or root / f"{'source' if corpus == 'source-v2' else corpus}-guided-v1.json")}
