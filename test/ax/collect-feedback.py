#!/usr/bin/env python3
"""Extract accepted feedback with stable delivery identities; never publishes."""
import hashlib
import json
import pathlib
import sys

for argument in sys.argv[1:]:
    path = pathlib.Path(argument)
    raw = path.read_bytes()
    transcript = json.loads(raw)
    digest = hashlib.sha256(raw).hexdigest()
    for turn in transcript.get("turns", []):
        for entry in turn.get("calls", []):
            call = entry.get("call", {})
            result = entry.get("result", {})
            if call.get("name") != "feedback" or result.get("is_error") is not False:
                continue
            identity = f"{digest}:{turn['index']}:{call['id']}"
            print(json.dumps({
                "delivery_id": hashlib.sha256(identity.encode()).hexdigest(),
                "transcript_sha256": digest,
                "transcript": str(path),
                "scenario_id": transcript["scenario_id"],
                "model_id": transcript["model_id"],
                "turn": turn["index"],
                "call_id": call["id"],
                "feedback": call["arguments"],
            }))
