"""Assessment receipt protocol. Validation never supplies evaluation labels."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading

VERSION = 1
MAX_BYTES = 16384


def validate(value, events, sources):
    if not isinstance(value, dict) or set(value) != {'assessment', 'rationale', 'requests', 'sources', 'limitations'}:
        raise ValueError('Expected exactly assessment, rationale, requests, sources, limitations')
    if value['assessment'] not in ('confirmed', 'refuted', 'blocked'):
        raise ValueError('assessment must be confirmed, refuted, or blocked')
    for field in ('rationale', 'limitations'):
        if not isinstance(value[field], str) or not value[field].strip() or len(value[field]) > 4000:
            raise ValueError(f'{field} must contain 1–4000 characters')
    refs = value['requests']
    if not isinstance(refs, list) or not refs or len(refs) > 64 or any(type(i) is not int or not 1 <= i <= len(events) for i in refs) or len(set(refs)) != len(refs):
        raise ValueError('requests must contain unique observed request IDs from GET /observations')
    refs = value['sources']
    if not isinstance(refs, list) or len(refs) > 32 or (sources and not refs):
        raise ValueError('sources must be an array, nonempty for source tasks, at most 32 references')
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {'path', 'start', 'end'}:
            raise ValueError('Each source reference requires path, start, end')
        path, start, end = ref['path'], ref['start'], ref['end']
        if not isinstance(path, str) or path not in sources or type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(sources[path].splitlines()):
            raise ValueError('Source reference must name a supplied file and valid inclusive line range')
    return value


def accepted(attempts, events, sources):
    """Replay receipts; a later invalid submission cannot replace an accepted one."""
    if not isinstance(attempts, list):
        raise ValueError('Submission attempts must be an array')
    answer = None
    previous_count = 0
    for attempt in attempts:
        if not isinstance(attempt, dict) or set(attempt) != {'value', 'observed_requests', 'accepted'}:
            raise ValueError('Malformed submission attempt')
        count = attempt['observed_requests']
        if type(count) is not int or not previous_count <= count <= len(events):
            raise ValueError('Invalid submission observation count')
        previous_count = count
        value = attempt.get('value')
        try:
            validate(value, events[:attempt['observed_requests']], sources)
            valid = answer is None or answer == value
        except (ValueError, TypeError, KeyError):
            valid = False
        if attempt.get('accepted') is not valid:
            raise ValueError('Submission receipt differs from validation')
        if valid:
            answer = value
    return answer


class Receiver:
    def __init__(self, events, sources):
        self.attempts = []
        self.answer = None
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, code, value):
                raw = json.dumps(value).encode()
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                if self.path != '/observations':
                    self.reply(404, {'error': 'Unknown receipt endpoint'})
                    return
                self.reply(200, [{'id': i, **event} for i, event in enumerate(events, 1)])

            def do_POST(self):
                if self.path != '/assessment':
                    self.reply(404, {'error': 'Unknown receipt endpoint'})
                    return
                value = None
                count = len(events)
                try:
                    size = int(self.headers.get('Content-Length', '0'))
                    if not 0 < size <= MAX_BYTES:
                        raise ValueError('Body must contain 1–16384 bytes')
                    self.connection.settimeout(3)
                    value = json.loads(self.rfile.read(size))
                    validate(value, events[:count], sources)
                    if owner.answer is not None and value != owner.answer:
                        raise ValueError('An assessment was already accepted; conflicting replacement refused')
                except (ValueError, TypeError, OSError) as error:
                    owner.attempts.append({'value': value, 'observed_requests': count, 'accepted': False})
                    self.reply(400, {'accepted': False, 'error': str(error)})
                    return
                owner.answer = value
                owner.attempts.append({'value': value, 'observed_requests': count, 'accepted': True})
                self.reply(200, {'accepted': True, 'note': 'Receipt only; correctness is scored separately'})
        # Serial request handling makes first accepted submission unambiguous.
        self.server = HTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.server.server_port}'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def instructions(url):
    return (f' Submit your assessment to the evaluator receipt service at {url}/assessment using HTTP POST JSON. '
            f'GET {url}/observations lists only your recorded target requests with 1-based IDs. '
            'Required fields: assessment (confirmed, refuted, blocked), rationale (nonempty string), '
            'requests (array of supporting request IDs), sources (array of {path,start,end} inclusive line references; '
            'empty for endpoint-only tasks), limitations (nonempty string). '
            'Read the response; repair rejected submissions within your existing budget. Once accepted the assessment is final. '
            'Then end the episode; final prose is not scored. A receipt validates structure and references, not correctness. '
            'Use blocked when unavailable runtime prevents verification; failure to reproduce alone does not establish refutation. '
            'X-User represents trusted, already-authenticated identity; changing it selects a test principal, not an authentication bypass.')
