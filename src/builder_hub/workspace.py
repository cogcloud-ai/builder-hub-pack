"""Owner workspace adapter around the pinned public Studio and Suite.

Only Studio's declared surface is exposed. Generic Workbench filesystem and
process endpoints are deliberately absent. Hub identity lives in another pod.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid

MAX_BODY = 4 * 1024 * 1024
READS = {'/studio', '/api/suite/catalog', '/api/suite/builds',
         '/api/suite/build', '/api/suite/job'}
CONTEXTS = {'cog-op-designer', 'cog-author', 'cog-build-evaluator'}
PROVIDERS = {'cog-claude'}
POLICY_MESSAGE = ('Generated-code execution is disabled until its isolation is qualified. '
                  'Design, authoring, packaging and saved evidence remain available.')


def execution_policy():
    path = Path(os.environ.get('BUILDER_EXECUTION_POLICY_FILE', '/etc/builder-execution/policy.json'))
    if not path.is_file():
        return None
    value = json.loads(path.read_text())
    if isinstance(value, dict) and value.get('qualified') is False:
        return None
    if not isinstance(value, dict) or value.get('qualified') is not True or value.get('mode') != 'docker' or not re.fullmatch(r'sha256:[a-f0-9]{64}', value.get('image', '')):
        raise ValueError('Execution qualification is missing or invalid.')
    return {'mode': 'docker', 'image': value['image'], 'timeout_seconds': 60, 'output_bytes': 1048576}


def initialize(workspace: Path):
    workspace = workspace.resolve(strict=True)
    sys.path.insert(0, str(workspace / 'cog-workbench/src'))
    import workbench_suite
    import suite_web

    class HostedSuite(workbench_suite.Suite):
        def __init__(self, *args, **kwargs):
            super().__init__(workspace=workspace, state=workspace / 'cog-workbench/var/suite',
                             journal=journal)

        def call(self, root, task, *args, **kwargs):
            # Only public manifest packages may execute in this service. Generated
            # package checks go through Smith, which parses rather than runs them.
            name = self.relative(root)
            if '/' in name or name not in self.trusted_packages:
                raise ValueError(POLICY_MESSAGE)
            return super().call(root, task, *args, **kwargs)

        def start_builder(self, request, binding):
            # Starting the native Op pauses at its contract Gate. Continuing an
            # accepted contract would reach generated code and is refused below.
            request = dict(request)
            if 'execution_policy' in request:
                raise ValueError('Execution policy is configured by the deployment.')
            if request.get('reference'):
                raise ValueError('Reference packages are not enabled in this hosted preview.')
            if type(request.get('max_attempts')) is not int or not 1 <= request['max_attempts'] <= 5:
                raise ValueError('Choose between one and five rounds.')
            if type(request.get('max_cost_units')) is not int or not 0 <= request['max_cost_units'] <= 30:
                raise ValueError('Choose a model turn budget between zero and thirty.')
            policy = execution_policy()
            if policy:
                request['execution_policy'] = policy
            else:
                # A missing qualified image must never select upstream's
                # trusted-local compatibility default, even if resumed elsewhere.
                request['execution_policy'] = {'mode': 'docker', 'image': 'sha256:' + '0' * 64,
                                               'timeout_seconds': 60, 'output_bytes': 1048576}
            return super().start_builder(request, binding)

        def resume_builder(self, ident, decision=None):
            if decision and decision.get('verdict') == 'reject':
                return super().resume_builder(ident, decision)
            policy = execution_policy()
            run = self.inspect_builder(ident)
            if not policy or run['cycle']['request'].get('execution_policy') != policy:
                raise ValueError(POLICY_MESSAGE + ' Start a new build after qualification.')
            return super().resume_builder(ident, decision)

        def verify(self, root, operation):
            if operation != 'check':
                raise ValueError(POLICY_MESSAGE)
            return super().verify(root, operation)

        def package(self, request, envelope, destination):
            root = self.root(destination)
            if root.parent != self.workspace or root.name in self.trusted_packages | {'cog-op-builder'} or not re.fullmatch(r'cog-[a-z0-9]+(?:-[a-z0-9]+)*', root.name):
                raise ValueError('New packages must be direct workspace children with a Cog name.')
            return super().package(request, envelope, destination)

        def evaluate(self, *args, **kwargs):
            raise ValueError(POLICY_MESSAGE)

    manifest = json.loads((workspace / 'cog-op-builder/repositories.json').read_text())
    HostedSuite.trusted_packages = {row['name'] for row in manifest['repositories']}
    suite_web.Suite = HostedSuite
    return HostedSuite, suite_web


_journal_path: Path | None = None


def journal(entry=None, **fields):
    if _journal_path is None:
        return
    _journal_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    record = {'ts': time.time(), **(entry or {}), **fields}
    with _journal_path.open('a') as stream:
        stream.write(json.dumps(record) + '\n')


def permitted(body, suite):
    if not isinstance(body, dict):
        raise ValueError('Expected a JSON object.')
    action = body.get('action')
    if action == 'invoke' and suite.relative(body.get('context', '')) not in CONTEXTS:
        raise ValueError('Only the designer, author and evaluator may be invoked.')
    if action == 'bind' and suite.relative(body.get('provider', '')) not in PROVIDERS:
        raise ValueError('Unsupported hosted provider.')
    if action == 'bind':
        request = body.get('request', {})
        if not isinstance(request, dict) or not isinstance(request.get('configuration'), dict) or not isinstance(request.get('requirement'), dict):
            raise ValueError('Invalid hosted binding request.')
        if (request.get('configuration', {}).get('model_id') != 'sonnet' or
                request.get('requirement', {}).get('model_id') != 'sonnet'):
            raise ValueError('This deployment admits the configured Claude sonnet selector only.')
    if action == 'verify' and body.get('operation') != 'check':
        raise ValueError(POLICY_MESSAGE)
    if action in {'gateway', 'evaluate'}:
        raise ValueError(POLICY_MESSAGE)
    if action not in {'invoke', 'bind', 'verify', 'handoff', 'package', 'snapshot',
                      'revoke', 'build-start', 'build-resume', 'smoke-fixture'}:
        raise ValueError('Unknown hosted action.')


def fixture(workspace, suite):
    package = workspace / 'op-builder-smoke'
    python = package / '.pixi/envs/default/bin/python'
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(('COLLAB_', 'BUILDER_', 'PIXI_'))
                   and key not in {'OPENROUTER_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY'}}
    with tempfile.TemporaryDirectory(prefix='builder-smoke-') as directory:
        result = subprocess.run([str(python), 'src/op_runner.py', '--request',
                                 'examples/request.json', '--runs-dir', directory],
                                cwd=package, env=environment, capture_output=True,
                                text=True, timeout=120)
        if result.returncode:
            raise ValueError('The trusted integration fixture failed; inspect service logs.')
        summary = json.loads(result.stdout)
        run = Path(summary['run_dir'])
        artifacts = {str(path.relative_to(run)): json.loads(path.read_text())
                     for path in sorted(run.rglob('*.json'))}
        if summary['outputs']['first_tally']['total_words'] != 21 or summary['outputs']['accumulated_tally']['total_words'] != 31:
            raise ValueError('Integration fixture totals did not match.')
        value = {'status': 'passed', 'scope': 'Trusted model-free integration fixture',
                 'outputs': summary['outputs'], 'native_track': artifacts['track.json'],
                 'artifacts': artifacts}
        value['record_path'] = suite.save('hosted-fixtures', value)
        return value


class WorkspaceServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, workspace, token):
        self.workspace = Path(workspace).resolve()
        self.suite_type, self.surface = initialize(self.workspace)
        self.token = token
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='builder')
        self.busy = threading.Lock()
        super().__init__(address, WorkspaceHandler)

    def server_close(self):
        super().server_close()
        self.executor.shutdown(wait=False, cancel_futures=True)


class WorkspaceHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    timeout = 15

    def log_message(self, *args):
        # Request bodies, cookies, query strings and provider results aren't logs.
        pass

    def _send(self, code, payload, content_type='application/json'):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def authorized(self):
        headers = self.headers.get_all('Authorization', [])
        return len(headers) == 1 and hmac.compare_digest(headers[0].encode(), ('Bearer ' + self.server.token).encode())

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == '/health' and not parsed.query:
            return self._send(200, {'status': 'ready'})
        if not self.authorized():
            return self._send(401, {'error': 'authentication required'})
        if parsed.path not in READS:
            return self._send(404, {'error': 'not found'})
        query = dict(urllib.parse.parse_qsl(parsed.query))
        try:
            if parsed.path == '/studio':
                from .studio import render
                template = (self.server.workspace / 'cog-workbench/src/studio.html').read_text()
                page = render(template, self.server.surface.TOKEN, execution_policy() is not None)
                return self._send(200, page.encode(), 'text/html; charset=utf-8')
            suite = self.server.suite_type()
            if parsed.path.endswith('/catalog'):
                result = {'catalog': [row for row in suite.catalog() if not row.get('provider') or suite.relative(row['path']) in PROVIDERS],
                          'bindings': suite.bindings()}
            elif parsed.path.endswith('/builds'):
                result = {'runs': suite.builder_runs()}
            elif parsed.path.endswith('/build'):
                result = suite.inspect_builder(query.get('id'))
            else:
                with self.server.surface.LOCK:
                    result = self.server.surface.JOBS.get(query.get('id'), {'status': 'missing'})
            return self._send(200, result)
        except (ValueError, OSError, KeyError, TypeError):
            return self._send(400, {'error': 'Unable to read this workspace record.'})

    def do_POST(self):
        if not self.authorized():
            return self._send(401, {'error': 'authentication required'})
        if self.path != '/api/suite/action':
            return self._send(404, {'error': 'not found'})
        page_tokens = self.headers.get_all('X-Cog-Workbench', [])
        if len(page_tokens) != 1 or not hmac.compare_digest(page_tokens[0].encode(), self.server.surface.TOKEN.encode()):
            return self._send(403, {'error': 'Reload Studio before submitting.'})
        try:
            if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) != 1:
                raise ValueError('One bounded content length is required.')
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= MAX_BODY:
                return self._send(413, {'error': 'Request too large or empty.'})
            if self.headers.get_content_type() != 'application/json':
                return self._send(415, {'error': 'Use application/json.'})
            self.connection.settimeout(15)
            data = self.rfile.read(size)
            if len(data) != size:
                raise ValueError('Incomplete request.')
            body = json.loads(data)
            suite = self.server.suite_type()
            permitted(body, suite)
            if not self.server.busy.acquire(blocking=False):
                return self._send(409, {'error': 'Another operation is running; wait for it to finish.'})
            ident = str(uuid.uuid4())
            with self.server.surface.LOCK:
                self.server.surface.JOBS[ident] = {'status': 'working', 'action': body['action']}
            def work():
                try:
                    if body['action'] == 'smoke-fixture':
                        result = fixture(self.server.workspace, suite)
                    else:
                        # Reuse the upstream dispatch; wait on its one local job.
                        upstream = self.server.surface.start(suite, body)['job']
                        while True:
                            with self.server.surface.LOCK:
                                state = self.server.surface.JOBS[upstream].copy()
                            if state['status'] != 'working':
                                break
                            time.sleep(.1)
                        if state['status'] == 'failed':
                            raise ValueError(state['error'])
                        result = state['result']
                    path = suite.save('hosted-jobs', {'action': body['action'], 'result': result})
                    state = {'status': 'done', 'result': result, 'record_path': path}
                except Exception as exc:
                    state = {'status': 'failed', 'error': str(exc) if isinstance(exc, ValueError)
                             else 'Operation failed; inspect workspace configuration.'}
                    journal({'event': 'hosted-operation-failed', 'error_type': type(exc).__name__})
                finally:
                    self.server.busy.release()
                with self.server.surface.LOCK:
                    self.server.surface.JOBS[ident] = state
                    while len(self.server.surface.JOBS) > 200:
                        old = next((key for key, value in self.server.surface.JOBS.items()
                                    if key != ident and value['status'] != 'working'), None)
                        if old is None:
                            break
                        del self.server.surface.JOBS[old]
            self.server.executor.submit(work)
            return self._send(202, {'job': ident})
        except (ValueError, TypeError, KeyError):
            return self._send(400, {'error': 'Invalid or unavailable hosted operation.'})


def main():
    global _journal_path
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path('/opt/builder-suite'))
    parser.add_argument('--port', type=int, default=8443)
    args = parser.parse_args()
    token_file = os.environ.get('BUILDER_WORKSPACE_TOKEN_FILE')
    token = Path(token_file).read_text().strip() if token_file else os.environ.get('BUILDER_WORKSPACE_TOKEN', '')
    if len(token) < 32:
        parser.error('A private workspace service token of at least 32 characters is required.')
    _journal_path = args.workspace / 'cog-workbench/var/hosted-activity.jsonl'
    server = WorkspaceServer(('0.0.0.0', args.port), args.workspace, token)
    os.environ.pop('BUILDER_WORKSPACE_TOKEN', None)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(os.environ['BUILDER_TLS_CERT'], os.environ['BUILDER_TLS_KEY'])
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    server.serve_forever()


if __name__ == '__main__':
    main()
