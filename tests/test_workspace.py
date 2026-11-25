import json
from pathlib import Path
import threading
from types import SimpleNamespace

import httpx
import pytest

from builder_hub import workspace as ws


class FakeSuite:
    def relative(self, value):
        if not isinstance(value, str) or value.startswith('/') or '..' in value:
            raise ValueError('invalid path')
        return value

    def catalog(self):
        return [{'path': 'cog-claude', 'provider': {'id': 'claude'}},
                {'path': 'cog-other', 'provider': {'id': 'other'}},
                {'path': 'cog-smith', 'provider': None}]

    def bindings(self):
        return []

    def builder_runs(self):
        return []


@pytest.fixture
def server(tmp_path, monkeypatch):
    surface = SimpleNamespace(TOKEN='page-token', LOCK=threading.Lock(), JOBS={})
    monkeypatch.setattr(ws, 'initialize', lambda path: (FakeSuite, surface))
    server = ws.WorkspaceServer(('127.0.0.1', 0), tmp_path, 'x' * 48)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    with httpx.Client(base_url='http://127.0.0.1:' + str(server.server_port),
                      headers={'Authorization': 'Bearer ' + 'x' * 48}, trust_env=False) as client:
        yield client, server
    server.shutdown()
    server.server_close()
    thread.join()


def test_private_data_requires_internal_auth(server):
    client, _ = server
    assert client.get('/api/suite/catalog', headers={'Authorization': 'forged'}).status_code == 401
    response = client.get('/api/suite/catalog')
    assert response.status_code == 200
    assert [row['path'] for row in response.json()['catalog']] == ['cog-claude', 'cog-smith']


@pytest.mark.parametrize('path', ['/api/browse', '/api/procs', '/api/chat', '/', '/studio/../api/browse'])
def test_legacy_surface_is_absent(server, path):
    client, _ = server
    assert client.get(path).status_code == 404


@pytest.mark.parametrize('body', [
    {'action': 'gateway'}, {'action': 'evaluate'},
    {'action': 'verify', 'operation': 'test'}, {'action': 'verify', 'operation': 'install'},
    {'action': 'invoke', 'context': 'cog-generated'},
    {'action': 'bind', 'provider': 'cog-chatgpt'}, {'action': 'arbitrary-shell'}, [],
])
def test_unsafe_operations_are_refused_server_side(server, body):
    client, _ = server
    response = client.post('/api/suite/action', headers={'X-Cog-Workbench': 'page-token'}, json=body)
    assert response.status_code == 400


def test_action_requires_page_token_and_body_limit(server):
    client, _ = server
    assert client.post('/api/suite/action', json={'action': 'smoke-fixture'}).status_code == 403
    assert client.post('/api/suite/action', headers={'X-Cog-Workbench': 'page-token'},
                       content=b'x' * (ws.MAX_BODY + 1)).status_code == 413


def test_execution_has_no_ambient_fallback(tmp_path, monkeypatch):
    policy = tmp_path / 'policy.json'
    monkeypatch.setenv('BUILDER_EXECUTION_POLICY_FILE', str(policy))
    assert ws.execution_policy() is None
    policy.write_text(json.dumps({'mode': 'trusted-local', 'qualified': True}))
    with pytest.raises(ValueError):
        ws.execution_policy()
    policy.write_text(json.dumps({'mode': 'docker', 'qualified': True, 'image': 'sha256:' + 'a' * 64,
                                 'timeout_seconds': 6000}))
    assert ws.execution_policy() == {'mode': 'docker', 'image': 'sha256:' + 'a' * 64,
                                     'timeout_seconds': 60, 'output_bytes': 1048576}


def test_idle_connection_does_not_block_workspace_tls(tmp_path, monkeypatch):
    import socket
    import ssl
    from test_host_bridge import _generate_self_signed_tls
    cert, key = _generate_self_signed_tls(tmp_path)
    monkeypatch.setattr(ws, 'initialize', lambda path: (FakeSuite, SimpleNamespace()))
    server = ws.WorkspaceServer(('127.0.0.1', 0), tmp_path, 'x' * 48)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        with socket.create_connection(('127.0.0.1', server.server_port), timeout=2):
            verify = ssl.create_default_context(cafile=str(cert))
            with httpx.Client(verify=verify, trust_env=False, timeout=2) as client:
                assert client.get('https://127.0.0.1:' + str(server.server_port) + '/health').status_code == 200
    finally:
        server.shutdown(); server.server_close(); thread.join()
