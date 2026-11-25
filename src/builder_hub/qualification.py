"""Operator-only live checks using short-lived synthetic signed test sessions.

Run inside the Hub API pod. Cookies never leave the process or enter reports.
The synthetic session is revoked afterwards. This is automated test evidence,
not a human review or an IdP login test.
"""
import argparse
import json
import os
import re
import secrets
import ssl
import time
import uuid

import httpx


def main():
    from collab_hub_api.config import Config, build_ended_web_sessions, build_postgres_pools
    from collab_hub_api.web.session import SESSION_COOKIE, SessionCodec, WebSession
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live-build', action='store_true')
    parser.add_argument('--retained-build')
    args = parser.parse_args()
    config = Config.parse()
    codec = SessionCodec(config.web.session_secret)
    origin = os.environ['BUILDER_PUBLIC_ORIGIN']
    owner = os.environ['BUILDER_OWNER_SUB']
    now = int(time.time())
    sid = 'builder-qualification-' + uuid.uuid4().hex
    session = WebSession(user=owner, name='Automated Builder qualification', email=None,
                         csrf=secrets.token_urlsafe(32), issued_at=now, expires_at=now + 3600, sid=sid)
    report = {'scope': 'Automated synthetic-session deployment qualification', 'status': 'PASS'}
    pools = build_postgres_pools(config)
    ended = build_ended_web_sessions(config, pools)
    context = ssl.create_default_context(cafile=os.environ['SSL_CERT_FILE'])
    try:
        with httpx.Client(base_url=origin, verify=context, trust_env=False, follow_redirects=False, timeout=30) as client:
            assert client.get('/builder/studio').status_code == 303
            assert client.get('/builder/api/suite/catalog').status_code == 401
            report['anonymous_page'] = 303; report['anonymous_api'] = 401
            other = WebSession(user='builder-negative-test', name=None, email=None, csrf='test',
                               issued_at=now, expires_at=now + 60, sid=sid + '-other')
            client.cookies.set(SESSION_COOKIE, codec.encode_session(other))
            assert client.get('/builder/studio').status_code == 403
            report['other_identity'] = 403
            client.cookies.set(SESSION_COOKIE, codec.encode_session(session))
            page = client.get('/builder/studio'); page.raise_for_status()
            assert '/builder/api/suite/action' in page.text
            assert 'unsafe-inline' not in page.headers['content-security-policy']
            token = re.search(r'<meta name="cog-workbench-token" content="([a-zA-Z0-9_-]+)">', page.text).group(1)
            report['studio_page'] = 200
            catalog = client.get('/builder/api/suite/catalog'); catalog.raise_for_status()
            bindings = catalog.json()['bindings']
            headers = {'Origin': origin, 'Content-Type': 'application/json',
                       'X-Cog-Workbench': token, 'Sec-Fetch-Site': 'same-origin'}
            bad = client.post('/builder/api/suite/action', headers={**headers, 'Origin': 'https://foreign.invalid'},
                              json={'action': 'smoke-fixture'})
            assert bad.status_code == 403
            report['foreign_origin'] = 403

            def job(body):
                response = client.post('/builder/api/suite/action', headers=headers, json=body)
                response.raise_for_status()
                ident = response.json()['job']
                deadline = time.monotonic() + 1200
                while time.monotonic() < deadline:
                    value = client.get('/builder/api/suite/job', params={'id': ident})
                    value.raise_for_status(); state = value.json()
                    if state['status'] == 'done':
                        return state['result']
                    if state['status'] == 'failed':
                        raise RuntimeError('Qualification operation failed: ' + state['error'])
                    time.sleep(1)
                raise RuntimeError('Qualification operation exceeded its bounded deadline.')

            smoke = job({'action': 'smoke-fixture'})
            assert smoke['outputs']['first_tally']['total_words'] == 21
            assert smoke['outputs']['accumulated_tally']['total_words'] == 31
            report['fixture'] = {'status': 'PASS', 'record_path': smoke['record_path'],
                                 'totals': [21, 31]}
            if args.live_build:
                binding = next(row['reference'] for row in bindings
                               if row['provider']['id'] == 'openteams/cog-claude' and row['status'] == 'admitted')
                name = 'cog-hosted-qualification-' + uuid.uuid4().hex[:6]
                request = {
                    'brief': 'Build one pure code Cog. Input bundle has a texts array of strings. Return payload with total_characters equal to the sum of Python len(text) for every string, including whitespace. Empty array gives zero. Do not write files or access network. Include stdlib unit tests for empty array, Unicode and multiple texts.',
                    'identity': {'cog_request': 1, 'name': name, 'id': 'openteams/' + name,
                                 'summary': 'Synthetic hosted Builder qualification fixture',
                                 'owner': 'Automated qualification on behalf of the workspace owner',
                                 'license': 'Apache-2.0', 'produces': 'task_result', 'kind': 'code',
                                 'prohibits': ['execute_actions', 'send_external_message']},
                    'kind': 'code', 'materials': [], 'max_attempts': 2, 'max_cost_units': 12,
                    'revision_paths': ['src/task_logic.py', 'tests/test_cog.py'], 'test_criterion_ids': [],
                }
                value = job({'action': 'build-start', 'binding': binding, 'request': request})
                ident = value['cycle_dir'].rsplit('/', 1)[-1]
                for _ in range(6):
                    response = client.get('/builder/api/suite/build', params={'id': ident})
                    response.raise_for_status(); current = response.json()
                    if current['status'] in {'completed', 'completed-with-problems', 'refused', 'budget-exhausted', 'rejected'}:
                        break
                    if current['pending']:
                        job({'action': 'build-resume', 'id': ident, 'decision': {
                            'verdict': 'accept', 'by': 'automated-qualification',
                            'reason': 'Automated synthetic integration fixture, not human review or release acceptance.',
                            'step': current['current_step'], 'artifact_sha256': current['pending']['artifact_sha256'],
                            'run_id': current['pending']['run_id']}})
                    elif current['actions']['resume']:
                        job({'action': 'build-resume', 'id': ident})
                    else:
                        raise RuntimeError('Native build cannot continue: ' + current['status'])
                assert current['status'] == 'completed', {'id': ident, 'status': current['status']}
                report['live_build'] = {'id': ident, 'status': current['status'],
                                        'model_turn_budget': 12,
                                        'note': 'Automated fixture acceptance; human review remains separate.'}
            if args.retained_build:
                response = client.get('/builder/api/suite/build', params={'id': args.retained_build})
                response.raise_for_status(); assert response.json()['status'] == 'completed'
                report['retained_build'] = {'id': args.retained_build, 'status': 'completed'}
            ended.end(sid)
            assert client.get('/builder/api/suite/catalog').status_code == 401
            report['revoked_session'] = 401
    finally:
        ended.end(sid)
        pools.close()
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
