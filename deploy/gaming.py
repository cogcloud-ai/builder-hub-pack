#!/usr/bin/env python3
"""Deploy the private preview beside the existing Builder test Hub.

Run on the cluster host with its dedicated KUBECONFIG. Credentials are generated
in Kubernetes and never written into the repository or printed.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import urllib.parse
import urllib.request

NAMESPACE = 'collab-builder'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def kube(*args):
    return json.loads(subprocess.check_output(['kubectl', *args, '-o', 'json']))


def apply(kind, name, spec=None, **fields):
    versions = {'Deployment': 'apps/v1', 'PersistentVolumeClaim': 'v1',
                'Secret': 'v1', 'Service': 'v1', 'Certificate': 'cert-manager.io/v1',
                'NetworkPolicy': 'networking.k8s.io/v1'}
    doc = {'apiVersion': versions[kind], 'kind': kind,
           'metadata': {'name': name, 'namespace': NAMESPACE}, **fields}
    if spec is not None:
        doc['spec'] = spec
    run('kubectl', 'apply', '-f', '-', input=json.dumps(doc), text=True)


def secret():
    response = subprocess.run(['kubectl', '-n', NAMESPACE, 'get', 'secret',
                               'builder-preview-channel', '-o', 'json'],
                              capture_output=True, text=True)
    if response.returncode == 0:
        stored = json.loads(response.stdout)['data']
        return {name: base64.b64decode(value).decode() for name, value in stored.items()}
    if 'NotFound' not in response.stderr:
        raise RuntimeError('Cannot read preview channel secret.')
    values = {name: secrets.token_urlsafe(48) for name in ('workspace-token', 'host-token')}
    apply('Secret', 'builder-preview-channel', stringData=values)
    return values


def owner(origin, username, ca):
    stored = kube('-n', 'collab-builder-infra', 'get', 'secret', 'builder-credentials')['data']
    password = base64.b64decode(stored['admin-password']).decode()
    context = ssl.create_default_context(cadata=ca)
    request = urllib.request.Request(origin + '/auth/realms/master/protocol/openid-connect/token',
        data=urllib.parse.urlencode({'grant_type': 'password', 'client_id': 'admin-cli',
                                    'username': 'admin', 'password': password}).encode())
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        token = json.load(response)['access_token']
    request = urllib.request.Request(origin + '/auth/admin/realms/builder/users?' +
                                    urllib.parse.urlencode({'username': username, 'exact': 'true'}),
                                    headers={'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        users = json.load(response)
    if len(users) != 1 or not users[0].get('enabled'):
        raise ValueError('Expected one enabled local Hub account.')
    return users[0]['id']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', required=True)
    parser.add_argument('--values', required=True, type=Path)
    parser.add_argument('--hub-source', required=True, type=Path)
    parser.add_argument('--image', required=True)
    parser.add_argument('--username', default='trent')
    parser.add_argument('--host-address', default='172.30.0.20')
    args = parser.parse_args()
    if not os.environ.get('KUBECONFIG'):
        parser.error('Set KUBECONFIG to the intended private test cluster.')
    if not re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}', args.image):
        parser.error('Use a loaded immutable image digest.')
    values = json.loads(args.values.read_text())
    origin = args.origin.rstrip('/')
    if not origin.startswith('https://') or values['frames']['auth']['bearer']['issuer'] != origin + '/auth/realms/builder':
        parser.error('Origin must match the existing HTTPS Hub issuer.')
    ca = kube('-n', NAMESPACE, 'get', 'configmap', 'builder-ca')['data']['ca.crt']
    owner_sub = owner(origin, args.username, ca)
    channel = secret()
    client = {'url': 'https://' + args.host_address + ':9443',
              'token': channel['host-token'], 'ca_file': '/etc/builder-host/ca.crt',
              'workspace_root': '/opt/builder-suite'}
    apply('Secret', 'builder-host-client', stringData={'client.json': json.dumps(client), 'ca.crt': ca})
    for name, dns, ip in [('builder-workspace-tls', ['builder-workspace.collab-builder.svc'], []),
                           ('builder-host-tls', ['builder-host'], [args.host_address])]:
        apply('Certificate', name, {'secretName': name, 'issuerRef': {'kind': 'ClusterIssuer', 'name': 'builder-ca'},
                                    'dnsNames': dns, **({'ipAddresses': ip} if ip else {}),
                                    'privateKey': {'algorithm': 'ECDSA', 'size': 256}})
    run('kubectl', '-n', NAMESPACE, 'wait', '--for=condition=Ready', 'certificate/builder-workspace-tls',
        'certificate/builder-host-tls', '--timeout=120s')
    apply('PersistentVolumeClaim', 'builder-workspace', {'accessModes': ['ReadWriteOnce'],
                                                       'resources': {'requests': {'storage': '12Gi'}}})
    apply('Service', 'builder-workspace', {'selector': {'app': 'builder-workspace'},
          'ports': [{'name': 'https', 'port': 8443, 'targetPort': 8443}]})
    security = {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                'capabilities': {'drop': ['ALL']}}
    pod = {'automountServiceAccountToken': False,
           'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'runAsGroup': 1000,
                               'fsGroup': 1000, 'fsGroupChangePolicy': 'OnRootMismatch',
                               'seccompProfile': {'type': 'RuntimeDefault'}},
           'initContainers': [{'name': 'workspace', 'image': args.image, 'imagePullPolicy': 'Never',
               'command': ['python', '-m', 'builder_hub.initialize'],
               'env': [{'name': 'BUILDER_OWNER_SUB', 'value': owner_sub},
                       {'name': 'BUILDER_REFRESH_TRUSTED', 'value': 'true'}],
               'securityContext': security,
               'volumeMounts': [{'name': 'workspace', 'mountPath': '/workspace'},
                                {'name': 'tmp', 'mountPath': '/tmp'}],
               'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'},
                             'limits': {'cpu': '1', 'memory': '512Mi'}}}],
           'containers': [{'name': 'studio', 'image': args.image, 'imagePullPolicy': 'Never',
               'command': ['python', '-m', 'builder_hub.entrypoint'],
               'securityContext': security,
               'ports': [{'name': 'https', 'containerPort': 8443}],
               'env': [{'name': 'BUILDER_WORKSPACE_TOKEN_FILE', 'value': '/etc/builder-channel/token'},
                       {'name': 'BUILDER_TLS_CERT', 'value': '/etc/builder-tls/tls.crt'},
                       {'name': 'BUILDER_TLS_KEY', 'value': '/etc/builder-tls/tls.key'},
                       {'name': 'HOME', 'value': '/tmp/builder-home'},
                       {'name': 'PIXI_HOME', 'value': '/opt/builder-pixi-config'},
                       {'name': 'PIXI_CACHE_DIR', 'value': '/tmp/pixi-cache'}],
               'volumeMounts': [{'name': 'workspace', 'mountPath': '/opt/builder-suite'},
                                {'name': 'tls', 'mountPath': '/etc/builder-tls', 'readOnly': True},
                                {'name': 'host-client', 'mountPath': '/etc/builder-host', 'readOnly': True},
                                {'name': 'channel', 'mountPath': '/etc/builder-channel', 'readOnly': True},
                                {'name': 'execution', 'mountPath': '/etc/builder-execution', 'readOnly': True},
                                {'name': 'tmp', 'mountPath': '/tmp'}],
               'readinessProbe': {'httpGet': {'path': '/health', 'port': 8443, 'scheme': 'HTTPS'},
                                  'initialDelaySeconds': 5},
               'resources': {'requests': {'cpu': '100m', 'memory': '256Mi'},
                             'limits': {'cpu': '2', 'memory': '1536Mi', 'ephemeral-storage': '2Gi'}}}],
           'volumes': [{'name': 'workspace', 'persistentVolumeClaim': {'claimName': 'builder-workspace'}},
                       {'name': 'tls', 'secret': {'secretName': 'builder-workspace-tls', 'defaultMode': 0o440}},
                       {'name': 'host-client', 'secret': {'secretName': 'builder-host-client', 'defaultMode': 0o440}},
                       {'name': 'channel', 'secret': {'secretName': 'builder-preview-channel', 'defaultMode': 0o440,
                            'items': [{'key': 'workspace-token', 'path': 'token'}]}},
                       {'name': 'execution', 'configMap': {'name': 'builder-execution', 'optional': True}},
                       {'name': 'tmp', 'emptyDir': {'sizeLimit': '1Gi'}}]}
    apply('Deployment', 'builder-workspace', {'replicas': 1, 'strategy': {'type': 'Recreate'},
        'selector': {'matchLabels': {'app': 'builder-workspace'}},
        'template': {'metadata': {'labels': {'app': 'builder-workspace'}}, 'spec': pod}})
    apply('NetworkPolicy', 'builder-workspace', {'podSelector': {'matchLabels': {'app': 'builder-workspace'}},
          'policyTypes': ['Ingress'], 'ingress': [{'from': [{'podSelector': {'matchLabels': {
              'app.kubernetes.io/component': 'api'}}}], 'ports': [{'protocol': 'TCP', 'port': 8443}]}]})
    run('kubectl', '-n', NAMESPACE, 'rollout', 'status', 'deployment/builder-workspace', '--timeout=300s')
    # The chart's image repository+tag string accepts the immutable @ digest.
    repository, digest = args.image.split('@', 1)
    values['api']['deployment']['image'] = {'repository': repository, 'tag': 'preview@' + digest, 'pullPolicy': 'Never'}
    entries = {'BUILDER_PUBLIC_ORIGIN': {'value': origin}, 'BUILDER_OWNER_SUB': {'value': owner_sub},
               'BUILDER_WORKSPACE_URL': {'value': 'https://builder-workspace.collab-builder.svc:8443'},
               'BUILDER_WORKSPACE_TOKEN': {'valueFrom': {'secretKeyRef': {
                   'name': 'builder-preview-channel', 'key': 'workspace-token'}}}}
    env = values['api']['deployment']['extraEnv']
    env[:] = [row for row in env if row['name'] not in entries]
    env.extend({'name': name, **value} for name, value in entries.items())
    args.values.write_text(json.dumps(values, indent=2) + '\n')
    run('helm', 'upgrade', 'collab-hub', str(args.hub_source / 'helm/collab-hub'),
        '-n', NAMESPACE, '-f', str(args.values), '--wait', '--timeout', '5m')
    print('Private Builder entry point: ' + origin + '/builder/studio')


if __name__ == '__main__':
    main()
