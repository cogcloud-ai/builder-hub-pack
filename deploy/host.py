#!/usr/bin/env python3
"""Run the restricted host bridge on the private kind Docker network.

Only this trusted bridge receives the native vendor store and Docker authority.
Studio and generated verification containers receive neither. Existing vendor
files are bind-mounted in place, never copied into Kubernetes or this repository.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess


def kube_secret(name):
    value = json.loads(subprocess.check_output(['kubectl', '-n', 'collab-builder',
                                              'get', 'secret', name, '-o', 'json']))
    return {key: base64.b64decode(data) for key, data in value['data'].items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--verify-image', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--claude', type=Path, default=Path.home() / '.local/bin/claude')
    parser.add_argument('--address', default='172.30.0.20')
    args = parser.parse_args()
    if not os.environ.get('KUBECONFIG'):
        parser.error('Set the dedicated test KUBECONFIG.')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', args.verify_image):
        parser.error('Verification image must be an immutable local image ID.')
    os.umask(0o077)
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    private = directory / 'private'; private.mkdir(exist_ok=True, mode=0o700)
    staging = directory / 'staging'; staging.mkdir(exist_ok=True, mode=0o700)
    tls = kube_secret('builder-host-tls')
    for key in ('tls.crt', 'tls.key'):
        path = private / key
        path.write_bytes(tls[key]); path.chmod(0o600)
    token = kube_secret('builder-preview-channel')['host-token'].decode()
    environment = {
        'BUILDER_HOST_TOKEN': token, 'BUILDER_HOST_BIND': '0.0.0.0',
        'BUILDER_HOST_PORT': '9443', 'BUILDER_HOST_TLS_CERT': str(private / 'tls.crt'),
        'BUILDER_HOST_TLS_KEY': str(private / 'tls.key'),
        'BUILDER_CLAUDE_CLI': '/opt/vendor/claude',
        'BUILDER_DOCKER_CLI': '/opt/vendor/docker',
        'BUILDER_VERIFY_IMAGE': args.verify_image, 'BUILDER_STAGING_ROOT': str(staging),
        'HOME': '/home/nonroot', 'CLAUDE_CONFIG_DIR': '/home/nonroot/.claude',
    }
    env_file = private / 'host.env'
    if any('\n' in value or '\r' in value for value in environment.values()):
        parser.error('Environment values may not contain newlines.')
    env_file.write_text(''.join(key + '=' + value + '\n' for key, value in environment.items()))
    env_file.chmod(0o600)
    docker = Path('/usr/bin/docker')
    if not docker.is_file():
        parser.error('Install the host Docker CLI at /usr/bin/docker.')
    vendor = Path.home() / '.claude'
    config = Path.home() / '.claude.json'
    if not args.claude.is_file() or not (vendor / '.credentials.json').is_file() or not config.is_file():
        parser.error('Use the native Claude CLI to sign in on this host first.')
    image = subprocess.check_output(['docker', 'image', 'inspect', args.image, '--format', '{{.Id}}'], text=True).strip()
    existing = subprocess.run(['docker', 'inspect', 'builder-host-services'], capture_output=True)
    if existing.returncode == 0:
        subprocess.run(['docker', 'rm', '-f', 'builder-host-services'], check=True, stdout=subprocess.DEVNULL)
    mounts = [(private, private, True), (staging, staging, False),
              (args.claude.resolve(), Path('/opt/vendor/claude'), True),
              (docker, Path('/opt/vendor/docker'), True),
              (Path('/var/run/docker.sock'), Path('/var/run/docker.sock'), False),
              (vendor, Path('/home/nonroot/.claude'), False),
              (config, Path('/home/nonroot/.claude.json'), False)]
    command = ['docker', 'run', '-d', '--name', 'builder-host-services', '--restart', 'unless-stopped',
               '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--user', str(os.getuid()) + ':' + str(os.getgid()),
               '--group-add', str(Path('/var/run/docker.sock').stat().st_gid),
               '--network', 'kind', '--ip', args.address, '--cpus', '1.5', '--memory', '1g',
               '--pids-limit', '128', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777',
               '--env-file', str(env_file)]
    for source, destination, readonly in mounts:
        if ',' in str(source) or ',' in str(destination):
            parser.error('Mount paths may not contain commas.')
        command.extend(['--mount', 'type=bind,src=' + str(source) + ',dst=' + str(destination) + (',readonly' if readonly else '')])
    command.extend(['--entrypoint', 'python', image, '-m', 'builder_hub.host_bridge', 'serve'])
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
    print('Restricted host bridge started on the private kind network.')


if __name__ == '__main__':
    main()
