#!/usr/bin/env python3
"""Build from exact public source revisions; reuse an explicitly supplied base."""
import argparse
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-image')
    parser.add_argument('--tag', default='collab-builder/studio:dev')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    dirty = subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True)
    if dirty.strip():
        parser.error('Commit the source before building a reviewable image.')
    revision = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    sources = json.loads((root / 'sources.json').read_text())
    with tempfile.TemporaryDirectory(prefix='builder-base-') as folder:
        if not args.base_image:
            source = sources['basePack']
            checkout = Path(folder) / 'coordinator'
            run('git', 'clone', source['url'], str(checkout))
            run('git', '-C', str(checkout), 'checkout', '--detach', source['revision'])
            foundation = json.loads((checkout / 'pack/sources.json').read_text())
            if any(foundation[key] != sources[key] for key in ('suite', 'hub')):
                parser.error('Foundation source pins differ from the integration pins.')
            run('bash', 'pack/build.sh', cwd=checkout)
        base = args.base_image or 'collab-builder/worker:step1'
        base_digest = subprocess.check_output(['docker', 'image', 'inspect', base, '--format', '{{.Id}}'], text=True).strip()
        archive = Path(folder) / 'source.tar'
        with archive.open('wb') as stream:
            run('git', '-C', str(root), 'archive', '--format=tar', revision, stdout=stream)
        context = Path(folder) / 'context'; context.mkdir()
        with tarfile.open(archive) as stream:
            stream.extractall(context, filter='data')
        run('docker', 'build', '--build-arg', 'BASE_IMAGE=' + base, '-t', args.tag,
            '--label', 'org.opencontainers.image.revision=' + revision,
            '--label', 'org.opencontainers.image.base.digest=' + base_digest, str(context))
        after = subprocess.check_output(['docker', 'image', 'inspect', base, '--format', '{{.Id}}'], text=True).strip()
        if after != base_digest:
            raise RuntimeError('Foundation tag changed during the build; refuse this image.')


if __name__ == '__main__':
    main()
