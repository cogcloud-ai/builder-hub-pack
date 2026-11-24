#!/usr/bin/env python3
"""Build from exact public source revisions; reuse an explicitly supplied base."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-image')
    parser.add_argument('--tag', default='collab-builder/studio:dev')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    sources = json.loads((root / 'sources.json').read_text())
    with tempfile.TemporaryDirectory(prefix='builder-base-') as folder:
        if not args.base_image:
            source = sources['basePack']
            checkout = Path(folder) / 'coordinator'
            run('git', 'clone', source['url'], str(checkout))
            run('git', '-C', str(checkout), 'checkout', '--detach', source['revision'])
            run('bash', 'pack/build.sh', cwd=checkout)
        base = args.base_image or 'collab-builder/worker:step1'
        run('docker', 'build', '--build-arg', 'BASE_IMAGE=' + base, '-t', args.tag, str(root))


if __name__ == '__main__':
    main()
