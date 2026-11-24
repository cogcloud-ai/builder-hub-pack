"""Populate one persistent owner workspace from the immutable suite image."""
import hashlib
import json
import os
from pathlib import Path
import shutil


def initialize(source, destination, owner):
    source, destination = Path(source), Path(destination)
    if not owner:
        raise ValueError('An explicit workspace owner is required.')
    expected = {'owner_sha256': hashlib.sha256(owner.encode()).hexdigest(),
                'sources': json.loads(Path('/opt/builder-hub/sources.json').read_text())}
    marker = destination / '.builder-owner.json'
    if marker.exists():
        if marker.is_symlink() or json.loads(marker.read_text()) != expected:
            raise ValueError('Workspace owner or source pins differ; explicit migration is required.')
    else:
        if any(destination.iterdir()):
            raise ValueError('Refusing to adopt a nonempty unmarked workspace.')
        shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=True)
        marker.write_text(json.dumps(expected, indent=2) + '\n')
        marker.chmod(0o600)
    for relative in ('cog-workbench/var', 'cog-workbench/var/suite', 'op-cog-builder/cycles'):
        folder = destination / relative
        if folder.is_symlink():
            raise ValueError('Workspace state must use real directories.')
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder.chmod(0o700)


if __name__ == '__main__':
    os.umask(0o077)
    initialize('/opt/builder-suite', '/workspace', os.environ.get('BUILDER_OWNER_SUB', ''))
