"""Populate one persistent owner workspace from the immutable suite image."""
import hashlib
import json
import os
from pathlib import Path
import shutil
from .trust import INVENTORY, checksum, verify, RUNTIME_DIRECTORIES, RUNTIME_FILES


def initialize(source, destination, owner, sources=None, trusted_files=None, refresh=False):
    source, destination = Path(source), Path(destination)
    if not owner:
        raise ValueError('An explicit workspace owner is required.')
    expected = {'owner_sha256': hashlib.sha256(owner.encode()).hexdigest(),
                'sources': sources if sources is not None else json.loads(Path('/opt/builder-hub/sources.json').read_text())}
    marker = destination / '.builder-owner.json'
    pending = destination / '.builder-initializing.json'
    if trusted_files is None and INVENTORY.is_file():
        trusted_files = json.loads(INVENTORY.read_text())
    expected_tree = checksum(trusted_files) if trusted_files is not None else None
    needs_copy = not marker.exists()
    if marker.exists():
        previous = json.loads(marker.read_text())
        if marker.is_symlink() or {key: previous.get(key) for key in expected} != expected:
            raise ValueError('Workspace owner or source pins differ; explicit migration is required.')
        if trusted_files is not None:
            if previous.get('suite_tree_sha256') not in (None, expected_tree):
                if not refresh:
                    raise ValueError('Execution image changed; use an explicit trusted-source refresh.')
                needs_copy = True
            elif previous.get('suite_tree_sha256') is None:
                # Adoption of the initial preview is allowed only when every
                # execution file already matches the image.
                verify(destination, trusted_files)
            else:
                verify(destination, trusted_files)
    else:
        if pending.exists():
            if pending.is_symlink() or json.loads(pending.read_text()) != expected:
                raise ValueError('Incomplete initialization belongs to another owner or revision.')
        elif any(row.name != 'lost+found' for row in destination.iterdir()):
            raise ValueError('Refusing to adopt a nonempty unmarked workspace.')
        else:
            pending.write_text(json.dumps(expected) + '\n')
            pending.chmod(0o600)
    if needs_copy:
        # The PVC root is owned by the provisioner. Copy children without
        # trying to chmod that root to match the image's directory metadata.
        for child in source.iterdir():
            target = destination / child.name
            if child.is_dir() and not child.is_symlink():
                if target.exists() and marker.exists():
                    # Preserve only declared runtime state on an explicit image
                    # refresh. Source and environments are replaced together.
                    for existing in target.iterdir():
                        if existing.name in RUNTIME_DIRECTORIES | RUNTIME_FILES:
                            continue
                        if existing.is_dir() and not existing.is_symlink():
                            shutil.rmtree(existing)
                        else:
                            existing.unlink()
                shutil.copytree(child, target, dirs_exist_ok=True, symlinks=True,
                                ignore=lambda folder, names: RUNTIME_DIRECTORIES | RUNTIME_FILES
                                if Path(folder) == child else ())
            else:
                shutil.copy2(child, target, follow_symlinks=False)
    if trusted_files is not None:
        verify(destination, trusted_files)
        expected['suite_tree_sha256'] = expected_tree
    marker.write_text(json.dumps(expected, indent=2) + '\n')
    marker.chmod(0o600)
    pending.unlink(missing_ok=True)
    for relative in ('cog-workbench/var', 'cog-workbench/var/suite', 'op-cog-builder/cycles'):
        folder = destination / relative
        if folder.is_symlink():
            raise ValueError('Workspace state must use real directories.')
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        folder.chmod(0o700)


if __name__ == '__main__':
    os.umask(0o077)
    initialize('/opt/builder-suite', '/workspace', os.environ.get('BUILDER_OWNER_SUB', ''),
               refresh=os.environ.get('BUILDER_REFRESH_TRUSTED') == 'true')
