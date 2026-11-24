"""Verify persistent execution files against the immutable image inventory."""
import hashlib
import json
import os
from pathlib import Path
import stat

RUNTIME_DIRECTORIES = {'var', 'cycles', 'runs', 'candidates'}
RUNTIME_FILES = {'.op-composition.json'}
INVENTORY = Path('/opt/builder-hub/suite-files.json')


def inventory(root):
    root = Path(root)
    manifest = json.loads((root / 'cog-op-builder/repositories.json').read_text())
    names = ['cog-op-builder', *[row['name'] for row in manifest['repositories']]]
    files = {}
    def visit(folder, relative, depth):
        for entry in sorted(os.scandir(folder), key=lambda row: row.name):
            if entry.name == '.git' or (depth == 0 and entry.name in RUNTIME_DIRECTORIES | RUNTIME_FILES):
                continue
            path = Path(entry.path)
            name = relative + '/' + entry.name
            if entry.is_symlink():
                files[name] = {'link': os.readlink(path)}
            elif entry.is_dir(follow_symlinks=False):
                visit(path, name, depth + 1)
            elif entry.is_file(follow_symlinks=False):
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                files[name] = {'sha256': digest.hexdigest(), 'executable': bool(path.stat().st_mode & 0o111)}
            else:
                raise ValueError('Unexpected special file in trusted source.')
    for name in names:
        if (root / name).is_symlink() or not (root / name).is_dir():
            raise ValueError('Missing trusted package directory: ' + name)
        visit(root / name, name, 0)
    return files


def checksum(files):
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def verify(root, expected=None):
    expected = json.loads(INVENTORY.read_text()) if expected is None else expected
    if inventory(root) != expected:
        raise ValueError('Persistent suite execution files differ from the immutable image. Refusing execution.')


if __name__ == '__main__':
    INVENTORY.write_text(json.dumps(inventory('/opt/builder-suite'), sort_keys=True) + '\n')
