import json
from pathlib import Path

import pytest

from builder_hub.initialize import initialize


def test_owner_and_sources_cannot_be_changed(tmp_path):
    source = tmp_path / 'source'
    destination = tmp_path / 'destination'
    source.mkdir(); destination.mkdir()
    (source / 'cog-workbench').mkdir()
    initialize(source, destination, 'owner-one', {'suite': 'revision-one'})
    state = destination / 'cog-workbench/var/suite'
    assert state.stat().st_mode & 0o777 == 0o700
    (state / 'retained.json').write_text('retained')
    initialize(source, destination, 'owner-one', {'suite': 'revision-one'})
    assert (state / 'retained.json').read_text() == 'retained'
    with pytest.raises(ValueError):
        initialize(source, destination, 'owner-two', {'suite': 'revision-one'})
    with pytest.raises(ValueError):
        initialize(source, destination, 'owner-one', {'suite': 'revision-two'})


def test_partial_copy_can_resume_only_with_matching_pending_marker(tmp_path):
    source = tmp_path / 'source'; source.mkdir()
    (source / 'package').mkdir(); (source / 'package/data').write_text('complete')
    destination = tmp_path / 'destination'; destination.mkdir()
    (destination / 'partial').write_text('existing')
    with pytest.raises(ValueError):
        initialize(source, destination, 'owner', {})
    import hashlib
    pending = destination / '.builder-initializing.json'
    pending.write_text(json.dumps({'owner_sha256': hashlib.sha256(b'owner').hexdigest(), 'sources': {}}))
    initialize(source, destination, 'owner', {})
    assert not pending.exists()
    assert (destination / 'package/data').read_text() == 'complete'


def test_explicit_image_refresh_preserves_state_but_tampering_fails(tmp_path):
    from builder_hub.trust import inventory
    source = tmp_path / 'source'; destination = tmp_path / 'destination'
    source.mkdir(); destination.mkdir()
    package = source / 'cog-op-builder'; package.mkdir()
    (package / 'repositories.json').write_text('{"repositories":[]}')
    (package / 'source.py').write_text('original')
    first = inventory(source)
    initialize(source, destination, 'owner', {}, first)
    runtime = destination / 'cog-op-builder/var'; runtime.mkdir()
    (runtime / 'evidence').write_text('retained')
    (package / 'source.py').write_text('updated image')
    second = inventory(source)
    with pytest.raises(ValueError):
        initialize(source, destination, 'owner', {}, second)
    initialize(source, destination, 'owner', {}, second, refresh=True)
    assert (runtime / 'evidence').read_text() == 'retained'
    assert (destination / 'cog-op-builder/source.py').read_text() == 'updated image'
    (destination / 'cog-op-builder/source.py').write_text('tampered')
    with pytest.raises(ValueError):
        initialize(source, destination, 'owner', {}, second, refresh=True)


def test_interrupted_copy_with_environment_symlinks_can_resume(tmp_path):
    import hashlib
    import shutil
    source = tmp_path / 'source'; source.mkdir()
    package = source / 'package'; package.mkdir()
    (package / 'real').write_text('source')
    (package / 'link').symlink_to('real')
    destination = tmp_path / 'destination'; destination.mkdir()
    shutil.copytree(package, destination / 'package', symlinks=True)
    (destination / '.builder-initializing.json').write_text(json.dumps({
        'owner_sha256': hashlib.sha256(b'owner').hexdigest(), 'sources': {}}))
    initialize(source, destination, 'owner', {})
    assert (destination / 'package/link').is_symlink()
    assert (destination / 'package/link').read_text() == 'source'


def test_initialization_does_not_follow_package_or_runtime_symlinks(tmp_path):
    import hashlib
    source = tmp_path / 'source'; source.mkdir()
    (source / 'package').mkdir()
    (source / 'package/source').write_text('safe')
    destination = tmp_path / 'destination'; destination.mkdir()
    outside = tmp_path / 'outside'; outside.mkdir()
    (destination / 'package').symlink_to(outside, target_is_directory=True)
    (destination / '.builder-initializing.json').write_text(json.dumps({
        'owner_sha256': hashlib.sha256(b'owner').hexdigest(), 'sources': {}}))
    with pytest.raises(ValueError):
        initialize(source, destination, 'owner', {})
    assert not list(outside.iterdir())
