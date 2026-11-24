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
