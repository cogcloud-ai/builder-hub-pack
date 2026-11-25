import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from builder_hub import workspace
from builder_hub.trust import inventory, verify


@pytest.fixture
def suite(tmp_path, monkeypatch):
    (tmp_path / 'cog-op-builder').mkdir()
    (tmp_path / 'cog-op-builder/repositories.json').write_text(json.dumps({
        'repositories': [{'name': 'cog-claude'}, {'name': 'cog-author'}]}))
    class Base:
        def __init__(self, workspace, **kwargs):
            self.workspace = workspace

        def root(self, value):
            path = (self.workspace / value).resolve()
            if not path.is_relative_to(self.workspace):
                raise ValueError('Outside workspace')
            return path

        def relative(self, value):
            return self.root(value).relative_to(self.workspace).as_posix()

        def call(self, root, task, *args, **kwargs):
            return (root, task)

        def start_builder(self, request, binding):
            return request

        def resume_builder(self, ident, decision=None):
            return 'resumed'

        def inspect_builder(self, ident):
            return {'cycle': {'request': {'execution_policy': self.recorded_policy}}}

        def package(self, request, envelope, destination):
            return destination

        def verify(self, root, operation):
            return operation
    monkeypatch.setitem(sys.modules, 'workbench_suite', SimpleNamespace(Suite=Base))
    monkeypatch.setitem(sys.modules, 'suite_web', SimpleNamespace())
    monkeypatch.setenv('BUILDER_EXECUTION_POLICY_FILE', str(tmp_path / 'policy.json'))
    hosted, _ = workspace.initialize(tmp_path)
    return hosted(), tmp_path


def test_only_manifest_packages_execute(suite):
    hosted, _ = suite
    assert hosted.call('cog-author', 'turn') == ('cog-author', 'turn')
    for path in ('cog-generated', 'cog-author/generated', '../outside'):
        with pytest.raises(ValueError):
            hosted.call(path, 'test')
    with pytest.raises(ValueError):
        hosted.verify('cog-generated', 'test')
    assert hosted.verify('cog-generated', 'check') == 'check'


def test_packages_cannot_replace_or_nest_in_trusted_code(suite):
    hosted, _ = suite
    assert hosted.package({}, {}, 'cog-new') == 'cog-new'
    for path in ('cog-author', 'cog-claude', 'cog-author/src/cog-new', '../cog-new'):
        with pytest.raises(ValueError):
            hosted.package({}, {}, path)


def test_unqualified_native_request_never_selects_trusted_local(suite):
    hosted, _ = suite
    request = hosted.start_builder({'max_attempts': 1, 'max_cost_units': 4}, {})
    assert request['execution_policy']['mode'] == 'docker'
    assert request['execution_policy']['image'] == 'sha256:' + '0' * 64
    hosted.recorded_policy = request['execution_policy']
    for decision in (None, {'verdict': 'accept'}):
        with pytest.raises(ValueError):
            hosted.resume_builder('fixture', decision)
    assert hosted.resume_builder('fixture', {'verdict': 'reject'}) == 'resumed'
    with pytest.raises(ValueError):
        hosted.start_builder({'max_attempts': True, 'max_cost_units': 4}, {})


def test_qualified_request_and_resume_keep_exact_policy(suite):
    hosted, root = suite
    (root / 'policy.json').write_text(json.dumps({'qualified': True, 'mode': 'docker', 'image': 'sha256:' + 'a' * 64}))
    request = hosted.start_builder({'max_attempts': 1, 'max_cost_units': 4}, {})
    hosted.recorded_policy = request['execution_policy']
    assert hosted.resume_builder('fixture', {'verdict': 'accept'}) == 'resumed'
    hosted.recorded_policy = {'mode': 'trusted-local'}
    with pytest.raises(ValueError):
        hosted.resume_builder('fixture')
    with pytest.raises(ValueError):
        hosted.start_builder({'execution_policy': {}, 'max_attempts': 1, 'max_cost_units': 4}, {})


def test_trust_inventory_detects_source_and_interpreter_changes(tmp_path):
    root = tmp_path
    package = root / 'cog-op-builder'; package.mkdir()
    (package / 'repositories.json').write_text('{"repositories":[]}')
    (package / 'src').mkdir(); (package / 'src/task.py').write_text('pass')
    (package / '.pixi').mkdir(); (package / '.pixi/python').write_text('interpreter')
    expected = inventory(root)
    (package / 'var').mkdir(); (package / 'var/data').write_text('retained state')
    verify(root, expected)
    (package / '.pixi/python').write_text('changed interpreter')
    with pytest.raises(ValueError):
        verify(root, expected)
    (package / '.pixi/python').write_text('interpreter')
    (package / 'src/extra.py').write_text('injected source')
    with pytest.raises(ValueError):
        verify(root, expected)
