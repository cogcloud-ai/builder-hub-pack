"""Admit the existing host-owned Claude subscription through the fixed bridge."""
import argparse
import json
from pathlib import Path
from .workspace import initialize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=Path('/opt/builder-suite'))
    parser.add_argument('--model', default='sonnet')
    args = parser.parse_args()
    suite_type, _ = initialize(args.workspace)
    suite = suite_type()
    ref = {'binding_id': 'hosted-claude', 'revision': 1}
    if suite.path(ref).exists():
        suite.load(ref)
        print('Existing hosted Claude binding is still admitted.')
        return
    request = json.loads((args.workspace / 'cog-claude/examples/bind-request.json').read_text())
    request['binding_id'] = ref['binding_id']
    request['configuration']['model_id'] = args.model
    request['requirement']['model_id'] = args.model
    result = suite.bind('cog-claude', request)
    print(json.dumps({'status': 'admitted', 'model': args.model, 'binding': ref}))


if __name__ == '__main__':
    main()
