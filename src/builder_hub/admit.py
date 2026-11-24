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
    while suite.path(ref).exists():
        try:
            entry = suite.load(ref)
        except ValueError:
            ref['revision'] += 1
            continue
        if entry['binding']['model']['id'] == args.model:
            print('Existing hosted Claude binding is still admitted for ' + args.model + '.')
            return
        ref['revision'] += 1
    request = json.loads((args.workspace / 'cog-claude/examples/bind-request.json').read_text())
    request['binding_id'] = ref['binding_id']
    request['revision'] = ref['revision']
    request['configuration']['model_id'] = args.model
    request['requirement']['model_id'] = args.model
    result = suite.bind('cog-claude', request)
    print(json.dumps({'status': 'admitted', 'model': args.model, 'binding': ref}))


if __name__ == '__main__':
    main()
