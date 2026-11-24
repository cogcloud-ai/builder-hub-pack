"""Check the complete suite and Python environments before executing PVC code."""
import os
from .trust import verify

if __name__ == '__main__':
    verify('/opt/builder-suite')
    python = '/opt/builder-suite/cog-workbench/.pixi/envs/default/bin/python'
    os.execv(python, [python, '-m', 'builder_hub.workspace'])
