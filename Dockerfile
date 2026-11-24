# BASE_IMAGE is the verified Builder foundation built from the public basePack
# revision in sources.json. build.py reproduces it from source when absent.
ARG BASE_IMAGE=collab-builder/worker:step1
FROM ${BASE_IMAGE}
USER root
COPY src /opt/builder-hub/src
COPY sources.json /opt/builder-hub/sources.json
RUN python -c 'import sysconfig; from pathlib import Path; Path(sysconfig.get_path("purelib"),"builder_hub.pth").write_text("/opt/builder-hub/src\n")' \
    && /opt/builder-suite/cog-workbench/.pixi/envs/default/bin/python -c 'import sysconfig; from pathlib import Path; Path(sysconfig.get_path("purelib"),"builder_hub.pth").write_text("/opt/builder-hub/src\n")' \
    && printf '#!/bin/sh\nexec /var/collab-hub-api/.venv/bin/python -m builder_hub.cli_bridge claude "$@"\n' > /usr/local/bin/claude \
    && printf '#!/bin/sh\nexec /var/collab-hub-api/.venv/bin/python -m builder_hub.cli_bridge docker "$@"\n' > /usr/local/bin/docker \
    && chmod 755 /usr/local/bin/claude /usr/local/bin/docker
USER 1000:1000
ENTRYPOINT ["/bin/bash"]
CMD ["-c", "python -m builder_hub.hub_extension"]
