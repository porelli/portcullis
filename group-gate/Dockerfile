# python:3.15.2-alpine3.24
FROM docker.io/library/python:3.16.0a1-alpine3.24@sha256:57d59f9badcd47eabb3ed920d3bd5ae02f44664fc224ae57f1687980227741d2
# Wheels only (no compiler in the image), every file checked against its hash.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --root-user-action=ignore --disable-pip-version-check \
      --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt
COPY group-gate.py /app/group-gate.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# The group_gate_data mountpoint (the opened log): a fresh volume takes this
# owner, 10003 with the Hub's group 10001 (./portcullis up also sets it).
RUN install -d -o 10003 -g 10001 -m 0750 /data
# Non-root, no home: reads only world-readable mounts (compose: read-only
# root FS, tmpfs /tmp). No ENTRYPOINT: `./portcullis backup` runs its SQLite
# helpers as `docker run <this image> python3 -c ...` under the volume owner's uid.
USER 10003:10003
EXPOSE 8080
CMD ["python3", "-u", "/app/group-gate.py"]
