# python:3.15.2-alpine3.24
FROM python:3.15.2-alpine3.24@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211
# Wheels only (no compiler in the image), every file checked against its hash.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --root-user-action=ignore --disable-pip-version-check \
      --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt
COPY group-gate.py /app/group-gate.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Non-root, no home: reads only world-readable mounts (compose: read-only
# root FS, tmpfs /tmp). No ENTRYPOINT: `./portcullis backup` runs its SQLite
# helpers as `docker run <this image> python3 -c ...` under the volume owner's uid.
USER 10003:10003
EXPOSE 8080
CMD ["python3", "-u", "/app/group-gate.py"]
