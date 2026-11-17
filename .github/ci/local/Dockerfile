# The job container of .github/ci/local/run-job.sh and of the self-hosted
# runner (.github/ci/local/runner/): an Ubuntu 24.04 system container
# (systemd as PID 1, its own dockerd — privileged, so every job has its own
# engine, networks, ports and /etc/hosts) shaped like GitHub's ubuntu-24.04
# image for what ci.yml uses: user `runner` (1001, passwordless sudo,
# docker group), Docker CE + buildx + compose, git, jq, yq, shellcheck,
# python3 + venv, gcc (go test -race), Node.js LTS, Playwright's system
# packages, the official actions/runner. Go comes from actions/setup-go (or
# its local emulation) into /opt/hostedtoolcache.
FROM docker.io/library/ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8

ARG YQ_VERSION=v4.54.3
ARG YQ_SHA256=129534601871538efe0ba4c5e62a34fb1d5f469bcb975c4fddeb467d82974973
ARG RUNNER_VERSION=2.338.2
ARG RUNNER_SHA256=baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40
ARG NODE_MAJOR=26
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv dbus sudo ca-certificates curl wget gnupg git jq python3 python3-venv python3-pip \
      python3-yaml iproute2 iptables kmod procps acl attr file openssl rsync unzip xz-utils zstd shellcheck \
      dnsutils netcat-openbsd libnss3-tools gcc libc6-dev make sqlite3 tzdata lsb-release less \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" > /etc/apt/sources.list.d/docker.list \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin nodejs \
    && curl -fsSL -o /usr/local/bin/yq "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64" \
    && echo "${YQ_SHA256}  /usr/local/bin/yq" | sha256sum -c - && chmod 0755 /usr/local/bin/yq \
    && useradd -m -u 1001 -s /bin/bash runner && usermod -aG docker,systemd-journal runner \
    && echo 'runner ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/runner && chmod 0440 /etc/sudoers.d/runner \
    && systemctl enable docker containerd \
    && systemctl mask systemd-resolved.service getty.target console-getty.service systemd-logind.service 2>/dev/null || true

# Playwright's Chromium system packages (the e2e steps' `playwright
# install-deps` then finds them installed): the version tests/e2e pins.
COPY requirements.txt /tmp/e2e-requirements.txt
RUN python3 -m venv /tmp/pw && /tmp/pw/bin/pip install -q "$(grep -m1 '^playwright==' /tmp/e2e-requirements.txt)" \
    && /tmp/pw/bin/playwright install-deps chromium >/dev/null && rm -rf /tmp/pw /tmp/e2e-requirements.txt \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# The official GitHub Actions runner (used only by the self-hosted runner).
RUN mkdir -p /home/runner/actions-runner && cd /home/runner/actions-runner \
    && curl -fsSL -o r.tgz "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
    && echo "${RUNNER_SHA256}  r.tgz" | sha256sum -c - && tar xzf r.tgz && rm r.tgz \
    && ./bin/installdependencies.sh >/dev/null && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /home/runner/work /home/runner/.cache /home/runner/go /opt/hostedtoolcache /pcci \
    && chown -R runner:runner /home/runner /opt/hostedtoolcache /pcci

COPY docker-sanitize.sh /usr/local/bin/pcci-docker-sanitize
ENV RUNNER_TOOL_CACHE=/opt/hostedtoolcache AGENT_TOOLSDIRECTORY=/opt/hostedtoolcache ImageOS=ubuntu24
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
